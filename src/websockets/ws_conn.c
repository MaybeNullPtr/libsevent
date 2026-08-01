/* =========================================================================
 *  ws_conn.c — WebSocket 连接状态机实现 (v2: 异步写队列)
 *
 *  send_frame 构造帧后入写队列, 异步 flush.
 *  控制帧 (PING/CLOSE) 插入队首优先发送.
 *  ========================================================================= */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <time.h>

#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "sevent_i.h"
#include "ws_conn.h"
#include "ws_frame.h"
#include "ws_handshake.h"

#ifdef SEVENT_WS_THREAD_SAFE
#include "../../include/sevent_platform.h"
#define WS_LOCK(c)                                                                                                     \
    do {                                                                                                               \
        if((c))                                                                                                        \
            sevent_mutex_lock(&(c)->lock);                                                                             \
    } while(0)
#define WS_UNLOCK(c)                                                                                                   \
    do {                                                                                                               \
        if((c))                                                                                                        \
            sevent_mutex_unlock(&(c)->lock);                                                                           \
    } while(0)
#else
#define WS_LOCK(c) ((void)0)
#define WS_UNLOCK(c) ((void)0)
#endif

/* recv_buf 同时用于 HTTP 升级响应读取, 至少确保能放下 101 响应头 */
#define SEVENT_WS_RECV_MIN 1024
#define SEVENT_WS_RECV_DEFAULT 4096

/* 最大重定向次数 */
#define SEVENT_WS_MAX_REDIRECTS 5

/* on_close reason 串 (与 sizeof-1 计算强绑定, 改字面量须同步) */
#define SEVENT_WS_REASON_EOF "connection closed"
#define SEVENT_WS_REASON_READ_ERR "read error"

/* 发送标志 (RSV 位, 供未来的扩展使用) */
#define WS_SEND_RSV1 0x01
#define WS_SEND_RSV2 0x02
#define WS_SEND_RSV3 0x04

/* UTF-8 校验: 1=启用 (默认), 0=禁用. 纯运行时校验, 大消息下耗时约 1ns/字节.
 * 禁用后不校验 TEXT payload 和 Close reason 的 UTF-8 合法性 (RFC 违规,
 * 但对端通常不受影响). 编译时通过 -DSEVENT_WS_UTF8_CHECK=0 关闭. */
#ifndef SEVENT_WS_UTF8_CHECK
#define SEVENT_WS_UTF8_CHECK 1
#endif

/* 前向声明 */
static int  send_frame_raw(struct sevent_ws_conn *c, uint8_t opcode, const void *payload, size_t len, uint8_t flags);
static int  send_frame(struct sevent_ws_conn *c, uint8_t opcode, const void *payload, size_t len);
static void msg_end(struct sevent_ws_conn *c, bool is_bin); /* 消息结束统一收尾 (定义见接收段) */

static int  decompress_stream_chunk(struct sevent_ws_conn *c, const uint8_t *data, size_t len, bool is_bin);
static int  decompress_stream_end(struct sevent_ws_conn *c, bool is_bin);
static int  decompress_oneshot(struct sevent_ws_conn *c, const uint8_t *in, size_t in_len, bool is_bin);
static void on_write_ready(void *data);
static void on_data(void *data);
static void on_handshake_data(void *data);
static void on_connect_ready(void *data);
static void on_connect_timeout(void *data);

/* ====================================================================
 *  内部辅助
 * ==================================================================== */

/* UTF-8 校验 (RFC 3629). 返回 true 表示合法. SEVENT_WS_UTF8_CHECK=0 时跳过. */
static bool ws_utf8_validate(const uint8_t *data, size_t len) {
#if SEVENT_WS_UTF8_CHECK
    size_t i = 0;
    while(i < len) {
        uint8_t b = data[i];
        if(b <= 0x7F) {
            i++;
        } else if(b >= 0xC2 && b <= 0xDF) {
            if(i + 1 >= len || (data[i + 1] & 0xC0) != 0x80)
                return false;
            i += 2;
        } else if(b == 0xE0) {
            if(i + 2 >= len || (data[i + 1] & 0xC0) != 0x80 || (data[i + 2] & 0xC0) != 0x80)
                return false;
            if(data[i + 1] < 0xA0)
                return false; /* overlong */
            i += 3;
        } else if(b >= 0xE1 && b <= 0xEC) {
            if(i + 2 >= len || (data[i + 1] & 0xC0) != 0x80 || (data[i + 2] & 0xC0) != 0x80)
                return false;
            i += 3;
        } else if(b == 0xED) {
            if(i + 2 >= len || (data[i + 1] & 0xC0) != 0x80 || (data[i + 2] & 0xC0) != 0x80)
                return false;
            if(data[i + 1] > 0x9F)
                return false; /* surrogate U+D800-U+DFFF */
            i += 3;
        } else if(b >= 0xEE && b <= 0xEF) {
            if(i + 2 >= len || (data[i + 1] & 0xC0) != 0x80 || (data[i + 2] & 0xC0) != 0x80)
                return false;
            i += 3;
        } else if(b == 0xF0) {
            if(i + 3 >= len || (data[i + 1] & 0xC0) != 0x80 || (data[i + 2] & 0xC0) != 0x80 ||
               (data[i + 3] & 0xC0) != 0x80)
                return false;
            if(data[i + 1] < 0x90)
                return false; /* overlong */
            i += 4;
        } else if(b >= 0xF1 && b <= 0xF3) {
            if(i + 3 >= len || (data[i + 1] & 0xC0) != 0x80 || (data[i + 2] & 0xC0) != 0x80 ||
               (data[i + 3] & 0xC0) != 0x80)
                return false;
            i += 4;
        } else if(b == 0xF4) {
            if(i + 3 >= len || (data[i + 1] & 0xC0) != 0x80 || (data[i + 2] & 0xC0) != 0x80 ||
               (data[i + 3] & 0xC0) != 0x80)
                return false;
            if(data[i + 1] > 0x8F)
                return false; /* > U+10FFFF */
            i += 4;
        } else {
            return false; /* 0x80-0xBF standalone, 0xC0-0xC1, 0xF5-0xFF */
        }
    }
    return true;
#else
    (void)data;
    (void)len;
    return true;
#endif
}

static unsigned int xorshift32(unsigned int *seed) {
    unsigned int x = *seed;
    x              ^= x << 13;
    x              ^= x >> 17;
    x              ^= x << 5;
    *seed          = x;
    return x;
}

static void gen_mask_key(struct sevent_ws_conn *c, uint8_t key[4]) {
    unsigned int r = xorshift32(&c->mask_seed);
    key[0]         = (uint8_t)(r >> 24);
    key[1]         = (uint8_t)(r >> 16);
    key[2]         = (uint8_t)(r >> 8);
    key[3]         = (uint8_t)(r);
}

/* 校验握手响应中的扩展均为客户端已 offer 的 (RFC 6455 §9 开头: 服务器不得
 * 响应未请求的扩展; §4.1 第 5 条: 客户端收到未请求的扩展 MUST Fail the
 * WebSocket Connection). 参数层不校验 — RFC 7692 §7.1.2.1 允许服务器主动带
 * server_max_window_bits (即使 offer 没有). 返回 true=合法. */
static bool ws_extensions_ok(const char *extensions, bool offered_deflate) {
    if(extensions[0] == '\0')
        return true; /* 未带扩展头 */
    if(!offered_deflate)
        return false; /* 未 offer 任何扩展, 响应带扩展 = 违规 */
    const char *p = extensions;
    while(*p) {
        while(*p == ' ' || *p == '\t')
            p++; /* 跳前导空白 (逗号分隔后的 OWS) */
        if(*p == '\0')
            break; /* 尾部逗号后的空 token */
        /* 一个扩展: token *( ";" param ), 扩展间以 ',' 分隔 */
        const char *semi    = strchr(p, ';');
        const char *comma   = strchr(p, ',');
        const char *tok_end = semi ? (comma && comma < semi ? comma : semi) : (comma ? comma : p + strlen(p));
        const char *e       = tok_end;
        while(e > p && (e[-1] == ' ' || e[-1] == '\t'))
            e--; /* 去尾空白 */
        size_t n = (size_t)(e - p);
        if(n != strlen(WS_EXT_PMD) || strncmp(p, WS_EXT_PMD, n) != 0)
            return false;
        if(!comma)
            break;
        p = comma + 1;
    }
    return true;
}

/* RFC 6455 §7.4: 校验 Close 码是否合法 */
static bool ws_close_code_valid(uint16_t code) {
    if(code < SEVENT_WS_CLOSE_NORMAL)
        return false; /* 0-999 保留 */
    if(code == 1004 || code == 1005 || code == 1006)
        return false; /* 1004-1006 保留/仅内部 */
    if(code == 1015)
        return false; /* 1015 保留, MUST NOT 发送 (IANA) */
    /* 1012-1014 (Service Restart / Try Again Later / Bad Gateway):
     * RFC 6455 发布后 IANA 已注册, 应正常接受 (发送/接收两侧) */
    if(code >= 1016 && code <= 2999)
        return false; /* 1016-2999 未分配 */
    if(code > 4999)
        return false; /* 5000+ 保留/非法 */
    return true;
}

static void ws_close_socket(struct sevent_ws_conn *c) {
    if(c->io_handle) {
        sevent_io_unregister(c->ev, c->io_handle);
        c->io_handle = NULL;
    }
    if(c->fd >= 0) {
        close(c->fd);
        c->fd = SEVENT_INVALID_SOCKET;
    }
}

static void ws_enter_closed(struct sevent_ws_conn *c, uint16_t code, const char *reason, size_t reason_len) {
    if(c->state == WS_STATE_CLOSED || c->destroyed)
        return;
    c->state = WS_STATE_CLOSED;
    if(c->ping_timer) {
        sevent_timer_unregister(c->ev, c->ping_timer);
        c->ping_timer = NULL;
    }
    ws_close_socket(c);
    if(c->on_close)
        c->on_close(c->user_data, code, reason, reason_len);
}

static void ws_send_close_code(struct sevent_ws_conn *c, uint16_t code) {
    uint8_t cp[] = {(uint8_t)(code >> 8), (uint8_t)(code & 0xFF)};
    (void)send_frame(c, WS_OPCODE_CLOSE, cp, sizeof(cp));
    ws_enter_closed(c, code, "", 0);
}

static void ws_fatal(struct sevent_ws_conn *c, int err) {
    if(c->destroyed || c->state == WS_STATE_CLOSED)
        return;

    /* 协议错误: 尽力发 Close 帧 (RFC 6455 §7.1.1) */
    if(err == SEVENT_WS_ERR_PROTOCOL && c->state == WS_STATE_OPEN) {
        c->state     = WS_STATE_CLOSING;
        uint8_t cp[] = {0x03, (uint8_t)(SEVENT_WS_CLOSE_PROTOCOL_ERR & 0xFF)};
        (void)send_frame(c, WS_OPCODE_CLOSE, cp, sizeof(cp));
    }

    c->state = WS_STATE_CLOSED;
    if(c->connect_timer) {
        sevent_timer_unregister(c->ev, c->connect_timer);
        c->connect_timer = NULL;
    }
    if(c->ping_timer) {
        sevent_timer_unregister(c->ev, c->ping_timer);
        c->ping_timer = NULL;
    }
    ws_close_socket(c);
    if(c->on_error)
        c->on_error(c->user_data, err);
    /* on_error 后不再访问 c (用户可能在其中 destroy) */
}

/* ====================================================================
 *  接收缓冲
 * ==================================================================== */

/* 统一读 socket (固定 buffer, 无 realloc) */
static int recv_read(struct sevent_ws_conn *c) {
    /* 先 compact: 搬移未消费数据到头部 */
    if(c->recv_pos > 0) {
        size_t rem = c->recv_len - c->recv_pos;
        if(rem > 0)
            memmove(c->recv_buf, c->recv_buf + c->recv_pos, rem);
        c->recv_len = rem;
        c->recv_pos = 0;
    }
    size_t space = c->recv_cap - c->recv_len;
    if(space == 0)
        return 0;
    ssize_t n = read(c->fd, c->recv_buf + c->recv_len, space);
    if(n > 0)
        c->recv_len += (size_t)n;
    return (int)n;
}

/* 大帧流式读取: 从 recv_buf 分块回调 payload (MSG_STREAM 路径) */
static void stream_consume(struct sevent_ws_conn *c) {
    void *d      = c->user_data;
    bool  is_bin = (c->msg.opcode == WS_OPCODE_BINARY);

    while(c->recv_pos < c->recv_len && c->stream_remaining > 0) {
        if(c->destroyed)
            return;
        size_t avail = c->recv_len - c->recv_pos;
        size_t chunk = (avail < c->recv_cap) ? avail : c->recv_cap;
        if(chunk > c->stream_remaining)
            chunk = (size_t)c->stream_remaining;
        bool last = (chunk == c->stream_remaining) && c->stream_fin;

        if(c->msg.compressed) {
            /* 压缩流: 不在此发 fin, 由 decompress_stream_end 统一发 */
            if(decompress_stream_chunk(c, c->recv_buf + c->recv_pos, chunk, is_bin) != 0)
                return;
        } else {
            if(c->on_message) {
                /* total 仅在 fin 回调时携带消息总长, 非 fin 回调传 0 */
                c->on_message(d, c->recv_buf + c->recv_pos, chunk, is_bin, last, last ? c->msg.total : 0);
                if(last)
                    c->msg.fin_sent = true; /* fin 回调已发, msg_end 不补发 */
            }
            if(c->destroyed)
                return;
        }

        c->recv_pos         += chunk;
        c->stream_remaining -= chunk;
    }
    if(c->stream_remaining == 0) {
        if(c->stream_fin) {
            /* [状态机] MSG_STREAM --fin 帧--> MSG_NONE: 统一收尾
             * (压缩补 tail + fin 回调由 msg_end/decompress_stream_end 负责) */
            msg_end(c, is_bin);
        }
        /* fin=0: 当前流式帧消费完, 保持 MSG_STREAM 等下一帧 */
    }
}

/* ====================================================================
 *  异步写队列
 *
 *  模块边界: 纯数据流逻辑, 零协议依赖 (不碰消息状态机/压缩).
 *  语义约定 (修改时注意):
 *    - 节点持有 data 所有权 (入队即转移, 须为堆分配; OOM 时 free 调用者 data)
 *    - 部分写由 io_write 回调 (on_write_ready) 驱动续写
 *    - 控制帧 (is_ctrl) 插队首优先发送
 *  若其他模块需要类似 queue: 抽为独立 ws_writeq.c 并补部分写续写单测.
 * ==================================================================== */

static int ws_enqueue(struct sevent_ws_conn *c, uint8_t *data, size_t len, bool is_ctrl) {
    ws_write_node *n = SEVENT_I_NEW(n);
    if(!n) {
        sevent_i_free(data);
        return -1;
    }
    n->data    = data;
    n->len     = len;
    n->offset  = 0;
    n->is_ctrl = is_ctrl;
    n->next    = NULL;

    if(is_ctrl && c->write_head) {
        /* 控制帧插入队首 */
        n->next       = c->write_head;
        c->write_head = n;
    } else {
        /* 数据帧追加队尾 */
        if(c->write_tail)
            c->write_tail->next = n;
        else
            c->write_head = n;
        c->write_tail = n;
    }
    c->write_count++;
    return 0;
}

/* 清空写队列 (释放所有节点); 用于连接关闭与重定向 (残留节点不得写到新连接) */
static void ws_queue_clear(struct sevent_ws_conn *c) {
    ws_write_node *wn = c->write_head;
    while(wn) {
        ws_write_node *n = wn->next;
        sevent_i_free(wn->data);
        sevent_i_free(wn);
        wn = n;
    }
    c->write_head  = NULL;
    c->write_tail  = NULL;
    c->write_count = 0;
}

/* 尝试写队列中的数据; 返回 0=写完, >0=剩余节点数, <0=致命写错误 */
static int ws_flush(struct sevent_ws_conn *c) {
    while(c->write_head) {
        ws_write_node *n = c->write_head;
        ssize_t        w = write(c->fd, n->data + n->offset, n->len - n->offset);
        if(w > 0) {
            n->offset += (size_t)w;
            if(n->offset < n->len)
                return (int)c->write_count; /* 部分写入, 停止本轮 flush */
            /* 节点写完, 释放 */
            c->write_head = n->next;
            if(!c->write_head)
                c->write_tail = NULL;
            c->write_count--;
            sevent_i_free(n->data);
            sevent_i_free(n);
        } else if(w < 0) {
            if(errno == EAGAIN || errno == EINTR)
                return (int)c->write_count;
            /* 致命写错误 — 清理当前节点, 返回 -1 由调用者调 ws_fatal */
            c->write_head = n->next;
            if(!c->write_head)
                c->write_tail = NULL;
            c->write_count--;
            sevent_i_free(n->data);
            sevent_i_free(n);
            return -1;
        } else {
            /* write 返回 0 (不可能在 TCP 上发生) */
            c->write_head = n->next;
            if(!c->write_head)
                c->write_tail = NULL;
            c->write_count--;
            sevent_i_free(n->data);
            sevent_i_free(n);
        }
    }
    return 0;
}

/* 根据是否有待写数据更新 io_write 注册 */
static void ws_update_io(struct sevent_ws_conn *c, void (*read_cb)(void *)) {
    sevent_io_handler h;
    h.fd       = c->fd;
    h.io_read  = read_cb;
    h.io_write = c->write_head ? on_write_ready : NULL;
    h.data     = c;
    if(c->io_handle)
        sevent_io_unregister(c->ev, c->io_handle);
    c->io_handle = sevent_io_register(c->ev, &h);
    if(!c->io_handle)
        ws_enter_closed(c, 0, "", 0);
}

/* 前向声明 */
static void on_write_ready(void *data);

/* ---- 解压: 协议层直接操作 zlib (分批输出, 见 doc/deflate-decompress-fix.md) ----
 * RFC 7692 §7.2.1/§7.2.2: 发送端压缩消息后剥掉尾部 00 00 FF FF 再发送,
 * 接收端解压前必须把 4 字节 00 00 FF FF 补回消息尾部.
 * 解压输出大小不可预判, 用固定缓冲分批循环 inflate:
 * 输入一段, 每次解满一批就 on_message 一批 (fin=false),
 * 压缩消息结束由 msg_end → decompress_stream_end 统一收尾 (补 tail + fin),
 * 单帧压缩 (oneshot) 路径自行发 fin=true.
 * total 压缩路径一律传 0 (解压前无法预知原始长度). */

/* 单批解压输出缓冲: 固定大小, 堆分配 (嵌入式栈小, 不上栈) */
#define SEVENT_WS_DECOMP_BATCH 4096

/* 三个解压函数 (chunk/end/oneshot) 共享同一循环骨架: next_out/avail_out →
 * inflate(flush) → 错误处理 → 分批 on_message → destroyed 检查 → 退出.
 * 差异点 (修改任一函数须同步另两处; 曾因三处细节不一致出过两次 bug):
 *   - flush 模式: chunk 用 Z_NO_FLUSH (等下一块输入),
 *     end/oneshot 用 Z_SYNC_FLUSH (必须到 sync 点)
 *   - 错误接受集: end/oneshot 额外接受 Z_STREAM_END
 *   - 退出条件: chunk 要求输入消费完 (avail_in==0),
 *     end/oneshot 只要求输出有空 (avail_out>0) */

/* 固定缓冲循环 inflate: 返回 0=OK, 协议错误=SEVENT_WS_ERR_PROTOCOL */
static int decompress_stream_chunk(struct sevent_ws_conn *c, const uint8_t *data, size_t len, bool is_bin) {
#ifdef SEVENT_WS_DEFLATE
    if(!c->on_message)
        return 0;
    z_stream *z = &c->deflate->inflate;
    /* 每次调用都是新 chunk: 循环保证输入消费完才返回, 重置输入安全 */
    z->next_in  = (uint8_t *)data;
    z->avail_in = (uInt)len;

    uint8_t *batch = (uint8_t *)sevent_i_malloc(SEVENT_WS_DECOMP_BATCH);
    if(!batch)
        return SEVENT_ERR_NOMEM;
    int ret = SEVENT_WS_ERR_PROTOCOL;

    for(;;) {
        z->next_out  = batch;
        z->avail_out = (uInt)SEVENT_WS_DECOMP_BATCH;
        int rc       = inflate(z, Z_NO_FLUSH);
        if(rc == Z_BUF_ERROR && z->avail_in > 0) {
            /* 有输入却无进展: 异常 */
            inflateReset(z);
            goto out;
        }
        if(rc != Z_OK && rc != Z_BUF_ERROR) {
            inflateReset(z);
            goto out;
        }
        size_t used = SEVENT_WS_DECOMP_BATCH - z->avail_out;
        if(used > 0) {
            c->on_message(c->user_data, batch, used, is_bin, false, 0);
            if(c->destroyed) {
                ret = 0; /* 回调内销毁, 中止 */
                goto out;
            }
        }
        if(z->avail_in == 0 && z->avail_out > 0)
            break; /* 输入消费完且输出未满; block 积压由 end 收尾 */
        /* 输出满 → 换下一批 */
    }
    ret = 0;
out:
    sevent_i_free(batch);
    return ret;
#else
    return -1;
#endif
}

/* 消息收尾: 补喂发送端剥掉的 0x0000FFFF (RFC 7692 §7.2.2, autobahn
 * endDecompressMessage 同款), Z_SYNC_FLUSH 吐尽积压, 发 fin */
static int decompress_stream_end(struct sevent_ws_conn *c, bool is_bin) {
#ifdef SEVENT_WS_DEFLATE
    if(!c->on_message)
        return 0;
    z_stream            *z       = &c->deflate->inflate;
    static const uint8_t tail[4] = {0x00, 0x00, 0xFF, 0xFF};
    z->next_in                   = (uint8_t *)tail; /* 只喂一次 */
    z->avail_in                  = 4;

    uint8_t *batch = (uint8_t *)sevent_i_malloc(SEVENT_WS_DECOMP_BATCH);
    if(!batch)
        return SEVENT_ERR_NOMEM;
    int ret = SEVENT_WS_ERR_PROTOCOL;

    for(;;) {
        z->next_out  = batch;
        z->avail_out = (uInt)SEVENT_WS_DECOMP_BATCH;
        int rc       = inflate(z, Z_SYNC_FLUSH);
        if(rc == Z_BUF_ERROR && z->avail_in > 0) {
            /* 有输入却无进展: 异常 */
            inflateReset(z);
            goto out;
        }
        if(rc != Z_OK && rc != Z_STREAM_END && rc != Z_BUF_ERROR) {
            inflateReset(z);
            goto out;
        }
        size_t used = SEVENT_WS_DECOMP_BATCH - z->avail_out;
        if(used > 0) {
            c->on_message(c->user_data, batch, used, is_bin, false, 0);
            if(c->destroyed) {
                ret = 0;
                goto out;
            }
        }
        if(z->avail_out > 0)
            break; /* 到达 sync 点, 积压清空 */
    }
    /* fin 回调恰好一次: 数据已由 frag_flush/stream_consume 的 last_flag 以 fin 回调
     * 送出时 (fin_sent 已置), 这里只补 tail 不再重复发 (消息结束收尾见 msg_end) */
    if(!c->msg.fin_sent) {
        c->msg.fin_sent = true;
        c->on_message(c->user_data, batch, 0, is_bin, true, 0);
    }
    if(c->deflate->server_no_context_takeover)
        inflateReset(z);
    ret = 0;
out:
    sevent_i_free(batch);
    return ret;
#else
    return -1;
#endif
}

/* 单帧整条消息解压: 拼 tail 后循环解到 sync 点, 直接发 on_message.
 * 与压缩分片路径一致, 不做 UTF-8 校验 (解压后码点可能跨批). */
static int decompress_oneshot(struct sevent_ws_conn *c, const uint8_t *in, size_t in_len, bool is_bin) {
#ifdef SEVENT_WS_DEFLATE
    if(!c->on_message)
        return 0;
    uint8_t *buf = (uint8_t *)sevent_i_malloc(in_len + 4);
    if(!buf)
        return SEVENT_ERR_NOMEM;
    memcpy(buf, in, in_len);
    buf[in_len]     = 0x00;
    buf[in_len + 1] = 0x00;
    buf[in_len + 2] = 0xFF;
    buf[in_len + 3] = 0xFF;

    z_stream *z = &c->deflate->inflate;
    z->next_in  = buf;
    z->avail_in = (uInt)(in_len + 4);

    uint8_t *batch = (uint8_t *)sevent_i_malloc(SEVENT_WS_DECOMP_BATCH);
    if(!batch) {
        sevent_i_free(buf);
        return SEVENT_ERR_NOMEM;
    }
    int ret = SEVENT_WS_ERR_PROTOCOL;

    for(;;) {
        z->next_out  = batch;
        z->avail_out = (uInt)SEVENT_WS_DECOMP_BATCH;
        int rc       = inflate(z, Z_SYNC_FLUSH);
        if(rc == Z_BUF_ERROR && z->avail_in > 0) {
            inflateReset(z);
            goto out;
        }
        if(rc != Z_OK && rc != Z_STREAM_END && rc != Z_BUF_ERROR) {
            inflateReset(z);
            goto out;
        }
        size_t used = SEVENT_WS_DECOMP_BATCH - z->avail_out;
        if(used > 0) {
            c->on_message(c->user_data, batch, used, is_bin, false, 0);
            if(c->destroyed) {
                ret = 0;
                goto out;
            }
        }
        if(z->avail_out > 0)
            break;
    }
    c->on_message(c->user_data, batch, 0, is_bin, true, 0);
    if(c->deflate->server_no_context_takeover)
        inflateReset(z); /* 与流式路径一致: 每条消息结束重置解压上下文 */
    ret = 0;
out:
    sevent_i_free(batch);
    sevent_i_free(buf);
    return ret;
#else
    return -1;
#endif
}

/* ---- send_message: 含压缩的 TEXT/BINARY 发送 ---- */
static int send_message(struct sevent_ws_conn *c, uint8_t opcode, const void *payload, size_t len) {
    /* NONE=显式关闭发送压缩 (RFC 7692 允许消息不压缩, RSV1=0) */
    if(c->deflate && c->deflate_level != SEVENT_WS_DEFLATE_LEVEL_NONE &&
       (opcode == WS_OPCODE_TEXT || opcode == WS_OPCODE_BINARY)) {
        size_t   cap  = ws_deflate_compress_maxlen(c->deflate, len);
        uint8_t *comp = (uint8_t *)sevent_i_malloc(cap);
        if(!comp)
            return SEVENT_ERR_NOMEM;
        if(!ws_deflate_compress(c->deflate, payload, len, comp, &cap)) {
            sevent_i_free(comp);
            return SEVENT_WS_ERR_PROTOCOL;
        }
        int r = send_frame_raw(c, opcode, comp, cap, WS_SEND_RSV1);
        sevent_i_free(comp);
        return r;
    }
    return send_frame(c, opcode, payload, len);
}

/* ====================================================================
 *  发送帧: 构造 → 入队 → flush
 * ==================================================================== */

static int send_frame_raw(struct sevent_ws_conn *c, uint8_t opcode, const void *payload, size_t len, uint8_t flags) {
    /* RFC 6455 §7.1.6: 数据帧 (TEXT/BINARY/CONT) 仅 OPEN 可发;
     * 控制帧 (PING/PONG/CLOSE) OPEN/CLOSING 均可发 (关闭握手期间仍可回 PONG). */
    bool is_ctrl = (opcode == WS_OPCODE_PING || opcode == WS_OPCODE_PONG || opcode == WS_OPCODE_CLOSE);
    if(c->state == WS_STATE_CLOSING && !is_ctrl)
        return SEVENT_ERR_INVAL;
    if(c->state != WS_STATE_OPEN && c->state != WS_STATE_CLOSING)
        return SEVENT_ERR_INVAL;

    uint8_t mask_key[4];
    gen_mask_key(c, mask_key);
    uint8_t hdr[16];
    int     hdr_len = ws_frame_build_header(hdr, 1, (flags & WS_SEND_RSV1) ? 1 : 0, opcode, mask_key, len);
    if(hdr_len < 0)
        return SEVENT_ERR_INVAL;

    size_t   total = (size_t)hdr_len + len;
    uint8_t *buf   = (uint8_t *)sevent_i_malloc(total);
    if(!buf)
        return SEVENT_ERR_NOMEM;
    memcpy(buf, hdr, (size_t)hdr_len);
    if(len > 0 && payload) {
        memcpy(buf + hdr_len, payload, len);
        ws_frame_apply_mask(buf + hdr_len, len, mask_key);
    }

    /* RFC 6455 §5.5: 控制帧 payload 不得超过 125 */
    if(is_ctrl && len > 125) {
        sevent_i_free(buf);
        return SEVENT_ERR_INVAL;
    }
    /* RFC 6455 §7.4: Close 帧状态码合法性 */
    if(opcode == WS_OPCODE_CLOSE && len >= 2) {
        const uint8_t *cp         = (const uint8_t *)payload;
        uint16_t       close_code = (uint16_t)(cp[0] << 8 | cp[1]);
        if(!ws_close_code_valid(close_code)) {
            sevent_i_free(buf);
            return SEVENT_ERR_INVAL;
        }
    }

    if(ws_enqueue(c, buf, total, is_ctrl) != 0)
        return SEVENT_ERR_NOMEM;
    if(ws_flush(c) < 0)
        return SEVENT_WS_ERR_WRITE;

    /* 队列非空则注册可写回调 (flush 可能在 io_write 回调内驱动) */
    if(c->write_head) {
        void (*rcb)(void *) = (c->state == WS_STATE_OPEN) ? on_data : NULL;
        ws_update_io(c, rcb);
    }

    return SEVENT_SUCCESS;
}

static int send_frame(struct sevent_ws_conn *c, uint8_t opcode, const void *payload, size_t len) {
    return send_frame_raw(c, opcode, payload, len, 0);
}

/* ====================================================================
 *  重定向支持
 * ==================================================================== */

/* 解析 Location: 支持 ws://host[:port]/path 和 /relative/path */
static int ws_redirect_parse(struct sevent_ws_conn *c, const char *loc) {
    if(loc[0] == '/') {
        strncpy(c->path, loc, sizeof(c->path) - 1);
        c->path[sizeof(c->path) - 1] = '\0';
        return 0;
    }
    if(strncmp(loc, "ws://", 5) != 0)
        return -1;
    loc += 5;

    const char *p = loc;
    while(*p && *p != ':' && *p != '/')
        p++;
    size_t hlen = (size_t)(p - loc);
    if(hlen == 0 || hlen >= sizeof(c->host))
        return -1;
    memcpy(c->host, loc, hlen);
    c->host[hlen] = '\0';

    if(*p == ':') {
        long port = 0;
        p++;
        while(*p >= '0' && *p <= '9') {
            port = port * 10 + (long)(*p - '0');
            p++;
        }
        if(port <= 0 || port > 65535)
            return -1;
        c->port = (uint16_t)port;
    } else {
        c->port = WS_DEFAULT_PORT;
    }
    if(*p == '/') {
        strncpy(c->path, p, sizeof(c->path) - 1);
        c->path[sizeof(c->path) - 1] = '\0';
    } else {
        strncpy(c->path, "/", sizeof(c->path));
    }
    return 0;
}

/* ---- 创建 nonblock TCP socket + connect (EINPROGRESS 也算成功) ---- */
static int ws_tcp_connect(const char *host, uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if(fd < 0)
        return -1;
        /* 最佳尝试 SO_REUSEADDR — 失败不影响建连 */
#ifdef SO_REUSEADDR
    {
        int on = 1;
        (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    }
#endif
    int fl = fcntl(fd, F_GETFL);
    if(fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0) {
        close(fd);
        return -1;
    }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    if(inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
        close(fd);
        return -1;
    }
    int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if(rc < 0 && errno != EINPROGRESS) {
        close(fd);
        return -1;
    }
    return fd;
}

/* ---- PING 定时器: 按 interval 发空 PING ---- */
static void on_ping_timer(void *data) {
    struct sevent_ws_conn *c = (struct sevent_ws_conn *)data;
    WS_LOCK(c);
    if(c->destroyed || c->state != WS_STATE_OPEN) {
        WS_UNLOCK(c);
        return;
    }
    (void)send_frame(c, WS_OPCODE_PING, NULL, 0);
    WS_UNLOCK(c);
}

/* ---- 为已连接的 fd 注册 IO 回调 + 连接超时定时器 ---- */
static bool ws_register_connect_io(struct sevent_ws_conn *c, int fd) {
    c->io_handle = sevent_io_register(c->ev, &(sevent_io_handler){.fd = fd, .io_write = on_connect_ready, .data = c});
    if(!c->io_handle) {
        close(fd);
        return false;
    }
    c->fd    = fd;
    c->state = WS_STATE_CONNECTING;
    int t_ms = c->connect_timeout_ms;
    if(t_ms == 0)
        t_ms = SEVENT_WS_CONNECT_TIMEOUT_MS;
    if(t_ms > 0) {
        c->connect_timer = sevent_timer_register(c->ev, (unsigned int)t_ms, on_connect_timeout, c);
        if(!c->connect_timer) {
            ws_close_socket(c);
            return false;
        }
    }
    return true;
}

/* 重连: 关闭旧 socket, 创建新 TCP 连接, 注册 on_connect_ready */
static bool ws_redirect_reconnect(struct sevent_ws_conn *c) {
    /* 清理旧连接 */
    if(c->connect_timer) {
        sevent_timer_unregister(c->ev, c->connect_timer);
        c->connect_timer = NULL;
    }
    ws_close_socket(c);
    c->recv_len = 0;
    c->recv_pos = 0;

    /* 重置消息接收状态机 (旧连接可能残留未完成消息) */
    c->msg.mode         = WS_MSG_NONE;
    c->msg.compressed   = false;
    c->msg.total        = 0;
    c->msg.fin_sent     = false;
    c->frag_len         = 0;
    c->stream_remaining = 0;
    c->stream_fin       = false;

    /* 清写队列: 旧连接残留的握手请求节点 (部分写) 不得写到新连接 */
    ws_queue_clear(c);

    int fd = ws_tcp_connect(c->host, c->port);
    if(fd < 0)
        return false;
    return ws_register_connect_io(c, fd);
}

/* ====================================================================
 *  IO 回调: on_write_ready (可写, 驱动写队列)
 * ==================================================================== */

static void on_write_ready(void *data) {
    struct sevent_ws_conn *c = (struct sevent_ws_conn *)data;
    WS_LOCK(c);
    int remain = ws_flush(c);
    if(remain < 0) {
        WS_UNLOCK(c);
        ws_fatal(c, SEVENT_WS_ERR_WRITE);
        return;
    }
    if(remain == 0) {
        /* 队列已空, 注销可写回调 (保持可读).
         * HANDSHAKE 阶段 (握手请求部分写续写完成) 读回调是 on_handshake_data. */
        /* FIXME(close-handshake): CLOSING 状态下 rcb=NULL → ws_update_io(NULL)
         * → sevent_io_register 拒绝无回调注册 → ws_enter_closed(0) 误触发:
         * shutdown 后写队列 flush 完成时提前 on_close + 强关 socket, 对端 CLOSE
         * 未收到, 关闭握手不完整 (RFC 6455 §7.1.2 "both sent and received" 才
         * clean close; §7.1.1 对端 MUST 回 CLOSE).
         * 修复方案: CLOSING 时 rcb=on_data (继续读等对端 CLOSE) + close_timer
         * 超时兜底 (RFC 6455 未规定关闭握手超时, 5s 是业界常用实现选择).
         * 待后续处理, 当前不动. */
        void (*rcb)(void *) = NULL;
        if(c->state == WS_STATE_OPEN)
            rcb = on_data;
        else if(c->state == WS_STATE_HANDSHAKE)
            rcb = on_handshake_data;
        ws_update_io(c, rcb);
    }
    /* 否则继续等下一次可写事件 */
    WS_UNLOCK(c);
}

/* ====================================================================
 *  帧处理 (接收方向, OPEN 状态)
 * ==================================================================== */

static int frag_append(struct sevent_ws_conn *c, const uint8_t *data, size_t len) {
    if(len == 0)
        return 0;
    if(len > c->recv_cap)
        return -1; /* 单分片超过缓冲区 (大帧由流式路径处理) */
    /* 放不下时先 flush 当前积压 (fin=0) 腾空间 */
    if(c->frag_len + len > c->recv_cap) {
        if(c->msg.compressed) {
            /* 压缩分片: 整块 frag_buf 喂给流式解压 (解压流式化后无消息边界问题) */
            if(c->on_message && c->frag_len > 0) {
                bool is_bin = (c->msg.opcode == WS_OPCODE_BINARY);
                decompress_stream_chunk(c, c->frag_buf, c->frag_len, is_bin);
                if(c->destroyed)
                    return 0;
            }
        } else if(c->on_message && c->frag_len > 0) {
            void *d      = c->user_data;
            bool  is_bin = (c->msg.opcode == WS_OPCODE_BINARY);
            c->on_message(d, c->frag_buf, c->frag_len, is_bin, false, 0);
            if(c->destroyed)
                return 0;
        }
        c->frag_len = 0;
    }
    c->msg.total += len;
    memcpy(c->frag_buf + c->frag_len, data, len);
    c->frag_len += len;
    return 0;
}

/* 消息结束统一收尾: MSG_FRAG / MSG_STREAM → MSG_NONE
 * 两个独立职责, 互不耦合:
 *   1. 压缩消息必补 tail (RFC 7692 §7.2.2: 发送端剥掉 00 00 FF FF, 接收端补回).
 *      与数据送达方式无关 — 数据可能经 frag_buf 余量 / while 刷出 / stream_consume
 *      送达, 消息结束都必须补 tail. (修复: 此前由 fin_sent 隐式控制, 数据恰好
 *      recv_cap 整数倍 (fin 帧 0 字节) 时 fin_sent 未置/已置都会漏补, 导致下一条
 *      消息压缩流错位)
 *   2. on_message(fin=true) 恰好一次 (fin_sent 保证):
 *      - 数据已以 fin 回调送出 (frag_flush last_flag / stream_consume last /
 *        decompress_stream_end 内部) → fin_sent=true, 不重复
 *      - 纯空消息 (全部分片 0 长度) / 流式后的 0 字节终止帧 → fin_sent 未置,
 *        补发空消息通知上层消息结束 (case 6.1.2) */
static void msg_end(struct sevent_ws_conn *c, bool is_bin) {
    if(c->msg.mode != WS_MSG_NONE) {
        if(c->msg.compressed) {
            /* 压缩流收尾: 补 tail + (fin_sent 未置时) 发 fin 回调 */
            decompress_stream_end(c, is_bin);
        } else if(!c->msg.fin_sent && c->on_message) {
            c->on_message(c->user_data, NULL, 0, is_bin, true, c->msg.total);
            c->msg.fin_sent = true;
        }
    }
    c->msg.mode       = WS_MSG_NONE;
    c->msg.compressed = false;
    c->msg.total      = 0;
    c->msg.fin_sent   = false; /* 下一条消息重新计数 */
    c->frag_len       = 0;
}

/* 从 frag_buf 吐出完整块给 on_message, fin=1 表示最后一次 (MSG_FRAG 路径) */
static int frag_flush(struct sevent_ws_conn *c, bool fin) {
    void *d      = c->user_data;
    bool  is_bin = (c->msg.opcode == WS_OPCODE_BINARY);

    /* 刷出完整 recv_cap 块。
     *
     *  条件 (fin || frag_len > recv_cap || msg.compressed):
     *    - fin=1 → 消息结束了，必须把数据全刷出去
     *    - frag_len > recv_cap → 缓冲区积压超过一块，必须刷（否则放不下）
     *    - fin=0 && frag_len == recv_cap → 非压缩精确填满时不刷，
     *      留在缓冲区里等下一帧。避免服务器用单独的 0 字节终止帧
     *      发 fin=1 时，这里已经把数据用 fin=0 刷出去了。
     *    - msg.compressed → 压缩分片整块喂流式解压，无上述边界问题，
     *      frag_len == recv_cap 即刷（否则下一片会溢出）。
     */
    /* FIXME(utf8-frag): 分片 TEXT 消息的 UTF-8 校验不完整 — 下面 while 刷出的
     * 完整块 (>= recv_cap) 直接回调不校验, 仅本函数 fin 分支的余量 (< recv_cap)
     * 在此校验. 无效 UTF-8 落在完整块内时漏检 (RFC 6455 §5.6 要求整条消息合法).
     * 修复方案: 增量 UTF-8 校验器 (跨块保留至多 3 字节尾态), 完整块也过校验.
     * 待后续处理, 当前不动. */
    while(c->frag_len >= c->recv_cap && (fin || c->frag_len > c->recv_cap || c->msg.compressed)) {
        /* 这次刷完 frag_buf 就空了 → 如果 fin=1 这就是最后一块 */
        bool last_flag = fin && (c->frag_len == c->recv_cap);
        if(last_flag)
            c->msg.fin_sent = true; /* fin 回调已发, msg_end 不补发 */
        if(c->msg.compressed) {
            decompress_stream_chunk(c, c->frag_buf, c->recv_cap, is_bin);
        } else {
            /* total 仅在 fin 回调时携带消息总长, 非 fin 回调传 0 */
            c->on_message(d, c->frag_buf, c->recv_cap, is_bin, last_flag, last_flag ? c->msg.total : 0);
        }
        if(c->destroyed)
            return 0;
        c->frag_len -= c->recv_cap;
        memmove(c->frag_buf, c->frag_buf + c->recv_cap, c->frag_len);
    }
    if(fin) {
        /* [状态机] MSG_FRAG --fin 帧--> MSG_NONE: 刷余量 + 统一收尾
         * (压缩补 tail 由 msg_end 统一负责, 不在此重复调 end) */
        if(c->frag_len > 0) {
            if(c->msg.compressed) {
                decompress_stream_chunk(c, c->frag_buf, c->frag_len, is_bin);
                if(c->destroyed)
                    return 0;
            } else {
                /* RFC 6455 §5.6: 分片 TEXT 结束时校验 UTF-8 */
                if(!is_bin && !ws_utf8_validate(c->frag_buf, c->frag_len)) {
                    ws_send_close_code(c, SEVENT_WS_CLOSE_INVALID_PAYLOAD);
                    return 0;
                }
                c->msg.fin_sent = true;
                c->on_message(d, c->frag_buf, c->frag_len, is_bin, true, c->msg.total);
            }
            if(c->destroyed)
                return 0;
            c->frag_len = 0;
        }
        msg_end(c, is_bin);
    }
    return 0;
}

/* 刷出 frag_buf 余量 (fin=0 回调), 用于 FRAG→STREAM 切换时保持数据顺序:
 * 小帧积压在 frag_buf 中未发, 必须先于大 CONT 帧的流式数据发出. */
static void frag_flush_tail(struct sevent_ws_conn *c) {
    if(c->frag_len == 0)
        return;
    bool is_bin = (c->msg.opcode == WS_OPCODE_BINARY);
    if(c->msg.compressed) {
        decompress_stream_chunk(c, c->frag_buf, c->frag_len, is_bin);
    } else if(c->on_message) {
        c->on_message(c->user_data, c->frag_buf, c->frag_len, is_bin, false, 0);
    }
    c->frag_len = 0;
}

/* ====================================================================
 *  Opcode 处理器 (从 process_frames 提取)
 *  返回: 0=OK, >0=错误码, <0=回调内调用了 close (c 仍存活)
 * ==================================================================== */

static int handle_text_binary(struct sevent_ws_conn *c, const ws_frame_header *hdr, const uint8_t *payload) {
    /* 新消息首帧 (TEXT/BINARY): 必须无消息进行中, 否则协议错误 */
    if(c->msg.mode != WS_MSG_NONE)
        return SEVENT_WS_ERR_PROTOCOL;
    if(hdr->fin) {
        /* 单帧消息: 直接回调, 不驻留消息状态 */
        /* RFC 6455 §5.6: TEXT 帧 payload 必须是 UTF-8 */
        if(hdr->opcode == WS_OPCODE_TEXT && !ws_utf8_validate(payload, (size_t)hdr->payload_len)) {
            ws_send_close_code(c, SEVENT_WS_CLOSE_INVALID_PAYLOAD);
            return -1;
        }
        if(c->on_message) {
            c->on_message(c->user_data,
                          payload,
                          (size_t)hdr->payload_len,
                          (hdr->opcode == WS_OPCODE_BINARY),
                          true,
                          hdr->payload_len);
            if(c->destroyed)
                return -1;
        }
    } else {
        /* [状态机] MSG_NONE → MSG_FRAG: 分片消息首帧 (数据走 frag_append/frag_flush).
         * opcode 消息级决定; compressed 由 process_frames 的 RSV1 分支置位 */
        c->msg.opcode   = hdr->opcode;
        c->msg.total    = 0;
        c->msg.fin_sent = false;
        c->msg.mode     = WS_MSG_FRAG;
        if(frag_append(c, payload, (size_t)hdr->payload_len) != 0)
            return SEVENT_ERR_NOMEM;
        frag_flush(c, false);
        if(c->destroyed)
            return -1;
    }
    return 0;
}

static int handle_cont(struct sevent_ws_conn *c, const ws_frame_header *hdr, const uint8_t *payload) {
    /* CONT 帧: 必须处于消息进行中 (FRAG/STREAM), 保持当前 mode */
    if(c->msg.mode == WS_MSG_NONE)
        return SEVENT_WS_ERR_PROTOCOL;
    if(frag_append(c, payload, (size_t)hdr->payload_len) != 0)
        return SEVENT_ERR_NOMEM;
    frag_flush(c, hdr->fin);
    if(c->destroyed)
        return -1;
    return 0;
}

static int handle_ping(struct sevent_ws_conn *c, const ws_frame_header *hdr, const uint8_t *payload) {
    if(send_frame(c, WS_OPCODE_PONG, payload, (size_t)hdr->payload_len) != 0)
        return SEVENT_WS_ERR_WRITE;
    return 0;
}

static int handle_pong(struct sevent_ws_conn *c, const ws_frame_header *hdr, const uint8_t *payload) {
    if(c->on_pong)
        c->on_pong(c->user_data, payload, (size_t)hdr->payload_len);
    if(c->destroyed)
        return -1;
    return 0;
}

static int handle_close(struct sevent_ws_conn *c, const ws_frame_header *hdr, const uint8_t *payload) {
    uint16_t    code   = SEVENT_WS_CLOSE_NORMAL;
    const char *reason = "";
    size_t      rl     = 0;
    if(hdr->payload_len >= 2) {
        code   = (uint16_t)((payload[0] << 8) | payload[1]);
        reason = (const char *)(payload + 2);
        rl     = (size_t)hdr->payload_len - 2;
        if(!ws_close_code_valid(code))
            return SEVENT_WS_ERR_PROTOCOL;
        /* RFC 6455 §5.5.1: reason 必须是 UTF-8 */
        if(rl > 0 && !ws_utf8_validate((const uint8_t *)reason, rl)) {
            ws_send_close_code(c, SEVENT_WS_CLOSE_INVALID_PAYLOAD);
            return 0;
        }
    }
    if(c->state == WS_STATE_CLOSING)
        ws_enter_closed(c, code, reason, rl);
    else {
        /* CLOSE 回应: 尽力发送, 失败仍继续关闭 */
        (void)send_frame(c, WS_OPCODE_CLOSE, payload, (size_t)hdr->payload_len);
        ws_enter_closed(c, code, reason, rl);
    }
    return 0;
}

/* 帧处理主循环 (5 个职责段, 修改任一须注意与其它段的交互):
 *   1. 帧头解析 (ws_frame_parse_header)
 *   2. 流式大帧路由 (frame_size > recv_cap → MSG_STREAM, 协议检查与
 *      正常路径 4 对齐 — RSV2/3、进行中仅 CONT、FRAG→STREAM 切换)
 *   3. RSV 位验证 + 解压调度 (oneshot / 分片标记)
 *   4. 控制帧约束检查 (payload ≤125、不可分片)
 *   5. opcode 分发 (handle_*)
 * 流式路由段与正常路径的协议检查必须保持一致 (曾因不一致漏检). */
static int process_frames(struct sevent_ws_conn *c) {
    while(c->recv_pos < c->recv_len) {
        if(c->destroyed)
            return 0;
        size_t          avail = c->recv_len - c->recv_pos;
        const uint8_t  *p     = c->recv_buf + c->recv_pos;
        ws_frame_header hdr;
        int             n = ws_frame_parse_header(p, avail, &hdr);
        if(n == 0)
            break;
        if(n < 0) {
            return SEVENT_WS_ERR_PROTOCOL;
        }
        /* 32 位截断保护: uint64_t payload_len 转 size_t 前检查溢出 */
        if(hdr.payload_len > SIZE_MAX - (size_t)n) {
            return SEVENT_WS_ERR_PROTOCOL;
        }
        size_t frame_size = (size_t)n + (size_t)hdr.payload_len;
        if(avail < frame_size) {
            /* 单帧 > recv_cap 时进入流式读取, 边收边消费 (控制 recv_buf 内存) */
            if(frame_size > c->recv_cap) {
                /* ---- 流式分支协议检查 (与正常路径 RSV 验证对齐) ---- */
                if(hdr.rsv2 || hdr.rsv3)
                    return SEVENT_WS_ERR_PROTOCOL;
                if(hdr.rsv1 && !c->deflate)
                    return SEVENT_WS_ERR_PROTOCOL;
                if(hdr.rsv1 && hdr.opcode == WS_OPCODE_CONT)
                    return SEVENT_WS_ERR_PROTOCOL; /* RFC 7692 §7.2.3: CONT 帧 RSV1 必须 0 */
                if(c->msg.mode == WS_MSG_STREAM || c->msg.mode == WS_MSG_FRAG) {
                    /* [状态机] 消息进行中 (FRAG/STREAM): 只允许 CONT 续帧
                     * (RFC 6455 §5.4: 消息未完成时的新数据帧是协议违规) */
                    if(hdr.opcode != WS_OPCODE_CONT)
                        return SEVENT_WS_ERR_PROTOCOL;
                    if(c->msg.mode == WS_MSG_FRAG) {
                        /* FRAG → STREAM 切换: 先刷 frag 积压 (fin=0)
                         * 保持数据顺序, 再转流式续帧 */
                        frag_flush_tail(c);
                        if(c->destroyed)
                            return 0;
                        c->msg.mode = WS_MSG_STREAM;
                    }
                } else if(hdr.opcode == WS_OPCODE_TEXT || hdr.opcode == WS_OPCODE_BINARY) {
                    /* [状态机] mode==NONE: 新消息首帧 (大帧) → MSG_STREAM.
                     * opcode/compressed 消息级决定, CONT 帧沿用 */
                    c->msg.opcode   = hdr.opcode;
                    c->msg.total    = 0;
                    c->msg.fin_sent = false;
                    if(hdr.rsv1)
                        c->msg.compressed = true; /* 消息级压缩, CONT 帧沿用 */
                    c->msg.mode = WS_MSG_STREAM;
                } else if(hdr.opcode != WS_OPCODE_CONT) {
                    return SEVENT_WS_ERR_PROTOCOL; /* 控制帧不流式 */
                } else {
                    return SEVENT_WS_ERR_PROTOCOL; /* CONT 无消息进行中 */
                }
                c->stream_remaining = hdr.payload_len; /* 帧级剩余, 消息状态保持 */
                c->stream_fin       = hdr.fin;
                c->msg.total        += hdr.payload_len; /* 消息总长累积 (压缩时为压缩字节) */
                c->recv_pos         += (size_t)n;       /* 消费帧头 */
                stream_consume(c);
            }
            break;
        }
        uint8_t *payload = (uint8_t *)p + n;
        if(hdr.mask)
            ws_frame_apply_mask(payload, hdr.payload_len, hdr.mask_key);

        /* ---- RSV 位验证 (RFC 7692) ---- */
        if(hdr.rsv2 || hdr.rsv3)
            return SEVENT_WS_ERR_PROTOCOL;
        if(hdr.rsv1 && (hdr.opcode & 0x08))
            return SEVENT_WS_ERR_PROTOCOL;
        if(hdr.rsv1 && !c->deflate)
            return SEVENT_WS_ERR_PROTOCOL;
        if(hdr.rsv1 && hdr.opcode == WS_OPCODE_CONT)
            return SEVENT_WS_ERR_PROTOCOL; /* RFC 7692 §7.2.3: 分片压缩消息的
                                            * CONT 帧 RSV1 必须为 0 (仅首帧置 1) */

        /* ---- RSV1: 一次性解压 or 分片标记 ---- */
        if(hdr.rsv1 && hdr.fin && hdr.opcode != WS_OPCODE_CONT) {
            if(c->msg.mode != WS_MSG_NONE)
                return SEVENT_WS_ERR_PROTOCOL;
            /* 单帧压缩消息: 解压后通过 on_message 分批+fin 送达, 不驻留消息状态 */
            int r = decompress_oneshot(c, payload, (size_t)hdr.payload_len, (hdr.opcode == WS_OPCODE_BINARY));
            if(r != 0)
                return r;
            if(c->destroyed)
                return 0;
            c->recv_pos += frame_size; /* 本帧已消费 */
            continue;
        } else if(hdr.rsv1 && !hdr.fin) {
            /* [状态机] 压缩分片消息首帧: 置消息级压缩标记, CONT 帧沿用 */
            if(hdr.opcode == WS_OPCODE_TEXT || hdr.opcode == WS_OPCODE_BINARY)
                c->msg.compressed = true;
        }

        /* RFC 6455 §5.5: 控制帧 payload 不得超过 125 */
        if((hdr.opcode & 0x08) && hdr.payload_len > 125) {
            return SEVENT_WS_ERR_PROTOCOL;
        }
        /* RFC 6455 §5.5: 控制帧 MUST NOT be fragmented */
        if((hdr.opcode & 0x08) && !hdr.fin) {
            return SEVENT_WS_ERR_PROTOCOL;
        }

        int ret = 0;
        switch(hdr.opcode) {
        case WS_OPCODE_CLOSE:
            /* CLOSE: on_close 中用 close() 非 destroy(), 之后 c 仍存活 */
            ret = handle_close(c, &hdr, payload);
            if(ret)
                return ret;
            return 0;
        case WS_OPCODE_TEXT:
        case WS_OPCODE_BINARY:
            ret = handle_text_binary(c, &hdr, payload);
            break;
        case WS_OPCODE_CONT:
            ret = handle_cont(c, &hdr, payload);
            break;
        case WS_OPCODE_PING:
            ret = handle_ping(c, &hdr, payload);
            break;
        case WS_OPCODE_PONG:
            ret = handle_pong(c, &hdr, payload);
            break;
        default:
            return SEVENT_WS_ERR_PROTOCOL; /* 保留 opcode */
        }
        if(ret < 0)
            return -1;
        if(ret > 0)
            return ret;
        c->recv_pos += frame_size;
    }
    return 0;
}

static void on_data(void *data) {
    struct sevent_ws_conn *c = (struct sevent_ws_conn *)data;
    WS_LOCK(c);

    /* 只读一次 (select 确保可读), 然后纯处理 buffer 已有数据 */
    int n = recv_read(c);
    if(n == 0) {
        /* EOF: 对端关连接. 之前每次 on_data 已通过 process_frames 处理完
         * 所有完整帧, 无需再处理. on_message 中可能调 close (设 destroyed=1). */
        if(c->destroyed) {
            WS_UNLOCK(c);
            return;
        }
        ws_enter_closed(c, SEVENT_WS_CLOSE_ABNORMAL, SEVENT_WS_REASON_EOF, sizeof(SEVENT_WS_REASON_EOF) - 1);
        WS_UNLOCK(c);
        return;
    }
    if(n < 0 && errno != EAGAIN && errno != EINTR) {
        ws_enter_closed(c, SEVENT_WS_CLOSE_ABNORMAL, SEVENT_WS_REASON_READ_ERR, sizeof(SEVENT_WS_REASON_READ_ERR) - 1);
        WS_UNLOCK(c);
        return;
    }

    if(c->msg.mode == WS_MSG_STREAM) {
        /* 流式模式: stream_consume 每次消费 up to recv_cap;
         * 当前帧消费完 (stream_remaining==0) 后必须交还 process_frames
         * 处理 recv_buf 中的后续帧 (流式消息的下一 CONT 帧等). */
        int err = 0;
        while(c->recv_pos < c->recv_len && err == 0) {
            size_t prev = c->recv_pos;
            if(c->stream_remaining > 0)
                stream_consume(c);
            if(c->stream_remaining == 0)
                err = process_frames(c);
            if(c->recv_pos == prev)
                break;
        }
        if(err) {
            WS_UNLOCK(c);
            ws_fatal(c, err);
            return;
        }
    } else {
        int err = process_frames(c);
        if(err) {
            WS_UNLOCK(c);
            ws_fatal(c, err);
            return;
        }
    }
    if(c->destroyed) {
        WS_UNLOCK(c);
        return;
    }
    WS_UNLOCK(c);
}

/* ====================================================================
 *  握手
 * ==================================================================== */

/* 握手响应处理 (5 个职责段, 按顺序串联; 3xx 与协商段互斥前置 return):
 *   1. 读响应 (recv_read)
 *   2. 解析 HTTP 响应 (ws_parse_response; 不完整 → 等下一轮)
 *   3. 3xx 重定向 (解析 Location → ws_redirect_reconnect, 前置 return)
 *   4. on_http_response 回调 / accept 校验 (非 101 或 accept 不匹配 → 收尾)
 *   5. deflate 协商 + 设 OPEN + on_open + 粘包残留帧处理
 * 若将来拆分, 协商段 (5) 可独立为 ws_negotiate_deflate(). */
static void on_handshake_data(void *data) {
    struct sevent_ws_conn *c = (struct sevent_ws_conn *)data;
    WS_LOCK(c);
    if(c->destroyed) {
        WS_UNLOCK(c);
        return;
    }
    int n = recv_read(c);
    if(n < 0) {
        if(errno != EAGAIN && errno != EINTR) {
            WS_UNLOCK(c);
            ws_fatal(c, SEVENT_WS_ERR_HANDSHAKE);
        } else {
            WS_UNLOCK(c);
        }
        return;
    }
    /* n >= 0: 刚读到数据或缓冲区满 (recv_read 返回 0, 但 recv_len > 0).
     * 只要有数据就尝试解析; 空缓冲区则是对端关闭连接. */
    if(c->recv_len == 0) {
        WS_UNLOCK(c);
        ws_fatal(c, SEVENT_WS_ERR_HANDSHAKE);
        return;
    }
    ws_handshake_response resp;
    int                   ret = ws_parse_response(c->recv_buf, c->recv_len, &resp);
    if(ret == 0) {
        WS_UNLOCK(c);
        return;
    }
    if(ret < 0) {
        /* 失败时如有 on_http_response 则回调原始数据 */
        if(c->on_http_response)
            c->on_http_response(c->user_data, resp.status_code, (const char *)c->recv_buf, c->recv_len, "", 0);
        WS_UNLOCK(c);
        ws_fatal(c, SEVENT_WS_ERR_HANDSHAKE);
        return;
    }
    /* 3xx 重定向: 库内部处理, 不回调上层 */
    if(resp.status_code >= WS_HTTP_STATUS_REDIRECT_MIN && resp.status_code < WS_HTTP_STATUS_REDIRECT_MAX &&
       resp.location[0]) {
        if(c->redirect_count >= SEVENT_WS_MAX_REDIRECTS) {
            WS_UNLOCK(c);
            ws_fatal(c, SEVENT_WS_ERR_HANDSHAKE);
            return;
        }
        if(ws_redirect_parse(c, resp.location) != 0) {
            WS_UNLOCK(c);
            ws_fatal(c, SEVENT_WS_ERR_HANDSHAKE);
            return;
        }
        c->redirect_count++;
        if(!ws_redirect_reconnect(c)) {
            WS_UNLOCK(c);
            ws_fatal(c, SEVENT_WS_ERR_CONNECT);
            return;
        }
        WS_UNLOCK(c);
        return;
    }
    /* 分离 header (含状态行) 和 body */
    const char *headers = (const char *)c->recv_buf;
    size_t      hlen    = (size_t)ret;
    const char *body    = (const char *)c->recv_buf + ret;
    size_t      blen    = c->recv_len - (size_t)ret;

    if(c->on_http_response) {
        if(resp.status_code != WS_HTTP_STATUS_SWITCHING || ws_verify_accept(c->sec_ws_key, resp.accept) != 0) {
            /* 非 101 或 accept 不匹配 → 回调让上层处理 */
            c->on_http_response(c->user_data, resp.status_code, headers, hlen, body, blen);
            if(c->destroyed) {
                WS_UNLOCK(c);
                return;
            }
            ws_enter_closed(c, 0, "", 0);
            WS_UNLOCK(c);
            return;
        }
    } else {
        /* 兼容旧模式: 库内部校验 accept */
        if(ws_verify_accept(c->sec_ws_key, resp.accept) != 0) {
            WS_UNLOCK(c);
            ws_fatal(c, SEVENT_WS_ERR_HANDSHAKE);
            return;
        }
    }
    /* 响应不得含未 offer 的扩展 (RFC 6455 §9/§4.1 第 5 条) */
    if(!ws_extensions_ok(resp.extensions, c->enable_deflate)) {
        WS_UNLOCK(c);
        ws_fatal(c, SEVENT_WS_ERR_HANDSHAKE);
        return;
    }
    /* permessage-deflate 协商 */
    if(c->enable_deflate && strstr(resp.extensions, WS_EXT_PMD)) {
        ws_deflate_params p = {0};
        if(strstr(resp.extensions, WS_EXT_SERVER_NO_CTX))
            p.server_no_context_takeover = true;
        if(strstr(resp.extensions, WS_EXT_CLIENT_NO_CTX))
            p.client_no_context_takeover = true;
        /* client_max_window_bits=N: 服务器限定本端发送窗口 (RFC 7692 §7.1.2.2,
         * MUST NOT 用更大窗口). 不遵守则 32KB 窗口压缩流超出服务器解压能力. */
        const char *cw = strstr(resp.extensions, WS_EXT_CLIENT_MAX_WB);
        if(cw) {
            const char *after = cw + strlen(WS_EXT_CLIENT_MAX_WB);
            if(*after == '=') {
                /* 带值必须为 8-15 数字且 ≤ offer 值 (offer 带值时);
                 * 违规 = 服务器违约 → Fail the Connection (RFC 7692 §7.1.2,
                 * atoi 溢出为 UB 用 strtol) */
                char   *end = NULL;
                long    v   = strtol(after + 1, &end, 10);
                uint8_t req = c->request_client_max_window_bits;
                if(end == after + 1 || v < 8 || v > 15 || (req && v > req)) {
                    WS_UNLOCK(c);
                    ws_fatal(c, SEVENT_WS_ERR_PROTOCOL);
                    return;
                }
                p.client_max_window_bits = (uint8_t)v;
            }
            /* 无值响应: 合法, 不限制 */
        }
        /* 自我承诺: offer 带值 (8-15) 时, 无论服务器是否响应该参数, 本端发送
         * 窗口 ≤ offer 值 (RFC 7692 §7.1.2.2); 响应带值优先 (上面已覆盖) */
        if(!p.client_max_window_bits && c->request_client_max_window_bits >= 8 &&
           c->request_client_max_window_bits <= 15)
            p.client_max_window_bits = c->request_client_max_window_bits;
        /* server_max_window_bits=N: 服务器承诺本端压缩窗口 ≤N (RFC 7692
         * §7.1.2.1). 响应可主动带 (即使 offer 未请求); offer 请求了则响应值
         * 必须 ≤ 请求值, 违规 = 服务器违约 → Fail the Connection. 客户端
         * 解压窗口随之缩小 (省接收侧内存), 安全前提: 解压窗口 ≥ 压缩窗口. */
        const char *sw = strstr(resp.extensions, WS_EXT_SERVER_MAX_WB);
        if(sw) {
            const char *after = sw + strlen(WS_EXT_SERVER_MAX_WB);
            if(*after == '=') {
                char   *end = NULL;
                long    v   = strtol(after + 1, &end, 10);
                uint8_t req = c->request_server_max_window_bits;
                if(end == after + 1 || v < 8 || v > 15 || (req && v > req)) {
                    WS_UNLOCK(c);
                    ws_fatal(c, SEVENT_WS_ERR_PROTOCOL);
                    return;
                }
                p.server_max_window_bits = (uint8_t)v;
            }
            /* 无值: 合法, 不限制 (保持 15) */
        }
        /* 自我承诺的 no_context_takeover 本地直接生效 (不依赖服务器响应);
         * server 侧 (request_server_no_context_takeover) 已在上面响应解析处理 */
        p.client_no_context_takeover = c->request_client_no_context_takeover;
        p.compression_level          = c->deflate_level;
        ws_deflate_create(&c->deflate, &p);
    }

    c->recv_pos = (size_t)ret; /* 跳过 HTTP 响应, 保留可能的 WS 帧 */
    c->state    = WS_STATE_OPEN;
    ws_update_io(c, on_data);
    if(c->on_open)
        c->on_open(c->user_data);
    if(c->destroyed) {
        WS_UNLOCK(c);
        return;
    }
    /* 启动 PING 心跳定时器 */
    if(c->ping_interval_ms > 0 && !c->ping_timer)
        c->ping_timer = sevent_timer_register(c->ev, (unsigned int)c->ping_interval_ms, on_ping_timer, c);
    /* 握手响应 + WS 帧粘包: 立即处理残留帧 */
    if(c->recv_len > c->recv_pos) {
        int err = process_frames(c);
        if(err > 0) {
            WS_UNLOCK(c);
            ws_fatal(c, err);
            return;
        }
    }
    if(c->destroyed) {
        WS_UNLOCK(c);
        return;
    }
    WS_UNLOCK(c);
}

/* 连接超时回调 */
static void on_connect_timeout(void *data) {
    struct sevent_ws_conn *c = (struct sevent_ws_conn *)data;
    WS_LOCK(c);
    if(c->destroyed || c->state != WS_STATE_CONNECTING) {
        WS_UNLOCK(c);
        return;
    }
    /* 先关定时器再 ws_fatal, 防止 destroy 路径下 c 释放后定时器悬空 */
    sevent_timer *t  = c->connect_timer;
    c->connect_timer = NULL;
    if(t)
        sevent_timer_unregister(c->ev, t);
    WS_UNLOCK(c);
    ws_fatal(c, SEVENT_WS_ERR_CONNECT);
}

static void on_connect_ready(void *data) {
    struct sevent_ws_conn *c = (struct sevent_ws_conn *)data;
    WS_LOCK(c);
    /* 连接有结果了, 关超时定时器 */
    if(c->connect_timer) {
        sevent_timer_unregister(c->ev, c->connect_timer);
        c->connect_timer = NULL;
    }
    int       err = 0;
    socklen_t el  = sizeof(err);
    if(getsockopt(c->fd, SOL_SOCKET, SO_ERROR, &err, &el) != 0 || err != 0) {
        WS_UNLOCK(c);
        ws_fatal(c, SEVENT_WS_ERR_CONNECT);
        return;
    }
    ws_gen_key(c->sec_ws_key);
    /* 压缩 offer 参数: nct 承诺 + 降窗请求 */
    ws_deflate_params pmd_offer = {0};
    if(c->enable_deflate) {
        pmd_offer.client_no_context_takeover = c->request_client_no_context_takeover;
        pmd_offer.server_no_context_takeover = c->request_server_no_context_takeover;
        /* 降窗: 仅 8-15 合法值生效 (0/范围外 = 默认行为) */
        if(c->request_client_max_window_bits >= 8 && c->request_client_max_window_bits <= 15)
            pmd_offer.client_max_window_bits = c->request_client_max_window_bits;
        if(c->request_server_max_window_bits >= 8 && c->request_server_max_window_bits <= 15)
            pmd_offer.server_max_window_bits = c->request_server_max_window_bits;
    }
    char req[1024];
    int  req_len = ws_build_request(req,
                                   sizeof(req),
                                   c->host,
                                   c->port,
                                   c->path,
                                   c->sec_ws_key,
                                   c->sub_protocol[0] ? c->sub_protocol : NULL,
                                   c->enable_deflate,
                                   c->enable_deflate ? &pmd_offer : NULL);
    if(req_len < 0) {
        WS_UNLOCK(c);
        ws_fatal(c, SEVENT_ERR_NOMEM);
        return;
    }
    /* 握手请求入写队列: 非阻塞 socket 可能部分写, 复用 ws_flush/on_write_ready
     * 的续写机制 (请求节点拷贝到堆, 节点引用调用者 buffer 需生命周期一致) */
    uint8_t *req_buf = (uint8_t *)sevent_i_malloc((size_t)req_len);
    if(!req_buf) {
        WS_UNLOCK(c);
        ws_fatal(c, SEVENT_ERR_NOMEM);
        return;
    }
    memcpy(req_buf, req, (size_t)req_len);
    if(ws_enqueue(c, req_buf, (size_t)req_len, true) != 0) {
        WS_UNLOCK(c); /* OOM: ws_enqueue 已 free req_buf */
        ws_fatal(c, SEVENT_ERR_NOMEM);
        return;
    }
    c->state = WS_STATE_HANDSHAKE;
    if(ws_flush(c) < 0) {
        WS_UNLOCK(c);
        ws_fatal(c, SEVENT_WS_ERR_CONNECT);
        return;
    }
    ws_update_io(c, on_handshake_data);
    WS_UNLOCK(c);
}

/* ====================================================================
 *  公开 API
 * ==================================================================== */

sevent_ws_conn *sevent_ws_connect(sevent_context *ev, const sevent_ws_config *cfg) {
    if(!ev || !cfg || !cfg->host || !cfg->path || (!cfg->on_open && !cfg->on_error))
        return NULL;
    struct sevent_ws_conn *c = SEVENT_I_NEW0(c);
    if(!c)
        return NULL;
#ifdef SEVENT_WS_THREAD_SAFE
    if(sevent_mutex_init_recursive(&c->lock) != 0) {
        sevent_i_free(c);
        return NULL;
    }
#endif
    c->ev    = ev;
    c->fd    = SEVENT_INVALID_SOCKET;
    c->state = WS_STATE_CONNECTING;
    {
        /* 用地址+时间+PID 播种 per-connection mask 序列 */
        c->mask_seed = (uint32_t)((uintptr_t)c ^ (unsigned int)time(NULL) ^ ((unsigned int)getpid() << 16));
    }
    strncpy(c->host, cfg->host, sizeof(c->host) - 1);
    c->host[sizeof(c->host) - 1] = '\0';
    c->port                      = cfg->port;
    strncpy(c->path, cfg->path, sizeof(c->path) - 1);
    c->path[sizeof(c->path) - 1] = '\0';
    if(cfg->sub_protocol) {
        strncpy(c->sub_protocol, cfg->sub_protocol, sizeof(c->sub_protocol) - 1);
        c->sub_protocol[sizeof(c->sub_protocol) - 1] = '\0';
    }
    c->on_open                            = cfg->on_open;
    c->on_message                         = cfg->on_message;
    c->on_close                           = cfg->on_close;
    c->on_error                           = cfg->on_error;
    c->on_http_response                   = cfg->on_http_response;
    c->on_pong                            = cfg->on_pong;
    c->user_data                          = cfg->user_data;
    c->connect_timeout_ms                 = cfg->connect_timeout_ms;
    c->ping_interval_ms                   = cfg->ping_interval_ms;
    c->enable_deflate                     = cfg->enable_deflate;
    c->deflate_level                      = cfg->deflate_level;
    c->request_client_no_context_takeover = cfg->request_client_no_context_takeover;
    c->request_server_no_context_takeover = cfg->request_server_no_context_takeover;
    c->request_client_max_window_bits     = cfg->request_client_max_window_bits;
    c->request_server_max_window_bits     = cfg->request_server_max_window_bits;

    /* 固定大小接收/分片缓冲区.
     * recv_buf 同时用于 HTTP 握手响应读取, 至少 SEVENT_WS_RECV_MIN. */
    size_t bufsz = cfg->recv_buf_size;
    if(bufsz == 0)
        bufsz = SEVENT_WS_RECV_DEFAULT;
    if(bufsz < SEVENT_WS_RECV_MIN)
        bufsz = SEVENT_WS_RECV_MIN;
    c->recv_buf = (uint8_t *)sevent_i_malloc(bufsz);
    c->frag_buf = (uint8_t *)sevent_i_malloc(bufsz);
    if(!c->recv_buf || !c->frag_buf)
        goto cleanup;
    c->recv_cap = bufsz;

    int fd = ws_tcp_connect(c->host, c->port);
    if(fd < 0)
        goto cleanup;
    if(!ws_register_connect_io(c, fd))
        goto cleanup;
    return c;

cleanup:
    if(c->fd >= 0)
        close(c->fd);
    sevent_i_free(c->recv_buf);
    sevent_i_free(c->frag_buf);
#ifdef SEVENT_WS_THREAD_SAFE
    sevent_mutex_destroy(&c->lock);
#endif
    sevent_i_free(c);
    return NULL;
}

int sevent_ws_send_text(sevent_ws_conn *c, const void *data, size_t len) {
    if(!c)
        return SEVENT_ERR_INVAL;
    if(!data && len > 0)
        return SEVENT_ERR_INVAL;
    /* RFC 6455 §5.6: TEXT 帧 payload MUST 为合法 UTF-8 */
    if(len > 0 && !ws_utf8_validate((const uint8_t *)data, len))
        return SEVENT_ERR_INVAL;
    /* 空帧 (len=0) 直接放行, send_frame 会构造零长度帧 */
    WS_LOCK(c);
    int r = send_message(c, WS_OPCODE_TEXT, data, len);
    WS_UNLOCK(c);
    if(r == SEVENT_WS_ERR_WRITE)
        ws_fatal(c, r);
    return r;
}

int sevent_ws_send_binary(sevent_ws_conn *c, const void *data, size_t len) {
    if(!c)
        return SEVENT_ERR_INVAL;
    WS_LOCK(c);
    int r;
    if(data || len == 0)
        r = send_message(c, WS_OPCODE_BINARY, data, len);
    else
        r = SEVENT_ERR_INVAL;
    WS_UNLOCK(c);
    if(r == SEVENT_WS_ERR_WRITE)
        ws_fatal(c, r);
    return r;
}

int sevent_ws_ping(sevent_ws_conn *c, const void *payload, size_t len) {
    if(!c || len > 125)
        return SEVENT_ERR_INVAL;
    WS_LOCK(c);
    int r = send_frame(c, WS_OPCODE_PING, payload, len);
    WS_UNLOCK(c);
    if(r == SEVENT_WS_ERR_WRITE)
        ws_fatal(c, r);
    return r;
}

int sevent_ws_shutdown(sevent_ws_conn *c, uint16_t code, const char *reason) {
    if(!c)
        return SEVENT_ERR_INVAL;
    WS_LOCK(c);
    if(c->state != WS_STATE_OPEN) {
        WS_UNLOCK(c);
        return SEVENT_ERR_INVAL;
    }
    size_t rl = reason ? strlen(reason) : 0;
    if(rl > 123)
        rl = 123;
    uint8_t cp[128];
    cp[0] = (uint8_t)(code >> 8);
    cp[1] = (uint8_t)(code);
    if(rl > 0)
        memcpy(cp + 2, reason, rl);
    int ret = send_frame(c, WS_OPCODE_CLOSE, cp, 2 + rl);
    if(ret == SEVENT_SUCCESS && !c->destroyed && c->state != WS_STATE_CLOSED)
        c->state = WS_STATE_CLOSING;
    WS_UNLOCK(c);
    if(ret == SEVENT_WS_ERR_WRITE)
        ws_fatal(c, ret);
    return ret;
}

void sevent_ws_close(sevent_ws_conn *c) {
    if(!c)
        return;
    /* 锁: close 与 loop 线程回调 (on_data/on_write_ready 的 ws_flush) 可能
     * 并发, 无锁时状态/队列操作会与 flush 交错.
     * 递归锁: 回调内 (on_open/on_close/on_error) 调用也安全.
     * close 不释放任何内存 (deflate/写队列/缓冲区统一由 ws_cleanup_conn
     * 在 run_posts 阶段释放) — 与文档 "不释放内存, 对象仍可安全访问" 一致. */
    WS_LOCK(c);
    c->destroyed = 1;
    c->state     = WS_STATE_CLOSED;
    ws_close_socket(c);
    if(c->connect_timer) {
        sevent_timer_unregister(c->ev, c->connect_timer);
        c->connect_timer = NULL;
    }
    if(c->ping_timer) {
        sevent_timer_unregister(c->ev, c->ping_timer);
        c->ping_timer = NULL;
    }
    WS_UNLOCK(c);
}

/* deferred free: 连接全部内存的单一释放出口.
 * 在 run_posts 阶段 (loop 线程) 执行 — 此时回调栈已展开, IO/定时器已摘除,
 * 且 destroy 保证恰好一次 → 不存在任何使用中的内存被释放 (UAF). */
static void ws_cleanup_conn(void *data) {
    struct sevent_ws_conn *c = (struct sevent_ws_conn *)data;
    if(c->deflate) {
        ws_deflate_destroy(c->deflate);
        c->deflate = NULL;
    }
    ws_queue_clear(c);
#ifdef SEVENT_WS_THREAD_SAFE
    sevent_mutex_destroy(&c->lock);
#endif
    sevent_i_free(c->recv_buf);
    sevent_i_free(c->frag_buf);
    sevent_i_free(c);
}

void sevent_ws_destroy(sevent_ws_conn *c) {
    if(!c)
        return;
    /* 注意: destroy 不允许幂等 — 调用后对象作废, 再使用 (含再次 destroy)
     * 是编程错误, 未定义行为 (对象可能已释放). 不做任何防护. */
    sevent_ws_close(c); /* 逻辑关闭: destroyed/CLOSED + 摘 IO/定时器, 不释放内存 */
    /* 将 c 的 free 推迟到 run_posts 阶段, 保证调用栈安全展开 */
    if(c->ev && sevent_is_running(c->ev)) {
        if(sevent_post(c->ev, ws_cleanup_conn, c) != SEVENT_SUCCESS)
            ws_cleanup_conn(c); /* OOM, 立即释放 */
    } else {
        ws_cleanup_conn(c);
    }
}

int sevent_ws_get_state(const sevent_ws_conn *c) {
    if(!c)
        return SEVENT_WS_STATE_CLOSED;
    WS_LOCK((struct sevent_ws_conn *)(uintptr_t)c); /* const cast for locking */
    int s;
    switch(c->state) {
    case WS_STATE_CONNECTING:
    case WS_STATE_HANDSHAKE:
        s = SEVENT_WS_STATE_CONNECTING;
        break;
    case WS_STATE_OPEN:
        s = SEVENT_WS_STATE_OPEN;
        break;
    case WS_STATE_CLOSING:
        s = SEVENT_WS_STATE_CLOSING;
        break;
    default:
        s = SEVENT_WS_STATE_CLOSED;
        break;
    }
    WS_UNLOCK((struct sevent_ws_conn *)(uintptr_t)c);
    return s;
}
