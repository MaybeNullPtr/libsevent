/* =========================================================================
 *  ws_conn.c — WebSocket 连接状态机实现 (v2: 异步写队列)
 *
 *  send_frame 构造帧后入写队列, 异步 flush.
 *  控制帧 (PING/CLOSE) 插入队首优先发送.
 *  ========================================================================= */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
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

/* 前向声明 (IO 回调, 供 ws_update_io / send_frame 引用) */
static void on_write_ready(void *data);
static void on_data(void *data);
static void on_handshake_data(void *data);

/* ====================================================================
 *  内部辅助
 * ==================================================================== */

static unsigned int xorshift32(unsigned int *seed) {
    unsigned int x = *seed;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *seed = x;
    return x;
}

static void gen_mask_key(struct sevent_ws_conn *c, uint8_t key[4]) {
    unsigned int r = xorshift32(&c->mask_seed);
    key[0]         = (uint8_t)(r >> 24);
    key[1]         = (uint8_t)(r >> 16);
    key[2]         = (uint8_t)(r >> 8);
    key[3]         = (uint8_t)(r);
}

/* RFC 6455 §7.4: 校验 Close 码是否合法 */
static bool ws_close_code_valid(uint16_t code) {
    if(code < 1000)
        return 0; /* 0-999 保留 */
    if(code == 1004 || code == 1005 || code == 1006)
        return 0; /* 1004-1006 保留/仅内部 */
    if(code >= 1012 && code <= 1015)
        return 0; /* 1012-1015 保留 (含 TLS 握手) */
    if(code >= 1016 && code <= 2999)
        return 0; /* 1016-2999 未分配 */
    if(code > 4999)
        return 0; /* 5000+ 保留/非法 */
    return 1;
}

static void ws_close_socket(struct sevent_ws_conn *c) {
    if(c->io_handle) {
        sevent_io_unregister(c->ev, c->io_handle);
        c->io_handle = NULL;
    }
    if(c->fd >= 0) {
        close(c->fd);
        c->fd = -1;
    }
}

static void ws_enter_closed(struct sevent_ws_conn *c, uint16_t code, const char *reason, size_t reason_len) {
    if(c->state == WS_STATE_CLOSED || c->destroyed)
        return;
    c->state = WS_STATE_CLOSED;
    ws_close_socket(c);
    if(c->on_close)
        c->on_close(c->user_data, code, reason, reason_len);
}

static void ws_fatal(struct sevent_ws_conn *c, int err) {
    if(c->destroyed || c->state == WS_STATE_CLOSED)
        return;
    c->state = WS_STATE_CLOSED;
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

/* 大帧流式读取: 从 recv_buf 分块回调 payload */
static void stream_consume(struct sevent_ws_conn *c) {
    void *d      = c->user_data;
    bool  is_bin = (c->stream_opcode == WS_OPCODE_BINARY);

    while(c->recv_pos < c->recv_len && c->stream_remaining > 0) {
        if(c->destroyed) return;
        size_t avail = c->recv_len - c->recv_pos;
        size_t chunk = (avail < c->recv_cap) ? avail : c->recv_cap;
        if(chunk > c->stream_remaining)
            chunk = (size_t)c->stream_remaining;
        bool last = (chunk == c->stream_remaining) ? c->stream_fin : 0;

        if(c->on_message)
            c->on_message(d, c->recv_buf + c->recv_pos, chunk, is_bin, last, c->stream_total);
        if(c->destroyed) return;

        c->recv_pos         += chunk;
        c->stream_remaining -= chunk;
    }
    if(c->stream_remaining == 0)
        c->stream_active = 0;
}

/* ====================================================================
 *  异步写队列
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

/* ====================================================================
 *  发送帧: 构造 → 入队 → flush
 * ==================================================================== */

static int send_frame(struct sevent_ws_conn *c, uint8_t opcode, const void *payload, size_t len) {
    if(c->state != WS_STATE_OPEN && c->state != WS_STATE_CLOSING)
        return SEVENT_ERR_INVAL;

    uint8_t mask_key[4];
    gen_mask_key(c, mask_key);
    uint8_t hdr[16];
    int     hdr_len = ws_frame_build_header(hdr, 1, opcode, mask_key, len);
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

    bool is_ctrl = (opcode == WS_OPCODE_PING || opcode == WS_OPCODE_PONG || opcode == WS_OPCODE_CLOSE);

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
        /* 队列已空, 注销可写回调 (保持可读) */
        void (*rcb)(void *) = (c->state == WS_STATE_OPEN) ? on_data : NULL;
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
        return -1; /* 单分片超过缓冲区 */
    /* 放不下时先 flush 当前积压 (fin=0) 腾空间 */
    if(c->frag_len + len > c->recv_cap) {
        if(c->on_message && c->frag_len > 0) {
            void *d      = c->user_data;
            bool  is_bin = (c->frag_opcode == WS_OPCODE_BINARY);
            c->on_message(d, c->frag_buf, c->frag_len, is_bin, 0, 0);
            if(c->destroyed) return 0;
        }
        c->frag_len = 0;
    }
    c->frag_total += len;
    memcpy(c->frag_buf + c->frag_len, data, len);
    c->frag_len += len;
    return 0;
}

/* 从 frag_buf 吐出完整块给 on_message, fin=1 表示最后一次 */
static int frag_flush(struct sevent_ws_conn *c, bool fin) {
    if(!c->on_message) {
        if(fin) {
            c->frag_pending = 0;
            c->frag_len     = 0;
            c->frag_total   = 0;
        }
        return 0;
    }
    void *d      = c->user_data;
    bool  is_bin = (c->frag_opcode == WS_OPCODE_BINARY);

    while(c->frag_len >= c->recv_cap) {
        c->on_message(d, c->frag_buf, c->recv_cap, is_bin, 0, 0);
        if(c->destroyed) return 0;
        c->frag_len -= c->recv_cap;
        memmove(c->frag_buf, c->frag_buf + c->recv_cap, c->frag_len);
    }
    if(fin && c->frag_len > 0) {
        c->on_message(d, c->frag_buf, c->frag_len, is_bin, 1, c->frag_total);
        if(c->destroyed) return 0;
        c->frag_len     = 0;
        c->frag_pending = 0;
        c->frag_total   = 0;
    } else if(fin) {
        c->frag_pending = 0;
        c->frag_total   = 0;
    }
    return 0;
}

/* ====================================================================
 *  Opcode 处理器 (从 process_frames 提取)
 *  返回: 0=OK, >0=错误码, <0=回调内调用了 close (c 仍存活)
 * ==================================================================== */

static int handle_text_binary(struct sevent_ws_conn *c, const ws_frame_header *hdr, const uint8_t *payload) {
    if(c->frag_pending)
        return SEVENT_WS_ERR_PROTOCOL;
    if(hdr->fin) {
        if(c->on_message) {
            c->on_message(c->user_data,
                          payload,
                          (size_t)hdr->payload_len,
                          (hdr->opcode == WS_OPCODE_BINARY) ? 1 : 0,
                          1,
                          hdr->payload_len);
            if(c->destroyed) return -1;
        }
    } else {
        c->frag_opcode  = hdr->opcode;
        c->frag_pending = 1;
        if(frag_append(c, payload, (size_t)hdr->payload_len) != 0)
            return SEVENT_ERR_NOMEM;
        frag_flush(c, 0);
        if(c->destroyed) return -1;
    }
    return 0;
}

static int handle_cont(struct sevent_ws_conn *c, const ws_frame_header *hdr, const uint8_t *payload) {
    if(!c->frag_pending)
        return SEVENT_WS_ERR_PROTOCOL;
    if(frag_append(c, payload, (size_t)hdr->payload_len) != 0)
        return SEVENT_ERR_NOMEM;
    frag_flush(c, hdr->fin);
    if(c->destroyed) return -1;
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
    if(c->destroyed) return -1;
    return 0;
}

static int handle_close(struct sevent_ws_conn *c, const ws_frame_header *hdr, const uint8_t *payload) {
    uint16_t    code   = 1000;
    const char *reason = "";
    size_t      rl     = 0;
    if(hdr->payload_len >= 2) {
        code   = (uint16_t)((payload[0] << 8) | payload[1]);
        reason = (const char *)(payload + 2);
        rl     = (size_t)hdr->payload_len - 2;
        if(!ws_close_code_valid(code))
            return SEVENT_WS_ERR_PROTOCOL;
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

static int process_frames(struct sevent_ws_conn *c) {
    while(c->recv_pos < c->recv_len) {
        if(c->destroyed) return 0;
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
            /* 单帧 > recv_cap 时进入流式读取, 不再等整帧收齐 */
            if(frame_size > c->recv_cap) {
                c->stream_active     = 1;
                c->stream_opcode     = hdr.opcode;
                c->stream_remaining  = hdr.payload_len;
                c->stream_total      = hdr.payload_len;
                c->stream_fin        = hdr.fin;
                c->recv_pos         += (size_t)n; /* 消费帧头 */
                stream_consume(c);
            }
            break;
        }
        uint8_t *payload = (uint8_t *)p + n;
        if(hdr.mask)
            ws_frame_apply_mask(payload, hdr.payload_len, hdr.mask_key);

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
            if(ret) return ret;
            return 0;
        case WS_OPCODE_TEXT:
        case WS_OPCODE_BINARY: ret = handle_text_binary(c, &hdr, payload); break;
        case WS_OPCODE_CONT:   ret = handle_cont(c, &hdr, payload); break;
        case WS_OPCODE_PING:   ret = handle_ping(c, &hdr, payload); break;
        case WS_OPCODE_PONG:   ret = handle_pong(c, &hdr, payload); break;
        default:
            return SEVENT_WS_ERR_PROTOCOL;
        }
        if(ret < 0) return -1;
        if(ret > 0) return ret;
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
        ws_enter_closed(c, 1006, "connection closed", 18);
        WS_UNLOCK(c);
        return;
    }
    if(n < 0 && errno != EAGAIN && errno != EINTR) {
        ws_enter_closed(c, 1006, "read error", 10);
        WS_UNLOCK(c);
        return;
    }

    if(c->stream_active) {
        /* 流式模式下可能多次循环: stream_consume 每次消费 up to recv_cap */
        int err = 0;
        while(c->recv_pos < c->recv_len && err == 0) {
            size_t prev = c->recv_pos;
            if(c->stream_active)
                stream_consume(c);
            if(!c->stream_active)
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

static void on_handshake_data(void *data) {
    struct sevent_ws_conn *c = (struct sevent_ws_conn *)data;
    WS_LOCK(c);
    if(c->destroyed) {
        WS_UNLOCK(c);
        return;
    }
    int n = recv_read(c);
    if(n <= 0) {
        if(n == 0 || (errno != EAGAIN && errno != EINTR)) {
            WS_UNLOCK(c);
            ws_fatal(c, SEVENT_WS_ERR_HANDSHAKE);
        } else {
            WS_UNLOCK(c);
        }
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
    /* 分离 header (含状态行) 和 body */
    const char *headers = (const char *)c->recv_buf;
    size_t      hlen    = (size_t)ret;
    const char *body    = (const char *)c->recv_buf + ret;
    size_t      blen    = c->recv_len - (size_t)ret;

    if(c->on_http_response) {
        if(resp.status_code != 101 || ws_verify_accept(c->sec_ws_key, resp.accept) != 0) {
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
    c->recv_pos = (size_t)ret; /* 跳过 HTTP 响应, 保留可能的 WS 帧 */
    c->state    = WS_STATE_OPEN;
    ws_update_io(c, on_data);
    if(c->on_open)
        c->on_open(c->user_data);
    if(c->destroyed) {
        WS_UNLOCK(c);
        return;
    }
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
    char req[1024];
    int  req_len = ws_build_request(
            req, sizeof(req), c->host, c->port, c->path, c->sec_ws_key, c->sub_protocol[0] ? c->sub_protocol : NULL);
    if(req_len < 0) {
        WS_UNLOCK(c);
        ws_fatal(c, SEVENT_ERR_NOMEM);
        return;
    }
    ssize_t w = write(c->fd, req, (size_t)req_len);
    if(w < 0) {
        WS_UNLOCK(c);
        ws_fatal(c, SEVENT_WS_ERR_CONNECT);
        return;
    }
    c->state = WS_STATE_HANDSHAKE;
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
    c->fd    = -1;
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
    c->on_open            = cfg->on_open;
    c->on_message         = cfg->on_message;
    c->on_close           = cfg->on_close;
    c->on_error           = cfg->on_error;
    c->on_http_response   = cfg->on_http_response;
    c->on_pong            = cfg->on_pong;
    c->user_data          = cfg->user_data;
    c->connect_timeout_ms = cfg->connect_timeout_ms;

    /* 固定大小接收/分片缓冲区 */
    size_t bufsz = cfg->recv_buf_size ? cfg->recv_buf_size : 4096;
    c->recv_buf  = (uint8_t *)sevent_i_malloc(bufsz);
    c->frag_buf  = (uint8_t *)sevent_i_malloc(bufsz);
    if(!c->recv_buf || !c->frag_buf)
        goto cleanup;
    c->recv_cap = bufsz;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if(fd < 0)
        goto cleanup;
    {
        int fl = fcntl(fd, F_GETFL);
        if(fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0) {
            close(fd);
            goto cleanup;
        }
    }
    c->fd = fd;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(c->port);
    if(inet_pton(AF_INET, c->host, &addr.sin_addr) <= 0) {
        close(fd);
        goto cleanup;
    }
    int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if(rc < 0 && errno != EINPROGRESS) {
        close(fd);
        goto cleanup;
    }
    sevent_io_handler h;
    h.fd         = fd;
    h.io_read    = NULL;
    h.io_write   = on_connect_ready;
    h.data       = c;
    c->io_handle = sevent_io_register(ev, &h);
    if(!c->io_handle) {
        close(fd);
        goto cleanup;
    }
    /* 连接超时定时器 */
    {
        int t_ms = c->connect_timeout_ms;
        if(t_ms == 0)
            t_ms = 10000; /* 默认 10 秒 */
        if(t_ms > 0)
            c->connect_timer = sevent_timer_register(c->ev, (unsigned int)t_ms, on_connect_timeout, c);
    }
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
    WS_LOCK(c);
    int r;
    if(data || len == 0)
        r = send_frame(c, WS_OPCODE_TEXT, data, len);
    else
        r = SEVENT_ERR_INVAL;
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
        r = send_frame(c, WS_OPCODE_BINARY, data, len);
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
    /* destroy 无锁 — loop 线程专用 */
    c->destroyed = 1;
    c->state     = WS_STATE_CLOSED;
    ws_close_socket(c);
    if(c->connect_timer) {
        sevent_timer_unregister(c->ev, c->connect_timer);
        c->connect_timer = NULL;
    }
    ws_write_node *wn = c->write_head;
    while(wn) {
        ws_write_node *n = wn->next;
        sevent_i_free(wn->data);
        sevent_i_free(wn);
        wn = n;
    }
    c->write_head = NULL;
}

void sevent_ws_destroy(sevent_ws_conn *c) {
    sevent_ws_close(c);
#ifdef SEVENT_WS_THREAD_SAFE
    sevent_mutex_destroy(&c->lock);
#endif
    sevent_i_free(c->recv_buf);
    sevent_i_free(c->frag_buf);
    sevent_i_free(c);
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
