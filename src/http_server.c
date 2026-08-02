/* =========================================================================
 *  http_server.c — HTTP 服务器层 (连接管理 + 响应构造 + 升级出口)
 *
 *  设计定稿 (doc/http-layer-design.md §4):
 *    - 服务器类: create(传输配置) → listen(5 回调) → port/destroy
 *    - 内部组合: tcp_acceptor (监听) + stream_conn (连接, TLS 握手消化)
 *    - 连接状态机 8 态 (sevent_http_conn_state_t) + 状态×API 矩阵
 *    - keep-alive: 响应完成后处理下一请求 (数据到达驱动, 无需写空信号)
 *    - 响应后关闭: stream_shutdown(WR) — 已入队数据发完 + FIN (内核保证),
 *      半双工语义 (之后只能读, 等对端 EOF)
 *    - 升级出口两段式: release (摘除) → ws_upgrade 消费 (stream+缓冲移交)
 *    - 空闲超时: 每连接 timer, 活动时重置; 覆盖 PARSING/AWAIT_RESP/CLOSING,
 *      RESPONDING (响应进行中) 不超时
 *
 *  线程: 全部 [loop 线程] — 连接对象 API 仅事件循环线程调用 (回调内外均可).
 *  ========================================================================= */

#include "sevent_http_server.h"
#include "http_server_i.h"
#include "sevent_tcp_acceptor.h"
#include "sevent_stream_conn.h"
#include "sevent_i.h"

#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h> /* close */

#define HTTP_UPGRADE_KEY_MAX 64 /* Sec-WebSocket-Key 缓冲 (实际 24 字节, 留余量) */

/* ===== 内部结构 ===== */

struct sevent_http_conn {
    struct http_server *srv;
    sevent_stream_conn *stream;

    sevent_http_conn_state_t state;

    /* 解析缓冲 (分帧累积; 响应未完成期间到达的数据也攒于此, 有界) */
    uint8_t *recv_buf;
    size_t   recv_len;
    size_t   recv_cap;

    /* 当前请求预解析字段 (分派/关闭判定用) */
    bool req_keep_alive;                    /* 请求的 keep_alive (HTTP/1.0 或 Connection: close → false) */
    char upgrade_key[HTTP_UPGRADE_KEY_MAX]; /* 升级请求的 Sec-WebSocket-Key (on_upgrade 分派时保存, ws_upgrade 消费) */
    bool close_pending;                     /* 响应后关 (close 字段 / keep_alive=false / 用户 close) */
    bool released;                          /* RELEASED: ws_upgrade 消费中 */
    bool wrote;                             /* 本请求已 write 过 (互斥判定: respond 拒绝; 流式判定) */

    /* 空闲超时 (活动时重置; <0 禁用) */
    sevent_timer *idle_timer;

    struct sevent_http_conn *next; /* 服务器连接列表 */
};

struct http_server {
    sevent_context           *ev;
    sevent_http_server_config cfg;
    sevent_tcp_acceptor      *acceptor;

    sevent_http_on_accept_fn     on_accept;
    sevent_http_on_request_fn    on_request;
    sevent_http_on_upgrade_fn    on_upgrade;
    sevent_http_on_conn_close_fn on_conn_close;
    sevent_http_on_error_fn      on_error;
    void                        *ud;

    struct sevent_http_conn *conns;
    bool                     destroyed; /* destroy 延迟执行 (回调栈安全) */
};

#define HTTP_HEADER_BUF_SIZE 4096          /* 响应头区构造上限 */
#define HTTP_PROCESS_BUDGET 64             /* 每轮事件处理请求数上限 (超限让出, 防事件循环饥饿) */
#define HTTP_RECV_BUF_DEFAULT 4096         /* 默认解析缓冲 (单请求上限, 头+body) */
#define HTTP_OVERFLOW_PROCESS_LIMIT 16     /* 缓冲溢出时最多消费轮数 (~1024 请求, 防 DoS) */
#define HTTP_IDLE_TIMEOUT_DEFAULT_MS 60000 /* 空闲超时默认值 (cfg 0=默认) */

/* ===== 状态文本查表 (text=NULL 时) ===== */
static const char *http_status_text(int status) {
    switch(status) {
    case 200:
        return "OK";
    case 201:
        return "Created";
    case 204:
        return "No Content";
    case 301:
        return "Moved Permanently";
    case 302:
        return "Found";
    case 304:
        return "Not Modified";
    case 400:
        return "Bad Request";
    case 401:
        return "Unauthorized";
    case 403:
        return "Forbidden";
    case 404:
        return "Not Found";
    case 405:
        return "Method Not Allowed";
    case 409:
        return "Conflict";
    case 413:
        return "Payload Too Large";
    case 429:
        return "Too Many Requests";
    case 500:
        return "Internal Server Error";
    case 501:
        return "Not Implemented";
    case 502:
        return "Bad Gateway";
    case 503:
        return "Service Unavailable";
    default:
        return NULL; /* 未知码: text 必填 */
    }
}

/* ===== 前向声明 ===== */
static void conn_free(struct sevent_http_conn *c); /* 摘列表 + 通知 + 延迟释放 (调用方保证安全) */
static void conn_close_graceful(struct sevent_http_conn *c); /* 半关: shutdown(WR) → CLOSING */
static void conn_terminate(struct sevent_http_conn *c);      /* 立即终结 (对端 EOF/错误) */
static void http_process(struct sevent_http_conn *c);        /* PARSING: 分帧 + 分派 */
static void http_process_post(void *data);                   /* budget 让出后续处理 (post) */
static void http_respond_internal(struct sevent_http_conn *c, int status, bool close_it);
static int  conn_respond_build(struct sevent_http_conn    *c,
                               const sevent_http_response *resp,
                               bool                        internal_close,
                               bool                       *need_shutdown);
static void conn_idle_reset(struct sevent_http_conn *c);
static void conn_idle_stop(struct sevent_http_conn *c);

/* ===== 终局态谓词 (状态机终止路径统一判定) ===== */

/* 收尾中/已销毁/已移交 — 任何 API 操作都应拒绝 */
static bool conn_dying(const struct sevent_http_conn *c) {
    return c->state == HTTP_CONN_CLOSING || c->state == HTTP_CONN_CLOSED || c->state == HTTP_CONN_RELEASED;
}

/* 已销毁/已移交 — 连接对象即将或已经脱离管理 (不能触碰 stream/缓冲) */
static bool conn_dead(const struct sevent_http_conn *c) {
    return c->state == HTTP_CONN_CLOSED || c->state == HTTP_CONN_RELEASED;
}

/* 摘列表 (conn_free / release 共用) */
static void conn_unlink(struct http_server *s, struct sevent_http_conn *c) {
    struct sevent_http_conn **pp = &s->conns;
    while(*pp && *pp != c)
        pp = &(*pp)->next;
    if(*pp)
        *pp = c->next;
}

/* 关闭 + 销毁底层 stream (终结/销毁路径共用) */
static void conn_stream_kill(struct sevent_http_conn *c) {
    if(c->stream) {
        sevent_stream_close(c->stream);
        sevent_stream_destroy(c->stream);
        c->stream = NULL;
    }
}

/* ===== 空闲超时 ===== */

static void on_idle_timeout(void *data) {
    struct sevent_http_conn *c = (struct sevent_http_conn *)data;
    /* interval timer: 回调内必须注销自身, 否则到期后再次触发 (连接可能已释放 → UAF) */
    conn_idle_stop(c);
    /* 空闲超时: 无请求/无响应进行中 → 关闭.
     * 关闭路径统一 conn_terminate — 仍走 on_conn_close 通知 + 延迟释放.
     * RESPONDING (响应流式中) 豁免 — 超长响应不误杀. */
    if(c->state == HTTP_CONN_PARSING || c->state == HTTP_CONN_AWAIT_RESP || c->state == HTTP_CONN_CLOSING) {
        conn_terminate(c);
    }
}

static void conn_idle_stop(struct sevent_http_conn *c) {
    if(c->idle_timer) {
        sevent_timer_unregister(c->srv->ev, c->idle_timer);
        c->idle_timer = NULL;
    }
}

static void conn_idle_reset(struct sevent_http_conn *c) {
    if(c->srv->cfg.idle_timeout_ms < 0)
        return; /* 禁用 */
    unsigned int ms =
            c->srv->cfg.idle_timeout_ms ? (unsigned int)c->srv->cfg.idle_timeout_ms : HTTP_IDLE_TIMEOUT_DEFAULT_MS;
    conn_idle_stop(c);
    c->idle_timer = sevent_timer_register(c->srv->ev, ms, on_idle_timeout, c);
}

/* ===== 连接终结 ===== */

/* 半关: 已入队数据发完 + FIN (内核保证), 之后只能读 — 等对端 EOF */
static void conn_close_graceful(struct sevent_http_conn *c) {
    if(conn_dying(c))
        return;
    c->state = HTTP_CONN_CLOSING;
    if(c->stream)
        (void)sevent_stream_shutdown(c->stream, SEVENT_SHUT_WR);
    /* 半关后空闲超时继续适用 (防挂起): timer 已存在, 活动停止后到期关 */
}

/* 立即终结: 对端 EOF / stream 错误 / 空闲超时 */
static void conn_terminate(struct sevent_http_conn *c) {
    if(conn_dead(c))
        return;
    c->state = HTTP_CONN_CLOSED;
    conn_idle_stop(c);
    conn_stream_kill(c);
    conn_free(c);
}

/* 延迟释放 (post 队列 — 回调栈安全: 执行时连接已摘列表, 只归还内存) */
static void conn_cleanup(void *data) {
    struct sevent_http_conn *c = (struct sevent_http_conn *)data;
    sevent_i_free(c->recv_buf);
    sevent_i_free(c);
}

/* 通知用户 + 延迟释放 (conn_free / srv_cleanup 共用; 升级转交的连接不通知) */
static void conn_notify_deferred_free(struct http_server *s, struct sevent_http_conn *c) {
    if(s->on_conn_close && !c->released)
        s->on_conn_close(s->ud, c);
    /* 延迟释放 (回调栈安全: on_conn_close 内用户可能还引用 conn) */
    if(sevent_post(s->ev, conn_cleanup, c) != 0)
        conn_cleanup(c); /* post 失败 (OOM): 直接释放 */
}

/* 摘列表 + 通知用户 + 延迟释放 (调用方保证已脱离活动状态) */
static void conn_free(struct sevent_http_conn *c) {
    conn_unlink(c->srv, c);
    conn_notify_deferred_free(c->srv, c);
}

/* ===== stream 回调组 ===== */

static void conn_on_open(void *d) {
    struct sevent_http_conn *c = (struct sevent_http_conn *)d;
    struct http_server      *s = c->srv;
    if(c->released)
        return;
    c->state = HTTP_CONN_NEW;
    /* 用户 on_accept: 可 close 拒绝 / 持有引用 */
    if(s->on_accept)
        s->on_accept(s->ud, c);
    if(conn_dying(c)) {
        conn_idle_reset(c); /* 拒绝分支: CLOSING 挂起也要空闲超时兜底 (防对端不关) */
        return;
    }
    c->state = HTTP_CONN_PARSING;
    conn_idle_reset(c);
}

static void conn_on_data(void *d, const uint8_t *data, size_t len) {
    struct sevent_http_conn *c = (struct sevent_http_conn *)d;
    if(conn_dying(c))
        return; /* 收尾期数据忽略 */
    /* 攒入解析缓冲 (响应进行中/等待响应期间到达的数据也攒 — 有界保护) */
    if(len > c->recv_cap - c->recv_len) {
        /* 缓冲将溢出: PARSING 态先尽力消费残留 (budget 让出期间的合法管道
         * burst — 残留+新数据超界不代表单请求超限; 处理有轮数上限防 DoS),
         * 仍放不下才关连接 (连接级缓冲不足, 非 413 语义) */
        if(c->state == HTTP_CONN_PARSING) {
            for(int k = 0;
                k < HTTP_OVERFLOW_PROCESS_LIMIT && !conn_dying(c) && c->recv_len > 0 && len > c->recv_cap - c->recv_len;
                k++)
                http_process(c);
            if(!conn_dying(c) && len <= c->recv_cap - c->recv_len)
                goto receive; /* 消费后腾出空间 — 接收新数据 */
        }
        conn_close_graceful(c);
        return;
    }
receive:
    memcpy(c->recv_buf + c->recv_len, data, len);
    c->recv_len += len;
    conn_idle_reset(c); /* 数据到达即活动 — 分片慢请求不被空闲超时误杀 */
    /* 状态机: PARSING (等请求, 含响应完成后转换回此态) → 处理;
     * 响应未完成 (REQUEST/AWAIT_RESP/流式 RESPONDING) → 攒着, 完成后再处理 */
    if(c->state == HTTP_CONN_PARSING)
        http_process(c);
}

static void conn_on_close(void *d) {
    struct sevent_http_conn *c = (struct sevent_http_conn *)d;
    if(c->released)
        return;
    conn_terminate(c); /* EOF → CLOSED + 释放 */
}

static void conn_on_error(void *d, int err) {
    struct sevent_http_conn *c = (struct sevent_http_conn *)d;
    (void)err;
    if(c->released)
        return;
    conn_terminate(c); /* 数据期致命错误: 同 EOF 收尾 */
}

static sevent_stream_conn_init conn_stream_init(struct sevent_http_conn *c) {
    sevent_stream_conn_init init;
    memset(&init, 0, sizeof(init));
    init.user_data     = c;
    init.on_open       = conn_on_open;
    init.on_data       = conn_on_data;
    init.on_close      = conn_on_close;
    init.on_error      = conn_on_error;
    init.recv_buf_size = c->recv_cap;
    return init;
}

/* ===== 请求处理 (PARSING) ===== */

/* 请求分派后回调返回: 响应完成则处理残留, 未完成则等 respond */
static void request_after_callback(struct sevent_http_conn *c, size_t consumed) {
    /* 残留数据 (粘包下一请求) */
    size_t remain = c->recv_len - consumed;
    if(remain > 0)
        memmove(c->recv_buf, c->recv_buf + consumed, remain);
    c->recv_len = remain;

    /* 响应完成 = 状态转换 (respond/write_end 内部已转换):
     *   PARSING → 回调内已响应完成 — 主循环 continue 迭代处理残留 (不在此递归)
     *   RESPONDING → 回调内已流式 write, 续写中 → 保持 (空闲超时豁免)
     *   CLOSING/CLOSED/RELEASED → 收尾/移交
     *   REQUEST → 未响应 → wrote 已流式 → RESPONDING; 未写 → AWAIT_RESP
     * 注: 不在此调 http_process — 主循环的 continue 已兜底迭代, 递归会爆栈
     *     (粘包 N 请求 → N 层栈, 恶意客户端可控). */
    if(c->state == HTTP_CONN_PARSING || conn_dying(c) || c->state == HTTP_CONN_RESPONDING)
        return;
    if(c->state == HTTP_CONN_REQUEST)
        c->state = c->wrote ? HTTP_CONN_RESPONDING : HTTP_CONN_AWAIT_RESP;
    conn_idle_reset(c); /* 异步窗口/流式中: 空闲超时适用 (RESPONDING 由超时回调豁免) */
}

/* 请求分派 (升级预处理 + 回调) — http_process 主循环每完整请求调用一次.
 * 返回 true = 已移交 ws (released), 主循环直接退出 */
static bool conn_dispatch(struct sevent_http_conn *c, const sevent_http_msg *m) {
    if(m->upgrade) {
        /* 保存 Sec-WebSocket-Key (请求消费后缓冲复用, ws_upgrade 需重算 accept) */
        c->upgrade_key[0] = '\0';
        size_t      kl;
        const char *kv = sevent_http_find_header(m, "sec-websocket-key", &kl);
        if(kv && kl + 1 < sizeof(c->upgrade_key)) {
            memcpy(c->upgrade_key, kv, kl);
            c->upgrade_key[kl] = '\0';
        }
        /* on_upgrade: 用户决定 拒绝 (respond) / 升级 (release + ws_upgrade) */
        if(c->srv->on_upgrade)
            c->srv->on_upgrade(c->srv->ud, m, c);
        else
            http_respond_internal(c, 400, true); /* 未注册升级处理: 明确拒绝 (不静默挂死) */
        return c->released;                      /* 已移交 ws — http 侧不再管理 */
    }
    if(c->srv->on_request)
        c->srv->on_request(c->srv->ud, m, c);
    return false;
}

static void http_process(struct sevent_http_conn *c) {
    int budget = HTTP_PROCESS_BUDGET;
    for(;;) {
        /* 关闭/移交后不再处理残留 (状态机: CLOSING/CLOSED/RELEASED 全禁) */
        if(c->recv_len == 0 || conn_dying(c))
            return;
        /* 事件循环公平性: 单轮处理预算 — 超限且残留未处理完 → post 让出
         * (粘包海量请求不饿死其他连接; 下一轮 run_posts 续处理) */
        if(budget-- <= 0) {
            if(sevent_post(c->srv->ev, http_process_post, c) != 0)
                conn_close_graceful(c); /* post 失败 (OOM): 收尾 */
            return;
        }
        sevent_http_msg m;
        int             r = sevent_http_parse((const char *)c->recv_buf, c->recv_len, &m);
        if(r < 0) {
            /* 分帧错误 / chunked (初版不支持) → 400 关 */
            http_respond_internal(c, 400, true);
            return;
        }
        if(r == 0) {
            if(c->recv_len >= c->recv_cap) {
                /* 缓冲满仍不完整 (超单请求上限) → 413 */
                http_respond_internal(c, 413, true);
            }
            return; /* 等更多 */
        }
        /* 完整请求 */
        size_t consumed   = (size_t)((const char *)m.body - (const char *)c->recv_buf) + m.body_len;
        c->req_keep_alive = m.keep_alive;
        c->state          = HTTP_CONN_REQUEST;
        c->close_pending  = !m.keep_alive; /* 关闭条件①: 请求带 close / HTTP/1.0 */
        c->wrote          = false;         /* 新请求: 清互斥/流式标记 */

        if(conn_dispatch(c, &m))
            return; /* 已移交 ws — http 侧不再管理 */
        if(conn_dying(c))
            return;
        request_after_callback(c, consumed);
        /* 仅回调内响应完成 (PARSING) 继续迭代残留 — AWAIT_RESP (异步窗口) /
         * RESPONDING (回调内已流式 write, 续写中) 必须停: 覆写 state 会
         * 截断流式响应并提前分派下一请求 (完成时 conn_response_complete
         * 会 post 让出续处理) */
        if(c->state == HTTP_CONN_PARSING)
            continue;
        return;
    }
}

/* budget 让出后的续处理. 安全性不变式: post 队列 FIFO 且连接 free 也是 post
 * (conn_cleanup) — 本回调先入队, 执行时 c 必然未释放; state 检查兜底
 * (连接可能在排队期间关闭 — CLOSED/CLOSING/RELEASED 直接返回). */
static void http_process_post(void *data) {
    struct sevent_http_conn *c = (struct sevent_http_conn *)data;
    if(conn_dying(c))
        return;
    if(c->recv_len > 0)
        http_process(c);
}

/* ===== 响应构造 ===== */

/* 头区追加 (vsnprintf + 溢出检查, 收敛 4 处重复的 snprintf 边界判断) */
static int head_append(char *head, size_t cap, size_t *hn, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(head + *hn, cap - *hn, fmt, ap);
    va_end(ap);
    if(n < 0 || (size_t)n >= cap - *hn)
        return SEVENT_ERR_INVAL; /* 头区溢出 */
    *hn += (size_t)n;
    return 0;
}

/* 构造头区 (状态行 + 头 + 自动 CL + close 注入) → 入写队列. 返回 0=OK.
 * 校验全部先于任何写入 (body/头非法时不产生半截响应). */
static int conn_respond_build(struct sevent_http_conn    *c,
                              const sevent_http_response *resp,
                              bool                        internal_close,
                              bool                       *need_shutdown) {
    *need_shutdown = false;

    const char *text = resp->text ? resp->text : http_status_text(resp->status);
    if(!text)
        return SEVENT_ERR_INVAL;
    if(resp->body_len > 0 && !resp->body)
        return SEVENT_ERR_INVAL; /* body_len>0 但 body=NULL — 校验先于写入 */

    /* 头区构造: 4096 超栈预算 → 堆分配, 错误路径 goto 统一释放 */
    char  *head = (char *)sevent_i_malloc(HTTP_HEADER_BUF_SIZE);
    size_t hn   = 0;
    int    rc   = SEVENT_ERR_INVAL;
    if(!head)
        return SEVENT_ERR_NOMEM;

    if(head_append(head, HTTP_HEADER_BUF_SIZE, &hn, "HTTP/1.1 %d %s\r\n", resp->status, text) != 0)
        goto out;

    for(const sevent_http_header *h = resp->headers; h; h = h->next) {
        if(!h->name || !h->value)
            goto out;
        if(head_append(head, HTTP_HEADER_BUF_SIZE, &hn, "%s: %s\r\n", h->name, h->value) != 0)
            goto out;
    }

    /* 自动 Content-Length */
    if(head_append(head, HTTP_HEADER_BUF_SIZE, &hn, "Content-Length: %zu\r\n", resp->body_len) != 0)
        goto out;

    /* close 注入: 响应 close 字段 / 内部关闭 / 请求 keep_alive=false */
    bool close_it = resp->close || internal_close || !c->req_keep_alive;
    if(close_it) {
        if(head_append(head, HTTP_HEADER_BUF_SIZE, &hn, "Connection: close\r\n") != 0)
            goto out;
    }
    if(hn + 2 > HTTP_HEADER_BUF_SIZE)
        goto out;
    memcpy(head + hn, "\r\n", 2);
    hn += 2;

    /* 入写队列: 头区 + body (一次写) */
    if(sevent_stream_write(c->stream, head, hn) != 0) {
        rc = SEVENT_ERR_WRITE;
        goto out;
    }
    if(resp->body_len > 0 && sevent_stream_write(c->stream, resp->body, resp->body_len) != 0) {
        rc = SEVENT_ERR_WRITE;
        goto out;
    }

    rc             = 0;
    *need_shutdown = close_it;
out:
    sevent_i_free(head);
    return rc;
}

/* 响应完成 = 状态转换 (respond/write_end 共用):
 *   close_pending → CLOSING (半关); 否则 → PARSING (keep-alive).
 * 残留处理: 仅异步完成 (was_async, 请求已消费) 有残留 — post 让出续处理
 * (http_process_post, 下一轮 run_posts — 不占本栈, 递归为零, 受 budget 约束);
 * 回调内完成 (REQUEST, 请求未消费) 由主循环 continue 迭代. */
static void conn_response_complete(struct sevent_http_conn *c, bool was_async) {
    if(c->close_pending) {
        conn_close_graceful(c);
    } else {
        c->state = HTTP_CONN_PARSING;
        conn_idle_reset(c);
        if(was_async && c->recv_len > 0)
            (void)sevent_post(c->srv->ev, http_process_post, c);
    }
}

/* 内部响应 (400/413): 无用户结构体 */
static void http_respond_internal(struct sevent_http_conn *c, int status, bool close_it) {
    if(conn_dying(c))
        return;
    sevent_http_response resp;
    memset(&resp, 0, sizeof(resp));
    resp.status        = status;
    bool need_shutdown = false;
    if(conn_respond_build(c, &resp, close_it, &need_shutdown) != 0)
        return;
    c->close_pending = true;
    conn_close_graceful(c); /* 内部错误响应一律关 */
}

/* ===== 连接对象 API ===== */

int sevent_http_conn_respond(sevent_http_conn *conn, sevent_http_response *resp) {
    struct sevent_http_conn *c = (struct sevent_http_conn *)conn;
    if(!c || !resp)
        return SEVENT_ERR_INVAL;
    if(c->state != HTTP_CONN_REQUEST && c->state != HTTP_CONN_AWAIT_RESP)
        return SEVENT_ERR_INVAL; /* 矩阵: 仅 REQUEST/AWAIT_RESP 可 respond (响应完成后回 PARSING, 重复 respond 报错) */
    if(c->wrote)
        return SEVENT_ERR_INVAL; /* 与 write 路径互斥: 已写过数据 (流式/原始) 后不再 respond */

    bool need_shutdown = false;
    int  rc            = conn_respond_build(c, resp, false, &need_shutdown);
    /* 无论成败都释放头节点 (调用后 resp 即弃 — 失败场景 (连接已关/状态非法)
     * 无法重试, 保留会泄漏; 可重试场景 (NOMEM/头区溢出) 用户重填即可) */
    sevent_http_response_clear(resp);
    if(rc != 0)
        return rc;

    bool was_await   = (c->state == HTTP_CONN_AWAIT_RESP);
    c->close_pending = c->close_pending || need_shutdown;
    conn_response_complete(c, was_await);
    return 0;
}

int sevent_http_conn_write(sevent_http_conn *conn, const uint8_t *buf, size_t len) {
    struct sevent_http_conn *c = (struct sevent_http_conn *)conn;
    if(!c || (!buf && len))
        return SEVENT_ERR_INVAL;
    if(c->state != HTTP_CONN_REQUEST && c->state != HTTP_CONN_AWAIT_RESP && c->state != HTTP_CONN_RESPONDING)
        return SEVENT_ERR_INVAL; /* respond 完成后回 PARSING — 再 write 报错 (路径互斥) */
    if(len == 0)
        return 0;
    if(sevent_stream_write(c->stream, buf, len) != 0)
        return SEVENT_ERR_WRITE;
    c->wrote = true;
    /* 仅异步窗口转 RESPONDING; 回调内 (REQUEST) 保持 — request_after_callback
     * 按 wrote 区分"回调内已流式"(→RESPONDING) vs "未写"(→AWAIT_RESP) */
    if(c->state == HTTP_CONN_AWAIT_RESP)
        c->state = HTTP_CONN_RESPONDING;
    return 0;
}

int sevent_http_conn_write_end(sevent_http_conn *conn) {
    struct sevent_http_conn *c = (struct sevent_http_conn *)conn;
    if(!c)
        return SEVENT_ERR_INVAL;
    if(c->state != HTTP_CONN_REQUEST && c->state != HTTP_CONN_RESPONDING)
        return SEVENT_ERR_INVAL; /* AWAIT_RESP = 本请求未写过数据, 无响应可结束 (流式中可 write 续写) */
    /* write 路径完成 = 状态转换 (conn_response_complete):
     * 残留: 回调内 (REQUEST) 由主循环 continue 迭代; 异步 (RESPONDING) post 让出 */
    bool was_async = (c->state == HTTP_CONN_RESPONDING);
    conn_response_complete(c, was_async);
    return 0;
}

void sevent_http_conn_close(sevent_http_conn *conn) {
    struct sevent_http_conn *c = (struct sevent_http_conn *)conn;
    if(!c)
        return;
    if(conn_dying(c))
        return;
    c->close_pending = true;
    conn_close_graceful(c); /* 半关: 无响应时仅 FIN */
}

sevent_stream_conn *sevent_http_conn_get_stream(sevent_http_conn *conn) {
    struct sevent_http_conn *c = (struct sevent_http_conn *)conn;
    if(!c || conn_dying(c))
        return NULL; /* 已关闭/移交 — 无可用 stream */
    return c->stream;
}

int sevent_http_conn_state(const sevent_http_conn *conn) {
    const struct sevent_http_conn *c = (const struct sevent_http_conn *)conn;
    if(!c)
        return HTTP_CONN_CLOSED;
    return (int)c->state;
}

int sevent_http_conn_release(sevent_http_conn *conn) {
    struct sevent_http_conn *c = (struct sevent_http_conn *)conn;
    if(!c)
        return SEVENT_ERR_INVAL;
    if(c->released)
        return SEVENT_ERR_INVAL;
    if(c->state != HTTP_CONN_REQUEST)
        return SEVENT_ERR_INVAL; /* 仅 on_upgrade 回调内 (REQUEST 态) */
    c->released = true;
    c->state    = HTTP_CONN_RELEASED;
    conn_idle_stop(c);
    /* 摘列表 (on_conn_close 不再触发 — 升级转交; 壳由 ws_upgrade 消费释放) */
    conn_unlink(c->srv, c);
    return 0;
}

/* ===== 响应辅助函数 ===== */

void sevent_http_response_init(sevent_http_response *resp) { memset(resp, 0, sizeof(*resp)); }

static int response_header_add_node(sevent_http_response *resp, const char *name, const char *value, bool dedup) {
    if(!resp || !name || !value)
        return SEVENT_ERR_INVAL;
    if(dedup) {
        /* 查重: 同名覆盖 (后一个生效) */
        sevent_http_header **pp = &resp->headers;
        while(*pp) {
            if(strcmp((*pp)->name, name) == 0) {
                (*pp)->value = value;
                return 0;
            }
            pp = &(*pp)->next;
        }
    }
    sevent_http_header *h = (sevent_http_header *)sevent_i_malloc(sizeof(*h));
    if(!h)
        return SEVENT_ERR_NOMEM;
    h->name       = name;
    h->value      = value;
    h->next       = resp->headers;
    resp->headers = h;
    return 0;
}

int sevent_http_response_header_set(sevent_http_response *resp, const char *name, const char *value) {
    return response_header_add_node(resp, name, value, true);
}

int sevent_http_response_header_add(sevent_http_response *resp, const char *name, const char *value) {
    return response_header_add_node(resp, name, value, false);
}

int sevent_http_response_header_del(sevent_http_response *resp, const char *name) {
    if(!resp || !name)
        return 0;
    int                  count = 0;
    sevent_http_header **pp    = &resp->headers;
    while(*pp) {
        if(strcmp((*pp)->name, name) == 0) {
            sevent_http_header *dead = *pp;
            *pp                      = dead->next;
            sevent_i_free(dead);
            count++;
        } else {
            pp = &(*pp)->next;
        }
    }
    return count;
}

void sevent_http_response_clear(sevent_http_response *resp) {
    if(!resp)
        return;
    sevent_http_header *h = resp->headers;
    while(h) {
        sevent_http_header *dead = h;
        h                        = h->next;
        sevent_i_free(dead);
    }
    resp->headers = NULL;
}

/* ===== 服务器 ===== */

/* 建连失败清理 (stream 未建/未入列表时安全; conn_cleanup 同步直调语义等价) */
static void srv_conn_abort(struct sevent_http_conn *c, int fd) {
    conn_stream_kill(c); /* stream 未建 (NULL) 时为空操作 */
    conn_cleanup(c);
    close(fd);
}

static void srv_on_accept(void *d, int fd) {
    struct http_server *s = (struct http_server *)d;

    struct sevent_http_conn *c = (struct sevent_http_conn *)sevent_i_calloc(1, sizeof(*c));
    if(!c) {
        close(fd);
        return;
    }
    c->srv      = s;
    c->state    = HTTP_CONN_NEW;
    c->recv_cap = s->cfg.recv_buf_size ? s->cfg.recv_buf_size : HTTP_RECV_BUF_DEFAULT;
    c->recv_buf = (uint8_t *)sevent_i_malloc(c->recv_cap);
    if(!c->recv_buf) {
        srv_conn_abort(c, fd);
        return;
    }

    /* stream 建连 (TLS 服务端握手在 stream 层消化) */
    sevent_stream_conn_config scfg;
    memset(&scfg, 0, sizeof(scfg));
    scfg.enable_tls             = s->cfg.enable_tls;
    scfg.ca_path                = s->cfg.ca_path;
    scfg.ca_pem                 = s->cfg.ca_pem;
    scfg.cert_path              = s->cfg.cert_path;
    scfg.cert_pem               = s->cfg.cert_pem;
    scfg.key_path               = s->cfg.key_path;
    scfg.key_pem                = s->cfg.key_pem;
    scfg.enable_peer_verify     = s->cfg.verify_peer;
    scfg.enable_hostname_verify = false; /* 服务端不对对端做 hostname 校验 */
    c->stream                   = sevent_stream_create(s->ev, &scfg);
    if(!c->stream) {
        srv_conn_abort(c, fd);
        return;
    }

    sevent_stream_conn_init init = conn_stream_init(c);
    if(sevent_stream_accept(c->stream, fd, &init) < 0) {
        /* 同步失败 (TLS 握手错误等) → on_error */
        srv_conn_abort(c, fd);
        if(s->on_error)
            s->on_error(s->ud, SEVENT_ERR_HANDSHAKE);
        return;
    }
    /* 入列表 (on_open 前, 回调栈内不摘除) */
    c->next  = s->conns;
    s->conns = c;
}

sevent_http_server *sevent_http_server_create(sevent_context *ev, const sevent_http_server_config *cfg) {
    if(!ev || !cfg)
        return NULL;
    struct http_server *s = (struct http_server *)sevent_i_calloc(1, sizeof(*s));
    if(!s)
        return NULL;
    s->ev       = ev;
    s->cfg      = *cfg;
    s->acceptor = sevent_tcp_acceptor_create(ev);
    if(!s->acceptor) {
        sevent_i_free(s);
        return NULL;
    }
    return (sevent_http_server *)s;
}

int sevent_http_server_listen(sevent_http_server          *server,
                              const char                  *host,
                              uint16_t                     port,
                              int                          backlog,
                              sevent_http_on_accept_fn     on_accept,
                              sevent_http_on_request_fn    on_request,
                              sevent_http_on_upgrade_fn    on_upgrade,
                              sevent_http_on_conn_close_fn on_conn_close,
                              sevent_http_on_error_fn      on_error,
                              void                        *ud) {
    struct http_server *s = (struct http_server *)server;
    if(!s || (!on_request && !on_upgrade))
        return SEVENT_ERR_INVAL;
    s->on_accept     = on_accept;
    s->on_request    = on_request;
    s->on_upgrade    = on_upgrade;
    s->on_conn_close = on_conn_close;
    s->on_error      = on_error;
    s->ud            = ud;
    return sevent_tcp_acceptor_listen(s->acceptor, host, port, backlog, srv_on_accept, s);
}

uint16_t sevent_http_server_port(const sevent_http_server *server) {
    const struct http_server *s = (const struct http_server *)server;
    if(!s)
        return 0;
    int port = sevent_tcp_acceptor_port(s->acceptor);
    return port > 0 ? (uint16_t)port : 0; /* 未监听 (底层 -1) → 0 */
}

static void srv_cleanup(void *data) {
    struct http_server      *s = (struct http_server *)data;
    /* 关闭全部未完成连接 (已升级转交的连接已摘除).
     * 每个连接: 置 CLOSED (阻断后续 http_process_post 续处理) → 通知
     * on_conn_close (用户清理持有的引用) → 销毁 stream → post 延迟释放.
     * 释放必须延迟: 连接活跃期入队的 http_process_post 可能在 srv_cleanup
     * 之后执行 (同轮 post FIFO) — 置 CLOSED 使其读到活连接并直接返回,
     * conn_cleanup 排在队尾, 保证任何续处理先于释放 (与 conn_free 的不变式一致). */
    struct sevent_http_conn *c = s->conns;
    while(c) {
        struct sevent_http_conn *next = c->next;
        c->state                      = HTTP_CONN_CLOSED;
        conn_idle_stop(c);
        if(s->on_conn_close && !c->released)
            s->on_conn_close(s->ud, c);
        conn_stream_kill(c);
        if(sevent_post(s->ev, conn_cleanup, c) != 0)
            conn_cleanup(c); /* post 失败 (OOM): 直接释放 (无续处理可抢先) */
        c = next;
    }
    s->conns = NULL;
    sevent_tcp_acceptor_destroy(s->acceptor);
    sevent_i_free(s);
}

void sevent_http_server_destroy(sevent_http_server *server) {
    struct http_server *s = (struct http_server *)server;
    if(!s || s->destroyed)
        return;
    s->destroyed = true;
    if(sevent_post(s->ev, srv_cleanup, s) != 0)
        srv_cleanup(s);
}

/* ===== 内部接口 (ws_upgrade 消费已释放连接) ===== */

sevent_stream_conn *sevent_http_conn_i_detach_stream(sevent_http_conn *conn) {
    struct sevent_http_conn *c = (struct sevent_http_conn *)conn;
    if(!c || !c->released)
        return NULL;
    sevent_stream_conn *s = c->stream;
    c->stream             = NULL;
    return s;
}

uint8_t *sevent_http_conn_i_take_recv(sevent_http_conn *conn, size_t *len, size_t *cap) {
    struct sevent_http_conn *c = (struct sevent_http_conn *)conn;
    if(!c || !c->released || !c->recv_buf)
        return NULL;
    uint8_t *b = c->recv_buf;
    if(len)
        *len = c->recv_len;
    if(cap)
        *cap = c->recv_cap;
    c->recv_buf = NULL;
    c->recv_len = c->recv_cap = 0;
    return b;
}

const char *sevent_http_conn_i_upgrade_key(sevent_http_conn *conn) {
    struct sevent_http_conn *c = (struct sevent_http_conn *)conn;
    if(!c || !c->released || c->upgrade_key[0] == '\0')
        return NULL;
    return c->upgrade_key;
}
