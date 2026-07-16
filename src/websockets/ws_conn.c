/* =========================================================================
 *  ws_conn.c — WebSocket 连接状态机实现 (v2: 异步写队列)
 *
 *  send_frame 构造帧后入写队列, 异步 flush.
 *  控制帧 (PING/CLOSE) 插入队首优先发送.
 *  ========================================================================= */

#include "ws_conn.h"
#include "ws_frame.h"
#include "ws_handshake.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef SEVENT_WS_THREAD_SAFE
#include "../../include/sevent_platform.h"
#define WS_LOCK(c)   do { if ((c)) sevent_mutex_lock(&(c)->lock); } while(0)
#define WS_UNLOCK(c) do { if ((c)) sevent_mutex_unlock(&(c)->lock); } while(0)
#else
#define WS_LOCK(c)   ((void)0)
#define WS_UNLOCK(c) ((void)0)
#endif

/* 前向声明 (IO 回调, 供 ws_update_io / send_frame 引用) */
static void on_write_ready(void *data);
static void on_data(void *data);
static void on_handshake_data(void *data);

/* ====================================================================
 *  内部辅助
 * ==================================================================== */

static unsigned int next_seed(void)
{
    static unsigned int seed = 0;
    if (seed == 0) {
        seed = (unsigned int)(__TIME__[0] ^ (__TIME__[7] << 8) ^
                              (__TIME__[3] << 16) ^ (__TIME__[5] << 24));
        seed ^= (unsigned int)(getpid() << 16);
    }
    seed ^= seed << 13;
    seed ^= seed >> 17;
    seed ^= seed << 5;
    return seed;
}

static void gen_mask_key(uint8_t key[4])
{
    unsigned int r = next_seed();
    key[0] = (uint8_t)(r >> 24);
    key[1] = (uint8_t)(r >> 16);
    key[2] = (uint8_t)(r >> 8);
    key[3] = (uint8_t)(r);
}

static void ws_close_socket(struct sevent_ws_conn *c)
{
    if (c->io_handle) {
        sevent_io_unregister(c->ev, c->io_handle);
        c->io_handle = NULL;
    }
    if (c->fd >= 0) { close(c->fd); c->fd = -1; }
}

static void ws_enter_closed(struct sevent_ws_conn *c, uint16_t code,
                              const char *reason, size_t reason_len)
{
    if (c->state == WS_STATE_CLOSED || c->destroyed) return;
    c->state = WS_STATE_CLOSED;
    ws_close_socket(c);
    if (c->on_close)
        c->on_close(c->on_close_data ? c->on_close_data : c->user_data,
                     code, reason, reason_len);
}

static void ws_fatal(struct sevent_ws_conn *c, int err)
{
    if (c->destroyed || c->state == WS_STATE_CLOSED) return;
    if (c->on_error)
        c->on_error(c->on_error_data ? c->on_error_data : c->user_data, err);
    if (c->destroyed) return;  /* on_error 中 destroy 了连接 */
    ws_enter_closed(c, 0, "", 0);
}

/* ====================================================================
 *  接收缓冲
 * ==================================================================== */

static int rx_append(struct sevent_ws_conn *c, const uint8_t *data, size_t len)
{
    if (len == 0) return 0;
    if (c->rx_len + len > c->rx_cap) {
        size_t new_cap = c->rx_cap ? c->rx_cap * 2 : 4096;
        while (c->rx_len + len > new_cap) new_cap *= 2;
        uint8_t *new_buf = (uint8_t *)realloc(c->rx_buf, new_cap);
        if (!new_buf) return -1;
        c->rx_buf = new_buf; c->rx_cap = new_cap;
    }
    memcpy(c->rx_buf + c->rx_len, data, len);
    c->rx_len += len;
    return 0;
}

static void rx_compact(struct sevent_ws_conn *c)
{
    if (c->rx_consumed > 0) {
        size_t rem = c->rx_len - c->rx_consumed;
        if (rem > 0) memmove(c->rx_buf, c->rx_buf + c->rx_consumed, rem);
        c->rx_len = rem; c->rx_consumed = 0;
    }
}

/* ====================================================================
 *  异步写队列
 * ==================================================================== */

static int ws_enqueue(struct sevent_ws_conn *c, uint8_t *data, size_t len,
                        int is_ctrl)
{
    struct ws_write_node *n = (struct ws_write_node *)malloc(sizeof(*n));
    if (!n) { free(data); return -1; }
    n->data = data; n->len = len; n->offset = 0; n->is_ctrl = is_ctrl; n->next = NULL;

    if (is_ctrl && c->write_head) {
        /* 控制帧插入队首 */
        n->next = c->write_head;
        c->write_head = n;
    } else {
        /* 数据帧追加队尾 */
        if (c->write_tail)
            c->write_tail->next = n;
        else
            c->write_head = n;
        c->write_tail = n;
    }
    c->write_count++;
    return 0;
}

/* 尝试写队列中的数据; 返回还剩余多少字节未写入 */
static size_t ws_flush(struct sevent_ws_conn *c)
{
    while (c->write_head) {
        struct ws_write_node *n = c->write_head;
        ssize_t w = write(c->fd, n->data + n->offset, n->len - n->offset);
        if (w > 0) {
            n->offset += (size_t)w;
            if (n->offset < n->len)
                return c->write_count;  /* 部分写入, 停止本轮 flush */
            /* 节点写完, 释放 */
            c->write_head = n->next;
            if (!c->write_head) c->write_tail = NULL;
            c->write_count--;
            free(n->data); free(n);
        } else if (w < 0) {
            if (errno == EAGAIN || errno == EINTR)
                return c->write_count;
            /* 致命写错误 */
            ws_fatal(c, SEVENT_WS_ERR_WRITE);
            return 0;
        } else {
            /* write 返回 0 (不可能在 TCP 上发生) */
            c->write_head = n->next;
            if (!c->write_head) c->write_tail = NULL;
            c->write_count--;
            free(n->data); free(n);
        }
    }
    return 0;
}

/* 根据是否有待写数据更新 io_write 注册 */
static void ws_update_io(struct sevent_ws_conn *c,
                          void (*read_cb)(void *))
{
    struct sevent_io_handler h;
    h.fd       = c->fd;
    h.io_read  = read_cb;
    h.io_write = c->write_head ? on_write_ready : NULL;
    h.data     = c;
    if (c->io_handle) sevent_io_unregister(c->ev, c->io_handle);
    c->io_handle = sevent_io_register(c->ev, &h);
    if (!c->io_handle) ws_enter_closed(c, 0, "", 0);
}

/* 前向声明 */
static void on_write_ready(void *data);

/* ====================================================================
 *  发送帧: 构造 → 入队 → flush
 * ==================================================================== */

static int send_frame(struct sevent_ws_conn *c, uint8_t opcode,
                       const void *payload, size_t len)
{
    if (c->state != WS_STATE_OPEN && c->state != WS_STATE_CLOSING)
        return SEVENT_ERR_INVAL;

    uint8_t mask_key[4];
    gen_mask_key(mask_key);
    uint8_t hdr[16];
    int hdr_len = ws_frame_build_header(hdr, 1, opcode, mask_key, len);
    if (hdr_len < 0) return SEVENT_ERR_INVAL;

    size_t total = (size_t)hdr_len + len;
    uint8_t *buf = (uint8_t *)malloc(total);
    if (!buf) return SEVENT_ERR_NOMEM;
    memcpy(buf, hdr, (size_t)hdr_len);
    if (len > 0 && payload) {
        memcpy(buf + hdr_len, payload, len);
        ws_frame_apply_mask(buf + hdr_len, len, mask_key);
    }

    int is_ctrl = (opcode == WS_OPCODE_PING ||
                   opcode == WS_OPCODE_PONG ||
                   opcode == WS_OPCODE_CLOSE);
    if (ws_enqueue(c, buf, total, is_ctrl) != 0) return SEVENT_ERR_NOMEM;
    ws_flush(c);
    if (c->destroyed) return SEVENT_WS_ERR_WRITE;  /* flush 触发 ws_fatal→destroy */

    /* 队列非空则注册可写回调 (flush 可能在 io_write 回调内驱动) */
    if (c->write_head) {
        void (*rcb)(void *) = (c->state == WS_STATE_OPEN) ? on_data : NULL;
        ws_update_io(c, rcb);
    }

    return SEVENT_SUCCESS;
}

/* ====================================================================
 *  IO 回调: on_write_ready (可写, 驱动写队列)
 * ==================================================================== */

static void on_write_ready(void *data)
{
    struct sevent_ws_conn *c = (struct sevent_ws_conn *)data;
    WS_LOCK(c); if (c->destroyed) { WS_UNLOCK(c); return; }
    size_t remain = ws_flush(c);
    if (c->destroyed) { WS_UNLOCK(c); return; }  /* ws_flush 触发 ws_fatal→destroy */
    if (remain == 0) {
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

static void process_frames(struct sevent_ws_conn *c)
{
    while (c->rx_consumed < c->rx_len) {
        size_t avail = c->rx_len - c->rx_consumed;
        const uint8_t *p = c->rx_buf + c->rx_consumed;
        ws_frame_header hdr;
        int n = ws_frame_parse_header(p, avail, &hdr);
        if (n == 0) break;
        if (n < 0) { ws_fatal(c, SEVENT_WS_ERR_PROTOCOL); return; }
        /* 32 位截断保护: uint64_t payload_len 转 size_t 前检查溢出 */
        if (hdr.payload_len > SIZE_MAX - (size_t)n) { ws_fatal(c, SEVENT_WS_ERR_PROTOCOL); return; }
        size_t frame_size = (size_t)n + (size_t)hdr.payload_len;
        if (avail < frame_size) break;
        uint8_t *payload = (uint8_t *)p + n;
        if (hdr.mask) ws_frame_apply_mask(payload, hdr.payload_len, hdr.mask_key);

        switch (hdr.opcode) {
        case WS_OPCODE_TEXT:
        case WS_OPCODE_BINARY:
            if (c->on_message) {
                void *d = c->on_message_data ? c->on_message_data : c->user_data;
                c->on_message(d, payload, (size_t)hdr.payload_len,
                               (hdr.opcode == WS_OPCODE_BINARY) ? 1 : 0);
            }
            break;
        case WS_OPCODE_PING:
            send_frame(c, WS_OPCODE_PONG, payload, (size_t)hdr.payload_len);
            if (c->destroyed) return;  /* send_frame 触发 ws_fatal→destroy */
            break;
        case WS_OPCODE_PONG:
            break;
        case WS_OPCODE_CLOSE: {
            uint16_t code = 1000;
            const char *reason = ""; size_t rl = 0;
            if (hdr.payload_len >= 2) {
                code = (uint16_t)((payload[0] << 8) | payload[1]);
                reason = (const char *)(payload + 2);
                rl = (size_t)hdr.payload_len - 2;
            }
            if (c->state == WS_STATE_CLOSING)
                ws_enter_closed(c, code, reason, rl);
            else {
                send_frame(c, WS_OPCODE_CLOSE, payload, (size_t)hdr.payload_len);
                if (c->destroyed) return;  /* send_frame 触发 ws_fatal→destroy */
                ws_enter_closed(c, code, reason, rl);
            }
            return;
        }
        default:
            break;
        }
        c->rx_consumed += frame_size;
    }
    rx_compact(c);
}

static void on_data(void *data)
{
    struct sevent_ws_conn *c = (struct sevent_ws_conn *)data;
    WS_LOCK(c); if (c->destroyed) { WS_UNLOCK(c); return; }
    uint8_t tmp[4096];
    ssize_t n = read(c->fd, tmp, sizeof(tmp));
    if (n > 0) {
        if (rx_append(c, tmp, (size_t)n) == 0) process_frames(c);
        else ws_fatal(c, SEVENT_ERR_NOMEM);
    } else if (n == 0) {
        ws_enter_closed(c, 1006, "connection closed", 18);
    } else {
        if (errno != EAGAIN && errno != EINTR)
            ws_enter_closed(c, 1006, "read error", 10);
    }
    WS_UNLOCK(c);
}

/* ====================================================================
 *  握手
 * ==================================================================== */

static void on_handshake_data(void *data)
{
    struct sevent_ws_conn *c = (struct sevent_ws_conn *)data;
    WS_LOCK(c); if (c->destroyed) { WS_UNLOCK(c); return; }
    uint8_t tmp[2048];
    ssize_t n = read(c->fd, tmp, sizeof(tmp));
    if (n <= 0) {
        if (n == 0 || (errno != EAGAIN && errno != EINTR))
            ws_fatal(c, SEVENT_WS_ERR_HANDSHAKE);
        WS_UNLOCK(c); return;
    }
    if (rx_append(c, tmp, (size_t)n) != 0) {
        ws_fatal(c, SEVENT_ERR_NOMEM); WS_UNLOCK(c); return;
    }
    ws_handshake_response resp;
    int ret = ws_parse_response(c->rx_buf, c->rx_len, &resp);
    if (ret == 0) { WS_UNLOCK(c); return; }
    if (ret < 0) { ws_fatal(c, SEVENT_WS_ERR_HANDSHAKE); WS_UNLOCK(c); return; }
    if (ws_verify_accept(c->sec_ws_key, resp.accept) != 0) {
        ws_fatal(c, SEVENT_WS_ERR_HANDSHAKE); WS_UNLOCK(c); return;
    }
    c->rx_len = 0; c->rx_consumed = 0;
    c->state = WS_STATE_OPEN;
    ws_update_io(c, on_data);
    if (c->on_open)
        c->on_open(c->on_open_data ? c->on_open_data : c->user_data);
    WS_UNLOCK(c);
}

static void on_connect_ready(void *data)
{
    struct sevent_ws_conn *c = (struct sevent_ws_conn *)data;
    WS_LOCK(c); if (c->destroyed) { WS_UNLOCK(c); return; }
    int err = 0; socklen_t el = sizeof(err);
    if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, &err, &el) != 0 || err != 0) {
        ws_fatal(c, SEVENT_WS_ERR_CONNECT); WS_UNLOCK(c); return;
    }
    ws_gen_key(c->sec_ws_key);
    char req[1024];
    int req_len = ws_build_request(req, sizeof(req),
                                    c->host, c->port, c->path,
                                    c->sec_ws_key,
                                    c->sub_protocol[0] ? c->sub_protocol : NULL);
    if (req_len < 0) { ws_fatal(c, SEVENT_ERR_NOMEM); WS_UNLOCK(c); return; }
    ssize_t w = write(c->fd, req, (size_t)req_len);
    if (w < 0) { ws_fatal(c, SEVENT_WS_ERR_CONNECT); WS_UNLOCK(c); return; }
    c->state = WS_STATE_HANDSHAKE;
    ws_update_io(c, on_handshake_data);
    WS_UNLOCK(c);
}

/* ====================================================================
 *  公开 API
 * ==================================================================== */

sevent_ws_conn *sevent_ws_connect(sevent_context *ev,
                                   const struct sevent_ws_config *cfg)
{
    if (!ev || !cfg || !cfg->host || !cfg->path ||
        (!cfg->on_open && !cfg->on_error))
        return NULL;
    struct sevent_ws_conn *c = (struct sevent_ws_conn *)calloc(1, sizeof(*c));
    if (!c) return NULL;
#ifdef SEVENT_WS_THREAD_SAFE
    if (sevent_mutex_init_recursive(&c->lock) != 0) { free(c); return NULL; }
#endif
    c->ev = ev; c->fd = -1; c->state = WS_STATE_CONNECTING;
    strncpy(c->host, cfg->host, sizeof(c->host)-1);
    c->host[sizeof(c->host)-1] = '\0';
    c->port = cfg->port;
    strncpy(c->path, cfg->path, sizeof(c->path)-1);
    c->path[sizeof(c->path)-1] = '\0';
    if (cfg->sub_protocol) {
        strncpy(c->sub_protocol, cfg->sub_protocol, sizeof(c->sub_protocol)-1);
        c->sub_protocol[sizeof(c->sub_protocol)-1] = '\0';
    }
    c->on_open = cfg->on_open; c->on_message = cfg->on_message;
    c->on_close = cfg->on_close; c->on_error = cfg->on_error;
    c->user_data = cfg->user_data;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { free(c); return NULL; }
    {
        int fl = fcntl(fd, F_GETFL);
        if (fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0)
            { close(fd); free(c); return NULL; }
    }
    c->fd = fd;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(c->port);
    if (inet_pton(AF_INET, c->host, &addr.sin_addr) <= 0)
        { close(fd); free(c); return NULL; }
    int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (rc < 0 && errno != EINPROGRESS) { close(fd); free(c); return NULL; }
    struct sevent_io_handler h;
    h.fd = fd; h.io_read = NULL; h.io_write = on_connect_ready; h.data = c;
    c->io_handle = sevent_io_register(ev, &h);
    if (!c->io_handle) { close(fd); free(c); return NULL; }
    return c;
}

int sevent_ws_send_text(sevent_ws_conn *c, const void *data, size_t len)
{
    if (!c) return SEVENT_ERR_INVAL;
    WS_LOCK(c);
    int r = (data || len == 0) ? send_frame(c, WS_OPCODE_TEXT, data, len) : SEVENT_ERR_INVAL;
    WS_UNLOCK(c);
    return r;
}

int sevent_ws_send_binary(sevent_ws_conn *c, const void *data, size_t len)
{
    if (!c) return SEVENT_ERR_INVAL;
    WS_LOCK(c);
    int r = (data || len == 0) ? send_frame(c, WS_OPCODE_BINARY, data, len) : SEVENT_ERR_INVAL;
    WS_UNLOCK(c);
    return r;
}

int sevent_ws_ping(sevent_ws_conn *c, const void *payload, size_t len)
{
    if (!c || len > 125) return SEVENT_ERR_INVAL;
    WS_LOCK(c);
    int r = send_frame(c, WS_OPCODE_PING, payload, len);
    WS_UNLOCK(c);
    return r;
}

int sevent_ws_close(sevent_ws_conn *c, uint16_t code, const char *reason)
{
    if (!c) return SEVENT_ERR_INVAL;
    WS_LOCK(c);
    if (c->state != WS_STATE_OPEN) { WS_UNLOCK(c); return SEVENT_ERR_INVAL; }
    size_t rl = reason ? strlen(reason) : 0;
    if (rl > 123) rl = 123;
    uint8_t cp[128];
    cp[0] = (uint8_t)(code >> 8); cp[1] = (uint8_t)(code);
    if (rl > 0) memcpy(cp + 2, reason, rl);
    int ret = send_frame(c, WS_OPCODE_CLOSE, cp, 2 + rl);
    /* send_frame 中 ws_flush 可能触发 ws_fatal→ws_enter_closed 置为 CLOSED */
    if (ret == SEVENT_SUCCESS && !c->destroyed && c->state != WS_STATE_CLOSED)
        c->state = WS_STATE_CLOSING;
    WS_UNLOCK(c);
    return ret;
}

void sevent_ws_destroy(sevent_ws_conn *c)
{
    if (!c) return;
    /* destroy 无锁 — loop 线程专用 */
    c->destroyed = 1;
    c->state = WS_STATE_CLOSED;
    ws_close_socket(c);
    free(c->rx_buf);
    struct ws_write_node *wn = c->write_head;
    while (wn) { struct ws_write_node *n = wn->next; free(wn->data); free(wn); wn = n; }
#ifdef SEVENT_WS_THREAD_SAFE
    sevent_mutex_destroy(&c->lock);
#endif
    free(c);
}

int sevent_ws_get_state(const sevent_ws_conn *c)
{
    if (!c) return SEVENT_WS_STATE_CLOSED;
    WS_LOCK((struct sevent_ws_conn *)(uintptr_t)c);  /* const cast for locking */
    int s;
    switch (c->state) {
    case WS_STATE_CONNECTING:
    case WS_STATE_HANDSHAKE:  s = SEVENT_WS_STATE_CONNECTING; break;
    case WS_STATE_OPEN:       s = SEVENT_WS_STATE_OPEN; break;
    case WS_STATE_CLOSING:    s = SEVENT_WS_STATE_CLOSING; break;
    default:                  s = SEVENT_WS_STATE_CLOSED; break;
    }
    WS_UNLOCK((struct sevent_ws_conn *)(uintptr_t)c);
    return s;
}
