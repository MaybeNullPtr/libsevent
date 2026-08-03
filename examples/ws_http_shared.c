/**
 *  ws_http_shared.c — HTTP + WebSocket 共用端口示例 (sevent_http_server + ws_upgrade)
 *
 *  功能: 同一端口 (8080) 同时服务:
 *    - HTTP 请求  → on_request → 普通 http 响应 (keep-alive)
 *    - WS 升级请求 → on_upgrade → sevent_ws_upgrade → ws echo 连接
 *
 *  用法: make example-ws-http-shared && ./example-ws-http-shared
 *        curl http://127.0.0.1:8080/            # http 响应
 *        # ws 客户端连 ws://127.0.0.1:8080/ws  (echo)
 *
 *  演示点:
 *    - 共用端口: http 服务与 ws 服务器同端口共存 — 分派由 http_server 完成
 *      (on_request vs on_upgrade), ws 层只消费升级连接 (release 已并入 ws_upgrade)
 *    - 升级转移: on_upgrade 内一步调用 sevent_ws_upgrade(conn, &cfg) —
 *      stream + 解析缓冲 (含粘包残留) 移交, 同步握手 (101/on_open 在回调栈内)
 *    - ws echo: on_message 回显 (消息级 — fin=true 才回显)
 *    - 生命周期: ws 连接归用户 (on_upgrade 返回后持有); on_conn_close 只处理
 *      http 连接 (升级转交的连接不走该回调)
 */

#include "sevent.h"
#include "sevent_http_server.h"
#include "sevent_ws.h"
#include "sevent_stream_conn.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PORT 8080

/* ---- ws echo 连接上下文 (user_data) ---- */
struct ws_app {
    sevent_ws_conn *ws;
    uint8_t        *msg_buf; /* 消息级回显缓存 (流式/分片攒到 fin) */
    size_t          msg_len, msg_cap;
    bool            msg_binary;
};

static void ws_msg_reset(struct ws_app *a) {
    a->msg_len    = 0;
    a->msg_binary = false;
}

static int ws_msg_append(struct ws_app *a, const void *m, size_t l, bool binary) {
    if(a->msg_len + l > a->msg_cap) {
        size_t nc = a->msg_cap ? a->msg_cap * 2 : 4096;
        while(nc < a->msg_len + l)
            nc *= 2;
        uint8_t *nb = (uint8_t *)realloc(a->msg_buf, nc);
        if(!nb)
            return -1;
        a->msg_buf = nb;
        a->msg_cap = nc;
    }
    memcpy(a->msg_buf + a->msg_len, m, l);
    a->msg_len    += l;
    a->msg_binary = binary;
    return 0;
}

static void ws_on_message(void *d, const void *m, size_t l, bool binary, bool fin, uint64_t total) {
    (void)total;
    struct ws_app *a = (struct ws_app *)d;
    if(ws_msg_append(a, m, l, binary) != 0)
        return;
    if(!fin)
        return; /* 消息未完: 攒着 */
    if(a->msg_binary)
        (void)sevent_ws_send_binary(a->ws, a->msg_buf, a->msg_len);
    else
        (void)sevent_ws_send_text(a->ws, a->msg_buf, a->msg_len);
    ws_msg_reset(a);
}

static void ws_on_close(void *d, uint16_t code, const char *reason, size_t reason_len) {
    (void)code;
    (void)reason;
    (void)reason_len;
    struct ws_app *a = (struct ws_app *)d;
    free(a->msg_buf);
    free(a);
}

static void ws_on_error(void *d, int err) {
    (void)err;
    struct ws_app *a = (struct ws_app *)d;
    if(a->ws) {
        sevent_ws_destroy(a->ws);
        a->ws = NULL;
    }
    free(a->msg_buf);
    free(a);
}

/* ---- http_server 回调 ---- */

static void on_request(void *ud, const sevent_http_msg *req, sevent_http_conn *conn) {
    (void)ud;
    static const char    body[] = "HTTP from shared port!\n";
    sevent_http_response resp;
    sevent_http_response_init(&resp);
    resp.status   = 200;
    resp.body     = body;
    resp.body_len = sizeof(body) - 1;
    (void)sevent_http_conn_respond(conn, &resp);
}

static sevent_http_upgrade_result_t on_upgrade(void *ud, const sevent_http_msg *req, sevent_http_conn *conn) {
    (void)ud;
    (void)req;
    struct ws_app *a = (struct ws_app *)calloc(1, sizeof(*a));
    if(!a) {
        /* 拒绝: 资源不足 — 回 503, 连接留 http server */
        sevent_http_response resp;
        sevent_http_response_init(&resp);
        resp.status = 503;
        (void)sevent_http_conn_respond(conn, &resp);
        return SEVENT_HTTP_UPGRADE_DECLINED;
    }
    /* cfg 为栈局部: 库内部自有拷贝, 返回后可安全释放.
     * 升级即调用 (release 已并入): stream + 缓冲移交, 同步握手 */
    sevent_ws_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.user_data  = a;
    cfg.on_message = ws_on_message;
    cfg.on_close   = ws_on_close;
    cfg.on_error   = ws_on_error;
    a->ws          = sevent_ws_upgrade(conn, &cfg);
    if(!a->ws) {
        /* 升级失败: 库已关闭底层连接 — 释放上下文 */
        free(a->msg_buf);
        free(a);
    }
    /* 契约: 调用了 ws_upgrade 一律 TAKEN (调用即接管 — 连接已脱离 http 管理) */
    return SEVENT_HTTP_UPGRADE_TAKEN;
}

static void on_conn_close(void *ud, sevent_http_conn *conn) {
    (void)ud;
    (void)conn;
    /* 仅 http 连接走本回调 (升级转交的 ws 连接已脱离) */
    printf("[shared] http conn closed\n");
}

static void on_error(void *ud, int err) {
    (void)ud;
    fprintf(stderr, "[shared] transport error: %d\n", err);
}

/* ---- main ---- */

int main(void) {
    sevent_context *ctx = sevent_create();
    if(!ctx) {
        fprintf(stderr, "sevent_create failed\n");
        return 1;
    }
    sevent_ignore_sigpipe();

    sevent_http_server_config cfg;
    memset(&cfg, 0, sizeof(cfg)); /* 全默认: 明文 */
    sevent_http_server *srv = sevent_http_server_create(ctx, &cfg);
    if(!srv) {
        fprintf(stderr, "create failed\n");
        return 1;
    }
    if(sevent_http_server_listen(
               srv, "127.0.0.1", PORT, 8, NULL, on_request, on_upgrade, on_conn_close, on_error, NULL) < 0) {
        fprintf(stderr, "listen %d failed\n", PORT);
        return 1;
    }

    printf("HTTP + WS shared server on 127.0.0.1:%d\n", PORT);
    printf("  http: curl http://127.0.0.1:%d/\n", PORT);
    printf("  ws:   connect ws://127.0.0.1:%d/  (echo)\n", PORT);
    printf("  (Ctrl-C to stop)\n\n");

    sevent_run(ctx);

    sevent_http_server_destroy(srv);
    sevent_destroy(ctx);
    return 0;
}
