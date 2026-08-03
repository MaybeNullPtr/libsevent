/**
 *  ws_server.c — WebSocket 独立端口服务器示例 (tcp_acceptor + sevent_ws_accept)
 *
 *  功能: 监听 8081 端口, ws echo 服务器 (消息级回显).
 *
 *  用法: make example-ws-server && ./example-ws-server
 *        # ws 客户端连 ws://127.0.0.1:8081/  (echo)
 *
 *  演示点:
 *    - 独立端口入口: tcp_acceptor 的 on_accept → sevent_ws_accept(fd, &cfg) —
 *      stream 建连 (enable_tls 时含 TLS 服务端握手, 证书来自 cfg) 由库完成
 *    - 握手: 收升级请求回 101 (非法请求 → 400/426 + on_error)
 *    - echo: on_message 消息级回显 (fin=true 才回显, 流式/分片攒齐)
 *    - 生命周期: ws 连接归用户 — on_close/on_error 里释放上下文
 *
 *  wss: cfg.enable_tls = true + cert_path/key_path (证书必填)
 */

#include "sevent.h"
#include "sevent_ws.h"
#include "sevent_tcp_acceptor.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static sevent_context *g_ctx; /* on_accept 回调使用 (声明前置) */

#define PORT 8081

/* ---- echo 连接上下文 (user_data) ---- */
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

static void on_accept(void *d, int fd) {
    (void)d;
    struct ws_app *a = (struct ws_app *)calloc(1, sizeof(*a));
    if(!a) {
        close(fd);
        return;
    }
    /* cfg 为栈局部: 库内部自有拷贝, 返回后可安全释放.
     * enable_deflate: 协商 permessage-deflate 压缩 */
    sevent_ws_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.enable_deflate = true;
    cfg.user_data      = a;
    cfg.on_message     = ws_on_message;
    cfg.on_close       = ws_on_close;
    cfg.on_error       = ws_on_error;
    a->ws              = sevent_ws_accept(g_ctx, fd, &cfg);
    if(!a->ws) {
        free(a->msg_buf);
        free(a);
        close(fd); /* 库未接管 fd (入口失败) */
    }
}

int main(void) {
    g_ctx = sevent_create();
    if(!g_ctx) {
        fprintf(stderr, "sevent_create failed\n");
        return 1;
    }
    sevent_ignore_sigpipe();

    sevent_tcp_acceptor *acc = sevent_tcp_acceptor_create(g_ctx);
    if(!acc) {
        fprintf(stderr, "acceptor create failed\n");
        return 1;
    }
    if(sevent_tcp_acceptor_listen(acc, "127.0.0.1", PORT, 8, on_accept, NULL) < 0) {
        fprintf(stderr, "listen %d failed\n", PORT);
        return 1;
    }

    printf("WebSocket echo server on 127.0.0.1:%d\n", PORT);
    printf("  connect ws://127.0.0.1:%d/  (echo, permessage-deflate)\n", PORT);
    printf("  (Ctrl-C to stop)\n\n");

    sevent_run(g_ctx);

    sevent_tcp_acceptor_destroy(acc);
    sevent_destroy(g_ctx);
    return 0;
}
