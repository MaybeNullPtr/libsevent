/**
 *  autobahn_echo_server.c — Autobahn 合规测试 echo 服务端 (ws_accept 入口)
 *
 *  用 tcp_acceptor + sevent_ws_accept 实现完整 ws 服务端栈:
 *  握手 (ws_parse_request/ws_build_response) + 状态机 + 掩码双向 +
 *  permessage-deflate 协商 (A 方案) — fuzzingclient 验证的即库实现.
 *
 *  用法: ./autobahn_echo_server [port]
 */

#include "sevent.h"
#include "sevent_ws.h"
#include "sevent_tcp_acceptor.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static sevent_context *g_ctx;

/* ---- 每连接应用上下文 (user_data): 持有 ws 句柄 + 消息级回显缓存 ----
 * 流式大消息/分片消息: on_message 分批回调 (fin=false), 攒到 fin=true
 * 才完整回显 (Autobahn echo 约定: 按消息回显, 非按帧). */
struct app {
    sevent_ws_conn *ws;
    uint8_t        *msg_buf; /* 攒消息缓冲 (fin=false 期间) */
    size_t          msg_len, msg_cap;
    bool            msg_binary;
};

static void app_msg_reset(struct app *a) {
    a->msg_len    = 0;
    a->msg_binary = false;
}

static int app_msg_append(struct app *a, const void *m, size_t l, bool binary) {
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

static void on_open(void *d) { (void)d; }

static void on_message(void *d, const void *m, size_t l, bool binary, bool fin, uint64_t total) {
    (void)total;
    struct app *a = (struct app *)d;
    if(!a->ws)
        return; /* 句柄未就绪 (理论上 accept 入口异步握手, 数据到达时已就绪) */
    if(app_msg_append(a, m, l, binary) != 0)
        return;
    if(!fin)
        return; /* 消息未完: 攒着 */
    /* 消息完整: 按消息回显 (Autobahn echo 约定) */
    if(a->msg_binary)
        (void)sevent_ws_send_binary(a->ws, a->msg_buf, a->msg_len);
    else
        (void)sevent_ws_send_text(a->ws, a->msg_buf, a->msg_len);
    app_msg_reset(a);
}

static void on_close(void *d, uint16_t code, const char *reason, size_t reason_len) {
    (void)code;
    (void)reason;
    (void)reason_len;
    struct app *a = (struct app *)d;
    free(a->msg_buf);
    free(a); /* 连接结束: 释放应用上下文 */
}

static void on_error(void *d, int err) {
    (void)err;
    struct app *a = (struct app *)d;
    if(a->ws) {
        sevent_ws_destroy(a->ws);
        a->ws = NULL;
    }
    free(a->msg_buf);
    free(a);
}

static void on_accept(void *d, int fd) {
    (void)d;
    struct app *a = (struct app *)calloc(1, sizeof(*a));
    if(!a) {
        close(fd);
        return;
    }
    /* cfg 为栈局部: 库内部自有拷贝 (所有权纪律), 返回后可安全释放.
     * enable_deflate: 协商 permessage-deflate (Autobahn 12.x 用例) */
    sevent_ws_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.enable_deflate = true;
    cfg.user_data      = a;
    cfg.on_open        = on_open;
    cfg.on_message     = on_message;
    cfg.on_close       = on_close;
    cfg.on_error       = on_error;
    a->ws              = sevent_ws_accept(g_ctx, fd, &cfg);
    if(!a->ws) {
        free(a);
        close(fd); /* fd 契约: 失败后 fd 归调用方 — 谁拥有谁关闭 */
    }
}

int main(int argc, char **argv) {
    int port = (argc > 1) ? atoi(argv[1]) : 9002;
    g_ctx    = sevent_create();
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
    if(sevent_tcp_acceptor_listen(acc, "127.0.0.1", (uint16_t)port, 8, on_accept, NULL) < 0) {
        fprintf(stderr, "listen %d failed\n", port);
        return 1;
    }
    printf("autobahn echo server (ws_accept) on %d\n", port);
    sevent_run(g_ctx);
    return 0;
}
