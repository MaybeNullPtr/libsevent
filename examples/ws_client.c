/**
 *  ws_client.c — WebSocket 交互式客户端 demo
 *
 *  从 stdin 读取一行发送到服务器, 同时打印收到的消息.
 *
 *  用法: ./example-ws-client [host] [port] [path]
 *        ./example-ws-client                (默认 127.0.0.1:9000/echo)
 *        ./example-ws-client example.com 80 /ws
 *
 *  配套 echo 服务器: python3 examples/ws_echo_server.py
 */

#include "sevent.h"
#include "sevent_ws.h"
#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

static sevent_context *g_ctx;
static sevent_ws_conn *g_ws;

static void on_message(void *u, const void *m, size_t l, bool bin, bool fin, uint64_t total) {
    (void)u;
    (void)fin;
    (void)total;
    printf("\n[recv] ");
    if(bin)
        printf("(binary %zu bytes)", l);
    else
        fwrite(m, 1, l, stdout);
    printf("\n> ");
    fflush(stdout);
}

static void on_open(void *u) {
    (void)u;
    printf("\n[connected]\n> ");
    fflush(stdout);
}

static void on_close(void *u, uint16_t code, const char *r, size_t rl) {
    (void)u;
    printf("\n[closed code=%u", code);
    if(rl)
        printf(" reason=%.*s", (int)rl, r);
    printf("]\n");
    fflush(stdout);
    sevent_stop(g_ctx);
}

static void on_error(void *u, int err) {
    (void)u;
    printf("\n[error 0x%x]\n", err);
    fflush(stdout);
    sevent_stop(g_ctx);
}

static void on_stdin_read(void *d) {
    (void)d;
    char buf[4096];
    if(!fgets(buf, sizeof(buf), stdin)) {
        printf("\n[EOF]\n");
        clearerr(stdin);
        sevent_ws_close(g_ws, 1000, "");
        return;
    }
    size_t len = strlen(buf);
    while(len && (buf[len - 1] == '\n' || buf[len - 1] == '\r'))
        buf[--len] = 0;
    if(!len) {
        printf("> ");
        fflush(stdout);
        return;
    }
    if(!strcmp(buf, "/quit") || !strcmp(buf, "/exit")) {
        printf("[bye]\n");
        sevent_ws_close(g_ws, 1000, "");
        return;
    }
    if(!strcmp(buf, "/ping")) {
        sevent_ws_ping(g_ws, "ping", 4);
        printf("> ");
        fflush(stdout);
        return;
    }
    int r = sevent_ws_send_text(g_ws, buf, len);
    if(r)
        printf("[send error: %d]\n", r);
    printf("> ");
    fflush(stdout);
}

int main(int argc, char **argv) {
    const char *host = argc > 1 ? argv[1] : "127.0.0.1";
    int         port = argc > 2 ? atoi(argv[2]) : 9000;
    const char *path = argc > 3 ? argv[3] : "/echo";

    printf("Connecting to %s:%d%s ...\n", host, port, path);
    printf("Commands: /quit  /ping\n> ");
    fflush(stdout);

    g_ctx = sevent_create();
    if(!g_ctx) {
        fprintf(stderr, "create fail\n");
        return 1;
    }
    sevent_ignore_sigpipe();
    register_stop_fn((void (*)(void *))sevent_stop, g_ctx);

    sevent_ws_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host       = host;
    cfg.port       = (uint16_t)port;
    cfg.path       = path;
    cfg.on_open    = on_open;
    cfg.on_message = on_message;
    cfg.on_close   = on_close;
    cfg.on_error   = on_error;
    g_ws           = sevent_ws_connect(g_ctx, &cfg);
    if(!g_ws) {
        fprintf(stderr, "connect fail\n");
        sevent_destroy(g_ctx);
        return 1;
    }

    int fd = fileno(stdin);
    int fl = fcntl(fd, F_GETFL);
    if(fl >= 0)
        fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    sevent_io_handler h;
    h.fd      = fd;
    h.io_read = on_stdin_read;
    h.data    = NULL;
    if(!sevent_io_register(g_ctx, &h)) {
        fprintf(stderr, "stdin fail\n");
        sevent_ws_destroy(g_ws);
        sevent_destroy(g_ctx);
        return 1;
    }

    sevent_run(g_ctx);

    if(fd >= 0) {
        fl = fcntl(fd, F_GETFL);
        if(fl >= 0)
            fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
    }
    sevent_ws_destroy(g_ws);
    sevent_destroy(g_ctx);
    return 0;
}
