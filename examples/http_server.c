/**
 *  http_server.c — 简单 HTTP/1.0 服务器 (tcp_acceptor + tcp_conn)
 *
 *  功能: 监听 8080 端口, 响应 GET 请求, 演示事件循环上构建协议
 *  用法: make example-http-server && ./example-http-server
 *        curl http://127.0.0.1:8080/
 *        curl http://127.0.0.1:8080/hello
 *
 *  演示点:
 *    - tcp_acceptor 服务端入口 + tcp_conn on_data 累积数据 + 协议解析
 *    - 短连接生命周期 (accept → on_data 解析 → 响应 → close)
 *    - HTTP/1.0 简单实现 (请求行解析, 状态行响应)
 */

#include "sevent.h"
#include "sevent_tcp_conn.h"
#include "sevent_tcp_acceptor.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PORT 8080

/* ---- 每个 HTTP 连接的状态 ---- */

struct http_conn {
    sevent_tcp_conn *c;
    char             buf[4096];
    int              buf_len;
};

static sevent_context *g_ctx;

/* ---- 简易 HTTP 响应模板 ---- */

static const char *g_status  = "HTTP/1.0 200 OK\r\n";
static const char *g_headers = "Content-Type: text/plain\r\n"
                               "Connection: close\r\n"
                               "\r\n";

static void send_response(struct http_conn *c, const char *body) {
    /* 三次 write 入队, 队列按序异步 flush (写失败经 on_error 通知) */
    sevent_tcp_conn_write(c->c, g_status, strlen(g_status));
    sevent_tcp_conn_write(c->c, g_headers, strlen(g_headers));
    sevent_tcp_conn_write(c->c, body, strlen(body));
    /* HTTP/1.0 短连接: 回包后主动关闭 + 释放 (回调内 destroy 安全) */
    sevent_tcp_conn_destroy(c->c);
    free(c);
}

/* ---- 连接回调 ---- */

static void on_open(void *d) {
    struct http_conn *c = (struct http_conn *)d;
    printf("[http] connection\n");
    (void)c;
}

static void on_data(void *d, const uint8_t *data, size_t len) {
    struct http_conn *c = (struct http_conn *)d;

    if(c->buf_len + (int)len >= (int)sizeof(c->buf)) {
        /* 请求头过长, 直接关闭 */
        send_response(c, "413 Payload Too Large\n");
        return;
    }
    memcpy(c->buf + c->buf_len, data, len);
    c->buf_len         += (int)len;
    c->buf[c->buf_len] = '\0';

    /* 查找 HTTP 请求结束标记 \r\n\r\n */
    if(!strstr(c->buf, "\r\n\r\n"))
        return; /* 继续等待更多数据 */

    /* 解析请求行: GET /path HTTP/1.0 */
    char method[16] = {0}, path[256] = {0};
    if(sscanf(c->buf, "%15s %255s", method, path) < 2) {
        send_response(c, "400 Bad Request\n");
        return;
    }

    if(strcmp(method, "GET") != 0) {
        send_response(c, "405 Method Not Allowed\n");
        return;
    }

    /* 根据路径返回不同内容 */
    if(strcmp(path, "/") == 0) {
        send_response(c,
                      "Hello from libsevent HTTP server!\n"
                      "Try: curl http://127.0.0.1:8080/hello\n");
    } else if(strcmp(path, "/hello") == 0) {
        send_response(c, "Hello, World!\n");
    } else {
        send_response(c, "404 Not Found\n");
    }
}

static void on_close(void *d) {
    struct http_conn *c = (struct http_conn *)d;
    sevent_tcp_conn_destroy(c->c);
    free(c);
}

static void on_error(void *d, int err) {
    struct http_conn *c = (struct http_conn *)d;
    (void)err;
    sevent_tcp_conn_destroy(c->c);
    free(c);
}

/* ---- acceptor 分发 ---- */

static void on_accept(void *d, int fd) {
    (void)d;
    struct http_conn *c = (struct http_conn *)calloc(1, sizeof(*c));
    if(!c) {
        close(fd);
        return;
    }
    c->c = sevent_tcp_conn_create(g_ctx);
    if(!c->c) {
        free(c);
        close(fd);
        return;
    }
    printf("[http] accept fd=%d\n", fd);
    sevent_stream_conn_init init = {
            .user_data = c, .on_open = on_open, .on_data = on_data, .on_close = on_close, .on_error = on_error};
    if(sevent_tcp_conn_accept(c->c, fd, &init) < 0) {
        /* 失败: fd 已由本层关闭 */
        sevent_tcp_conn_destroy(c->c);
        free(c);
    }
}

/* ---- main ---- */

int main(void) {
    g_ctx = sevent_create();
    if(!g_ctx) {
        fprintf(stderr, "sevent_create failed\n");
        return 1;
    }
    sevent_ignore_sigpipe();

    sevent_tcp_acceptor *acc = sevent_tcp_acceptor_create(g_ctx);
    if(!acc)
        return 1;
    if(sevent_tcp_acceptor_listen(acc, "127.0.0.1", PORT, 8, on_accept, NULL) < 0) {
        fprintf(stderr, "listen %d failed\n", PORT);
        return 1;
    }

    printf("HTTP server listening on 127.0.0.1:%d\n", PORT);
    printf("  try: curl http://127.0.0.1:%d/\n", PORT);
    printf("  try: curl http://127.0.0.1:%d/hello\n", PORT);
    printf("  (Ctrl-C to stop)\n\n");

    sevent_run(g_ctx);

    sevent_tcp_acceptor_destroy(acc);
    sevent_destroy(g_ctx);
    return 0;
}
