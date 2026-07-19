/**
 *  http_server.c — 简单 HTTP/1.0 服务器
 *
 *  功能: 监听 8080 端口, 响应 GET 请求, 演示事件循环上构建协议
 *  用法: make example-http-server && ./example-http-server
 *        curl http://127.0.0.1:8080/
 *        curl http://127.0.0.1:8080/hello
 *
 *  演示点:
 *    - IO 回调中累积数据 + 协议解析
 *    - 短连接生命周期 (accept → read → write → close)
 *    - HTTP/1.0 简单实现 (请求行解析, 状态行响应)
 */

#include "sevent.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define PORT 8080

/* ---- 每个 HTTP 连接的状态 ---- */

struct http_conn {
    int         fd;
    sevent_io *h_io;
    char        buf[4096];
    int         buf_len;
};

static sevent_context *g_ctx;

/* ---- 简易 HTTP 响应模板 ---- */

static const char *g_status  = "HTTP/1.0 200 OK\r\n";
static const char *g_headers = "Content-Type: text/plain\r\n"
                               "Connection: close\r\n"
                               "\r\n";

static void send_response(struct http_conn *c, const char *body) {
    /* 一次 send 尽量写完 (nonblock + 小数据通常一次完成) */
    ssize_t r;
    r = write(c->fd, g_status, strlen(g_status));
    if(r < 0)
        goto close;
    r = write(c->fd, g_headers, strlen(g_headers));
    if(r < 0)
        goto close;
    r = write(c->fd, body, strlen(body));
    (void)r;

close:
    /* HTTP/1.0 短连接: 回包后关闭, 写失败也一样处理 */
    sevent_io_unregister(g_ctx, c->h_io);
    close(c->fd);
    free(c);
}

/* ---- 客户端可读回调 ---- */

static void on_client_read(void *data) {
    struct http_conn *c = (struct http_conn *)data;

    ssize_t n = read(c->fd, c->buf + c->buf_len, sizeof(c->buf) - 1 - c->buf_len);
    if(n <= 0) {
        if(n < 0)
            perror("read");
        sevent_io_unregister(g_ctx, c->h_io);
        close(c->fd);
        free(c);
        return;
    }
    c->buf_len         += n;
    c->buf[c->buf_len] = '\0';

    /* 查找 HTTP 请求结束标记 \r\n\r\n */
    char *end = strstr(c->buf, "\r\n\r\n");
    if(!end) {
        if(c->buf_len >= (int)sizeof(c->buf) - 1) {
            /* 请求头过长, 直接关闭 */
            sevent_io_unregister(g_ctx, c->h_io);
            close(c->fd);
            free(c);
        }
        return; /* 继续等待更多数据 */
    }

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

/* ---- 监听 socket 可读 = 有新连接 ---- */

static void on_accept(void *data) {
    int                listen_fd = *(int *)data;
    struct sockaddr_in addr;
    socklen_t          addrlen = sizeof(addr);

    int cfd = accept(listen_fd, (struct sockaddr *)&addr, &addrlen);
    if(cfd < 0) {
        if(errno != EAGAIN && errno != EINTR)
            perror("accept");
        return;
    }

    /* 非阻塞 */
    int flags = fcntl(cfd, F_GETFL);
    if(flags < 0) {
        close(cfd);
        return;
    }
    fcntl(cfd, F_SETFL, flags | O_NONBLOCK);

    struct http_conn *c = (struct http_conn *)calloc(1, sizeof(*c));
    if(!c) {
        close(cfd);
        return;
    }
    c->fd = cfd;

    sevent_io_handler h = {
            .fd      = cfd,
            .io_read = on_client_read,
            .data    = c,
    };
    c->h_io = sevent_io_register(g_ctx, &h);
    if(!c->h_io) {
        free(c);
        close(cfd);
        return;
    }

    printf("[http] connection from fd=%d\n", cfd);
}

/* ---- main ---- */

int main(void) {
    g_ctx = sevent_create();
    if(!g_ctx) {
        fprintf(stderr, "sevent_create failed\n");
        return 1;
    }
    sevent_ignore_sigpipe();

    int listen_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if(listen_fd < 0) {
        perror("socket");
        return 1;
    }

    int optval = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    struct sockaddr_in addr = {
            .sin_family      = AF_INET,
            .sin_port        = htons(PORT),
            .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    };
    if(bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(listen_fd);
        return 1;
    }
    if(listen(listen_fd, SOMAXCONN) < 0) {
        perror("listen");
        close(listen_fd);
        return 1;
    }

    sevent_io_handler h = {
            .fd      = listen_fd,
            .io_read = on_accept,
            .data    = &listen_fd,
    };
    if(!sevent_io_register(g_ctx, &h)) {
        fprintf(stderr, "io_register failed\n");
        close(listen_fd);
        return 1;
    }

    printf("HTTP server listening on 127.0.0.1:%d\n", PORT);
    printf("  try: curl http://127.0.0.1:%d/\n", PORT);
    printf("  try: curl http://127.0.0.1:%d/hello\n", PORT);
    printf("  (Ctrl-C to stop)\n\n");

    sevent_run(g_ctx);

    close(listen_fd);
    sevent_destroy(g_ctx);
    return 0;
}
