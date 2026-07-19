/**
 *  echo_server.c — TCP Echo Server
 *
 *  功能: 监听 7777 端口，收到数据原样返回
 *  用法: make example-echo-server && ./example-echo-server
 *        telnet 127.0.0.1 7777  (另一个终端)
 *
 *  类似 libuv 的 tcp-echo-server 示例 / libevent 的 hello-world
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
#include <arpa/inet.h>

#define PORT 7777

/* ---- 每个客户端连接的状态 ---- */

struct client {
    int        fd;   /* 客户端 socket fd */
    sevent_io *h_io; /* 自己的注册句柄，断连时用于注销 */
    char       buf[4096];
};

static sevent_context *g_ctx; /* 所有回调共享 ctx */

/* ---- 客户端可读回调 ---- */

static void on_client_read(void *data) {
    struct client *c = (struct client *)data;

    ssize_t n = read(c->fd, c->buf, sizeof(c->buf) - 1);
    if(n <= 0) {
        /* 断开连接或错误 */
        if(n == 0)
            printf("[disconnect] fd=%d\n", c->fd);
        else
            perror("read");
        sevent_io_unregister(g_ctx, c->h_io);
        close(c->fd);
        free(c);
        return;
    }

    /* Echo 回显 */
    c->buf[n] = '\0';

    /* 直接写回 (小数据，非阻塞 socket 下通常一次写完) */
    size_t written = 0;
    while(written < (size_t)n) {
        ssize_t w = write(c->fd, c->buf + written, (size_t)(n - written));
        if(w > 0) {
            written += (size_t)w;
        } else if(errno != EAGAIN && errno != EINTR) {
            perror("write");
            sevent_io_unregister(g_ctx, c->h_io);
            close(c->fd);
            free(c);
            return;
        }
    }

    /* 去掉换行符后打印收到的内容 */
    c->buf[n] = '\0';
    if(c->buf[n - 1] == '\n')
        c->buf[n - 1] = '\0';
    printf("[echo] fd=%d: %s\n", c->fd, c->buf);
}

/* ---- 监听 socket 可读 = 有新连接 ---- */

static void on_accept(void *data) {
    int listen_fd = *(int *)data;

    struct sockaddr_in addr;
    socklen_t          addrlen = sizeof(addr);

    int cfd = accept(listen_fd, (struct sockaddr *)&addr, &addrlen);

    if(cfd < 0) {
        if(errno != EAGAIN && errno != EINTR)
            perror("accept");
        return;
    }

    /* 设置非阻塞 */
    int flags = fcntl(cfd, F_GETFL);
    if(flags < 0) {
        close(cfd);
        return;
    }
    fcntl(cfd, F_SETFL, flags | O_NONBLOCK);

    /* 分配客户端状态 */
    struct client *c = (struct client *)malloc(sizeof(*c));
    if(!c) {
        close(cfd);
        return;
    }
    c->fd = cfd;

    /* 注册客户端 fd */
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

    printf("[accept] fd=%d from %s:%d\n", cfd, inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
}

/* ---- main ---- */

int main(void) {
    g_ctx = sevent_create();
    if(!g_ctx) {
        fprintf(stderr, "sevent_create failed\n");
        return 1;
    }
    sevent_ignore_sigpipe();

    /* ---- 创建 listen socket ---- */

    int listen_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if(listen_fd < 0) {
        perror("socket");
        return 1;
    }

    int optval = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    struct sockaddr_in addr = {
            .sin_family = AF_INET, .sin_port = htons(PORT), .sin_addr.s_addr = htonl(INADDR_LOOPBACK), /* 127.0.0.1 */
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

    /* ---- 注册 listen fd ---- */

    sevent_io_handler h = {
            .fd      = listen_fd,
            .io_read = on_accept,
            .data    = &listen_fd,
    };

    if(!sevent_io_register(g_ctx, &h)) {
        fprintf(stderr, "sevent_io_register failed\n");
        close(listen_fd);
        return 1;
    }

    printf("echo server listening on 127.0.0.1:%d\n", PORT);
    printf("  try: telnet 127.0.0.1 %d\n", PORT);
    printf("  or:  nc -t 127.0.0.1 %d\n", PORT);
    printf("  (Ctrl-C to stop)\n\n");

    /* ---- 启动 loop ---- */
    sevent_run(g_ctx);

    /* ---- cleanup ---- */
    close(listen_fd);
    sevent_destroy(g_ctx);
    return 0;
}
