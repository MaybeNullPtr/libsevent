/**
 *  chat_server.c — 多客户端聊天中继
 *
 *  功能: 监听 7778 端口, 任意客户端发来的消息广播给其他所有客户端
 *  用法: make example-chat-server && ./example-chat-server
 *        终端1: telnet 127.0.0.1 7778
 *        终端2: telnet 127.0.0.1 7778
 *        终端3: telnet 127.0.0.1 7778
 *        在任一终端输入消息, 其他终端都能收到
 *
 *  演示点:
 *    - 动态连接管理 (accept/close 时操作客户端链表)
 *    - 回调内 unregister 自己 (延迟释放, 不 crash)
 *    - 回调内遍历/操作其他连接的 IO (不干扰当前迭代)
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

#define PORT 7778

/* ---- 客户端链表 ---- */

struct client {
    int            fd;
    sevent_io     *h_io;
    char           name[32]; /* fd 编号, 用于识别 */
    struct client *next;
};

static struct client  *g_clients; /* 所有在线客户端 */
static sevent_context *g_ctx;

static void client_list_add(struct client *c) {
    c->next   = g_clients;
    g_clients = c;
}

static void client_list_remove(struct client *c) {
    struct client **pp = &g_clients;
    while(*pp) {
        if(*pp == c) {
            *pp = c->next;
            return;
        }
        pp = &(*pp)->next;
    }
}

/* ---- 广播消息给所有在线客户端 ---- */

static void broadcast(int from_fd, const char *msg) {
    for(struct client *p = g_clients; p; p = p->next) {
        if(p->fd == from_fd)
            continue; /* 不发给自己 */
        if(write(p->fd, msg, strlen(msg)) < 0) {
            /* 客户端可能已断开, 下次读事件会清理 */
        }
    }
}

/* ---- 客户端可读回调 ---- */

static void on_client_read(void *data) {
    struct client *c = (struct client *)data;
    char           buf[512];

    ssize_t n = read(c->fd, buf, sizeof(buf) - 1);
    if(n <= 0) {
        /* 断开连接 */
        if(n == 0) {
            printf("[%s] disconnected\n", c->name);
        } else {
            perror("read");
        }

        /* 通知其他客户端 */
        char leave_msg[64];
        snprintf(leave_msg, sizeof(leave_msg), "[%s] has left\n", c->name);
        broadcast(c->fd, leave_msg);

        /* 清理: 从链表移除 + 注销 IO + 关闭 fd + 释放 */
        client_list_remove(c);
        sevent_io_unregister(g_ctx, c->h_io); /* 回调内 unregister 自己, 安全 */
        close(c->fd);
        free(c);
        return;
    }

    buf[n] = '\0';
    if(n > 0 && buf[n - 1] == '\n')
        buf[n - 1] = '\0'; /* 去换行 */

    /* 构造带发送者前缀的消息 */
    char msg[576];
    snprintf(msg, sizeof(msg), "[%s]: %s\n", c->name, buf);

    printf("%s", msg);     /* 服务端也打印 */
    broadcast(c->fd, msg); /* 广播给其他客户端 */
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

    int flags = fcntl(cfd, F_GETFL);
    if(flags < 0) {
        close(cfd);
        return;
    }
    fcntl(cfd, F_SETFL, flags | O_NONBLOCK);

    struct client *c = (struct client *)calloc(1, sizeof(*c));
    if(!c) {
        close(cfd);
        return;
    }
    c->fd = cfd;
    snprintf(c->name, sizeof(c->name), "fd=%d", cfd);

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

    client_list_add(c);

    char join_msg[64];
    snprintf(join_msg, sizeof(join_msg), "[%s] joined\n", c->name);
    printf("%s", join_msg);
    broadcast(c->fd, join_msg);
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

    printf("Chat server listening on 127.0.0.1:%d\n", PORT);
    printf("  try: telnet 127.0.0.1 %d   (multiple terminals)\n", PORT);
    printf("  or:  nc -t 127.0.0.1 %d\n", PORT);
    printf("  (Ctrl-C to stop)\n\n");

    sevent_run(g_ctx);

    /* cleanup: 关闭所有在线客户端 */
    while(g_clients) {
        struct client *next = g_clients->next;
        close(g_clients->fd);
        free(g_clients);
        g_clients = next;
    }
    close(listen_fd);
    sevent_destroy(g_ctx);
    return 0;
}
