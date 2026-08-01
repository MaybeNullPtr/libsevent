/**
 *  chat_server.c — 多客户端聊天中继 (tcp_acceptor + tcp_conn)
 *
 *  功能: 监听 7778 端口, 任意客户端发来的消息广播给其他所有客户端
 *  用法: make example-chat-server && ./example-chat-server
 *        终端1: telnet 127.0.0.1 7778
 *        终端2: telnet 127.0.0.1 7778
 *        在任一终端输入消息, 其他终端都能收到
 *
 *  演示点:
 *    - tcp_acceptor 服务端入口 + tcp_conn 纯回调连接管理
 *    - 动态连接管理 (accept/close 时操作客户端链表)
 *    - 广播时逐连接 write (返回"已接受", 队列异步 flush)
 *    - 回调内 destroy 安全 (on_close 里移除链表 + 释放)
 */

#include "sevent.h"
#include "sevent_tcp_conn.h"
#include "sevent_tcp_acceptor.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PORT 7778

/* ---- 客户端链表 ---- */

struct client {
    sevent_tcp_conn *c;
    char             name[32]; /* fd 编号, 用于识别 */
    struct client   *next;
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

/* ---- 连接回调 ---- */

static void on_open(void *d) {
    struct client *cl = (struct client *)d;
    printf("[%s] connected\n", cl->name);
}

static void on_data(void *d, const uint8_t *data, size_t len) {
    struct client *cl = (struct client *)d;
    char           msg[512];
    if(len >= sizeof(msg))
        len = sizeof(msg) - 1;
    memcpy(msg, data, len);
    msg[len] = '\0';
    /* 去掉换行符 */
    if(len > 0 && msg[len - 1] == '\n')
        msg[len - 1] = '\0';

    printf("[%s] %s\n", cl->name, msg);
    /* 广播给其他人: 构造 "[名字] 消息" 格式 */
    char out[560];
    snprintf(out, sizeof(out), "[%s] %s\n", cl->name, msg);
    for(struct client *p = g_clients; p; p = p->next) {
        if(p == cl)
            continue; /* 不发给自己 */
        int rc = sevent_tcp_conn_write(p->c, out, strlen(out));
        if(rc != 0)
            printf("[%s] write failed: %d\n", p->name, rc);
    }
}

static void on_close(void *d) {
    struct client *cl = (struct client *)d;
    printf("[%s] disconnected\n", cl->name);
    client_list_remove(cl);
    sevent_tcp_conn_destroy(cl->c); /* 回调内 destroy: 延迟释放, 栈安全 */
    free(cl);
}

static void on_error(void *d, int err) {
    struct client *cl = (struct client *)d;
    printf("[%s] error: %d\n", cl->name, err);
    on_close(d); /* 同一收尾路径 */
}

/* ---- acceptor 分发 ---- */

static void on_accept(void *d, int fd) {
    (void)d;
    struct client *cl = (struct client *)malloc(sizeof(*cl));
    if(!cl) {
        close(fd);
        return;
    }
    cl->c = sevent_tcp_conn_create(g_ctx);
    if(!cl->c) {
        free(cl);
        close(fd);
        return;
    }
    snprintf(cl->name, sizeof(cl->name), "client-%d", fd);
    cl->next = NULL;
    client_list_add(cl);

    sevent_stream_conn_init init = {
            .user_data = cl, .on_open = on_open, .on_data = on_data, .on_close = on_close, .on_error = on_error};
    if(sevent_tcp_conn_accept(cl->c, fd, &init) < 0) {
        /* 失败: fd 已由本层关闭 */
        client_list_remove(cl);
        sevent_tcp_conn_destroy(cl->c);
        free(cl);
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

    printf("chat server listening on 127.0.0.1:%d\n", PORT);
    printf("  try: telnet 127.0.0.1 %d\n", PORT);
    printf("  (Ctrl-C to stop)\n\n");

    sevent_run(g_ctx);

    /* 清理残留连接 */
    while(g_clients) {
        struct client *p = g_clients;
        g_clients        = p->next;
        sevent_tcp_conn_destroy(p->c);
        free(p);
    }
    sevent_tcp_acceptor_destroy(acc);
    sevent_destroy(g_ctx);
    return 0;
}
