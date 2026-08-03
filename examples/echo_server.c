/**
 *  echo_server.c — TCP Echo Server (tcp_acceptor + tcp_conn)
 *
 *  功能: 监听 7777 端口，收到数据原样返回
 *  用法: make example-echo-server && ./example-echo-server
 *        telnet 127.0.0.1 7777  (另一个终端)
 *
 *  演示点:
 *    - tcp_acceptor 封装服务端样板 (listen + accept 循环 + 分发)
 *    - tcp_conn 纯回调模型: on_data 推送 / write 返回"已接受" (异步 flush)
 *    - 回调内 destroy 安全 (free 推迟到 run_posts)
 */

#include "sevent.h"
#include "sevent_tcp_conn.h"
#include "sevent_tcp_acceptor.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PORT 7777

static sevent_context *g_ctx;

/* ---- 连接回调 (user_data = tcp_conn) ---- */

static void on_open(void *d) {
    (void)d;
    printf("[connect]\n");
}

static void on_data(void *d, const uint8_t *data, size_t len) {
    sevent_tcp_conn *c  = (sevent_tcp_conn *)d;
    /* 回显: write 拷贝进写队列, 异步自动 flush, 调用方 buffer 可随即复用 */
    int              rc = sevent_tcp_conn_write(c, data, len);
    if(rc != 0)
        printf("[write] failed: %d\n", rc);
    /* 去掉换行符后打印收到的内容 */
    if(len > 0 && data[len - 1] == '\n')
        len--;
    printf("[echo] %.*s\n", (int)len, (const char *)data);
}

static void on_close(void *d) {
    sevent_tcp_conn *c = (sevent_tcp_conn *)d;
    printf("[disconnect]\n");
    sevent_tcp_conn_destroy(c); /* 回调内 destroy: 延迟释放, 栈安全 */
}

static void on_error(void *d, int err) {
    sevent_tcp_conn *c = (sevent_tcp_conn *)d;
    printf("[error] %d\n", err);
    sevent_tcp_conn_destroy(c);
}

/* ---- acceptor 分发: fd 已 accept (非阻塞), 包装成 tcp_conn ---- */

static void on_accept(void *d, int fd) {
    (void)d;
    sevent_tcp_conn *c = sevent_tcp_conn_create(g_ctx);
    if(!c) {
        close(fd);
        return;
    }
    printf("[accept] fd=%d\n", fd);
    sevent_stream_conn_init init = {
            .user_data = c, .on_open = on_open, .on_data = on_data, .on_close = on_close, .on_error = on_error};
    if(sevent_tcp_conn_accept(c, fd, &init) < 0) {
        sevent_tcp_conn_destroy(c); /* 失败: 对象销毁 */
        close(fd);                  /* fd 归还调用方 — 谁拥有谁关闭 */
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

    printf("echo server listening on 127.0.0.1:%d\n", PORT);
    printf("  try: telnet 127.0.0.1 %d\n", PORT);
    printf("  or:  nc -t 127.0.0.1 %d\n", PORT);
    printf("  (Ctrl-C to stop)\n\n");

    sevent_run(g_ctx);

    sevent_tcp_acceptor_destroy(acc);
    sevent_destroy(g_ctx);
    return 0;
}
