/**
 *  stdin_echo.c — 最简单的 libsevent 例子
 *
 *  功能: 从 stdin 读一行，原样打印，输入 "quit" 退出
 *  编译: make example-stdin-echo && ./example-stdin-echo
 *
 *  类似 libuv 的 uv_tty_echo 示例
 */

#include "sevent.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void on_stdin_read(void *data) {
    (void)data;
    char    buf[256];
    ssize_t n = read(0, buf, sizeof(buf) - 1);
    if(n <= 0) {
        /* EOF (Ctrl-D) → 退出 */
        printf("\nbye\n");
        /* ctx 存在 data 中？简化处理：用全局 */
        extern sevent_context *g_ctx;
        sevent_stop(g_ctx);
        return;
    }
    buf[n] = '\0';
    printf("echo: %s", buf);

    /* "quit\n" → 退出 */
    if(strcmp(buf, "quit\n") == 0) {
        extern sevent_context *g_ctx;
        sevent_stop(g_ctx);
    }
}

sevent_context *g_ctx;

int main(void) {
    g_ctx = sevent_create();
    if(!g_ctx) {
        fprintf(stderr, "sevent_create failed\n");
        return 1;
    }

    struct sevent_io_handler h = {
            .fd      = 0, /* stdin */
            .io_read = on_stdin_read,
    };

    if(!sevent_io_register(g_ctx, &h)) {
        fprintf(stderr, "sevent_io_register failed\n");
        return 1;
    }

    printf("type something (or 'quit' to exit):\n");
    sevent_run(g_ctx);

    /* 到达这里说明 loop 已退出（quit / Ctrl-D） */
    /* sevent_io_unregister 不需要了，因为 destroy 会清理 */
    sevent_destroy(g_ctx);
    return 0;
}
