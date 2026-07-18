/**
 *  signal_demo.c — 信号驱动的优雅退出
 *
 *  功能: 捕获 SIGINT/SIGTERM, 通过 self-pipe 桥接到事件循环,
 *        配合定时器演示退出前的工作循环
 *  用法: make example-signal-demo && ./example-signal-demo
 *        (Ctrl-C 触发优雅退出)
 *
 *  演示点:
 *    - 信号处理函数写入管道 → IO 事件触发回调
 *    - 优雅退出模式: 停止定时器 → 清理资源 → sevent_stop()
 *    - self-pipe 与库内部 wake_fds 互不干扰
 */

#include "sevent.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>

/* ---- 信号管道 (自定义, 与 sevent 内部 wake_fds 无关) ---- */

static int sig_fds[2]; /* 信号管道: [0]=读, [1]=写 */

static void signal_handler(int sig) {
    /* 信号处理函数中只能调异步安全函数, write 是安全的 */
    char c = (char)sig;
    if(write(sig_fds[1], &c, 1) < 0) {
        /* 管道满或已关闭, 信号丢失, 异步安全函数内只能做这些 */
    }
}

static void setup_signals(void) {
    if(pipe(sig_fds) < 0) {
        perror("pipe");
        exit(1);
    }
    /* 读端设为非阻塞 */
    for(int i = 0; i < 2; i++) {
        int fl = fcntl(sig_fds[i], F_GETFL);
        fcntl(sig_fds[i], F_SETFL, fl | O_NONBLOCK);
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
}

/* ---- 信号管道可读回调 ---- */

static void on_signal(void *data) {
    sevent_context *ctx = (sevent_context *)data;
    char            buf[16];
    ssize_t         n;
    while((n = read(sig_fds[0], buf, sizeof(buf))) > 0) {
        for(ssize_t i = 0; i < n; i++) {
            int sig = (int)buf[i];
            if(sig == 0)
                break;
            printf("\n[signal] received %s, shutting down...\n", sig == SIGINT ? "SIGINT" : "SIGTERM");
        }
    }
    sevent_stop(ctx);
}

/* ---- 定时器回调: 每秒打印心跳 ---- */

static int g_tick;

static void on_tick(void *data) {
    (void)data;
    g_tick++;
    printf("[tick %d] running... (Ctrl-C to stop)\n", g_tick);
}

/* ---- main ---- */

int main(void) {
    sevent_context *ctx = sevent_create();
    if(!ctx) {
        fprintf(stderr, "sevent_create failed\n");
        return 1;
    }

    setup_signals();

    /* 注册信号管道读端 */
    struct sevent_io_handler h = {
            .fd      = sig_fds[0],
            .io_read = on_signal,
            .data    = ctx,
    };
    if(!sevent_io_register(ctx, &h)) {
        fprintf(stderr, "io_register failed\n");
        return 1;
    }

    /* 每秒心跳定时器 */
    sevent_timer_t ticker = sevent_timer_register(ctx, 1000, on_tick, NULL);
    if(!ticker) {
        fprintf(stderr, "timer_register failed\n");
        return 1;
    }

    printf("Signal demo started (PID %d)\n", getpid());
    printf("  Press Ctrl-C to trigger graceful shutdown\n");
    printf("  Or: kill -INT %d\n", getpid());
    printf("  Or: kill -TERM %d\n\n", getpid());

    sevent_run(ctx);

    /* 优雅退出清理 */
    sevent_timer_unregister(ctx, ticker);
    printf("\nClean shutdown after %d ticks. Goodbye.\n", g_tick);

    close(sig_fds[0]);
    close(sig_fds[1]);
    sevent_destroy(ctx);
    return 0;
}
