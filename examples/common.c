/* =========================================================================
 *  libsevent 示例公用工具 — 实现
 * ========================================================================= */

#include "common.h"
#include <stdarg.h>
#include <time.h>
#include <signal.h>
#include <stdio.h>

/* ---- Ctrl+C 信号处理 (全局状态) ---- */

static void (*g_stop_fn)(void *) = NULL;
static void  *g_stop_arg         = NULL;

static void on_sigint(int sig)
{
    (void)sig;
    if (g_stop_fn)
        g_stop_fn(g_stop_arg);
}

void register_stop_fn(void (*fn)(void *), void *arg)
{
    g_stop_fn  = fn;
    g_stop_arg = arg;
    signal(SIGINT, on_sigint);
}

/* ---- 日志 ---- */

void log_printf(const char *file, int line, const char *fmt, ...)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    printf("[%ld.%03ld] %s:%d: ",
           ts.tv_sec, ts.tv_nsec / 1000000, file, line);

    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);

    printf("\n");
}
