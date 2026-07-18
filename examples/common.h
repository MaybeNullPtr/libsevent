/* =========================================================================
 *  libsevent 示例公用工具
 *
 *  功能:
 *    1. LOG(fmt, ...) — 带时间戳和文件名行号的日志宏
 *    2. register_stop_fn() — 注册 Ctrl+C 停止函数, 所有 example 统一处理
 *
 *  用法:
 *    #include "common.h"
 *
 *    // C 中使用
 *    register_stop_fn((void(*)(void*))sevent_stop, ctx);
 *    LOG("server listening on port %d", port);
 *
 *    // C++ 中使用
 *    register_stop_fn([](void *p) {
 *        static_cast<sevent::EventLoop*>(p)->stop();
 *    }, &loop);
 *    LOG("server listening on port %d", port);
 *
 *  编译: 链接 common.c 即可, 无需额外依赖.
 * ========================================================================= */

#ifndef EXAMPLES_COMMON_H
#define EXAMPLES_COMMON_H

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- 带时间戳的日志 ---- */

/**
 * 打印日志: "[秒.毫秒] 文件名:行号: 消息\n"
 * 通过 LOG 宏调用, 自动填充 __FILE__ 和 __LINE__.
 */
void log_printf(const char *file, int line, const char *fmt, ...);

#define LOG(fmt, ...) log_printf(__FILE__, __LINE__, fmt, ##__VA_ARGS__)

/* ---- Ctrl+C 信号处理 ---- */

/**
 * 注册 Ctrl+C 停止函数.
 * @param fn  收到 SIGINT 时调用的函数, 参数为 arg
 * @param arg 透传给 fn 的参数
 *
 * 典型用法:
 *   C:   register_stop_fn((void(*)(void*))sevent_stop, ctx);
 *   C++: register_stop_fn([](void *p){ ((EventLoop*)p)->stop(); }, &loop);
 */
void register_stop_fn(void (*fn)(void *), void *arg);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* EXAMPLES_COMMON_H */
