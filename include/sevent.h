#ifndef SEVENT_H
#define SEVENT_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ==================== libsevent - 轻量 select 事件循环 ====================
 *
 * 循环顺序: I/O(select) → 异步任务(post) → 定时器
 *
 * 限制:
 *   - select 上限: fd < FD_SETSIZE (通常 1024)
 *   - 非线程安全: sevent_context 需按下方分类调用
 *   - 所有回调在 loop 线程同步执行, 应避免长时间阻塞
 *
 * 线程安全分类:
 *   [跨线程, 内部锁]   sevent_post / sevent_dispatch
 *                      sevent_io_register / sevent_io_unregister
 *                      sevent_timer_register / sevent_timer_unregister
 *   [跨线程, 无锁]     sevent_stop / sevent_wakeup / sevent_ignore_sigpipe
 *   [loop 线程]        回调函数 (io_read / io_write / timer_fn / handler)
 *   [串行]             sevent_create / sevent_destroy / sevent_run
 *                      sevent_run_once / sevent_set_allocator
 *
 * 句柄生命周期:
 *   - IO / Timer: 由用户主动 unregister 释放, 释放前始终有效
 *   - Post:       run_posts 阶段自动释放, 执行后句柄失效
 * ========================================================================= */

/* ==================== 版本 ==================== */

#define SEVENT_VERSION_MAJOR 1
#define SEVENT_VERSION_MINOR 0
#define SEVENT_VERSION_PATCH 0
#define SEVENT_VERSION "1.0.0"

/* ==================== 错误码 ==================== */

#define SEVENT_SUCCESS 0
#define SEVENT_ERR_INVAL -1 /* 参数无效 */
#define SEVENT_ERR_NOMEM -2 /* 内存不足 */

/* ==================== 内存分配器 ==================== */

typedef void *(*sevent_malloc_fn)(size_t size);
typedef void (*sevent_free_fn)(void *ptr);

/*
 * 替换内部分配器.
 * 前置条件: 应在 sevent_create 之前调用, loop 运行期间不应切换.
 * 使用:     sevent_set_allocator(my_malloc, my_free) — 设置;
 *           sevent_set_allocator(NULL, NULL)          — 恢复默认 (libc).
 * 返回:     SEVENT_SUCCESS 或 SEVENT_ERR_INVAL (仅一个参数为 NULL).
 * 线程:     串行.
 */
int sevent_set_allocator(sevent_malloc_fn malloc_fn, sevent_free_fn free_fn);

/* ==================== 回调类型 ==================== */

typedef void (*sevent_handler_fn)(void *data);  /* 通用回调, 用于 post */
typedef void (*sevent_io_read_fn)(void *data);  /* fd 可读时触发 */
typedef void (*sevent_io_write_fn)(void *data); /* fd 可写时触发 */
typedef void (*sevent_timer_fn)(void *data);    /* 定时器到期触发 */

/* ==================== 不透明句柄 ==================== */

typedef struct sevent_context sevent_context; /* 事件循环上下文 */
typedef struct sevent_io      sevent_io;      /* IO 注册句柄 (不透明) */
typedef struct sevent_timer   sevent_timer;   /* 定时器句柄 (不透明) */

/* ==================== 公开结构体 ==================== */

typedef struct sevent_io_handler {
    int                fd;       /* 要监听的 fd                    */
    sevent_io_read_fn  io_read;  /* 可读回调, NULL=忽略            */
    sevent_io_write_fn io_write; /* 可写回调, NULL=忽略            */
    void              *data;     /* 透传给回调的参数               */
} sevent_io_handler;

/* ==================== Core API ==================== */

/*
 * 创建事件循环上下文.
 * 前置条件: 首次调用前可配置 sevent_set_allocator.
 * 返回:     NULL 表示内存不足.
 * 线程:     串行.
 */
sevent_context *sevent_create(void);

/*
 * 销毁上下文, 释放所有内部资源.
 * 前置条件: loop 已停止 (sevent_run 已返回), 无其他线程正在操作此 ctx.
 *           所有活跃的 IO/Timer 句柄在 destroy 后不可再用于 unregister.
 *           如果外层仍有句柄指针, 需在 destroy 前调 unregister 释放.
 * 后置条件: ctx 指针及所有 IO/Timer 句柄不可再用于任何 API.
 * 线程:     串行.
 */
void sevent_destroy(sevent_context *ctx);

/*
 * 阻塞运行事件循环, 直到 sevent_stop 被调用.
 * 前置条件: ctx 已通过 sevent_create 创建, 无其他线程并发调用此函数.
 * 返回:     SEVENT_SUCCESS 或 SEVENT_ERR_INVAL (参数无效).
 * 线程:     串行 (单 loop 线程).
 */
int sevent_run(sevent_context *ctx);

/*
 * 执行一轮事件循环.
 * 顺序: run_free_death → run_build_fdset → select → IO 回调
 *       → post 任务 → 定时器.
 * 返回: 1 (有事件处理) / 0 (空闲) / <0 (select 致命错误).
 * 线程: loop 线程专用 (串行).
 */
int sevent_run_once(sevent_context *ctx);

/*
 * 通知事件循环退出. 回调内可安全调用, 跨线程安全.
 * 后置条件: 当前/下一轮 run_once 返回后, sevent_run 退出.
 * 线程:     跨线程 (无锁, volatile 标志).
 */
void sevent_stop(sevent_context *ctx);

/*
 * 唤醒事件循环 (select 立即返回).
 * 常用于跨线程通知 loop 有异步任务已入队.
 * 线程: 跨线程 (无锁).
 * 返回: SEVENT_SUCCESS 或 SEVENT_ERR_INVAL.
 */
int sevent_wakeup(sevent_context *ctx);

/*
 * 投递异步任务, loop 的 post 阶段按 FIFO 顺序执行.
 * 回调内调用时, 新任务在本轮继续执行 (post 阶段逐个处理).
 * 返回: SEVENT_SUCCESS 或 SEVENT_ERR_NOMEM.
 * 线程: 跨线程 (内部锁, post_lock).
 */
int sevent_post(sevent_context *ctx, sevent_handler_fn h, void *data);

/*
 * 投递任务. 如果在 loop 线程内则立即执行, 否则入队等待.
 * 回调内调用为立即执行. 跨线程调用退化为 sevent_post.
 * 线程: 跨线程 (loop 线程内直接调用, 其他线程走 post_lock).
 * 返回: SEVENT_SUCCESS 或 SEVENT_ERR_NOMEM.
 */
int sevent_dispatch(sevent_context *ctx, sevent_handler_fn h, void *data);

/* ==================== 信号 ==================== */

/*
 * 忽略 SIGPIPE. 使用 TCP 时应在 main 启动时调用.
 * 避免 write 到已关闭连接时进程被 SIGPIPE 杀死.
 * 默认不改变信号处理方式.
 * 线程: 跨线程 (无锁).
 */
void sevent_ignore_sigpipe(void);

/* ==================== I/O API ==================== */

/*
 * 注册 fd 监听.
 * 前置条件: fd 已创建, fd < FD_SETSIZE, 同一 fd 不能重复注册.
 * 回调:     io_read / io_write 在 fd 可读/写时触发.
 * 返回:     句柄, 或 NULL (参数无效 / fd>=FD_SETSIZE / fd 重复 / 内存不足).
 * h 的内容在调用后不再使用.
 * 线程:     跨线程 (内部锁, lock).
 */
sevent_io *sevent_io_register(sevent_context *ctx, sevent_io_handler *h);

/*
 * 注销 fd 监听, 释放内部资源.
 * 未注册或已注销的句柄安全 (幂等). 回调内可安全调用 (延迟释放).
 * h 必须为有效句柄 (来自 sevent_io_register).
 * 线程: 跨线程 (内部锁, lock).
 */
void sevent_io_unregister(sevent_context *ctx, sevent_io *h);

/* ==================== Timer API ==================== */

/*
 * 注册循环定时器.
 * 前置条件: interval_ms > 0.
 * 回调:     timer_fn 在到期后每 interval_ms 触发一次.
 * 返回:     句柄, 或 NULL (interval_ms == 0 / 内存不足).
 * 线程:     跨线程 (内部锁, lock).
 */
sevent_timer *sevent_timer_register(sevent_context *ctx, unsigned int interval_ms, sevent_timer_fn cb, void *data);

/*
 * 注销定时器, 释放内部资源.
 * 未注册或已注销的句柄安全 (幂等). 回调内可安全调用 (延迟释放).
 * h 必须为有效句柄 (来自 sevent_timer_register).
 * 线程: 跨线程 (内部锁, lock).
 */
void sevent_timer_unregister(sevent_context *ctx, sevent_timer *h);

/* ==================== 可观测性 ==================== */

/*
 * 获取当前各类型活跃对象数量.
 * io_count:    活跃的 IO 注册数.
 * timer_count: 活跃的定时器数.
 * post_count:  待处理的异步任务数 (pending 队列).
 * 任一指针为 NULL 表示不关心该项, 取到的值仅为瞬间快照.
 * 线程: 跨线程 (内部锁).
 */
void sevent_get_counts(sevent_context *ctx, int *io_count, int *timer_count, int *post_count);

#ifdef __cplusplus
}
#endif

#endif /* SEVENT_H */
