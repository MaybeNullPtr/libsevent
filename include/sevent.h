#ifndef SEVENT_H
#define SEVENT_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ==================== libsevent - 轻量 select 事件循环 ====================
 *
 * loop 顺序: I/O(select) → 异步任务(post) → 定时器
 *
 * 限制:
 *   - select 上限: fd < FD_SETSIZE (通常 1024)
 *   - 非线程安全: sevent_context (需按下方分类调用)
 *
 * 线程安全分类:
 *   [跨线程, 内部锁]   sevent_post / sevent_io_register
 *                      sevent_io_unregister / sevent_timer_register
 *                      sevent_timer_unregister
 *   [跨线程, 无锁]     sevent_stop / sevent_wakeup / sevent_ignore_sigpipe
 *   [loop 线程]        回调函数 (io_read / io_write / timer_fn / handler)
 *   [串行]             sevent_create / sevent_destroy / sevent_run
 *                      sevent_run_once / sevent_set_allocator
 * ========================================================================= */

/* ==================== 错误码 ==================== */

#define SEVENT_SUCCESS       0
#define SEVENT_ERR_INVAL   -1   /* 参数无效 */
#define SEVENT_ERR_NOMEM   -2   /* 内存不足 */

/* ==================== 内存分配器 ==================== */

typedef void *(*sevent_malloc_fn)(size_t size);
typedef void  (*sevent_free_fn)(void *ptr);

/*
 * 替换内部分配器, 需在 create 前调用.
 *   sevent_set_allocator(my_malloc, my_free)  — 设置
 *   sevent_set_allocator(NULL, NULL)          — 恢复默认 (libc)
 *   一个 NULL 一个非 NULL → 返回 SEVENT_ERR_INVAL
 */
int sevent_set_allocator(sevent_malloc_fn malloc_fn,
                         sevent_free_fn  free_fn);

/* ==================== 回调类型 ==================== */

typedef void (*sevent_handler_fn)(void *data);       /* 通用回调, 用于 post */
typedef void (*sevent_io_read_fn)(void *data);       /* fd 可读时触发 */
typedef void (*sevent_io_write_fn)(void *data);      /* fd 可写时触发 */
typedef void (*sevent_timer_fn)(void *data);         /* 定时器到期触发 */

/* ==================== 不透明句柄 ==================== */

typedef struct sevent_context sevent_context;        /* 事件循环上下文 */
typedef struct sevent_io      *sevent_io_t;          /* IO 注册句柄 */
typedef struct sevent_timer   *sevent_timer_t;       /* 定时器句柄 */

/* ==================== 公开结构体 ==================== */

struct sevent_io_handler
{
    int                 fd;          /* 要监听的 fd                    */
    sevent_io_read_fn   io_read;     /* 可读回调, NULL=忽略            */
    sevent_io_write_fn  io_write;    /* 可写回调, NULL=忽略            */
    void               *data;        /* 透传给回调的参数               */
};

/* ==================== Core API ==================== */

/* 创建上下文, 返回 NULL 表示失败 */
sevent_context *sevent_create(void);

/* 销毁上下文, 自动释放内部资源. 确保 loop 已停止 */
void            sevent_destroy(sevent_context *ctx);

/*
 * 阻塞运行事件循环, 直到 stop 被调用.
 * 返回: SEVENT_SUCCESS 或 SEVENT_ERR_INVAL
 * 线程: 一个 ctx 只能有一个线程调 run
 */
int             sevent_run(sevent_context *ctx);

/*
 * 跑一轮事件循环.
 * 返回: 1 处理了事件 / 0 空闲 / <0 错误
 * 线程: loop 线程专用
 */
int             sevent_run_once(sevent_context *ctx);

/* 请求退出事件循环. 回调内可安全调用. 跨线程安全 */
void            sevent_stop(sevent_context *ctx);

/* 唤醒事件循环, 让 select 立即返回. 跨线程安全 */
int             sevent_wakeup(sevent_context *ctx);

/*
 * 投递异步任务, loop 的 post 阶段按 FIFO 执行.
 * 回调内调用时新任务进入下一轮.
 * 跨线程安全 (内部锁)
 */
int             sevent_post(sevent_context *ctx,
                            sevent_handler_fn h, void *data);

/* ==================== 信号 ==================== */

/*
 * 忽略 SIGPIPE. 使用 TCP 时应在 main 启动时调用.
 * 避免 write 到已关闭连接时进程被 SIGPIPE 杀死.
 * 默认不改变信号处理. 跨线程安全
 */
void            sevent_ignore_sigpipe(void);

/* ==================== I/O API ==================== */

/*
 * 注册 fd 监听.
 * 返回句柄或 NULL (参数无效 / fd>=FD_SETSIZE / 内存不足).
 * h 的内容在调用后不再使用.
 * 跨线程安全 (内部锁)
 */
sevent_io_t     sevent_io_register(sevent_context *ctx,
                                   struct sevent_io_handler *h);

/*
 * 注销 fd 监听, 释放内部资源.
 * 回调内 unregister 自己是安全的 (延迟释放).
 * 传入 NULL 无效果. 跨线程安全
 */
void            sevent_io_unregister(sevent_io_t h);

/* ==================== Timer API ==================== */

/*
 * 注册循环定时器. interval_ms 后首次触发, 之后每 interval_ms 触发一次.
 * interval_ms == 0 → 返回 NULL.
 * 跨线程安全 (内部锁)
 */
sevent_timer_t  sevent_timer_register(sevent_context *ctx,
                                      unsigned int interval_ms,
                                      sevent_timer_fn cb, void *data);

/*
 * 注销定时器, 释放内部资源.
 * 回调内 unregister 自己是安全的 (延迟释放).
 * 传入 NULL 无效果. 跨线程安全
 */
void            sevent_timer_unregister(sevent_timer_t h);

#ifdef __cplusplus
}
#endif

#endif /* SEVENT_H */
