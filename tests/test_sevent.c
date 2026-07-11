/* =========================================================================
 *  libsevent 单元测试
 *
 *  编译: gcc -Wall -Wextra -std=c99 -o test test.c sevent.c && ./test
 * ========================================================================= */

#include "sevent.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/select.h>

/* ==================== 简易测试框架 ==================== */

struct test_entry {
    const char        *label;
    void              (*fn)(void);
    struct test_entry *next;
};

static int fail_count;  /* per-test 计数器 */

#define TEST(t) static void test_##t(void)

#define ASSERT(cond) do {                                          \
    if (!(cond)) {                                                  \
        fprintf(stderr, "      [FAIL] %s:%d: %s\n",                \
                __FILE__, __LINE__, #cond);                        \
        fail_count++;                                               \
    }                                                               \
} while(0)

#define ASSERT_EQ(a, b) do {                                       \
    long _a = (long)(a);                                           \
    long _b = (long)(b);                                           \
    if (_a != _b) {                                                 \
        fprintf(stderr, "      [FAIL] %s:%d: \n"                   \
                "        left:  %ld  (%s)\n"                       \
                "        right: %ld  (%s)\n",                      \
                __FILE__, __LINE__,                                \
                _a, #a, _b, #b);                                   \
        fail_count++;                                               \
    }                                                               \
} while(0)

/* ==================== 辅助函数 ==================== */

static int cb_count;

static void reset_cb(void)
{
    cb_count = 0;
}

static void count_cb(void *data)
{
    (void)data;
    cb_count++;
}

static void stop_cb(void *data)
{
    sevent_stop((sevent_context *)data);
}

/* ====================================================================
 *  Core API 测试
 * ==================================================================== */

TEST(core_create_destroy)
{
    sevent_context *ctx = sevent_create();
    ASSERT(ctx != NULL);
    sevent_destroy(ctx);
}

TEST(core_create_destroy_many)
{
    for (int i = 0; i < 100; i++) {
        sevent_context *ctx = sevent_create();
        ASSERT(ctx != NULL);
        sevent_destroy(ctx);
    }
}

TEST(core_run_stop)
{
    reset_cb();
    sevent_context *ctx = sevent_create();
    ASSERT(ctx != NULL);

    ASSERT(NULL != sevent_post(ctx, stop_cb, ctx));
    ASSERT_EQ(SEVENT_SUCCESS, sevent_run(ctx));

    sevent_destroy(ctx);
}

TEST(core_run_once_empty)
{
    sevent_context *ctx = sevent_create();
    ASSERT(ctx != NULL);
    ASSERT_EQ(0, sevent_run_once(ctx));
    sevent_destroy(ctx);
}

TEST(core_run_once_with_post)
{
    reset_cb();
    sevent_context *ctx = sevent_create();
    ASSERT(ctx != NULL);

    ASSERT(NULL != sevent_post(ctx, count_cb, NULL));
    ASSERT_EQ(1, sevent_run_once(ctx));
    ASSERT_EQ(1, cb_count);

    /* 再跑一轮，没任务了 */
    ASSERT_EQ(0, sevent_run_once(ctx));
    sevent_destroy(ctx);
}

TEST(core_post_order)
{
    static int order[4];
    reset_cb();
    sevent_context *ctx = sevent_create();
    ASSERT(ctx != NULL);

    for (int i = 0; i < 4; i++) {
        order[i] = 0;
        ASSERT(NULL != sevent_post(ctx, count_cb, &order[i]));
    }
    /* TODO: 实现后验证 order 递增 */
    sevent_destroy(ctx);
}

TEST(core_wakeup)
{
    sevent_context *ctx = sevent_create();
    ASSERT(ctx != NULL);

    ASSERT(NULL != sevent_post(ctx, stop_cb, ctx));
    ASSERT_EQ(SEVENT_SUCCESS, sevent_wakeup(ctx));
    ASSERT_EQ(SEVENT_SUCCESS, sevent_run(ctx));

    sevent_destroy(ctx);
}

TEST(core_stop_aborts_pending)
{
    reset_cb();
    sevent_context *ctx = sevent_create();
    ASSERT(ctx != NULL);

    /* 先 post stop，再 post count
       — 一轮里两个都会执行（同一次队列快照），
       但 loop 在下一轮开始前检查 running 标志退出 */
    ASSERT(NULL != sevent_post(ctx, stop_cb, ctx));
    ASSERT(NULL != sevent_post(ctx, count_cb, NULL));
    ASSERT_EQ(SEVENT_SUCCESS, sevent_run(ctx));

    /* count_cb 和 stop_cb 在同一轮执行 */
    ASSERT_EQ(1, cb_count);
    sevent_destroy(ctx);
}

TEST(core_double_stop_safe)
{
    sevent_context *ctx = sevent_create();
    ASSERT(ctx != NULL);
    sevent_stop(ctx);
    sevent_stop(ctx);
    sevent_destroy(ctx);
}

TEST(core_destroy_null_safe)
{
    sevent_destroy(NULL);
}

TEST(core_run_null)
{
    ASSERT_EQ(SEVENT_ERR_INVAL, sevent_run(NULL));
}

TEST(core_run_once_null)
{
    ASSERT_EQ(SEVENT_ERR_INVAL, sevent_run_once(NULL));
}

TEST(core_post_null_handler)
{
    sevent_context *ctx = sevent_create();
    ASSERT(ctx != NULL);
    ASSERT_EQ(NULL, sevent_post(ctx, NULL, NULL));
    sevent_destroy(ctx);
}

/* 验证 post 返回非空句柄 */
TEST(post_handle_not_null)
{
    sevent_context *ctx = sevent_create();
    ASSERT(ctx != NULL);
    ASSERT(NULL != sevent_post(ctx, count_cb, NULL));
    /* 不执行, 仅验证返回句柄 */
    sevent_destroy(ctx);
}

/* 验证取消未执行的任务 */
TEST(post_cancel_before_run)
{
    reset_cb();
    sevent_context *ctx = sevent_create();
    ASSERT(ctx != NULL);

    /* post 一个任务, 然后取消 */
    sevent_post_t p = sevent_post(ctx, count_cb, NULL);
    ASSERT(p != NULL);
    sevent_post_cancel(ctx, p);

    /* 跑 loop, 取消的任务不应触发 */
    sevent_post(ctx, stop_cb, ctx);
    sevent_run(ctx);
    ASSERT_EQ(0, cb_count);
    sevent_destroy(ctx);
}

/* 验证取消已执行的任务(无效果) */
TEST(post_cancel_after_run)
{
    reset_cb();
    sevent_context *ctx = sevent_create();
    ASSERT(ctx != NULL);

    sevent_post_t p = sevent_post(ctx, count_cb, NULL);
    ASSERT(p != NULL);

    /* 执行 */
    sevent_post(ctx, stop_cb, ctx);
    sevent_run(ctx);
    ASSERT_EQ(1, cb_count);

    /* 已执行后再取消: h 已 free, cancel 只查 pending 链表, 不崩溃 */
    sevent_post_cancel(ctx, p);
    sevent_destroy(ctx);
}

/* 验证取消 NULL 安全 */
TEST(post_cancel_null)
{
    sevent_context *ctx = sevent_create();
    ASSERT(ctx != NULL);
    sevent_post_cancel(NULL, NULL);
    sevent_post_cancel(ctx, NULL);  /* ctx 有效, h=NULL */
    sevent_destroy(ctx);
}

/* ----- 回调内取消辅助 ----- */
static sevent_post_t g_cancel_target;
static int           g_cancel_ran;

static void on_count_and_cancel(void *data)
{
    sevent_context *ctx = (sevent_context *)data;
    /* B 在这里 post, 进入 pending (不是当前 active 队列), cancel 能找到 */
    g_cancel_target = sevent_post(ctx, count_cb, NULL);
    g_cancel_ran = 1;
    sevent_post_cancel(ctx, g_cancel_target);
    sevent_post(ctx, stop_cb, ctx);
}

/* 验证回调内取消另一任务: B 由回调内发 (在 pending 中), cancel 有效 */
TEST(post_cancel_in_callback)
{
    reset_cb();
    g_cancel_ran = 0;
    g_cancel_target = NULL;

    sevent_context *ctx = sevent_create();
    ASSERT(ctx != NULL);

    /* A: 入队. 回调内 发 B → cancel B → post stop */
    ASSERT(NULL != sevent_post(ctx, on_count_and_cancel, ctx));

    sevent_run(ctx);

    /* A 执行了, B 被取消 */
    ASSERT(g_cancel_ran);      /* A 确实执行了 */
    ASSERT_EQ(0, cb_count);    /* B 没执行 */

    g_cancel_target = NULL;
    sevent_destroy(ctx);
}

/* 验证回调内 post 的任务在下轮执行 (双队列) */
static int g_deferred_count;

static void on_deferred_worker(void *data)
{
    (void)data;
    /* run_posts 正在处理 active 队列, 此 post 进 pending */
    sevent_post((sevent_context *)data, count_cb, NULL);
}

TEST(post_defer_to_next_iter)
{
    reset_cb();
    g_deferred_count = 0;

    sevent_context *ctx = sevent_create();
    ASSERT(ctx != NULL);

    /* A: 在回调中 post 新任务 */
    ASSERT(NULL != sevent_post(ctx, on_deferred_worker, ctx));

    /* B: stop */
    ASSERT(NULL != sevent_post(ctx, stop_cb, ctx));

    /* run_once 应处理 A, A 再 post C. C 应进入下轮, 而不是本轮 */
    sevent_run_once(ctx);
    /* 此时 A 执行了, 但 C 还没执行 */
    ASSERT_EQ(0, cb_count);

    /* 再跑一轮, C 被执行 */
    sevent_run_once(ctx);
    ASSERT_EQ(1, cb_count);

    sevent_destroy(ctx);
}

/* 验证同线程立即执行 */
TEST(post_dispatch_same_thread)
{
    reset_cb();
    sevent_context *ctx = sevent_create();
    ASSERT(ctx != NULL);

    /* loop 未启动, loop_thread 未设置, 会走 post 路径 */
    /* 先跑一次 run_once 让 loop_thread 被记录 */
    sevent_run_once(ctx);

    /* loop 线程中调用: 应立即执行 */
    ASSERT_EQ(SEVENT_SUCCESS, sevent_dispatch(ctx, count_cb, NULL));
    ASSERT_EQ(1, cb_count);

    /* 再测一个 */
    ASSERT_EQ(SEVENT_SUCCESS, sevent_dispatch(ctx, count_cb, NULL));
    ASSERT_EQ(2, cb_count);

    sevent_destroy(ctx);
}

/* 验证跨线程入队 */
TEST(post_dispatch_cross_thread)
{
    reset_cb();
    sevent_context *ctx = sevent_create();
    ASSERT(ctx != NULL);

    /* 从另一线程调用: 应入队, 在 run_once 中执行 */
    /* 用当前线程模拟: loop_thread 是空值, pthread_equal 不会匹配 */
    /* 直接验证: loop 未跑时调用 → 入队 → run_once 执行 */
    ASSERT_EQ(SEVENT_SUCCESS, sevent_dispatch(ctx, count_cb, NULL));
    ASSERT_EQ(0, cb_count);

    sevent_run_once(ctx);
    ASSERT_EQ(1, cb_count);

    sevent_destroy(ctx);
}

TEST(core_ignore_sigpipe)
{
    /* 只是验证调用不崩溃，不验证信号行为（进程级副作用） */
    sevent_ignore_sigpipe();
}

TEST(core_restart_loop)
{
    /* 验证 loop 可以 stop 后重新 run */
    reset_cb();
    sevent_context *ctx = sevent_create();
    ASSERT(ctx != NULL);

    ASSERT(NULL != sevent_post(ctx, stop_cb, ctx));
    ASSERT_EQ(SEVENT_SUCCESS, sevent_run(ctx));

    /* 再跑一次 */
    reset_cb();
    ASSERT(NULL != sevent_post(ctx, count_cb, NULL));
    ASSERT(NULL != sevent_post(ctx, stop_cb, ctx));
    ASSERT_EQ(SEVENT_SUCCESS, sevent_run(ctx));
    ASSERT_EQ(1, cb_count);

    sevent_destroy(ctx);
}

/* ----- 自定义分配器测试辅助 ----- */

static int alloc_calls, free_calls;

static void *track_malloc(size_t sz)
{
    alloc_calls++;
    return malloc(sz);
}

static void track_free(void *p)
{
    free_calls++;
    free(p);
}

TEST(core_set_allocator)
{
    /* 重复调用应返回 SEVENT_ERR_INVAL */
    ASSERT_EQ(SEVENT_ERR_INVAL, sevent_set_allocator(track_malloc, NULL));
    ASSERT_EQ(SEVENT_ERR_INVAL, sevent_set_allocator(NULL, track_free));

    /* 设置自定义分配器 */
    alloc_calls = free_calls = 0;
    ASSERT_EQ(SEVENT_SUCCESS, sevent_set_allocator(track_malloc, track_free));

    /* 创建/销毁应该使用自定义分配器 */
    sevent_context *ctx = sevent_create();
    ASSERT(ctx != NULL);
    ASSERT(alloc_calls > 0);  /* create 里分配了上下文 */

    int old_free  = free_calls;
    sevent_destroy(ctx);
    ASSERT(free_calls > old_free);  /* destroy 释放了所有资源 */

    /* 恢复默认分配器 */
    ASSERT_EQ(SEVENT_SUCCESS, sevent_set_allocator(NULL, NULL));

    /* 验证恢复后依然正常工作 */
    ctx = sevent_create();
    ASSERT(ctx != NULL);
    sevent_destroy(ctx);
}

TEST(memory_no_leak)
{
    /* 复杂工作流下的内存泄漏检测:
       创建/销毁多次, 注册/注销 IO 和 timer, 投递任务, 跑 loop */
    ASSERT_EQ(SEVENT_SUCCESS, sevent_set_allocator(track_malloc, track_free));
    alloc_calls = free_calls = 0;

    for (int round = 0; round < 5; round++) {
        sevent_context *ctx = sevent_create();
        ASSERT(ctx != NULL);

        /* 注册多个 IO */
        int fds[10][2];
        sevent_io_t ios[10];
        for (int i = 0; i < 10; i++) {
            ASSERT_EQ(0, pipe(fds[i]));
            struct sevent_io_handler h = { .fd = fds[i][0], .io_read = count_cb };
            ios[i] = sevent_io_register(ctx, &h);
            ASSERT(ios[i] != NULL);
        }

        /* 注册多个定时器 */
        sevent_timer_t timers[10];
        for (int i = 0; i < 10; i++) {
            timers[i] = sevent_timer_register(ctx, 1000, count_cb, NULL);
            ASSERT(timers[i] != NULL);
        }

        /* 投递一些任务 */
        for (int i = 0; i < 5; i++)
            ASSERT(NULL != sevent_post(ctx, count_cb, NULL));

        /* 注销一半 IO */
        for (int i = 0; i < 5; i++) {
            sevent_io_unregister(ctx, ios[i]);
            close(fds[i][0]);
            close(fds[i][1]);
        }

        /* 注销一半 timer */
        for (int i = 0; i < 5; i++)
            sevent_timer_unregister(ctx, timers[i]);

        /* 跑 loop 处理剩余事件 */
        sevent_post(ctx, stop_cb, ctx);
        sevent_run(ctx);

        /* 清理剩余资源 */
        for (int i = 5; i < 10; i++) {
            sevent_io_unregister(ctx, ios[i]);
            close(fds[i][0]);
            close(fds[i][1]);
        }
        for (int i = 5; i < 10; i++)
            sevent_timer_unregister(ctx, timers[i]);

        sevent_destroy(ctx);
    }

    /* 核心: 所有分配必须全部释放 */
    ASSERT_EQ(alloc_calls, free_calls);

    /* 恢复默认分配器 */
    ASSERT_EQ(SEVENT_SUCCESS, sevent_set_allocator(NULL, NULL));
}

/* ====================================================================
 *  I/O API 测试
 * ==================================================================== */

TEST(io_register_pipe_read)
{
    reset_cb();
    sevent_context *ctx = sevent_create();
    ASSERT(ctx != NULL);

    int fds[2];
    ASSERT_EQ(0, pipe(fds));

    struct sevent_io_handler h = {
        .fd      = fds[0],
        .io_read = count_cb,
    };
    sevent_io_t hdl = sevent_io_register(ctx, &h);
    ASSERT(hdl != NULL);

    ASSERT(5 == (int)write(fds[1], "hello", 5));

    ASSERT(NULL != sevent_post(ctx, stop_cb, ctx));
    ASSERT_EQ(SEVENT_SUCCESS, sevent_run(ctx));
    ASSERT_EQ(1, cb_count);

    sevent_io_unregister(ctx, hdl);
    close(fds[0]);
    close(fds[1]);
    sevent_destroy(ctx);
}

TEST(io_null_read_cb_no_fire)
{
    reset_cb();
    sevent_context *ctx = sevent_create();
    ASSERT(ctx != NULL);

    int fds[2];
    ASSERT_EQ(0, pipe(fds));

    /* 有 io_write 但不设置 io_read，验证可读事件不触发写回调 */
    struct sevent_io_handler h = {
        .fd       = fds[0],
        .io_read  = NULL,
        .io_write = count_cb,
    };
    sevent_io_t hdl = sevent_io_register(ctx, &h);
    ASSERT(hdl != NULL);

    ASSERT_EQ(1, (int)write(fds[1], "x", 1));
    ASSERT(NULL != sevent_post(ctx, stop_cb, ctx));
    ASSERT_EQ(SEVENT_SUCCESS, sevent_run(ctx));

    /* 管道可读但没有 io_read，io_write 不应该被触发 */
    ASSERT_EQ(0, cb_count);

    sevent_io_unregister(ctx, hdl);
    close(fds[0]);
    close(fds[1]);
    sevent_destroy(ctx);
}

TEST(io_unregister_self_in_callback)
{
    /* 这里需要回调里 unregister 自己，验证不 crash */
    /* TODO: 实现后用 static sevent_io_t 传进去 */
    reset_cb();
    sevent_context *ctx = sevent_create();
    ASSERT(ctx != NULL);

    int fds[2];
    ASSERT_EQ(0, pipe(fds));

    struct sevent_io_handler h = {
        .fd      = fds[0],
        .io_read = count_cb,
    };
    sevent_io_t hdl = sevent_io_register(ctx, &h);
    ASSERT(hdl != NULL);

    ASSERT_EQ(1, (int)write(fds[1], "x", 1));
    ASSERT(NULL != sevent_post(ctx, stop_cb, ctx));
    ASSERT_EQ(SEVENT_SUCCESS, sevent_run(ctx));

    sevent_io_unregister(ctx, hdl);
    close(fds[0]);
    close(fds[1]);
    sevent_destroy(ctx);
}

TEST(io_multiple_fds_partial_ready)
{
    reset_cb();
    sevent_context *ctx = sevent_create();
    ASSERT(ctx != NULL);

    int fds1[2], fds2[2], fds3[2];
    ASSERT_EQ(0, pipe(fds1));
    ASSERT_EQ(0, pipe(fds2));
    ASSERT_EQ(0, pipe(fds3));

    struct sevent_io_handler h1 = { .fd = fds1[0], .io_read = count_cb };
    struct sevent_io_handler h2 = { .fd = fds2[0], .io_read = count_cb };
    struct sevent_io_handler h3 = { .fd = fds3[0], .io_read = count_cb };

    sevent_io_t hdl1 = sevent_io_register(ctx, &h1);
    sevent_io_t hdl2 = sevent_io_register(ctx, &h2);
    sevent_io_t hdl3 = sevent_io_register(ctx, &h3);
    ASSERT(hdl1 && hdl2 && hdl3);

    /* 只写 fds1 和 fds3 */
    ASSERT_EQ(1, (int)write(fds1[1], "a", 1));
    ASSERT_EQ(1, (int)write(fds3[1], "c", 1));

    ASSERT(NULL != sevent_post(ctx, stop_cb, ctx));
    ASSERT_EQ(SEVENT_SUCCESS, sevent_run(ctx));

    /* 应该只有两个 callback 触发 */
    ASSERT_EQ(2, cb_count);

    sevent_io_unregister(ctx, hdl1);
    sevent_io_unregister(ctx, hdl2);
    sevent_io_unregister(ctx, hdl3);
    close(fds1[0]); close(fds1[1]);
    close(fds2[0]); close(fds2[1]);
    close(fds3[0]); close(fds3[1]);
    sevent_destroy(ctx);
}

TEST(io_write_monitor)
{
    reset_cb();
    sevent_context *ctx = sevent_create();
    ASSERT(ctx != NULL);

    int fds[2];
    ASSERT_EQ(0, pipe(fds));

    struct sevent_io_handler h = {
        .fd       = fds[1],  /* pipe 写端 */
        .io_write = count_cb,
    };
    sevent_io_t hdl = sevent_io_register(ctx, &h);
    ASSERT(hdl != NULL);

    /* 写端通常可写，应触发 io_write */
    ASSERT(NULL != sevent_post(ctx, stop_cb, ctx));
    ASSERT_EQ(SEVENT_SUCCESS, sevent_run(ctx));
    ASSERT(cb_count >= 1);

    sevent_io_unregister(ctx, hdl);
    close(fds[0]);
    close(fds[1]);
    sevent_destroy(ctx);
}

/* ====================================================================
 *  Timer API 测试
 * ==================================================================== */

TEST(io_both_null_rejected)
{
    sevent_context *ctx = sevent_create();
    ASSERT(ctx != NULL);

    struct sevent_io_handler h = { .fd = 3, .io_read = NULL, .io_write = NULL };
    ASSERT_EQ(NULL, sevent_io_register(ctx, &h));

    sevent_destroy(ctx);
}

TEST(timer_interval_zero_rejected)
{
    sevent_context *ctx = sevent_create();
    ASSERT(ctx != NULL);
    ASSERT_EQ(NULL, sevent_timer_register(ctx, 0, count_cb, NULL));
    sevent_destroy(ctx);
}

TEST(timer_unregister_null_safe)
{
    sevent_context *ctx = sevent_create();
    ASSERT(ctx != NULL);
    sevent_timer_unregister(NULL, NULL);
    sevent_timer_unregister(ctx, NULL);  /* ctx 有效, h=NULL */
    sevent_destroy(ctx);
}

TEST(timer_fire_once)
{
    reset_cb();
    sevent_context *ctx = sevent_create();
    ASSERT(ctx != NULL);

    sevent_timer_t t = sevent_timer_register(ctx, 1, count_cb, NULL);
    ASSERT(t != NULL);

    /* 跑几轮，期望触发至少 1 次 */
    for (int i = 0; i < 10; i++)
        sevent_run_once(ctx);
    ASSERT(cb_count >= 1);

    sevent_timer_unregister(ctx, t);
    sevent_destroy(ctx);
}

TEST(timer_unregister_before_fire)
{
    reset_cb();
    sevent_context *ctx = sevent_create();
    ASSERT(ctx != NULL);

    sevent_timer_t t = sevent_timer_register(ctx, 10000, count_cb, NULL);
    ASSERT(t != NULL);

    sevent_timer_unregister(ctx, t);

    sevent_run_once(ctx);
    ASSERT_EQ(0, cb_count);
    sevent_destroy(ctx);
}

/* ----- 动态增删定时器辅助 ----- */
static int              dyn_pipe_fd;
static sevent_context *dyn_ctx;

static void dyn_on_io(void *data)
{
    (void)data;
    char buf[4];
    ssize_t _r = read(dyn_pipe_fd, buf, sizeof(buf));
    (void)_r;
    /* IO 回调中动态添加定时器 */
    sevent_timer_register(dyn_ctx, 1, count_cb, NULL);
}

TEST(timer_dynamic_add_in_callback)
{
    /*
     * 验证在 IO 回调中动态添加定时器后，新定时器能正确触发。
     *
     * 场景：长周期定时器 (10s) 让 select 准备睡 10s。
     * IO 事件触发 → 回调中加短定时器 (1ms)。
     * 依赖 sevent_timer_register 内的 sevent_wakeup 唤醒 select。
     */
    reset_cb();
    dyn_ctx = NULL;

    sevent_context *ctx = sevent_create();
    ASSERT(ctx != NULL);
    dyn_ctx = ctx;

    int fds[2];
    ASSERT_EQ(0, pipe(fds));
    dyn_pipe_fd = fds[0];

    struct sevent_io_handler h = {
        .fd = fds[0], .io_read = dyn_on_io,
    };
    sevent_io_t h_io = sevent_io_register(ctx, &h);
    ASSERT(h_io != NULL);

    /* 长定时器 → next_timer = 10000 */
    sevent_timer_t t_long = sevent_timer_register(ctx, 10000, count_cb, NULL);
    ASSERT(t_long != NULL);

    /* IO 事件触发 → 回调中动态添加短定时器 */
    ASSERT_EQ(2, (int)write(fds[1], "go", 2));

    /* 跑几轮验证短定时器触发了 */
    for (int i = 0; i < 10; i++)
        sevent_run_once(ctx);
    ASSERT(cb_count >= 1);

    sevent_io_unregister(ctx, h_io);
    close(fds[0]); close(fds[1]);
    sevent_timer_unregister(ctx, t_long);
    dyn_ctx = NULL;
    sevent_destroy(ctx);
}

TEST(timer_dynamic_remove_safe)
{
    /* 验证注销定时器后不会 crash */
    reset_cb();
    sevent_context *ctx = sevent_create();
    ASSERT(ctx != NULL);

    sevent_timer_t t = sevent_timer_register(ctx, 1, count_cb, NULL);
    ASSERT(t != NULL);

    sevent_run_once(ctx);

    sevent_timer_unregister(ctx, t);
    sevent_run_once(ctx);
    sevent_destroy(ctx);
}

/* ----- 两阶段定时器专项测试 ----- */

/* 回调中 unregister 自己: 应触发一次, 不 crash */
static sevent_timer_t g_self_timer;

static void on_timer_self_unregister(void *data)
{
    cb_count++;
    sevent_timer_unregister((sevent_context *)data, g_self_timer);
}

TEST(timer_self_unregister_in_callback)
{
    reset_cb();
    sevent_context *ctx = sevent_create();
    ASSERT(ctx != NULL);

    g_self_timer = sevent_timer_register(ctx, 1, on_timer_self_unregister, ctx);
    ASSERT(g_self_timer != NULL);

    /* 跑多轮, 验证只触发一次且不 crash */
    for (int i = 0; i < 10; i++)
        sevent_run_once(ctx);
    ASSERT_EQ(1, cb_count);

    g_self_timer = NULL;
    sevent_destroy(ctx);
}

/* 回调中 unregister 另一个到期 timer: 被取消的应跳过 */
static sevent_timer_t g_cross_target;
static int            g_cross_a_fired;

static void on_timer_cross_a(void *data)
{
    if (g_cross_a_fired) return;  /* 只执行一次, 防止第二轮访问野指针 */
    g_cross_a_fired = 1;
    sevent_timer_unregister((sevent_context *)data, g_cross_target);
    g_cross_target = NULL;
    cb_count++;
}

static void on_timer_cross_b(void *data)
{
    (void)data;
    /* B 不应执行到这里 */
    cb_count += 100;
}

TEST(timer_cross_unregister_in_callback)
{
    reset_cb();
    g_cross_a_fired = 0;
    sevent_context *ctx = sevent_create();
    ASSERT(ctx != NULL);

    /* 两个同时间隔的定时器, 同一轮到期 */
    g_cross_target = sevent_timer_register(ctx, 1, on_timer_cross_b, NULL);
    ASSERT(g_cross_target != NULL);

    sevent_timer_t ta = sevent_timer_register(ctx, 1, on_timer_cross_a, ctx);
    ASSERT(ta != NULL);

    for (int i = 0; i < 10; i++)
        sevent_run_once(ctx);

    /* A 触发 = 1, B 被取消不应触发 */
    ASSERT_EQ(1, cb_count);

    /* A 在回调内取消了 B, A 后续轮次不会再访问 g_cross_target */
    sevent_timer_unregister(ctx, ta);
    sevent_destroy(ctx);
}

/* 定时器回调中注册新定时器: 新定时器后续应正常触发 */
static sevent_context *g_dyn_ctx;

static void on_timer_register_another(void *data)
{
    (void)data;
    cb_count++;
    /* 在定时器回调中注册另一个定时器 */
    sevent_timer_register(g_dyn_ctx, 1, count_cb, NULL);
}

TEST(timer_register_in_timer_callback)
{
    reset_cb();
    sevent_context *ctx = sevent_create();
    ASSERT(ctx != NULL);
    g_dyn_ctx = ctx;

    sevent_timer_t t = sevent_timer_register(ctx, 1, on_timer_register_another, NULL);
    ASSERT(t != NULL);

    /* 跑多轮: 第一轮触发 t (cb_count=1) 并注册新定时器,
     * 后续轮次新定时器触发 count_cb */
    for (int i = 0; i < 10; i++)
        sevent_run_once(ctx);

    /* 至少 2 次: t 1次 + 新定时器 >=1次 */
    ASSERT(cb_count >= 2);

    sevent_timer_unregister(ctx, t);
    g_dyn_ctx = NULL;
    sevent_destroy(ctx);
}

/* 多轮触发: 超短间隔定时器在连续 run_once 中累积触发 */
TEST(timer_multi_fire_per_tick)
{
    reset_cb();
    sevent_context *ctx = sevent_create();
    ASSERT(ctx != NULL);

    /* 1ms 间隔定时器, 跑多轮每轮 delta ~1ms, 每轮触发 1 次 */
    sevent_timer_t t = sevent_timer_register(ctx, 1, count_cb, NULL);
    ASSERT(t != NULL);

    for (int i = 0; i < 30; i++)
        sevent_run_once(ctx);

    /* 30 轮, 每轮至少触发 1 次 => 至少 20 次 (留足余量) */
    ASSERT(cb_count >= 20);

    sevent_timer_unregister(ctx, t);
    sevent_destroy(ctx);
}

/* 定时器回调中 unregister 自己 + 多轮验证无残留触发 */
static void on_timer_multi_self_unregister(void *data)
{
    cb_count++;
    sevent_timer_unregister((sevent_context *)data, g_self_timer);
}

TEST(timer_multi_fire_self_unregister)
{
    reset_cb();
    sevent_context *ctx = sevent_create();
    ASSERT(ctx != NULL);

    g_self_timer = sevent_timer_register(ctx, 1, on_timer_multi_self_unregister, ctx);
    ASSERT(g_self_timer != NULL);

    /* 跑多轮, 首轮触发并 unregister 自己, 后续不应再触发 */
    for (int i = 0; i < 10; i++)
        sevent_run_once(ctx);

    ASSERT_EQ(1, cb_count);  /* 只触发 1 次 */

    g_self_timer = NULL;
    sevent_destroy(ctx);
}

/* ====================================================================
 *  Integration 测试
 * ==================================================================== */

TEST(integration_io_timer_post)
{
    reset_cb();
    sevent_context *ctx = sevent_create();
    ASSERT(ctx != NULL);

    int fds[2];
    ASSERT_EQ(0, pipe(fds));

    struct sevent_io_handler h = { .fd = fds[0], .io_read = count_cb };
    sevent_io_t ih = sevent_io_register(ctx, &h);
    ASSERT(ih != NULL);

    sevent_timer_t th = sevent_timer_register(ctx, 50, count_cb, NULL);
    ASSERT(th != NULL);

    ASSERT(NULL != sevent_post(ctx, count_cb, NULL));
    ASSERT_EQ(1, (int)write(fds[1], "x", 1));

    /* 跑多轮，让所有事件都有机会触发 */
    for (int i = 0; i < 20; i++)
        sevent_run_once(ctx);

    ASSERT(cb_count >= 3);

    sevent_io_unregister(ctx, ih);
    sevent_timer_unregister(ctx, th);
    close(fds[0]);
    close(fds[1]);
    sevent_destroy(ctx);
}

TEST(integration_stop_then_destroy)
{
    sevent_context *ctx = sevent_create();
    ASSERT(ctx != NULL);

    ASSERT(NULL != sevent_post(ctx, stop_cb, ctx));
    ASSERT_EQ(SEVENT_SUCCESS, sevent_run(ctx));

    sevent_destroy(ctx);
}

/* ====================================================================
 *  边界条件测试
 * ==================================================================== */

TEST(edge_null_context_doesnt_crash)
{
    /* 所有函数传入 NULL context 应该不崩溃 */
    sevent_stop(NULL);
    sevent_wakeup(NULL);
    sevent_post(NULL, count_cb, NULL);
    sevent_io_register(NULL, NULL);
    sevent_timer_register(NULL, 10, count_cb, NULL);
    sevent_destroy(NULL);
}

TEST(edge_invalid_fd_rejected)
{
    sevent_context *ctx = sevent_create();
    ASSERT(ctx != NULL);

    struct sevent_io_handler h = {
        .fd      = -1,
        .io_read = count_cb,
    };
    sevent_io_t hdl = sevent_io_register(ctx, &h);
    ASSERT(hdl == NULL);

    sevent_destroy(ctx);
}

TEST(edge_null_io_handler)
{
    sevent_context *ctx = sevent_create();
    ASSERT(ctx != NULL);
    ASSERT_EQ(NULL, sevent_io_register(ctx, NULL));
    sevent_destroy(ctx);
}

TEST(edge_large_fd_rejected)
{
    sevent_context *ctx = sevent_create();
    ASSERT(ctx != NULL);

    struct sevent_io_handler h = {
        .fd      = FD_SETSIZE,  /* select 的最大 fd 是 FD_SETSIZE-1 */
        .io_read = count_cb,
    };
    sevent_io_t hdl = sevent_io_register(ctx, &h);
    ASSERT(hdl == NULL);

    sevent_destroy(ctx);
}

TEST(edge_many_timers)
{
    reset_cb();
    sevent_context *ctx = sevent_create();
    ASSERT(ctx != NULL);

    sevent_timer_t timers[100];
    int count = 0;
    for (int i = 0; i < 100; i++) {
        sevent_timer_t t = sevent_timer_register(ctx, 1000, count_cb, NULL);
        if (!t) break;
        timers[count++] = t;
    }
    ASSERT(count >= 50);

    for (int i = 0; i < count; i++)
        sevent_timer_unregister(ctx, timers[i]);
    sevent_destroy(ctx);
}

TEST(edge_unregister_twice_safe)
{
    sevent_context *ctx = sevent_create();
    ASSERT(ctx != NULL);

    int fds[2];
    ASSERT_EQ(0, pipe(fds));

    struct sevent_io_handler h = { .fd = fds[0], .io_read = count_cb };
    sevent_io_t hdl = sevent_io_register(ctx, &h);
    ASSERT(hdl != NULL);

    sevent_io_unregister(ctx, hdl);
    sevent_io_unregister(ctx, NULL);  /* NULL 安全 (安全网) */

    close(fds[0]);
    close(fds[1]);
    sevent_destroy(ctx);
}

TEST(edge_io_unregister_multiple)
{
    reset_cb();
    sevent_context *ctx = sevent_create();
    ASSERT(ctx != NULL);

    int fds[2];
    ASSERT_EQ(0, pipe(fds));

    struct sevent_io_handler h = { .fd = fds[0], .io_read = count_cb };
    sevent_io_t hdl = sevent_io_register(ctx, &h);
    ASSERT(hdl != NULL);

    /* 多次释放应安全 */
    sevent_io_unregister(ctx, hdl);
    sevent_io_unregister(ctx, hdl);
    sevent_io_unregister(ctx, hdl);

    close(fds[0]);
    close(fds[1]);
    sevent_destroy(ctx);
}

TEST(edge_timer_unregister_multiple)
{
    reset_cb();
    sevent_context *ctx = sevent_create();
    ASSERT(ctx != NULL);

    sevent_timer_t t = sevent_timer_register(ctx, 100, count_cb, NULL);
    ASSERT(t != NULL);

    /* 多次释放应安全 */
    sevent_timer_unregister(ctx, t);
    sevent_timer_unregister(ctx, t);
    sevent_timer_unregister(ctx, t);

    sevent_destroy(ctx);
}

TEST(edge_post_cancel_multiple)
{
    reset_cb();
    sevent_context *ctx = sevent_create();
    ASSERT(ctx != NULL);

    sevent_post_t p = sevent_post(ctx, count_cb, NULL);
    ASSERT(p != NULL);

    /* 未执行前多次 cancel 应安全 */
    sevent_post_cancel(ctx, p);
    sevent_post_cancel(ctx, p);
    sevent_post_cancel(ctx, p);

    /* 执行后 cancel 也应安全 (只查 pending, 不崩溃) */
    sevent_post(ctx, stop_cb, ctx);
    sevent_run(ctx);
    ASSERT_EQ(0, cb_count);
    sevent_post_cancel(ctx, p);

    sevent_destroy(ctx);
}

TEST(edge_io_unregister_after_free)
{
    sevent_context *ctx = sevent_create();
    ASSERT(ctx != NULL);

    int fds[2];
    ASSERT_EQ(0, pipe(fds));
    struct sevent_io_handler h = { .fd = fds[0], .io_read = count_cb };
    sevent_io_t hdl = sevent_io_register(ctx, &h);
    ASSERT(hdl != NULL);

    sevent_io_unregister(ctx, hdl);      /* death_io */
    sevent_run_once(ctx);                 /* run_free_death 释放 death_io */
    sevent_io_unregister(ctx, hdl);      /* 已 free, 遍历 io_list 找不到 → 安全 no-op */

    close(fds[0]); close(fds[1]);
    sevent_destroy(ctx);
}

TEST(edge_timer_unregister_after_free)
{
    sevent_context *ctx = sevent_create();
    ASSERT(ctx != NULL);

    sevent_timer_t t = sevent_timer_register(ctx, 1, count_cb, NULL);
    ASSERT(t != NULL);

    sevent_timer_unregister(ctx, t);     /* death_timer */
    sevent_run_once(ctx);                 /* run_free_death 释放 death_timer */
    sevent_timer_unregister(ctx, t);     /* 已 free, 遍历 timer_list 找不到 → 安全 no-op */

    sevent_destroy(ctx);
}

TEST(edge_io_unregister_wrong_ctx)
{
    sevent_context *ctx1 = sevent_create();
    sevent_context *ctx2 = sevent_create();
    ASSERT(ctx1 && ctx2);

    int fds[2];
    ASSERT_EQ(0, pipe(fds));
    struct sevent_io_handler h = { .fd = fds[0], .io_read = count_cb };
    sevent_io_t hdl = sevent_io_register(ctx1, &h);
    ASSERT(hdl != NULL);

    /* 用 ctx2 注销 ctx1 的句柄: 遍历 ctx2->io_list 找不到 → 安全 no-op */
    sevent_io_unregister(ctx2, hdl);
    /* 原 ctx 仍能正常注销 */
    sevent_io_unregister(ctx1, hdl);

    close(fds[0]); close(fds[1]);
    sevent_destroy(ctx1);
    sevent_destroy(ctx2);
}

TEST(edge_timer_unregister_wrong_ctx)
{
    sevent_context *ctx1 = sevent_create();
    sevent_context *ctx2 = sevent_create();
    ASSERT(ctx1 && ctx2);

    sevent_timer_t t = sevent_timer_register(ctx1, 100, count_cb, NULL);
    ASSERT(t != NULL);

    /* 用 ctx2 注销 ctx1 的句柄: 遍历 ctx2->timer_list 找不到 → 安全 no-op */
    sevent_timer_unregister(ctx2, t);
    /* 原 ctx 仍能正常注销 */
    sevent_timer_unregister(ctx1, t);

    sevent_destroy(ctx1);
    sevent_destroy(ctx2);
}

/* ====================================================================
 *  线程安全测试 (RTOS 下 mutex 为骨架, 多线程不安全, 跳过)
 * ==================================================================== */

#ifndef SEVENT_RTOS

#include <pthread.h>
#include <time.h>

/* ----- 跨线程 post 辅助 ----- */

static sevent_context *g_ts_ctx;
static int g_ts_done;

static void *ts_post_worker(void *arg)
{
    (void)arg;
    /* 等 loop 跑起来, 然后跨线程 post */
    struct timespec ts = { .tv_sec = 0, .tv_nsec = 1000000 }; /* 1ms */
    nanosleep(&ts, NULL);
    sevent_post(g_ts_ctx, count_cb, NULL);
    sevent_post(g_ts_ctx, stop_cb, g_ts_ctx);
    return NULL;
}

TEST(thread_post_cross)
{
    reset_cb();
    g_ts_done = 0;

    sevent_context *ctx = sevent_create();
    ASSERT(ctx != NULL);
    g_ts_ctx = ctx;

    pthread_t th;
    ASSERT_EQ(0, pthread_create(&th, NULL, ts_post_worker, NULL));

    sevent_run(ctx);
    ASSERT_EQ(1, cb_count);

    pthread_join(th, NULL);
    g_ts_ctx = NULL;
    sevent_destroy(ctx);
}

/* ----- 跨线程 register IO 辅助 ----- */

static int ts_pipe_fds[2];

static void *ts_io_worker(void *arg)
{
    (void)arg;
    struct timespec ts = { .tv_sec = 0, .tv_nsec = 2000000 }; /* 2ms */
    nanosleep(&ts, NULL);

    /* loop 运行中跨线程注册 IO */
    struct sevent_io_handler h = { .fd = ts_pipe_fds[0], .io_read = count_cb };
    sevent_io_t io = sevent_io_register(g_ts_ctx, &h);
    (void)io;

    /* 写 pipe 触发可读, 让 IO 回调在下一轮执行 */
    ssize_t _r = write(ts_pipe_fds[1], "x", 1);
    (void)_r;

    /* 稍后再 unregister */
    nanosleep(&ts, NULL);
    /* 如果 io 还没被处理... 等 loop 跑完 */
    return NULL;
}

TEST(thread_io_register_cross)
{
    reset_cb();
    ASSERT_EQ(0, pipe(ts_pipe_fds));

    sevent_context *ctx = sevent_create();
    ASSERT(ctx != NULL);
    g_ts_ctx = ctx;

    pthread_t th;
    ASSERT_EQ(0, pthread_create(&th, NULL, ts_io_worker, NULL));

    /* loop 会处理跨线程注册的 IO */
    sevent_post(ctx, count_cb, NULL);     /* 至少有一个任务 */
    sevent_post(ctx, stop_cb, ctx);
    sevent_run(ctx);

    /* IO 回调可能已经触发, 也可能跨线程还没注册上 */
    /* 至少 post 的任务被执行了 */
    ASSERT(cb_count >= 1);

    pthread_join(th, NULL);
    close(ts_pipe_fds[0]);
    close(ts_pipe_fds[1]);
    g_ts_ctx = NULL;
    sevent_destroy(ctx);
}

/* ----- 多线程压力测试 ----- */

#define TS_NTHR 10
#define TS_NMSG 100

static struct {
    sevent_context *ctx;
    int             pipes[TS_NTHR][2];
} g_stress;

static void *ts_stress_worker(void *arg)
{
    long id = (long)arg;
    int rd = g_stress.pipes[id][0];
    int wr = g_stress.pipes[id][1];

    /* 注册 IO (跨线程) */
    struct sevent_io_handler h = { .fd = rd, .io_read = count_cb };
    sevent_io_t io = sevent_io_register(g_stress.ctx, &h);
    if (!io) return NULL;

    /* 跨线程 post 任务 */
    for (int i = 0; i < TS_NMSG; i++) {
        ssize_t _r = write(wr, "x", 1);
        (void)_r;
        sevent_post(g_stress.ctx, count_cb, NULL);
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 100000 };
        nanosleep(&ts, NULL);
    }

    /* 注销 IO (跨线程) */
    sevent_io_unregister(g_stress.ctx, io);
    return NULL;
}

TEST(thread_stress)
{
    reset_cb();
    sevent_context *ctx = sevent_create();
    ASSERT(ctx != NULL);
    g_stress.ctx = ctx;

    for (int i = 0; i < TS_NTHR; i++)
        ASSERT_EQ(0, pipe(g_stress.pipes[i]));

    pthread_t threads[TS_NTHR];
    for (long i = 0; i < TS_NTHR; i++)
        pthread_create(&threads[i], NULL, ts_stress_worker, (void *)i);

    /* 跑 loop, 等所有线程发完 */
    struct timespec ts = { .tv_sec = 1, .tv_nsec = 0 };
    nanosleep(&ts, NULL);
    sevent_stop(ctx);
    /* 重新跑一下处理剩余事件 */
    sevent_run_once(ctx);

    for (int i = 0; i < TS_NTHR; i++) {
        pthread_join(threads[i], NULL);
        close(g_stress.pipes[i][0]);
        close(g_stress.pipes[i][1]);
    }

    /* 至少收到一些事件 */
    ASSERT(cb_count > 0);
    g_stress.ctx = NULL;
    sevent_destroy(ctx);
}

#endif /* SEVENT_RTOS */

/* ====================================================================
 *  可观测性测试
 * ==================================================================== */

TEST(observability_io_count)
{
    sevent_context *ctx = sevent_create();
    ASSERT(ctx != NULL);

    int io = -1;
    sevent_get_counts(ctx, &io, NULL, NULL);
    ASSERT_EQ(0, io);

    int fds[3][2];
    sevent_io_t handles[3];
    for (int i = 0; i < 3; i++) {
        ASSERT_EQ(0, pipe(fds[i]));
        struct sevent_io_handler h = { .fd = fds[i][0], .io_read = count_cb };
        handles[i] = sevent_io_register(ctx, &h);
        ASSERT(handles[i] != NULL);
    }
    sevent_get_counts(ctx, &io, NULL, NULL);
    ASSERT_EQ(3, io);

    /* 注销 1 个 */
    sevent_io_unregister(ctx, handles[0]);
    close(fds[0][0]); close(fds[0][1]);
    sevent_get_counts(ctx, &io, NULL, NULL);
    ASSERT_EQ(2, io);

    /* 注销剩余 */
    for (int i = 1; i < 3; i++) {
        sevent_io_unregister(ctx, handles[i]);
        close(fds[i][0]); close(fds[i][1]);
    }
    sevent_get_counts(ctx, &io, NULL, NULL);
    ASSERT_EQ(0, io);

    sevent_destroy(ctx);
}

TEST(observability_timer_count)
{
    sevent_context *ctx = sevent_create();
    ASSERT(ctx != NULL);

    int timer = -1;
    sevent_get_counts(ctx, NULL, &timer, NULL);
    ASSERT_EQ(0, timer);

    sevent_timer_t t1 = sevent_timer_register(ctx, 1000, count_cb, NULL);
    sevent_timer_t t2 = sevent_timer_register(ctx, 1000, count_cb, NULL);
    ASSERT(t1 != NULL); ASSERT(t2 != NULL);
    sevent_get_counts(ctx, NULL, &timer, NULL);
    ASSERT_EQ(2, timer);

    sevent_timer_unregister(ctx, t1);
    sevent_get_counts(ctx, NULL, &timer, NULL);
    ASSERT_EQ(1, timer);

    sevent_timer_unregister(ctx, t2);
    sevent_get_counts(ctx, NULL, &timer, NULL);
    ASSERT_EQ(0, timer);

    sevent_destroy(ctx);
}

TEST(observability_post_count)
{
    reset_cb();
    sevent_context *ctx = sevent_create();
    ASSERT(ctx != NULL);

    int post = -1;
    sevent_get_counts(ctx, NULL, NULL, &post);
    ASSERT_EQ(0, post);

    ASSERT(NULL != sevent_post(ctx, count_cb, NULL));
    ASSERT(NULL != sevent_post(ctx, count_cb, NULL));
    ASSERT(NULL != sevent_post(ctx, count_cb, NULL));
    sevent_get_counts(ctx, NULL, NULL, &post);
    ASSERT_EQ(3, post);

    /* run_once 处理并排空 post 队列 */
    sevent_run_once(ctx);
    sevent_get_counts(ctx, NULL, NULL, &post);
    ASSERT_EQ(0, post);

    sevent_destroy(ctx);
}

TEST(observability_get_counts_null_safe)
{
    /* NULL ctx */
    sevent_get_counts(NULL, NULL, NULL, NULL);

    int dummy;
    sevent_get_counts(NULL, &dummy, NULL, NULL);

    /* NULL 指针 */
    sevent_context *ctx = sevent_create();
    ASSERT(ctx != NULL);
    sevent_get_counts(ctx, NULL, NULL, NULL);
    sevent_destroy(ctx);
}

TEST(observability_combined)
{
    reset_cb();
    sevent_context *ctx = sevent_create();
    ASSERT(ctx != NULL);

    int io = -1, timer = -1, post = -1;

    int fds[2];
    ASSERT_EQ(0, pipe(fds));
    struct sevent_io_handler h = { .fd = fds[0], .io_read = count_cb };
    sevent_io_t io_h = sevent_io_register(ctx, &h);
    ASSERT(io_h != NULL);

    sevent_timer_t t = sevent_timer_register(ctx, 100, count_cb, NULL);
    ASSERT(t != NULL);

    ASSERT(NULL != sevent_post(ctx, count_cb, NULL));
    ASSERT(NULL != sevent_post(ctx, count_cb, NULL));

    sevent_get_counts(ctx, &io, &timer, &post);
    ASSERT_EQ(1, io);
    ASSERT_EQ(1, timer);
    ASSERT_EQ(2, post);

    /* 跑 loop, posts 被消耗 */
    ASSERT_EQ(1, (int)write(fds[1], "x", 1));
    for (int i = 0; i < 20; i++)
        sevent_run_once(ctx);

    /* posts 已排空, io 和 timer 仍活跃 */
    sevent_get_counts(ctx, &io, &timer, &post);
    ASSERT_EQ(1, io);
    ASSERT_EQ(1, timer);
    ASSERT_EQ(0, post);

    /* 注销后全部归零 */
    sevent_io_unregister(ctx, io_h);
    sevent_timer_unregister(ctx, t);
    close(fds[0]); close(fds[1]);

    sevent_get_counts(ctx, &io, &timer, &post);
    ASSERT_EQ(0, io);
    ASSERT_EQ(0, timer);
    ASSERT_EQ(0, post);

    sevent_destroy(ctx);
}

/* ==================== 测试清单 (X-MACRO) ==================== */

#define TEST_LIST                                                           \
    T(core_create_destroy) T(core_create_destroy_many)                      \
    T(core_run_stop) T(core_run_once_empty) T(core_run_once_with_post)     \
    T(core_post_order) T(core_wakeup) T(core_stop_aborts_pending)          \
    T(core_double_stop_safe) T(core_destroy_null_safe)                     \
    T(core_run_null) T(core_run_once_null) T(core_post_null_handler)       \
    T(core_ignore_sigpipe) T(core_restart_loop) T(core_set_allocator)      \
    T(memory_no_leak)                                                       \
    T(post_handle_not_null) T(post_cancel_before_run)                      \
    T(post_cancel_after_run) T(post_cancel_null)                           \
    T(post_cancel_in_callback) T(post_defer_to_next_iter)                  \
    T(post_dispatch_same_thread) T(post_dispatch_cross_thread)             \
    T(io_register_pipe_read) T(io_null_read_cb_no_fire)                    \
    T(io_unregister_self_in_callback) T(io_multiple_fds_partial_ready)     \
    T(io_write_monitor) T(io_both_null_rejected)                           \
    T(timer_interval_zero_rejected) T(timer_unregister_null_safe)          \
    T(timer_fire_once) T(timer_unregister_before_fire)                     \
    T(timer_dynamic_add_in_callback) T(timer_dynamic_remove_safe)          \
    T(timer_self_unregister_in_callback)                                    \
    T(timer_cross_unregister_in_callback)                                   \
    T(timer_register_in_timer_callback)                                     \
    T(timer_multi_fire_per_tick)                                            \
    T(timer_multi_fire_self_unregister)                                     \
    T(integration_io_timer_post) T(integration_stop_then_destroy)          \
    T(edge_null_context_doesnt_crash) T(edge_invalid_fd_rejected)          \
    T(edge_null_io_handler) T(edge_large_fd_rejected)                      \
    T(edge_many_timers) T(edge_unregister_twice_safe)                      \
    T(edge_io_unregister_multiple) T(edge_timer_unregister_multiple)       \
    T(edge_post_cancel_multiple)                                            \
    T(edge_io_unregister_after_free) T(edge_timer_unregister_after_free)   \
    T(edge_io_unregister_wrong_ctx) T(edge_timer_unregister_wrong_ctx)     \
    T(observability_io_count) T(observability_timer_count)                \
    T(observability_post_count) T(observability_get_counts_null_safe)     \
    T(observability_combined)

/* ====================================================================
 *  主函数
 * ==================================================================== */

int main(void)
{
    /* 注册所有测试 */
    struct test_entry *test_list = NULL;
#define T(name) do {                                                        \
        struct test_entry *e = malloc(sizeof(*e));                          \
        e->label = #name; e->fn = test_##name;                             \
        e->next = test_list; test_list = e;                                \
    } while(0);
    TEST_LIST
#ifndef SEVENT_RTOS
    T(thread_post_cross) T(thread_io_register_cross) T(thread_stress)
#endif
#undef T

    printf("\n  libsevent 单元测试\n");
    printf("  ==================\n");

    int n = 0, passed = 0;
    for (struct test_entry *e = test_list; e; e = e->next) {
        n++;
        fail_count = 0;
        e->fn();
        if (fail_count == 0) {
            printf("  \xE2\x9C\x93  %s\n", e->label);
            passed++;
        } else {
            printf("  \xC3\x97  %s  (%d assertions failed)\n", e->label, fail_count);
        }
    }

    /* 释放 test_list */
    while (test_list) { struct test_entry *n = test_list->next; free(test_list); test_list = n; }

    printf("\n  result: %d / %d passed\n", passed, n);
    return n == passed ? 0 : 1;
}
