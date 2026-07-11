/**
 *  thread_worker.c — 跨线程异步任务
 *
 *  功能: 主线程事件循环 + N 个 worker 线程, worker 计算完成后
 *        通过 sevent_post 将结果投递回主线程
 *  用法: make example-thread-worker && ./example-thread-worker
 *
 *  演示点:
 *    - sevent_post 跨线程安全 (worker 线程直接调用)
 *    - 主线程 FIFO 收集 worker 结果
 *    - 全部完成后 sevent_stop() 退出
 */

#include "sevent.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>

#define N_WORKERS 4

/* ---- 结果数据结构 (worker → main) ---- */

struct task_result {
    int worker_id;
    int value;
};

static sevent_context *g_ctx;
static int            g_results_received;
static int            g_results_total;
static int            g_values[N_WORKERS];

/* ---- 主线程回调: 收集 worker 结果 ---- */

static void on_worker_result(void *data)
{
    struct task_result *r = (struct task_result *)data;

    printf("  [main] worker %d → value=%d\n", r->worker_id, r->value);
    g_values[r->worker_id] = r->value;
    g_results_total += r->value;
    g_results_received++;
    free(r);

    /* 全部完成则停止事件循环 */
    if (g_results_received >= N_WORKERS) {
        printf("  [main] all %d workers done, total=%d\n",
               N_WORKERS, g_results_total);
        sevent_stop(g_ctx);
    }
}

/* ---- worker 线程 ---- */

static void *worker_do(void *arg)
{
    int id = (int)(long)arg;

    /* 模拟不同耗时的计算 */
    struct timespec ts = { .tv_sec = 0,
                           .tv_nsec = (long)(50 + id * 30) * 1000000L };
    nanosleep(&ts, NULL);

    /* 分配结果 (回调中 free) */
    struct task_result *r = malloc(sizeof(*r));
    r->worker_id = id;
    r->value     = (id + 1) * 100;

    printf("[worker %d] done, posting to main thread\n", id);

    /* 跨线程 post! sevent_post 内部加锁 + wakeup, 线程安全 */
    sevent_post(g_ctx, on_worker_result, r);

    return NULL;
}

/* ---- main ---- */

int main(void)
{
    printf("Thread worker demo\n");
    printf("  spawning %d workers...\n\n", N_WORKERS);

    g_ctx = sevent_create();
    if (!g_ctx) { fprintf(stderr, "sevent_create failed\n"); return 1; }

    /* 启动 worker 线程 */
    pthread_t threads[N_WORKERS];
    for (long i = 0; i < N_WORKERS; i++)
        pthread_create(&threads[i], NULL, worker_do, (void *)i);

    /* 主线程跑事件循环, 等待 worker 结果 */
    printf("[main] waiting for worker results...\n\n");
    sevent_run(g_ctx);

    /* 等待所有线程结束 */
    for (int i = 0; i < N_WORKERS; i++)
        pthread_join(threads[i], NULL);

    printf("\nResults summary:\n");
    for (int i = 0; i < N_WORKERS; i++)
        printf("  worker %d: %d\n", i, g_values[i]);
    printf("  total:   %d (expected %d)\n",
           g_results_total, (1 + 2 + 3 + 4) * 100);

    sevent_destroy(g_ctx);
    return 0;
}
