/**
 *  timer_demo.c — 多定时器示例 + 精度观测
 *
 *  功能: 三个不同周期的定时器，各自计数，打印时间戳
 *        通过对比 actual 与 interval 观察 select 误差
 *  编译: make example-timer-demo && ./example-timer-demo
 */

#include "sevent.h"
#include <stdio.h>
#include <time.h>

/* ---- 每个定时器关联的状态 ---- */

struct ticker {
    sevent_context *ctx;
    const char     *name;        /* 名字，仅用于打印 */
    int             interval;    /* 设定周期 ms */
    int             count;       /* 已触发次数 */
    int             limit;       /* 达到后停止 (0=不限) */
    struct timespec last_fire;   /* 上次触发时间 */
    long            max_drift;   /* 最大偏移 ms */
    long            total_drift; /* 累计偏移 ms */
};

static struct timespec t0; /* 全局起始时间 */

static long ms_since(struct timespec *start) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (now.tv_sec - start->tv_sec) * 1000L + (now.tv_nsec - start->tv_nsec) / 1000000L;
}

static long ms_between(struct timespec *a, struct timespec *b) {
    return (b->tv_sec - a->tv_sec) * 1000L + (b->tv_nsec - a->tv_nsec) / 1000000L;
}

static void on_tick(void *data) {
    struct ticker *t = (struct ticker *)data;

    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    long elapsed         = ms_since(&t0);
    int  is_first        = (t->count == 0);
    long actual_interval = is_first ? 0 : ms_between(&t->last_fire, &now);
    long drift           = is_first ? 0 : actual_interval - t->interval;

    if(drift > t->max_drift)
        t->max_drift = drift;
    t->total_drift += (drift > 0) ? drift : 0;
    t->last_fire   = now;
    t->count++;

    if(is_first)
        printf("  %5s  %5ldms  first fire\n", t->name, elapsed);
    else {
        printf("  %5s  %5ldms     %dms     %ldms   %+ldms", t->name, elapsed, t->interval, actual_interval, drift);

        /* 偏差较大时加标记 */
        if(drift > t->interval / 2)
            printf("  ⚠️");
        printf("\n");
    }

    if(t->limit > 0 && t->count >= t->limit)
        sevent_stop(t->ctx);
}

int main(void) {
    sevent_context *ctx = sevent_create();
    if(!ctx) {
        fprintf(stderr, "sevent_create failed\n");
        return 1;
    }

    clock_gettime(CLOCK_MONOTONIC, &t0);

    struct ticker fast = {
            .ctx       = ctx,
            .name      = "fast",
            .interval  = 200,
            .limit     = 0,
            .last_fire = t0,
    };
    struct ticker medium = {
            .ctx       = ctx,
            .name      = "med ",
            .interval  = 500,
            .limit     = 0,
            .last_fire = t0,
    };
    struct ticker slow = {
            .ctx       = ctx,
            .name      = "slow",
            .interval  = 1000,
            .limit     = 5,
            .last_fire = t0,
    };

    sevent_timer *t1 = sevent_timer_register(ctx, fast.interval, on_tick, &fast);
    sevent_timer *t2 = sevent_timer_register(ctx, medium.interval, on_tick, &medium);
    sevent_timer *t3 = sevent_timer_register(ctx, slow.interval, on_tick, &slow);

    if(!t1 || !t2 || !t3) {
        fprintf(stderr, "sevent_timer_register failed\n");
        return 1;
    }

    printf("定时器精度观测 (周期 = fast 200ms / med 500ms / slow 1000ms)\n");
    printf("  drift = actual_interval - 设定周期, 正值表示晚触发\n\n");
    printf("  ─────────────────────────────────────────────\n");

    sevent_run(ctx);

    printf("  ─────────────────────────────────────────────\n");
    printf("\n统计:\n");
    printf("  fast   %2d 次, max_drift=%ldms, avg_drift=%ldms\n",
           fast.count,
           fast.max_drift,
           fast.count > 0 ? fast.total_drift / fast.count : 0);
    printf("  med    %2d 次, max_drift=%ldms, avg_drift=%ldms\n",
           medium.count,
           medium.max_drift,
           medium.count > 0 ? medium.total_drift / medium.count : 0);
    printf("  slow   %2d 次, max_drift=%ldms, avg_drift=%ldms\n",
           slow.count,
           slow.max_drift,
           slow.count > 0 ? slow.total_drift / slow.count : 0);

    sevent_timer_unregister(ctx, t1);
    sevent_timer_unregister(ctx, t2);
    sevent_timer_unregister(ctx, t3);
    sevent_destroy(ctx);
    return 0;
}
