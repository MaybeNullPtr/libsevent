/* ==================== libsevent - select 事件循环 ========================
 *
 * loop 流程:
 *   1. select() 超时 = 最短定时器的剩余时间
 *   2. 遍历就绪 fd, 触发 io_read / io_write
 *   3. 执行 post 队列中的异步任务
 *   4. 检查定时器, 到期的触发 timer_fn
 *
 * 线程安全:
 *   [跨线程, 锁]   register/unregister/timer 族, post
 *   [跨线程, 无锁] stop, wakeup
 *   [loop 线程]    run, run_once
 *   [串行]         create, destroy, set_allocator
 * ========================================================================= */

#include "sevent.h"
#include "sevent_platform.h"

/* ==================== 可替换分配器 ==================== */

static sevent_malloc_fn g_malloc = malloc;
static sevent_free_fn   g_free   = free;

int sevent_set_allocator(sevent_malloc_fn mf, sevent_free_fn ff)
{
    if ((mf == NULL) != (ff == NULL))
        return SEVENT_ERR_INVAL;
    if (mf) { g_malloc = mf; g_free = ff; }
    else    { g_malloc = malloc; g_free = free; }
    return SEVENT_SUCCESS;
}

static void *xzalloc(size_t sz)
{
    void *p = g_malloc(sz);
    if (p) memset(p, 0, sz);
    return p;
}

/* ==================== 内部节点 ==================== */

struct sevent_io
{
    struct sevent_io    *next;
    struct sevent_io   **prev;       /* 指向上一个节点的 next 域 */
    int                  fd;
    sevent_io_read_fn    read_cb;
    sevent_io_write_fn   write_cb;
    void                *data;
    struct sevent_context *ctx;
    int                   deleted;        /* unregister 标记, 用于快照保护 */
};

struct sevent_timer
{
    struct sevent_timer  *next;
    struct sevent_timer **prev;
    unsigned int          interval_ms;
    int                   remaining_ms;
    sevent_timer_fn              cb;
    void                 *data;
    struct sevent_context *ctx;
    int                   deleted;        /* unregister 标记 */
};

struct sevent_post
{
    struct sevent_post *next;
    sevent_handler_fn cb;
    void        *data;
    int          cancelled;
    int          done;
    struct sevent_context *ctx;  /* 跨线程 cancel 时用于加锁 */
};

struct sevent_context
{
    volatile int running;
    sevent_thread_t loop_thread;  /* loop 所在线程, 用于 dispatch 判断 */
    int wake_fds[2];

    sevent_mutex_t lock;       /* io_list / timer_list / death lists */
    sevent_mutex_t post_lock;  /* task 队列 */

    struct sevent_io    *io_list;
    struct sevent_io    *death_io;      /* 已注销 IO, 下轮 loop 释放 */
    struct sevent_timer *timer_list;
    struct sevent_timer *death_timer;   /* 已注销定时器, 下轮 loop 释放 */

    struct sevent_post *post_pending;      /* FIFO 队列, post_lock 保护 */
    struct sevent_post *post_pending_tail;

    int io_count;             /* 活跃 IO 数量, lock 保护 */
    int timer_count;          /* 活跃定时器数量, lock 保护 */
    int post_pending_count;   /* 待处理 post 数量, post_lock 保护 */
};

/* ==================== 链表操作 ==================== */

static void io_list_add(struct sevent_io **head, struct sevent_io *n)
{
    n->next = *head;
    if (*head) (*head)->prev = &n->next;
    n->prev = head;
    *head = n;
}

static void io_list_del(struct sevent_io *n)
{
    if (n->next) n->next->prev = n->prev;
    *n->prev = n->next;
}

static void timer_list_add(struct sevent_timer **head, struct sevent_timer *n)
{
    n->next = *head;
    if (*head) (*head)->prev = &n->next;
    n->prev = head;
    *head = n;
}

static void timer_list_del(struct sevent_timer *n)
{
    if (n->next) n->next->prev = n->prev;
    *n->prev = n->next;
}

/* ==================== 辅助函数 ==================== */

static long ms_elapsed(const struct timespec *a, const struct timespec *b)
{
    return (b->tv_sec  - a->tv_sec) * 1000L
         + (b->tv_nsec - a->tv_nsec) / 1000000L;
}

/* 释放延迟链表 */
static void free_death_io(struct sevent_io *list)
{
    while (list) { struct sevent_io *n = list->next; g_free(list); list = n; }
}
static void free_death_timer(struct sevent_timer *list)
{
    while (list) { struct sevent_timer *n = list->next; g_free(list); list = n; }
}

/* ==================== Core API ==================== */

sevent_context *sevent_create(void)
{
    struct sevent_context *ctx = xzalloc(sizeof(*ctx));
    if (!ctx) return NULL;

    ctx->loop_thread = (sevent_thread_t)-1;  /* sentinel: 未启动, 不匹配任何线程 */

    ctx->wake_fds[0] = ctx->wake_fds[1] = -1;

    sevent_mutex_init(&ctx->lock);
    sevent_mutex_init(&ctx->post_lock);

    if (sevent_wakeup_pair(ctx->wake_fds) < 0) {
        sevent_mutex_destroy(&ctx->lock);
        sevent_mutex_destroy(&ctx->post_lock);
        g_free(ctx);
        return NULL;
    }
    return ctx;
}

void sevent_destroy(sevent_context *ctx)
{
    if (!ctx) return;
    ctx->running = 0;

    /* 释放所有异步任务 */
    {
        struct sevent_post *t = ctx->post_pending;
        while (t) { struct sevent_post *n = t->next; g_free(t); t = n; }
    }

    /* 释放 IO 活跃链表 */
    {
        struct sevent_io *io = ctx->io_list;
        while (io) { struct sevent_io *n = io->next; g_free(io); io = n; }
    }

    /* 释放 IO 延迟链表 */
    free_death_io(ctx->death_io);

    /* 释放定时器活跃链表 */
    {
        struct sevent_timer *t = ctx->timer_list;
        while (t) { struct sevent_timer *n = t->next; g_free(t); t = n; }
    }

    /* 释放定时器延迟链表 */
    free_death_timer(ctx->death_timer);

    if (ctx->wake_fds[0] >= 0) close(ctx->wake_fds[0]);
    if (ctx->wake_fds[1] >= 0) close(ctx->wake_fds[1]);

    sevent_mutex_destroy(&ctx->lock);
    sevent_mutex_destroy(&ctx->post_lock);
    g_free(ctx);
}

void sevent_stop(sevent_context *ctx)
{
    if (!ctx) return;
    ctx->running = 0;
    sevent_wakeup(ctx);
}

int sevent_wakeup(sevent_context *ctx)
{
    if (!ctx) return SEVENT_ERR_INVAL;
    uint64_t val = 1;
    /* write 到 wake fd: eventfd 要求 8 字节, pipe/socket 也兼容 */
    ssize_t r = write(ctx->wake_fds[1], &val, sizeof(val));
    (void)r;
    return SEVENT_SUCCESS;
}

sevent_post_t sevent_post(sevent_context *ctx, sevent_handler_fn h, void *data)
{
    if (!ctx || !h) return NULL;

    struct sevent_post *t = g_malloc(sizeof(*t));
    if (!t) return NULL;
    t->next = NULL; t->cb = h; t->data = data;
    t->cancelled = 0; t->done = 0; t->ctx = ctx;

    sevent_mutex_lock(&ctx->post_lock);
    if (ctx->post_pending_tail)
        ctx->post_pending_tail->next = t;
    else
        ctx->post_pending = t;
    ctx->post_pending_tail = t;
    ctx->post_pending_count++;
    sevent_mutex_unlock(&ctx->post_lock);

    sevent_wakeup(ctx);
    return t;
}

void sevent_ignore_sigpipe(void)
{
#ifndef SEVENT_NO_SIGPIPE
    struct sigaction sa = { .sa_handler = SIG_IGN };
    sigaction(SIGPIPE, &sa, NULL);
#endif
}

/* ==================== run 阶段函数 ==================== */

static void run_free_death(sevent_context *ctx)
{
    sevent_mutex_lock(&ctx->lock);
    struct sevent_io    *die_io  = ctx->death_io;    ctx->death_io    = NULL;
    struct sevent_timer *die_tmr = ctx->death_timer; ctx->death_timer = NULL;
    sevent_mutex_unlock(&ctx->lock);
    free_death_io(die_io);
    free_death_timer(die_tmr);
}

/*
 * 构建 fd_set 和 IO 快照, 计算 select 超时.
 * 返回 1 应继续 select, 0 表示无 IO 无定时器, 跳过 select.
 */
static int run_build_fdset(sevent_context *ctx,
                           fd_set *rfds, fd_set *wfds,
                           struct sevent_io **iosnap, int *out_n_io,
                           int *out_max_fd, int *out_has_io,
                           int *out_has_timer, struct timeval *tv)
{
    int n_io = 0, max_fd, has_io = 0;

    sevent_mutex_lock(&ctx->lock);

    FD_ZERO(rfds);  FD_ZERO(wfds);
    FD_SET(ctx->wake_fds[0], rfds);
    max_fd = ctx->wake_fds[0];

    for (struct sevent_io *io = ctx->io_list; io; io = io->next) {
        has_io = 1;
        if (io->read_cb)  FD_SET(io->fd, rfds);
        if (io->write_cb) FD_SET(io->fd, wfds);
        if (io->fd > max_fd) max_fd = io->fd;
        if (n_io < FD_SETSIZE) iosnap[n_io++] = io;
    }

    int has_timer = (ctx->timer_list != NULL);

    if (has_timer) {
        unsigned int next_timer = (unsigned int)-1;
        for (struct sevent_timer *t = ctx->timer_list; t; t = t->next) {
            unsigned int r = (t->remaining_ms > 0) ? (unsigned int)t->remaining_ms : 0;
            if (r < next_timer) next_timer = r;
        }
        tv->tv_sec  = next_timer / 1000;
        tv->tv_usec = (next_timer % 1000) * 1000;
    }

    sevent_mutex_unlock(&ctx->lock);

    *out_n_io      = n_io;
    *out_max_fd    = max_fd;
    *out_has_io    = has_io;
    *out_has_timer = has_timer;
    return (has_io || has_timer) ? 1 : 0;
}

static void run_io_callbacks(sevent_context *ctx, int nfds,
                             fd_set *rfds, fd_set *wfds,
                             struct sevent_io **iosnap, int n_io, int *fired)
{
    if (nfds <= 0) return;
    if (FD_ISSET(ctx->wake_fds[0], rfds))
        sevent_wakeup_drain(ctx->wake_fds[0]);

    for (int i = 0; i < n_io; i++) {
        struct sevent_io *io = iosnap[i];
        if (io->deleted) continue;
        if (io->read_cb && FD_ISSET(io->fd, rfds)) {
            io->read_cb(io->data);
            *fired = 1;
        } else if (io->write_cb && FD_ISSET(io->fd, wfds)) {
            io->write_cb(io->data);
            *fired = 1;
        }
    }
}

void sevent_post_cancel(sevent_context *ctx, sevent_post_t h)
{
    if (!ctx || !h) return;
    /* 只查 pending 链表: 已出队的 post 正在执行或已 free.
       指针比较安全, 不解引用野指针. */
    sevent_mutex_lock(&ctx->post_lock);
    for (struct sevent_post *p = ctx->post_pending; p; p = p->next)
        if (p == h) { p->cancelled = 1; break; }
    sevent_mutex_unlock(&ctx->post_lock);
}

int sevent_dispatch(sevent_context *ctx, sevent_handler_fn h, void *data)
{
    if (!ctx || !h) return SEVENT_ERR_INVAL;
    if (sevent_thread_equal(ctx->loop_thread, sevent_thread_self())) {
        h(data);
        return SEVENT_SUCCESS;
    }
    return sevent_post(ctx, h, data) ? SEVENT_SUCCESS : SEVENT_ERR_NOMEM;
}

static void run_posts(sevent_context *ctx, int *fired)
{
    /* 双队列: 将 pending 队列入队到本地 active, 新任务进 pending 下轮处理 */
    sevent_mutex_lock(&ctx->post_lock);
    struct sevent_post *active = ctx->post_pending;
    ctx->post_pending = ctx->post_pending_tail = NULL;
    ctx->post_pending_count = 0;
    sevent_mutex_unlock(&ctx->post_lock);

    while (active) {
        struct sevent_post *next = active->next;
        int skip;
        sevent_mutex_lock(&ctx->post_lock);
        skip = active->cancelled;
        if (!skip) active->done = 1;
        sevent_mutex_unlock(&ctx->post_lock);

        if (!skip) {
            active->cb(active->data);
            *fired = 1;
        }
        g_free(active);
        active = next;
    }
}

#define MAX_EXPIRED_PER_TICK  32

struct expire_entry {
    struct sevent_timer *t;
    int times;                   /* 需要连续触发多少次 */
};

static void run_timers(sevent_context *ctx, int has_timer,
                       long delta, int *fired)
{
    if (!has_timer || delta <= 0) return;

    struct expire_entry expired[MAX_EXPIRED_PER_TICK];
    int n_expired = 0;

    /* 阶段 A：持锁计算并收集到期 timer */
    sevent_mutex_lock(&ctx->lock);
    for (struct sevent_timer *t = ctx->timer_list; t; t = t->next) {
        if (t->deleted) continue;

        t->remaining_ms -= (int)delta;
        int fire_count = 0;
        while (t->remaining_ms <= 0 && fire_count < 100) {
            fire_count++;
            t->remaining_ms += (int)t->interval_ms;
        }

        if (fire_count > 0 && n_expired < MAX_EXPIRED_PER_TICK) {
            expired[n_expired].t = t;
            expired[n_expired].times = fire_count;
            n_expired++;
        } else if (fire_count > 0) {
            /* 数组满了，设 0 让下轮 delta>0 立即补触发 */
            t->remaining_ms = 0;
        }
    }
    sevent_mutex_unlock(&ctx->lock);

    /* 阶段 B：无锁调用用户回调 */
    for (int i = 0; i < n_expired; i++) {
        struct sevent_timer *t = expired[i].t;
        if (t->deleted) continue;      /* 回调前已被其他回调 unregister，跳过 */
        for (int k = 0; k < expired[i].times; k++) {
            t->cb(t->data);
            *fired = 1;
        }
    }
}

/* ==================== run / run_once ==================== */

int sevent_run_once(sevent_context *ctx)
{
    if (!ctx) return SEVENT_ERR_INVAL;
    ctx->loop_thread = sevent_thread_self();

    fd_set rfds, wfds;
    struct sevent_io *iosnap[FD_SETSIZE];
    int n_io, max_fd, has_io, has_timer;
    long delta = 0;
    int fired = 0;

    /* 阶段 0: 释放上一轮的延迟链表 */
    run_free_death(ctx);

    /* 阶段 1: 构建 fd_set + 超时 */
    struct timeval tv;
    int do_select = run_build_fdset(ctx, &rfds, &wfds, iosnap,
                                    &n_io, &max_fd, &has_io, &has_timer, &tv);

    /* 阶段 2: select */
    if (do_select) {
        struct timeval *tvp = has_timer ? &tv : NULL;
        struct timespec t0;
        clock_gettime(CLOCK_MONOTONIC, &t0);

        int nfds = select(max_fd + 1, &rfds, &wfds, NULL, tvp);

        struct timespec t1;
        clock_gettime(CLOCK_MONOTONIC, &t1);
        delta = ms_elapsed(&t0, &t1);
        if (delta < 0) delta = 0;

        if (nfds < 0) {
            if (errno != EINTR && errno != EBADF)
                return SEVENT_ERR_INVAL;
            /* EINTR (信号打断) / EBADF (fd 在 select 期间被 unregister+close):
               跳过 IO 回调, fall through 到 posts + timers */
        } else {
            /* 阶段 3: IO 回调 */
            run_io_callbacks(ctx, nfds, &rfds, &wfds, iosnap, n_io, &fired);
        }
    }

    /* 阶段 4: 异步任务 */
    run_posts(ctx, &fired);

    /* 阶段 5: 定时器 */
    run_timers(ctx, has_timer, delta, &fired);

    return fired ? 1 : 0;
}

int sevent_run(sevent_context *ctx)
{
    if (!ctx) return SEVENT_ERR_INVAL;
    ctx->running = 1;
    while (ctx->running)
        sevent_run_once(ctx);
    return SEVENT_SUCCESS;
}

/* ==================== I/O API ==================== */

sevent_io_t sevent_io_register(sevent_context *ctx, struct sevent_io_handler *h)
{
    if (!ctx || !h) return NULL;
    if (h->fd < 0 || h->fd >= FD_SETSIZE) return NULL;
    if (!h->io_read && !h->io_write) return NULL;

    struct sevent_io *io = g_malloc(sizeof(*io));
    if (!io) return NULL;

    io->fd       = h->fd;
    io->read_cb  = h->io_read;
    io->write_cb = h->io_write;
    io->data     = h->data;
    io->ctx      = ctx;
    io->deleted  = 0;

    sevent_mutex_lock(&ctx->lock);
    /* 去重: 不允许同一 fd 注册两次 */
    for (struct sevent_io *p = ctx->io_list; p; p = p->next) {
        if (p->fd == h->fd && !p->deleted) {
            sevent_mutex_unlock(&ctx->lock);
            g_free(io);
            return NULL;
        }
    }
    io_list_add(&ctx->io_list, io);
    ctx->io_count++;
    sevent_mutex_unlock(&ctx->lock);

    sevent_wakeup(ctx);
    return io;
}

void sevent_io_unregister(sevent_context *ctx, sevent_io_t h)
{
    if (!ctx || !h) return;
    int found = 0;
    sevent_mutex_lock(&ctx->lock);
    for (struct sevent_io *p = ctx->io_list; p; p = p->next) {
        if (p == h) {
            h->deleted = 1;     /* 快照遍历时跳过 */
            io_list_del(h);
            ctx->io_count--;
            h->next = ctx->death_io;
            ctx->death_io = h;
            found = 1;
            break;
        }
    }
    sevent_mutex_unlock(&ctx->lock);
    if (found) sevent_wakeup(ctx);
}

/* ==================== Timer API ==================== */

sevent_timer_t sevent_timer_register(sevent_context *ctx,
                                     unsigned int interval_ms,
                                     sevent_timer_fn cb, void *data)
{
    if (!ctx || !cb || interval_ms == 0) return NULL;

    struct sevent_timer *t = g_malloc(sizeof(*t));
    if (!t) return NULL;

    t->interval_ms  = interval_ms;
    t->remaining_ms = (int)interval_ms;
    t->cb           = cb;
    t->data         = data;
    t->ctx          = ctx;
    t->deleted      = 0;

    sevent_mutex_lock(&ctx->lock);
    timer_list_add(&ctx->timer_list, t);
    ctx->timer_count++;
    sevent_mutex_unlock(&ctx->lock);

    sevent_wakeup(ctx);
    return t;
}

void sevent_timer_unregister(sevent_context *ctx, sevent_timer_t h)
{
    if (!ctx || !h) return;
    if (!ctx) return;
    sevent_mutex_lock(&ctx->lock);
    /* 遍历活跃链表查找 h. 不在链表中说明已释放或从不属于此 ctx,
       指针比较不依赖 h 有效性, 已释放句柄不会误匹配. */
    for (struct sevent_timer *p = ctx->timer_list; p; p = p->next) {
        if (p == h) {
            h->deleted = 1;     /* 快照遍历时跳过 */
            timer_list_del(h);
            ctx->timer_count--;
            h->next = ctx->death_timer;
            ctx->death_timer = h;
            break;
        }
    }
    sevent_mutex_unlock(&ctx->lock);
}

/* ==================== 可观测性 ==================== */

void sevent_get_counts(sevent_context *ctx,
                       int *io_count, int *timer_count, int *post_count)
{
    if (!ctx) return;

    if (io_count || timer_count) {
        sevent_mutex_lock(&ctx->lock);
        if (io_count)   *io_count   = ctx->io_count;
        if (timer_count) *timer_count = ctx->timer_count;
        sevent_mutex_unlock(&ctx->lock);
    }

    if (post_count) {
        sevent_mutex_lock(&ctx->post_lock);
        *post_count = ctx->post_pending_count;
        sevent_mutex_unlock(&ctx->post_lock);
    }
}
