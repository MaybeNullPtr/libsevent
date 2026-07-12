/* =========================================================================
 *  libsevent C++ Header-Only Wrapper
 *
 *  三层架构:
 *    Layer 1 — RAII 资源管理 (EventLoop / IoGuard / TimerGuard)
 *    Layer 2 — OOP 常驻事件 (IoWatcher / TimerWatcher + watch / timer)
 *    Layer 3 — Lambda 一次性任务 (post / dispatch)
 *
 *  #include "sevent.hpp" 即用, 无需 .cpp 编译.
 *  C 内核: 见 sevent.h / sevent.c, 不因本封装做任何修改.
 * ========================================================================= */

#ifndef SEVENT_HPP
#define SEVENT_HPP

#include "sevent.h"

#include <functional>
#include <utility>

namespace sevent {

/* ====================================================================
 *  Forward declarations
 * ==================================================================== */

class EventLoop;
class IoWatcher;
class TimerWatcher;

/* ====================================================================
 *  Layer 1 — RAII Guard 句柄
 *
 *  职责: 包装 C 层不透明句柄, 析构时自动 unregister.
 *  语义: move-only, reset() 用于回调中自注销.
 * ==================================================================== */

class IoGuard {
    friend class EventLoop;
public:
    IoGuard() = default;

    ~IoGuard() { cleanup(); }

    IoGuard(const IoGuard &) = delete;
    IoGuard &operator=(const IoGuard &) = delete;

    IoGuard(IoGuard &&o) noexcept
        : ctx_(o.ctx_), h_(o.h_)
    {
        o.h_ = nullptr;
    }

    IoGuard &operator=(IoGuard &&o) noexcept
    {
        if (this != &o) {
            cleanup();
            ctx_ = o.ctx_;
            h_   = o.h_;
            o.h_ = nullptr;
        }
        return *this;
    }

    /* 主动 unregister, 用于回调中自注销. reset() 后 guard 为空, 可重新赋值. */
    void reset() { cleanup(); }

    explicit operator bool() const noexcept { return h_ != nullptr; }

private:
    void cleanup()
    {
        if (h_) {
            sevent_io_unregister(ctx_, h_);
            h_ = nullptr;
        }
    }

    /* EventLoop::watch() 通过此私有构造返回 IoGuard */
    IoGuard(sevent_context *ctx, sevent_io_t h)
        : ctx_(ctx), h_(h)
    {}

    sevent_context *ctx_ = nullptr;
    sevent_io_t     h_   = nullptr;
};

class TimerGuard {
    friend class EventLoop;
public:
    TimerGuard() = default;

    ~TimerGuard() { cleanup(); }

    TimerGuard(const TimerGuard &) = delete;
    TimerGuard &operator=(const TimerGuard &) = delete;

    TimerGuard(TimerGuard &&o) noexcept
        : ctx_(o.ctx_), h_(o.h_)
    {
        o.h_ = nullptr;
    }

    TimerGuard &operator=(TimerGuard &&o) noexcept
    {
        if (this != &o) {
            cleanup();
            ctx_ = o.ctx_;
            h_   = o.h_;
            o.h_ = nullptr;
        }
        return *this;
    }

    void reset() { cleanup(); }

    explicit operator bool() const noexcept { return h_ != nullptr; }

private:
    void cleanup()
    {
        if (h_) {
            sevent_timer_unregister(ctx_, h_);
            h_ = nullptr;
        }
    }

    TimerGuard(sevent_context *ctx, sevent_timer_t h)
        : ctx_(ctx), h_(h)
    {}

    sevent_context *ctx_ = nullptr;
    sevent_timer_t  h_   = nullptr;
};

/* ====================================================================
 *  Layer 2 — OOP 常驻事件 纯虚基类
 *
 *  用户继承 IoWatcher / TimerWatcher, override 回调方法.
 *  通过 HAS-A 组合持有 IoGuard / TimerGuard 成员管理生命周期.
 * ==================================================================== */

class IoWatcher {
    friend class EventLoop;
public:
    virtual void onRead(EventLoop &loop) = 0;
    virtual void onWrite(EventLoop &loop) {}
    virtual ~IoWatcher() = default;

    /** 返回正在监听的 fd, 注册前为 -1. */
    int fd() const noexcept { return fd_; }

protected:
    /* EventLoop::watch() 注册时设置, trampoline 回调通过此指针传入 loop 引用.
       用户无需自行存储 EventLoop&. */
    EventLoop *loop_ = nullptr;
    int        fd_   = -1;
};

class TimerWatcher {
    friend class EventLoop;
public:
    virtual void onTimer(EventLoop &loop) = 0;
    virtual ~TimerWatcher() = default;

protected:
    EventLoop *loop_ = nullptr;
};

/* ====================================================================
 *  EventLoop — 三层合一的事件循环封装
 *
 *  构造时 sevent_create(), 析构时 sevent_destroy().
 *  Move-only, 不可拷贝.
 * ==================================================================== */

class EventLoop {
public:
    EventLoop()
        : ctx_(sevent_create())
    {}

    ~EventLoop()
    {
        if (ctx_) {
            sevent_destroy(ctx_);
            ctx_ = nullptr;
        }
    }

    EventLoop(const EventLoop &) = delete;
    EventLoop &operator=(const EventLoop &) = delete;

    EventLoop(EventLoop &&o) noexcept
        : ctx_(o.ctx_)
    {
        o.ctx_ = nullptr;
    }

    EventLoop &operator=(EventLoop &&o) noexcept
    {
        if (this != &o) {
            if (ctx_) sevent_destroy(ctx_);
            ctx_   = o.ctx_;
            o.ctx_ = nullptr;
        }
        return *this;
    }

    /* ---- 循环控制 ---- */

    /** 阻塞运行, 直到 stop() 被调用. */
    int run() { return sevent_run(ctx_); }

    /** 执行一轮事件循环. 返回 1=有事件, 0=空闲, <0=错误. */
    int runOnce() { return sevent_run_once(ctx_); }

    /** 通知 loop 退出. 可在回调内调用, 跨线程安全. */
    void stop()
    {
        if (ctx_) sevent_stop(ctx_);
    }

    /** 唤醒 select (跨线程通知 loop 有新任务). */
    int wakeup() { return sevent_wakeup(ctx_); }

    explicit operator bool() const noexcept { return ctx_ != nullptr; }

    /* ---- Layer 2: OOP 常驻 IO ---- */

    /**
     * 注册 IO 监听.
     * @param fd     监听的 fd
     * @param w      IoWatcher 派生类实例, onRead/onWrite 在事件就绪时被调用
     * @param read   是否监听可读事件
     * @param write  是否监听可写事件
     * @return IoGuard RAII 句柄, 析构时自动 unregister;
     *         回调中用 guard.reset() 自注销.
     */
    IoGuard watch(int fd, IoWatcher *w,
                  bool read = true, bool write = false)
    {
        if (!w || (!read && !write))
            return IoGuard();

        struct sevent_io_handler h;
        h.fd       = fd;
        h.io_read  = read  ? trampoline_io_read  : nullptr;
        h.io_write = write ? trampoline_io_write : nullptr;
        h.data     = w;

        w->loop_  = this;
        w->fd_    = fd;
        auto *raw = sevent_io_register(ctx_, &h);
        return IoGuard(ctx_, raw);
    }

    /* ---- Layer 2: OOP 常驻定时器 ---- */

    /**
     * 注册循环定时器.
     * @param ms  间隔, 单位毫秒
     * @param w   TimerWatcher 派生类实例, onTimer 在到期时被调用
     * @return TimerGuard RAII 句柄, 析构时自动 unregister;
     *         回调中用 guard.reset() 自注销.
     */
    TimerGuard timer(unsigned int ms, TimerWatcher *w)
    {
        if (!w)
            return TimerGuard();

        w->loop_   = this;
        auto *raw  = sevent_timer_register(ctx_, ms, trampoline_timer, w);
        return TimerGuard(ctx_, raw);
    }

    /* ---- Layer 3: Lambda 一次性任务 ---- */

    /**
     * 异步投递一次性任务.
     * lambda 内部使用 operator new 分配, 执行后自动释放.
     * 返回 false 表示分配失败.
     */
    bool post(std::function<void()> task)
    {
        if (!ctx_) return false;

        auto *p = new (std::nothrow) std::function<void()>(std::move(task));
        if (!p) return false;

        int ret = sevent_post(ctx_, &trampoline_post_fn, p);
        if (ret != 0) {
            delete p;
            return false;
        }
        return true;
    }

    /**
     * 同步分派: 如在 loop 线程则立即执行, 否则入队.
     * 返回 false 表示分配失败.
     */
    bool dispatch(std::function<void()> task)
    {
        if (!ctx_) return false;

        auto *p = new (std::nothrow) std::function<void()>(std::move(task));
        if (!p) return false;

        int ret = sevent_dispatch(ctx_, &trampoline_post_fn, p);
        if (ret != 0) {
            delete p;
            return false;
        }
        return true;
    }

    /* ---- 可观测性 ---- */

    /**
     * 获取当前活跃对象数量快照.
     * 任一参数为 nullptr 表示不关心该项.
     */
    void getCounts(int *io = nullptr, int *timer = nullptr,
                   int *post = nullptr) const
    {
        sevent_get_counts(ctx_, io, timer, post);
    }

    /** 取底层 C 句柄 (给需要混用 C API 的场景). */
    struct sevent_context *handle() const noexcept { return ctx_; }

private:
    /* ---- C 回调 trampoline 函数 ---- */

    static void trampoline_io_read(void *data)
    {
        auto *w = static_cast<IoWatcher *>(data);
        w->onRead(*w->loop_);
    }

    static void trampoline_io_write(void *data)
    {
        auto *w = static_cast<IoWatcher *>(data);
        w->onWrite(*w->loop_);
    }

    static void trampoline_timer(void *data)
    {
        auto *w = static_cast<TimerWatcher *>(data);
        w->onTimer(*w->loop_);
    }

    static void trampoline_post_fn(void *data)
    {
        auto *f = static_cast<std::function<void()> *>(data);
        (*f)();
        delete f;
    }

    struct sevent_context *ctx_ = nullptr;
};

/* ---- 自由函数 ---- */

/** 忽略 SIGPIPE, 避免 write 到关闭连接时进程被杀死. */
inline void ignoreSigpipe()
{
    sevent_ignore_sigpipe();
}

/**
 * 替换内部分配器.
 * 应在 EventLoop 构造之前调用; 两个参数必须同时非 NULL 或同时 NULL.
 */
inline int setAllocator(sevent_malloc_fn mf, sevent_free_fn ff)
{
    return sevent_set_allocator(mf, ff);
}

} // namespace sevent

#endif /* SEVENT_HPP */
