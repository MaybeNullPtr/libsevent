/**
 *  timer_oop.cpp — 定时器 C++ OOP 示例
 *
 *  演示:
 *    - TimerWatcher 继承
 *    - TimerGuard 成员, guard_.reset() 自注销
 *    - 多定时器, 各自独立状态
 *
 *  编译: make example-timer-oop && ./example-timer-oop
 *  退出: Ctrl+C
 */

#include "sevent.hpp"
#include "common.h"

/* ---- 可自注销的循环定时器 ---- */

class Ticker : public sevent::TimerWatcher {
public:
    Ticker(sevent::EventLoop &loop, const char *name,
           unsigned ms, int limit)
        : name_(name), limit_(limit)
    {
        guard_ = loop.timer(ms, this);
    }

    int count() const { return count_; }

private:
    void onTimer(sevent::EventLoop &loop) override
    {
        LOG("%s tick %d/%d", name_, ++count_, limit_);
        if (count_ >= limit_)
            guard_.reset();       // 自注销，仅停止本定时器
    }

    const char      *name_;
    int              count_ = 0;
    int              limit_;
    sevent::TimerGuard guard_;   // HAS-A, 析构/reset 时 unregister
};

/* ---- main ---- */

int main()
{
    sevent::EventLoop loop;

    register_stop_fn([](void *p) {
        static_cast<sevent::EventLoop *>(p)->stop();
    }, &loop);

    Ticker fast(loop, "fast", 200,  8);
    Ticker med( loop, "med",  500,  5);
    Ticker slow(loop, "slow", 1000, 3);

    LOG("demo started (fast=200ms/8, med=500ms/5, slow=1000ms/3, Ctrl+C to stop)");
    loop.run();
    LOG("fired: fast=%d, med=%d, slow=%d", fast.count(), med.count(), slow.count());

    return 0;
}
