/**
 *  post_lambda.cpp — Lambda post/dispatch 示例
 *
 *  演示:
 *    - post(lambda) 投递一次性任务
 *    - dispatch(lambda) 立即执行或入队
 *    - lambda 捕获局部变量
 *
 *  编译: make example-post-lambda && ./example-post-lambda
 *  退出: Ctrl+C
 */

#include "sevent.hpp"
#include "common.h"

#include <thread>
#include <chrono>

/* ---- main ---- */

int main() {
    sevent::EventLoop loop;

    register_stop_fn([](void *p) { static_cast<sevent::EventLoop *>(p)->stop(); }, &loop);

    LOG("started (Ctrl+C to stop)");

    /* ---- post: 跨线程投递 ---- */

    std::thread worker([&] {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        LOG("[worker] posting result to event loop...");

        loop.post([&] { LOG("[loop] received worker result"); });
    });

    /* ---- dispatch: 同一线程（回调内） ---- */

    loop.post([&] {
        LOG("[loop] first post, dispatching another task...");

        /* 在 loop 线程内 dispatch = 立即执行 */
        loop.dispatch([&] { LOG("[loop] dispatch immediate inside callback"); });
    });

    loop.run();
    worker.join();

    LOG("done");
    return 0;
}
