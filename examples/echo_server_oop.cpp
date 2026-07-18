/**
 *  echo_server_oop.cpp — TCP Echo Server (C++ OOP 风格)
 *
 *  演示:
 *    - IoWatcher 继承, onRead 处理 IO
 *    - IoGuard 成员管理注册生命周期
 *    - 回调中 guard_.reset() 自注销
 *    - self-owned 对象 (delete this)
 *    - 基类 fd() 访问器
 *
 *  编译: make example-echo-server-oop && ./example-echo-server-oop
 *        telnet 127.0.0.1 7777
 *  退出: Ctrl+C
 */

#include "sevent.hpp"
#include "common.h"

#include <cstdio>
#include <cerrno>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#define PORT 7777

/* 服务端全局统计 */
static long g_total_read = 0, g_total_wrote = 0;

/* ================================================================
 *  每个客户端连接一个对象，self-owned（回调内 delete this）
 * ================================================================ */

class TcpConnection : public sevent::IoWatcher {
public:
    /* 注册后立即 self-owned，不再返回 */
    static void start(sevent::EventLoop &loop, int fd) {
        auto *c   = new TcpConnection(loop, fd);
        c->guard_ = loop.watch(fd, c); // move-assign IoGuard
    }

private:
    TcpConnection(sevent::EventLoop &loop, int fd) : loop_(loop) {}

    ~TcpConnection() {
        g_total_read  += bytes_read_;
        g_total_wrote += bytes_wrote_;
        // LOG("fd=%d closed, read=%ld, wrote=%ld",
        //     fd(), bytes_read_, bytes_wrote_);
    }

    void onRead(sevent::EventLoop &loop) override {
        char buf[4096];
        auto n = read(fd(), buf, sizeof(buf));
        if(n <= 0) {
            if(n == 0)
                LOG("client fd=%d disconnected (read=%ld, wrote=%ld)", fd(), bytes_read_, bytes_wrote_);
            else
                LOG("client fd=%d error, read=%ld, wrote=%ld (n=%ld)", fd(), bytes_read_, bytes_wrote_, (long)n);
            guard_.reset();
            close(fd());
            delete this;
            return;
        }
        bytes_read_ += n;

        /* Echo 回显 */
        size_t written = 0;
        while(written < (size_t)n) {
            auto w = write(fd(), buf + written, (size_t)(n - written));
            if(w > 0) {
                written += (size_t)w;
            } else if(errno != EAGAIN && errno != EINTR) {
                if(errno != ECONNRESET && errno != EPIPE)
                    LOG("write error fd=%d, err=%d %s", fd(), errno, strerror(errno));
                else
                    LOG("client fd=%d disconnected (read=%ld, wrote=%ld)", fd(), bytes_read_, bytes_wrote_);
                guard_.reset();
                close(fd());
                delete this;
                return;
            }
        }
        bytes_wrote_ += written;
    }

    sevent::EventLoop &loop_;
    sevent::IoGuard    guard_;
    long               bytes_read_  = 0;
    long               bytes_wrote_ = 0;
};

/* ================================================================
 *  监听者 — 持有 IoGuard，析构时自动注销
 * ================================================================ */

static int create_listen_fd(int port) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if(fd < 0) {
        LOG("socket failed");
        return -1;
    }

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr {};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if(bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0 || listen(fd, SOMAXCONN) < 0) {
        LOG("bind/listen failed");
        close(fd);
        return -1;
    }
    return fd;
}

class Listener : public sevent::IoWatcher {
public:
    Listener(sevent::EventLoop &loop, int port) : listen_fd_(create_listen_fd(port)) {
        if(listen_fd_ < 0)
            return;
        guard_ = loop.watch(listen_fd_, this); // 持有 guard，持续监听
        LOG("echo server listening on 127.0.0.1:%d", port);
    }

private:
    void onRead(sevent::EventLoop &loop) override {
        struct sockaddr_in addr;
        socklen_t          addrlen = sizeof(addr);
        int                cfd     = accept(listen_fd_, (struct sockaddr *)&addr, &addrlen);
        if(cfd < 0) {
            if(errno != EAGAIN && errno != EINTR)
                LOG("accept error");
            return;
        }

        int flags = fcntl(cfd, F_GETFL);
        if(flags >= 0)
            fcntl(cfd, F_SETFL, flags | O_NONBLOCK);

        LOG("accept fd=%d from %s:%d", cfd, inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

        TcpConnection::start(loop, cfd); // self-owned
    }

    int             listen_fd_ = -1;
    sevent::IoGuard guard_; // 持有注册，析构时 unregister
};

/* ================================================================
 *  main
 * ================================================================ */

int main() {
    sevent::ignoreSigpipe();
    sevent::EventLoop loop;

    register_stop_fn([](void *p) { static_cast<sevent::EventLoop *>(p)->stop(); }, &loop);

    Listener listener(loop, PORT);
    LOG("started (Ctrl+C to stop)");
    loop.run();
    LOG("stopped — total read=%ld, wrote=%ld, diff=%ld", g_total_read, g_total_wrote, g_total_read - g_total_wrote);
    return 0;
}
