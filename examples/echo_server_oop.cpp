/**
 *  echo_server_oop.cpp — TCP Echo Server (C++ OOP 风格)
 *
 *  演示:
 *    - IoWatcher 继承, onRead 处理 IO
 *    - IoGuard 成员管理注册生命周期
 *    - 回调中 guard_.reset() 自注销
 *    - self-owned 对象 (delete this)
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

#define PORT 7777

/* ---- 每个客户端连接一个对象 ---- */

class TcpConnection : public sevent::IoWatcher {
public:
    TcpConnection(sevent::EventLoop &loop, int fd)
        : fd_(fd)
    {
        guard_ = loop.watch(fd_, this);   // move-assign IoGuard
    }

private:
    void onRead(sevent::EventLoop &loop) override
    {
        char buf[4096];
        auto n = read(fd_, buf, sizeof(buf));
        if (n <= 0) {
            if (n == 0)
                LOG("disconnect fd=%d", fd_);
            else
                LOG("read error fd=%d", fd_);
            guard_.reset();               // unregister 自己
            close(fd_);
            delete this;                  // self-owned
            return;
        }

        /* Echo 回显 */
        size_t written = 0;
        while (written < (size_t)n) {
            auto w = write(fd_, buf + written, (size_t)(n - written));
            if (w > 0) {
                written += (size_t)w;
            } else if (errno != EAGAIN && errno != EINTR) {
                LOG("write error fd=%d", fd_);
                guard_.reset();
                close(fd_);
                delete this;
                return;
            }
        }

        buf[n] = '\0';
        if (buf[n - 1] == '\n') buf[n - 1] = '\0';
        LOG("echo fd=%d: %s", fd_, buf);
    }

    int             fd_;
    sevent::IoGuard guard_;   // 析构或 reset() 时 unregister
};

/* ---- 监听 socket 也是 IoWatcher ---- */

class Listener : public sevent::IoWatcher {
public:
    Listener(sevent::EventLoop &loop, int port)
    {
        listen_fd_ = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        if (listen_fd_ < 0) { LOG("socket failed"); return; }

        int opt = 1;
        setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        struct sockaddr_in addr{};
        addr.sin_family      = AF_INET;
        addr.sin_port        = htons(port);
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

        if (bind(listen_fd_, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            LOG("bind failed"); close(listen_fd_); return;
        }
        if (listen(listen_fd_, SOMAXCONN) < 0) {
            LOG("listen failed"); close(listen_fd_); return;
        }

        loop.watch(listen_fd_, this);
        LOG("echo server listening on 127.0.0.1:%d", port);
    }

    ~Listener() { if (listen_fd_ >= 0) close(listen_fd_); }

private:
    void onRead(sevent::EventLoop &loop) override
    {
        struct sockaddr_in addr;
        socklen_t addrlen = sizeof(addr);
        int cfd = accept(listen_fd_, (struct sockaddr *)&addr, &addrlen);
        if (cfd < 0) {
            if (errno != EAGAIN && errno != EINTR) LOG("accept error");
            return;
        }

        int flags = fcntl(cfd, F_GETFL);
        if (flags >= 0) fcntl(cfd, F_SETFL, flags | O_NONBLOCK);

        LOG("accept fd=%d from %s:%d",
            cfd, inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

        new TcpConnection(loop, cfd);   // self-owned
    }

    int listen_fd_ = -1;
};

/* ---- main ---- */

int main()
{
    sevent::ignoreSigpipe();
    sevent::EventLoop loop;

    register_stop_fn([](void *p) {
        static_cast<sevent::EventLoop *>(p)->stop();
    }, &loop);

    Listener listener(loop, PORT);
    LOG("started (Ctrl+C to stop)");
    loop.run();
    LOG("stopped");
    return 0;
}
