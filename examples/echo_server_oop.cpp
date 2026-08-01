/**
 *  echo_server_oop.cpp — TCP Echo Server (C++ OOP 风格, tcp_acceptor + tcp_conn)
 *
 *  演示:
 *    - tcp_acceptor / tcp_conn C API + C++ 类封装
 *    - 静态回调转发到成员函数 (user_data = this)
 *    - self-owned 对象 (回调内 delete this)
 *    - 回调内 destroy 安全 (统一 post 延迟释放)
 *
 *  编译: make example-echo-server-oop && ./example-echo-server-oop
 *        telnet 127.0.0.1 7777
 *  退出: Ctrl+C
 */

#include "sevent.h"
#include "sevent_tcp_conn.h"
#include "sevent_tcp_acceptor.h"
#include "sevent.hpp"
#include "common.h"

#include <cstdio>
#include <cerrno>
#include <unistd.h>
#include <string.h>

#define PORT 7777

/* 服务端全局统计 */
static long g_total_read = 0, g_total_wrote = 0;

/* ================================================================
 *  每个客户端连接一个对象，self-owned（回调内 delete this）
 * ================================================================ */

class TcpConnection {
public:
    /* 包装已 accept 的 fd; 失败返回 nullptr (fd 已由本层关闭) */
    static TcpConnection *create(sevent_context *ctx, int fd) {
        auto                   *c    = new TcpConnection(ctx);
        sevent_stream_conn_init init = {.user_data = c,
                                        .on_open   = &TcpConnection::onOpenCb,
                                        .on_data   = &TcpConnection::onDataCb,
                                        .on_close  = &TcpConnection::onCloseCb,
                                        .on_error  = &TcpConnection::onErrorCb};
        if(sevent_tcp_conn_accept(c->conn_, fd, &init) < 0) {
            delete c;
            return nullptr;
        }
        return c;
    }

private:
    explicit TcpConnection(sevent_context *ctx) : ctx_(ctx) { conn_ = sevent_tcp_conn_create(ctx_); }

    ~TcpConnection() {
        g_total_read  += bytes_read_;
        g_total_wrote += bytes_wrote_;
        sevent_tcp_conn_destroy(conn_);
    }

    /* ---- 静态回调转发 ---- */
    static void onOpenCb(void *d) { static_cast<TcpConnection *>(d)->onOpen(); }
    static void onDataCb(void *d, const uint8_t *data, size_t len) {
        static_cast<TcpConnection *>(d)->onData(data, len);
    }
    static void onCloseCb(void *d) { static_cast<TcpConnection *>(d)->onClose(); }
    static void onErrorCb(void *d, int err) { static_cast<TcpConnection *>(d)->onError(err); }

    void onOpen() { LOG("client connected"); }

    void onData(const uint8_t *data, size_t len) {
        bytes_read_ += (long)len;
        /* 回显: write 返回"已接受", 队列异步 flush */
        int rc      = sevent_tcp_conn_write(conn_, data, len);
        if(rc != 0) {
            LOG("write error fd=%d, rc=%d", -1, rc);
            onClose();
            return;
        }
        bytes_wrote_ += (long)len;
    }

    void onClose() {
        LOG("client disconnected (read=%ld, wrote=%ld)", bytes_read_, bytes_wrote_);
        delete this; /* self-owned: 析构里 destroy (post 延迟释放) */
    }

    void onError(int err) {
        LOG("client error %d (read=%ld, wrote=%ld)", err, bytes_read_, bytes_wrote_);
        delete this;
    }

    sevent_context  *ctx_;
    sevent_tcp_conn *conn_;
    long             bytes_read_  = 0;
    long             bytes_wrote_ = 0;
};

/* ================================================================
 *  监听者 — tcp_acceptor 封装, 析构时释放
 * ================================================================ */

class Listener {
public:
    Listener(sevent_context *ctx, int port) : ctx_(ctx) {
        acc_ = sevent_tcp_acceptor_create(ctx_);
        if(!acc_)
            return;
        if(sevent_tcp_acceptor_listen(acc_, "127.0.0.1", port, 8, &Listener::onAcceptCb, this) < 0) {
            LOG("listen %d failed", port);
            return;
        }
        LOG("echo server listening on 127.0.0.1:%d", port);
    }

    ~Listener() { sevent_tcp_acceptor_destroy(acc_); }

private:
    static void onAcceptCb(void *d, int fd) { static_cast<Listener *>(d)->onAccept(fd); }

    void onAccept(int fd) {
        LOG("accept fd=%d", fd);
        auto *c = TcpConnection::create(ctx_, fd);
        if(!c)
            LOG("connection create failed");
    }

    sevent_context      *ctx_;
    sevent_tcp_acceptor *acc_ = nullptr;
};

/* ================================================================
 *  main
 * ================================================================ */

int main() {
    sevent::ignoreSigpipe();
    sevent_context *ctx = sevent_create();
    if(!ctx) {
        LOG("sevent_create failed");
        return 1;
    }

    register_stop_fn([](void *p) { sevent_stop(static_cast<sevent_context *>(p)); }, ctx);

    Listener listener(ctx, PORT);
    LOG("started (Ctrl+C to stop)");
    sevent_run(ctx);
    LOG("stopped — total read=%ld, wrote=%ld, diff=%ld", g_total_read, g_total_wrote, g_total_read - g_total_wrote);
    sevent_destroy(ctx);
    return 0;
}
