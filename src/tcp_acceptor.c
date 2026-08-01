/* =========================================================================
 *  tcp_acceptor.c — TCP 监听器实现 (公开层 sevent_tcp_acceptor)
 *
 *  封装服务端样板: socket + bind + listen + 读事件注册 + accept 循环.
 *  生命周期与回调安全语义与 tcp_conn 对齐: destroyed 守卫 + post 延迟释放,
 *  on_accept 回调内可安全 close/destroy.
 *  ========================================================================= */

#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "sevent_i.h"
#include "sevent_tcp_acceptor.h"

#ifdef SEVENT_THREAD_SAFE
#include "sevent_platform.h"
#define ACC_LOCK(a)                                                                                                    \
    do {                                                                                                               \
        if((a))                                                                                                        \
            sevent_mutex_lock(&(a)->lock);                                                                             \
    } while(0)
#define ACC_UNLOCK(a)                                                                                                  \
    do {                                                                                                               \
        if((a))                                                                                                        \
            sevent_mutex_unlock(&(a)->lock);                                                                           \
    } while(0)
#else
#define ACC_LOCK(a) ((void)0)
#define ACC_UNLOCK(a) ((void)0)
#endif

#define SEVENT_INVALID_SOCKET (-1)
#define SEVENT_ACCEPTOR_BACKLOG 8 /* 默认 listen backlog */

/* 内部实现结构 (公开层句柄 = 本结构指针) */
struct tcp_acceptor {
    sevent_context *ev;

    /* ---- 监听 socket ---- */
    int        fd;
    sevent_io *io_handle;
    int        port; /* 实际监听端口, <0=未监听 */

    /* ---- 状态 ---- */
    bool destroyed; /* 回调重入守卫: on_accept 中 destroy 后不再访问 */
#ifdef SEVENT_THREAD_SAFE
    sevent_mutex_t lock; /* 跨线程锁 (递归) */
#endif

    /* ---- 用户回调 ---- */
    sevent_tcp_accept_fn on_accept;
    void                *user_data;
};

/* ---- 前向声明 ---- */
static void on_accept_ready(void *data);
static void acc_close_io(struct tcp_acceptor *a);

/* 读就绪: accept 循环 (一次就绪可能多个连接, 循环到 EAGAIN).
 * destroy 统一 post 延迟释放 → 回调内 destroy 后对象存活, 回调返回后
 * 的 destroyed 检查安全 (回调内 destroy 后退出本轮, 不再分发). */
static void on_accept_ready(void *data) {
    struct tcp_acceptor *a = (struct tcp_acceptor *)data;
    ACC_LOCK(a);
    if(a->destroyed) {
        ACC_UNLOCK(a);
        return;
    }
    for(;;) {
        int fd = accept(a->fd, NULL, NULL);
        if(fd < 0)
            break; /* EAGAIN/ECONNABORTED 等均退出本轮 */
        a->on_accept(a->user_data, fd);
        if(a->destroyed)
            break; /* 回调内 destroy: 退出本轮 */
    }
    ACC_UNLOCK(a);
}

/* 摘事件 + 关监听 fd (不通知) */
static void acc_close_io(struct tcp_acceptor *a) {
    if(a->io_handle) {
        sevent_io_unregister(a->ev, a->io_handle);
        a->io_handle = NULL;
    }
    if(a->fd >= 0) {
        close(a->fd);
        a->fd = SEVENT_INVALID_SOCKET;
    }
    a->port = -1;
}

/* ===== 公开 API ===== */

sevent_tcp_acceptor *sevent_tcp_acceptor_create(sevent_context *ev) {
    if(!ev)
        return NULL;
    struct tcp_acceptor *a = (struct tcp_acceptor *)sevent_i_calloc(1, sizeof(*a));
    if(!a)
        return NULL;
#ifdef SEVENT_THREAD_SAFE
    if(sevent_mutex_init_recursive(&a->lock) != 0) {
        sevent_i_free(a);
        return NULL;
    }
#endif
    a->ev   = ev;
    a->fd   = SEVENT_INVALID_SOCKET;
    a->port = -1;
    return (sevent_tcp_acceptor *)a;
}

int sevent_tcp_acceptor_listen(sevent_tcp_acceptor *a,
                               const char          *bind_addr,
                               uint16_t             port,
                               int                  backlog,
                               sevent_tcp_accept_fn on_accept,
                               void                *user_data) {
    struct tcp_acceptor *acc = (struct tcp_acceptor *)a;
    if(!acc || !on_accept || acc->fd >= 0)
        return SEVENT_ERR_INVAL; /* 参数/状态非法 (已在监听) */
    if(backlog <= 0)
        backlog = SEVENT_ACCEPTOR_BACKLOG;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if(fd < 0)
        return SEVENT_ERR_LISTEN;
    /* 服务端 bind: SO_REUSEADDR 允许 TIME_WAIT 端口复用 (客户端无需, 见 tcp_conn.c) */
    int on = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    /* 监听 fd 必须非阻塞: on_accept_ready 的 accept 循环第二次 accept 无连接时
     * 阻塞 fd 会无限等待 — EAGAIN 返回后退出本轮 */
    int fl = fcntl(fd, F_GETFL);
    if(fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0) {
        close(fd);
        return SEVENT_ERR_LISTEN;
    }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    if(bind_addr && inet_pton(AF_INET, bind_addr, &addr.sin_addr) <= 0) {
        close(fd);
        return SEVENT_ERR_INVAL; /* 非法 bind_addr */
    }
    if(bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0 || listen(fd, backlog) < 0) {
        close(fd);
        return SEVENT_ERR_LISTEN; /* 含端口占用 */
    }
    socklen_t al = sizeof(addr);
    if(getsockname(fd, (struct sockaddr *)&addr, &al) < 0) {
        close(fd);
        return SEVENT_ERR_LISTEN;
    }
    acc->fd        = fd;
    acc->port      = ntohs(addr.sin_port);
    acc->on_accept = on_accept;
    acc->user_data = user_data;
    acc->io_handle =
            sevent_io_register(acc->ev, &(sevent_io_handler){.fd = fd, .io_read = on_accept_ready, .data = acc});
    if(!acc->io_handle) {
        acc_close_io(acc);
        return SEVENT_ERR_NOMEM; /* 失败后 fd 已关, 可重新 listen */
    }
    return 0;
}

int sevent_tcp_acceptor_port(sevent_tcp_acceptor *a) {
    struct tcp_acceptor *acc = (struct tcp_acceptor *)a;
    if(!acc)
        return -1;
    return acc->port;
}

void sevent_tcp_acceptor_close(sevent_tcp_acceptor *a) {
    if(!a)
        return;
    struct tcp_acceptor *acc = (struct tcp_acceptor *)a;
    ACC_LOCK(acc);
    acc_close_io(acc);
    ACC_UNLOCK(acc);
}

/* deferred free: run_posts 阶段执行, 保证回调栈安全展开 (与 tcp_conn 同模式) */
static void acc_cleanup(void *data) {
    struct tcp_acceptor *acc = (struct tcp_acceptor *)data;
#ifdef SEVENT_THREAD_SAFE
    sevent_mutex_destroy(&acc->lock);
#endif
    sevent_i_free(acc);
}

void sevent_tcp_acceptor_destroy(sevent_tcp_acceptor *a) {
    if(!a)
        return;
    struct tcp_acceptor *acc = (struct tcp_acceptor *)a;
    /* destroy 不允许幂等 — 调用后对象作废 (与 tcp_conn 同) */
    acc->destroyed           = true; /* 回调重入守卫: 回调栈内 destroy 后不再访问 */
    sevent_tcp_acceptor_close(a);    /* 逻辑关闭, 不释放内存 */
    /* 统一 post 延迟释放 (不判断 is_running, 与 tcp_conn 同): 回调栈内
     * destroy 后回调返回仍需访问对象; 事件循环须继续推进执行 cleanup,
     * sevent_destroy 丢弃未执行的 post — 销毁 ev 前须推进循环. */
    if(sevent_post(acc->ev, acc_cleanup, acc) != SEVENT_SUCCESS)
        acc_cleanup(acc); /* OOM: 立即释放 (极端情况) */
}
