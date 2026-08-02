/* =========================================================================
 *  tcp_conn.c — TCP 传输实现 (公开层 sevent_tcp_conn + stream_conn 适配)
 *
 *  纯回调推送模型 (与 sevent_ws 同风格):
 *   - IO 骨架 (recv_buf 游标/写队列 flush/update_io/connect SO_ERROR 检查/
 *     deferred free/destroyed 守卫) 从 ws_conn.c 拷贝, 删除 WebSocket 协议
 *     部分 (握手/帧解析/Close/PING/deflate/UTF-8/重定向) 所得
 *   - 数据经 on_data 推送 (本层持有 recv_buf), 不提供 read API
 *   - write 返回"已接受": 数据拷贝进写队列, 异步自动 flush
 *   - 生命周期通知: on_open / on_data / on_close (EOF) / on_error (错误),
 *     主动 close 不触发 on_close; 收尾后状态回 IDLE 可重开
 *   - stream_conn 适配: 组合模型 (has-a) — stream 壳持有 struct tcp_conn,
 *     ops 函数经 impl 强转调用公开 API (本文件不持有 stream 内部布局)
 *  ========================================================================= */

#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "sevent_i.h"
#include "sevent_stream_conn.h"
#include "sevent_stream_conn_i.h"
#include "sevent_tcp_conn.h"

#ifdef SEVENT_THREAD_SAFE
#include "sevent_platform.h"
/* 跨线程锁 (递归, 与 ws_conn 同约定): write/close/destroy 与 loop 线程 IO
 * 回调并发 — 回调与公开 API 均持锁; 用户回调在持锁状态下调用 (递归锁,
 * 回调内调 write/close/destroy 安全, 与 ws_conn 的 on_message 同模式) */
#define TCP_LOCK(t)                                                                                                    \
    do {                                                                                                               \
        if((t))                                                                                                        \
            sevent_mutex_lock(&(t)->lock);                                                                             \
    } while(0)
#define TCP_UNLOCK(t)                                                                                                  \
    do {                                                                                                               \
        if((t))                                                                                                        \
            sevent_mutex_unlock(&(t)->lock);                                                                           \
    } while(0)
#else
#define TCP_LOCK(t) ((void)0)
#define TCP_UNLOCK(t) ((void)0)
#endif

/* 接收缓冲大小 (on_data 单次推送上限, 与 ws_conn recv_buf 同规格) */
#define SEVENT_TCP_RECV_DEFAULT 4096
/* 连接超时默认 10 秒 (与 ws 层默认一致) */
#define SEVENT_TCP_CONNECT_TIMEOUT_MS 10000
/* SEVENT_INVALID_SOCKET 公共定义见 sevent_stream_conn.h */

/* ---- 状态机 (与 ws_conn 的 ws_state 同级别) ---- */
typedef enum tcp_state {
    TCP_STATE_IDLE = 0, /* 可 open/accept */
    TCP_STATE_OPENING,  /* 建连中 (open 等 SO_ERROR / accept 等首次就绪) */
    TCP_STATE_OPEN,     /* 已建立, 可 write */
} tcp_state;

/* 内部实现结构 (公开层句柄 = 本结构指针) */
struct tcp_conn {
    sevent_context *ev;

    /* ---- socket ---- */
    int        fd;
    sevent_io *io_handle;

    /* ---- 状态 ---- */
    tcp_state state;
    bool      destroyed; /* 回调重入守卫: on_close/on_error 中 destroy 后不再访问 */
#ifdef SEVENT_THREAD_SAFE
    sevent_mutex_t lock; /* 跨线程锁 (递归) */
#endif

    /* ---- 用户回调 (open/accept 时传入, 每轮建立重置) ---- */
    void                  *user_data;
    sevent_stream_open_fn  on_open;
    sevent_stream_data_fn  on_data;
    sevent_stream_close_fn on_close;
    sevent_stream_error_fn on_error;

    /* ---- 连接超时 (0=默认, <0=禁用) ---- */
    int           connect_timeout_ms;
    sevent_timer *connect_timer;

    /* ---- 接收缓冲 (固定大小, on_data 推送即消费) ---- */
    uint8_t *recv_buf;
    size_t   recv_cap;
    size_t   recv_len;
    size_t   recv_pos;

    /* ---- 写队列 (FIFO; 数据入队即拷贝, 调用方 buffer 可随即复用) ---- */
    struct tcp_write_node *write_head;
    struct tcp_write_node *write_tail;
    size_t                 write_count;
};

struct tcp_write_node {
    struct tcp_write_node *next;
    uint8_t               *data;   /* 待发数据 (已拷贝) */
    size_t                 len;    /* 总长度 */
    size_t                 offset; /* 已写入偏移 */
};

/* ---- 前向声明 ---- */
static void on_write_ready(void *data);
static void on_readable(void *data);
static void on_connect_ready(void *data);
static void on_connect_timeout(void *data);
static void on_first_ready(void *data);
static bool tcp_update_io(struct tcp_conn *t);
static void tcp_close_io(struct tcp_conn *t);
static void tcp_queue_clear(struct tcp_conn *t);

/* ---- 内部辅助 ---- */

/* 收尾: 摘事件 + 关 fd + 清队列 + 状态回 IDLE → 通知.
 * err=0 → on_close (EOF 语义); err!=0 → on_error(err).
 * 主动 close 用 tcp_close_io (不通知). 回调后不再访问 t (用户可能 destroy). */
static void tcp_teardown(struct tcp_conn *t, int err) {
    if(t->destroyed || t->state == TCP_STATE_IDLE)
        return; /* 已收尾 (close/EOF/error 竞争), 不重复通知 */
    if(t->connect_timer) {
        sevent_timer_unregister(t->ev, t->connect_timer);
        t->connect_timer = NULL;
    }
    tcp_close_io(t);
    tcp_queue_clear(t);
    t->state = TCP_STATE_IDLE;
    if(err) {
        if(t->on_error)
            t->on_error(t->user_data, err);
    } else {
        if(t->on_close)
            t->on_close(t->user_data);
    }
}

/* 摘事件 + 关 fd (不通知, 状态不变) */
static void tcp_close_io(struct tcp_conn *t) {
    if(t->io_handle) {
        sevent_io_unregister(t->ev, t->io_handle);
        t->io_handle = NULL;
    }
    if(t->fd >= 0) {
        close(t->fd);
        t->fd = SEVENT_INVALID_SOCKET;
    }
}

/* 清空写队列 (释放所有节点) */
static void tcp_queue_clear(struct tcp_conn *t) {
    struct tcp_write_node *wn = t->write_head;
    while(wn) {
        struct tcp_write_node *n = wn->next;
        sevent_i_free(wn->data);
        sevent_i_free(wn);
        wn = n;
    }
    t->write_head  = NULL;
    t->write_tail  = NULL;
    t->write_count = 0;
}

/* 重新注册 IO: 读回调固定 on_readable, 写回调按队列非空 (从 ws_update_io 删改) */
static bool tcp_update_io(struct tcp_conn *t) {
    sevent_io_handler h;
    h.fd       = t->fd;
    h.io_read  = on_readable;
    h.io_write = t->write_head ? on_write_ready : NULL;
    h.data     = t;
    if(t->io_handle)
        sevent_io_unregister(t->ev, t->io_handle);
    t->io_handle = sevent_io_register(t->ev, &h);
    if(!t->io_handle) {
        tcp_teardown(t, 0); /* 注册失败 (资源耗尽): 对端风格收尾 */
        return false;
    }
    return true;
}

/* 入队 (数据已拷贝, 所有权移交; FIFO) */
static int tcp_enqueue(struct tcp_conn *t, uint8_t *data, size_t len) {
    struct tcp_write_node *n = (struct tcp_write_node *)sevent_i_malloc(sizeof(*n));
    if(!n)
        return -1;
    n->data   = data;
    n->len    = len;
    n->offset = 0;
    n->next   = NULL;
    if(t->write_tail)
        t->write_tail->next = n;
    else
        t->write_head = n;
    t->write_tail = n;
    t->write_count++;
    return 0;
}

/* 尝试写队列中的数据; 返回 0=写完, >0=剩余节点数, <0=致命写错误 (从 ws_flush 删改).
 * send(MSG_NOSIGNAL): 对端关闭后写触发 EPIPE 时不得发 SIGPIPE 杀进程
 * (库 API 的错误经 on_error 通知; ws_conn 的 write 同病, 接入 stream 时清理). */
static int tcp_flush(struct tcp_conn *t) {
    while(t->write_head) {
        struct tcp_write_node *n = t->write_head;
#ifdef MSG_NOSIGNAL
        ssize_t w = send(t->fd, n->data + n->offset, n->len - n->offset, MSG_NOSIGNAL);
#else
        ssize_t w = write(t->fd, n->data + n->offset, n->len - n->offset);
#endif
        if(w > 0) {
            n->offset += (size_t)w;
            if(n->offset < n->len)
                return (int)t->write_count; /* 部分写入, 停止本轮 flush */
            /* 节点写完, 释放 */
            t->write_head = n->next;
            if(!t->write_head)
                t->write_tail = NULL;
            t->write_count--;
            sevent_i_free(n->data);
            sevent_i_free(n);
        } else if(w < 0) {
            if(errno == EAGAIN || errno == EINTR)
                return (int)t->write_count;
            /* 致命写错误 — 清理当前节点, 返回 -1 由调用者 teardown */
            t->write_head = n->next;
            if(!t->write_head)
                t->write_tail = NULL;
            t->write_count--;
            sevent_i_free(n->data);
            sevent_i_free(n);
            return -1;
        } else {
            /* write 返回 0 (不可能在 TCP 上发生) */
            t->write_head = n->next;
            if(!t->write_head)
                t->write_tail = NULL;
            t->write_count--;
            sevent_i_free(n->data);
            sevent_i_free(n);
        }
    }
    return 0;
}

/* ---- 连接建立 ---- */

/* 非阻塞 connect, EINPROGRESS 容忍 (从 ws_tcp_connect 删改).
 * 注: ws 版带 SO_REUSEADDR (对 bind 才有意义) — 客户端不 bind, 已删.
 * 注: 传输层不解析域名 (DNS 是应用层工作) — host 必须是 IP 字面量
 *     (IPv4; 域名解析由调用方经 sevent_dns_resolve 或自有 DNS 完成). */
static int tcp_socket_connect(const char *host, uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if(fd < 0)
        return -1;
    int fl = fcntl(fd, F_GETFL);
    if(fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0) {
        close(fd);
        return -1;
    }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    if(inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
        close(fd);
        return -1;
    }
    int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if(rc < 0 && errno != EINPROGRESS) {
        close(fd);
        return -1;
    }
    return fd;
}

/* 为已连接的 fd 注册 connect 完成回调 + 超时定时器 (从 ws_register_connect_io 删改) */
static bool tcp_register_connect_io(struct tcp_conn *t, int fd) {
    t->io_handle = sevent_io_register(t->ev, &(sevent_io_handler){.fd = fd, .io_write = on_connect_ready, .data = t});
    if(!t->io_handle) {
        close(fd);
        return false;
    }
    t->fd    = fd;
    t->state = TCP_STATE_OPENING;
    /* 超时: 0=默认 10s; <0=禁用 (不注册定时器) */
    int t_ms = t->connect_timeout_ms;
    if(t_ms == 0)
        t_ms = SEVENT_TCP_CONNECT_TIMEOUT_MS;
    if(t_ms > 0) {
        t->connect_timer = sevent_timer_register(t->ev, (unsigned int)t_ms, on_connect_timeout, t);
        if(!t->connect_timer) {
            tcp_close_io(t);
            t->state = TCP_STATE_IDLE; /* 失败后回 IDLE, 对象可重开 */
            return false;
        }
    }
    return true;
}

/* 写就绪: 检查连接结果 (SO_ERROR) — 从 ws_conn on_connect_ready 删改 (去掉握手段) */
static void on_connect_ready(void *data) {
    struct tcp_conn *t = (struct tcp_conn *)data;
    TCP_LOCK(t);
    if(t->destroyed || t->state != TCP_STATE_OPENING) {
        TCP_UNLOCK(t);
        return; /* 已被 close/超时收尾 */
    }
    if(t->connect_timer) {
        sevent_timer_unregister(t->ev, t->connect_timer);
        t->connect_timer = NULL;
    }
    int       err = 0;
    socklen_t el  = sizeof(err);
    if(getsockopt(t->fd, SOL_SOCKET, SO_ERROR, &err, &el) != 0 || err != 0) {
        tcp_teardown(t, SEVENT_ERR_CONNECT);
        TCP_UNLOCK(t);
        return;
    }
    t->state = TCP_STATE_OPEN;
    /* 先换回调再 on_open: on_open 里可能 destroy, 之后不得访问 t */
    if(!tcp_update_io(t)) {
        TCP_UNLOCK(t);
        return;
    }
    t->on_open(t->user_data);
    TCP_UNLOCK(t);
}

/* 连接超时 (从 ws_conn on_connect_timeout 删改) */
static void on_connect_timeout(void *data) {
    struct tcp_conn *t = (struct tcp_conn *)data;
    TCP_LOCK(t);
    if(t->destroyed || t->state != TCP_STATE_OPENING) {
        TCP_UNLOCK(t);
        return;
    }
    /* 先摘定时器再 teardown, 防止 teardown 内回调 destroy 后定时器悬空 */
    sevent_timer *timer = t->connect_timer;
    t->connect_timer    = NULL;
    if(timer)
        sevent_timer_unregister(t->ev, timer);
    tcp_teardown(t, SEVENT_ERR_CONNECT);
    TCP_UNLOCK(t);
}

/* 服务端: 首次就绪 (读或写) 触发 on_open — 写就绪保证立即触发, 不依赖对端发数据 */
static void on_first_ready(void *data) {
    struct tcp_conn *t = (struct tcp_conn *)data;
    TCP_LOCK(t);
    if(t->destroyed || t->state != TCP_STATE_OPENING) {
        TCP_UNLOCK(t);
        return;
    }
    t->state = TCP_STATE_OPEN;
    if(!tcp_update_io(t)) {
        TCP_UNLOCK(t);
        return;
    }
    t->on_open(t->user_data);
    TCP_UNLOCK(t);
}

/* ---- IO 回调: on_readable (读就绪, 驱动接收) ---- */

/* 读进 recv_buf (compact + read, 从 ws_conn recv_read 原样搬移).
 * 本层 on_data 推送即消费 (推送后 recv_pos==recv_len), 每轮 compact 后
 * space 必 > 0 — space==0 保护与 ws 对齐, 防御未来推送逻辑变化. */
static int recv_read(struct tcp_conn *t) {
    /* 先 compact: 搬移未消费数据到头部 */
    if(t->recv_pos > 0) {
        size_t rem = t->recv_len - t->recv_pos;
        if(rem > 0)
            memmove(t->recv_buf, t->recv_buf + t->recv_pos, rem);
        t->recv_len = rem;
        t->recv_pos = 0;
    }
    size_t space = t->recv_cap - t->recv_len;
    if(space == 0)
        return 0;
    ssize_t n = read(t->fd, t->recv_buf + t->recv_len, space);
    if(n > 0)
        t->recv_len += (size_t)n;
    return (int)n;
}

static void on_readable(void *data) {
    struct tcp_conn *t = (struct tcp_conn *)data;
    TCP_LOCK(t);
    if(t->destroyed) {
        TCP_UNLOCK(t);
        return;
    }
    int n = recv_read(t);
    if(n == 0) {
        /* EOF: 对端关闭 — 收尾后 on_close */
        tcp_teardown(t, 0);
        TCP_UNLOCK(t);
        return;
    }
    if(n < 0 && errno != EAGAIN && errno != EINTR) {
        tcp_teardown(t, SEVENT_ERR_READ);
        TCP_UNLOCK(t);
        return;
    }
    if(n < 0) {
        TCP_UNLOCK(t);
        return; /* EAGAIN: 等下一次就绪 */
    }
    /* 推送: 上轮 compact 已保证 pos==0, 推送即消费 (下轮 recv_read compact) */
    t->recv_pos = t->recv_len;
    t->on_data(t->user_data, t->recv_buf, t->recv_len);
    /* on_data 中可能 close/destroy — 之后不再访问 t (锁在 cleanup 前释放) */
    TCP_UNLOCK(t);
}

/* ---- IO 回调: on_write_ready (可写, 驱动写队列) ---- */

static void on_write_ready(void *data) {
    struct tcp_conn *t = (struct tcp_conn *)data;
    TCP_LOCK(t);
    if(t->destroyed || t->state != TCP_STATE_OPEN) {
        TCP_UNLOCK(t);
        return; /* 已收尾 */
    }
    if(tcp_flush(t) < 0) {
        tcp_teardown(t, SEVENT_ERR_WRITE);
        TCP_UNLOCK(t);
        return;
    }
    if(!t->write_head)
        tcp_update_io(t); /* 队列空 → 撤写兴趣 (保持可读) */
    TCP_UNLOCK(t);
}

/* ===== 公开 API (核心实现) ===== */

sevent_tcp_conn *sevent_tcp_conn_create(sevent_context *ev) {
    if(!ev)
        return NULL;
    struct tcp_conn *t = (struct tcp_conn *)sevent_i_calloc(1, sizeof(*t));
    if(!t)
        return NULL;
#ifdef SEVENT_THREAD_SAFE
    if(sevent_mutex_init_recursive(&t->lock) != 0) {
        sevent_i_free(t);
        return NULL;
    }
#endif
    t->ev = ev;
    t->fd = SEVENT_INVALID_SOCKET;
    return (sevent_tcp_conn *)t;
}

/* 按 init.recv_buf_size 分配接收缓冲 (0=默认; 重开时尺寸变化则重建) */
static int tcp_setup_recv(struct tcp_conn *t, size_t recv_buf_size) {
    size_t cap = recv_buf_size ? recv_buf_size : SEVENT_TCP_RECV_DEFAULT;
    if(t->recv_buf && t->recv_cap == cap)
        return 0; /* 复用 (重开且尺寸未变) */
    if(t->recv_buf) {
        sevent_i_free(t->recv_buf);
        t->recv_buf = NULL;
    }
    t->recv_cap = cap;
    t->recv_buf = (uint8_t *)sevent_i_malloc(cap);
    return t->recv_buf ? 0 : -1;
}

int sevent_tcp_conn_open(sevent_tcp_conn *c, const char *host, uint16_t port, const sevent_stream_conn_init *init) {
    struct tcp_conn *t = (struct tcp_conn *)c;
    if(!host || !init || !init->on_open || !init->on_data || t->state != TCP_STATE_IDLE)
        return SEVENT_ERR_INVAL;
    if(tcp_setup_recv(t, init->recv_buf_size) != 0)
        return SEVENT_ERR_NOMEM;
    int fd = tcp_socket_connect(host, port);
    if(fd < 0)
        return SEVENT_ERR_CONNECT;
    t->on_open            = init->on_open;
    t->on_data            = init->on_data;
    t->on_close           = init->on_close;
    t->on_error           = init->on_error;
    t->user_data          = init->user_data;
    t->connect_timeout_ms = init->connect_timeout_ms;
    if(!tcp_register_connect_io(t, fd))
        return SEVENT_ERR_NOMEM; /* register 失败已关 fd */
    return 0;
}

int sevent_tcp_conn_accept(sevent_tcp_conn *c, int fd, const sevent_stream_conn_init *init) {
    struct tcp_conn *t = (struct tcp_conn *)c;
    if(fd < 0 || !init || !init->on_open || !init->on_data || t->state != TCP_STATE_IDLE)
        return SEVENT_ERR_INVAL;
    int fl = fcntl(fd, F_GETFL);
    if(fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0) {
        close(fd); /* accept 失败 = fd 已由本层关闭 (所有权无条件移交) */
        return SEVENT_ERR_INVAL;
    }
    if(tcp_setup_recv(t, init->recv_buf_size) != 0) {
        close(fd);
        return SEVENT_ERR_NOMEM;
    }
    t->on_open            = init->on_open;
    t->on_data            = init->on_data;
    t->on_close           = init->on_close;
    t->on_error           = init->on_error;
    t->user_data          = init->user_data;
    t->connect_timeout_ms = init->connect_timeout_ms;
    /* 读+写都指向 on_first_ready: 写就绪保证 on_open 立即触发 (TCP 无握手);
     * on_open 前 write 返回 INVAL (state==OPENING) — 语义与 open 一致 */
    t->state              = TCP_STATE_OPENING;
    t->fd                 = fd;
    t->io_handle          = sevent_io_register(
            t->ev, &(sevent_io_handler){.fd = fd, .io_read = on_first_ready, .io_write = on_first_ready, .data = t});
    if(!t->io_handle) {
        tcp_close_io(t);
        t->state = TCP_STATE_IDLE; /* 失败后回 IDLE (fd 已由本层关闭) */
        return SEVENT_ERR_NOMEM;
    }
    return 0;
}

int sevent_tcp_conn_write(sevent_tcp_conn *c, const void *data, size_t len) {
    struct tcp_conn *t = (struct tcp_conn *)c;
    TCP_LOCK(t);
    if(!data && len) {
        TCP_UNLOCK(t);
        return SEVENT_ERR_INVAL;
    }
    if(t->destroyed || t->state != TCP_STATE_OPEN) {
        TCP_UNLOCK(t);
        return SEVENT_ERR_INVAL; /* 未 OPEN (on_open 前) 或已收尾 */
    }
    if(len == 0) {
        TCP_UNLOCK(t);
        return 0;
    }
    uint8_t *buf = (uint8_t *)sevent_i_malloc(len);
    if(!buf) {
        TCP_UNLOCK(t);
        return SEVENT_ERR_NOMEM;
    }
    memcpy(buf, data, len);
    if(tcp_enqueue(t, buf, len) != 0) {
        sevent_i_free(buf);
        TCP_UNLOCK(t);
        return SEVENT_ERR_NOMEM;
    }
    if(tcp_flush(t) < 0) {
        tcp_teardown(t, SEVENT_ERR_WRITE);
        TCP_UNLOCK(t);
        return SEVENT_ERR_WRITE;
    }
    if(t->write_head)
        tcp_update_io(t); /* 有积压 → 注册写兴趣; 队列空 → io 已是 (on_readable, NULL) */
    TCP_UNLOCK(t);
    return 0;
}

void sevent_tcp_conn_close(sevent_tcp_conn *c) {
    if(!c)
        return;
    struct tcp_conn *t = (struct tcp_conn *)c;
    TCP_LOCK(t);
    if(t->connect_timer) {
        sevent_timer_unregister(t->ev, t->connect_timer);
        t->connect_timer = NULL;
    }
    tcp_close_io(t);
    tcp_queue_clear(t);
    t->state = TCP_STATE_IDLE; /* 可重新 open/accept; 幂等 */
    TCP_UNLOCK(t);
}

/* deferred free: run_posts 阶段执行, 保证回调栈安全展开 (与 ws_cleanup_conn 同模式) */
static void tcp_cleanup(void *data) {
    struct tcp_conn *t = (struct tcp_conn *)data;
    tcp_queue_clear(t);
#ifdef SEVENT_THREAD_SAFE
    sevent_mutex_destroy(&t->lock);
#endif
    sevent_i_free(t->recv_buf);
    sevent_i_free(t);
}

void sevent_tcp_conn_destroy(sevent_tcp_conn *c) {
    if(!c)
        return;
    struct tcp_conn *t = (struct tcp_conn *)c;
    /* 注意: destroy 不允许幂等 — 调用后对象作废, 再使用 (含再次 destroy)
     * 是编程错误, 未定义行为. 不做任何防护. */
    t->destroyed       = true; /* 回调重入守卫: 回调栈内 destroy 后不再访问 */
    sevent_tcp_conn_close(c);  /* 逻辑关闭, 不释放内存 */
    /* 统一 post 延迟释放 (不判断 is_running): 回调栈内 destroy 后, 库的回调
     * 代码仍要访问对象 (解锁等), 立即释放会造成 UAF — run_once 手动驱动
     * 模式同样延迟. 前提: 事件循环继续推进 (run_posts 执行 cleanup);
     * sevent_destroy 丢弃未执行的 post (不执行回调), 调用方须在销毁 ev
     * 前推进循环, 否则对象泄漏. */
    if(sevent_post(t->ev, tcp_cleanup, t) != SEVENT_SUCCESS)
        tcp_cleanup(t); /* OOM: 立即释放 (极端情况, 与 ws 层同) */
}

/* ===== stream_conn 适配层 (ws 模块经 sevent_stream_* 使用) ===== */

/* 组合模型: stream 壳 (sevent_stream_conn) 持有 struct tcp_conn (s->impl),
 * ops 函数经 impl 强转调用公开 API; 回调类型/init 结构体与 stream 层共用,
 * 无需转换. */

static int tcp_open(sevent_stream_conn *s, const char *host, uint16_t port, const sevent_stream_conn_init *init) {
    return sevent_tcp_conn_open((sevent_tcp_conn *)s->impl, host, port, init);
}

static int tcp_accept(sevent_stream_conn *s, int fd, const sevent_stream_conn_init *init) {
    return sevent_tcp_conn_accept((sevent_tcp_conn *)s->impl, fd, init);
}

static int tcp_write(sevent_stream_conn *s, const void *data, size_t len) {
    return sevent_tcp_conn_write((sevent_tcp_conn *)s->impl, data, len);
}

static void tcp_close(sevent_stream_conn *s) { sevent_tcp_conn_close((sevent_tcp_conn *)s->impl); }

static void tcp_destroy(sevent_stream_conn *s) {
    sevent_tcp_conn_destroy((sevent_tcp_conn *)s->impl);
    sevent_i_free(s); /* 壳立即释放: destroy 后对象作废, 不再访问 s */
}

static const sevent_stream_ops tcp_ops = {
        .open    = tcp_open,
        .accept  = tcp_accept,
        .write   = tcp_write,
        .close   = tcp_close,
        .destroy = tcp_destroy,
};

/* 供 stream_conn.c 工厂分发: 创建 TCP 实现 + 包壳挂接 ops */
sevent_stream_conn *tcp_stream_create(sevent_context *ev) {
    struct tcp_conn *t = (struct tcp_conn *)sevent_tcp_conn_create(ev);
    if(!t)
        return NULL;
    sevent_stream_conn *s = (sevent_stream_conn *)sevent_i_malloc(sizeof(*s));
    if(!s) {
        sevent_tcp_conn_destroy((sevent_tcp_conn *)t);
        return NULL;
    }
    s->ops  = &tcp_ops;
    s->impl = t;
    return s;
}
