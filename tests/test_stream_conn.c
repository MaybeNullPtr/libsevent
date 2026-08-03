/* stream_conn 传输层单测 (tcp; SEVENT_WS_TLS 下扩展 TLS 用例)
 *
 * 纯回调推送模型 (与 sevent_ws 同风格):
 *  - 内嵌 mini echo server (listen + sevent_stream_accept 服务端入口)
 *  - 客户端 sevent_stream_open 连接, 验证接口契约:
 *    - open/accept 异步建连回调 (on_open 由事件循环触发)
 *    - 数据经 on_data 推送 (不提供 read API)
 *    - write 返回"已接受", 写队列自动 flush (1MB 大消息验证部分写/续写)
 *    - EOF → on_close (on_close 覆盖 EOF), 之后状态回 IDLE 可重开
 *    - 主动 close 不触发 on_close
 *    - close 后重开 / 非法调用返回 INVAL / 回调内 destroy 安全
 */
#include "sevent.h"
#include "sevent_stream_conn.h"
#include "sevent_tcp_conn.h"
#include "sevent_tcp_acceptor.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h> /* inet_pton */
#include <time.h>      /* nanosleep */

/* ---- 全局状态 ---- */
static int    g_ev_open;
static int    g_ev_data;
static int    g_ev_close;
static int    g_ev_close_count; /* 主动 close 不触发 on_close 断言用 */
static int    g_ev_error;
static int    g_ev_error_code;
static int    g_accept_open;          /* accept 后 on_open 是否已触发 */
static int    g_srv_close_after_recv; /* server 收到数据后立即关闭 (EOF 用例) */
static int    g_cli_close_on_data;    /* client 收到数据后主动 close (不触发 on_close) */
static char   g_recv[512];
static size_t g_rlen;

/* ---- 内嵌 echo server (acceptor 封装 listen + 分发) ---- */
static sevent_context      *g_ev;
static sevent_tcp_acceptor *g_acc;
static void                 srv_on_data(void *d, const uint8_t *data, size_t len);
static void                 cli_on_data(void *d, const uint8_t *data, size_t len); /* 前向声明 */

static void srv_on_open(void *d) {
    (void)d;
    g_accept_open = 1;
}
static void srv_on_data(void *d, const uint8_t *data, size_t len) {
    if(g_srv_close_after_recv) {
        sevent_stream_close(d); /* EOF 用例: 不回显直接关闭 */
        return;
    }
    (void)sevent_stream_write(d, data, len); /* 回显 (write 已拷贝, buffer 可随即复用) */
}
/* server 连接登记: 用例结束时统一销毁 (回调内销毁的置 NULL, 防双销毁) */
static sevent_stream_conn *g_srv_conns[64];
static int                 g_srv_conn_count;

static void srv_conn_drop(sevent_stream_conn *s) {
    for(int i = 0; i < g_srv_conn_count; i++) {
        if(g_srv_conns[i] == s) {
            g_srv_conns[i] = NULL;
            break;
        }
    }
    sevent_stream_destroy(s);
}
static void srv_on_close(void *d) { srv_conn_drop((sevent_stream_conn *)d); /* 对端关闭, 连接收尾 */ }
static void srv_on_error(void *d, int err) {
    (void)err;
    srv_conn_drop((sevent_stream_conn *)d);
}
/* acceptor 分发: fd 已 accept, 包装成 stream_conn 连接 */
static void on_accept(void *d, int fd) {
    (void)d;
    sevent_stream_conn_config cfg = {0};
    sevent_stream_conn       *s   = sevent_stream_create(g_ev, &cfg);
    if(!s) {
        close(fd);
        return;
    }
    if(g_srv_conn_count < (int)(sizeof(g_srv_conns) / sizeof(g_srv_conns[0])))
        g_srv_conns[g_srv_conn_count++] = s;
    sevent_stream_conn_init cb = {.user_data = s,
                                  .on_open   = srv_on_open,
                                  .on_data   = srv_on_data,
                                  .on_close  = srv_on_close,
                                  .on_error  = srv_on_error};
    if(sevent_stream_accept(s, fd, &cb) < 0) {
        /* accept 失败: fd 归还调用方 */
        sevent_stream_destroy(s);
        close(fd); /* 谁拥有谁关闭 */
    }
}

/* 跑完 pending post: destroy 统一 post 后, 延迟 free 由 run_posts 执行 —
 * sevent_destroy 丢弃未执行的 post (不执行回调), 销毁 ev 前必须推进循环.
 * 用 sevent_get_counts 观测 post_pending_count (替代固定轮数 wakeup) */
static void flush_posts(sevent_context *ev) {
    for(int i = 0; i < 1000; i++) {
        int post_count = -1;
        sevent_get_counts(ev, NULL, NULL, &post_count);
        if(post_count <= 0)
            return;
        sevent_wakeup(ev);
        sevent_run_once(ev); /* run_posts: 执行 post → count 递减 */
    }
}

/* 用例统一收尾: 销毁残余 server 连接 + acceptor → 等延迟 free 执行 → 销毁 ev */
static void finish_case(sevent_context *ev) {
    for(int i = 0; i < g_srv_conn_count; i++) {
        if(g_srv_conns[i])
            sevent_stream_destroy(g_srv_conns[i]);
    }
    g_srv_conn_count = 0;
    sevent_tcp_acceptor_destroy(g_acc);
    g_acc = NULL;
    flush_posts(ev);
    sevent_destroy(ev);
}

/* 启动 echo server (acceptor + 随机端口), 返回实际监听端口 */
static int start_server(sevent_context *ev) {
    g_acc = sevent_tcp_acceptor_create(ev);
    if(!g_acc)
        return -1;
    if(sevent_tcp_acceptor_listen(g_acc, "127.0.0.1", 0, 8, on_accept, NULL) < 0)
        return -1;
    return sevent_tcp_acceptor_port(g_acc);
}

/* ---- 客户端回调 ---- */
static void cli_on_open(void *d) {
    g_ev_open = 1;
    (void)sevent_stream_write(d, "hello", 5);
}
static void cli_on_data(void *d, const uint8_t *data, size_t len) {
    if(g_rlen + len <= sizeof(g_recv)) {
        memcpy(g_recv + g_rlen, data, len);
        g_rlen += len;
    }
    g_ev_data = 1;
    if(g_cli_close_on_data)
        sevent_stream_close(d); /* 主动 close: 不触发 on_close */
}
static void cli_on_close(void *d) {
    g_ev_close = 1;
    g_ev_close_count++;
    (void)d;
}
static void cli_on_error(void *d, int err) {
    (void)d;
    g_ev_error      = 1;
    g_ev_error_code = err;
}

/* ---- 写队列顺序用例 (连续 write, FIFO) ---- */
static void cli_on_open_order(void *d) {
    g_ev_open = 1;
    (void)sevent_stream_write(d, "one", 3);
    (void)sevent_stream_write(d, "two", 3);
    (void)sevent_stream_write(d, "three", 5);
}

/* ---- 大消息用例 (1MB 一次 write: 部分写/写兴趣续写路径) ---- */
static uint8_t *g_big;
static size_t   g_big_len;
static uint8_t *g_big_recv;
static size_t   g_big_rlen;

static void cli_on_open_big(void *d) {
    g_ev_open = 1;
    int rc    = sevent_stream_write(d, g_big, g_big_len);
    if(rc != 0) {
        g_ev_error      = 1;
        g_ev_error_code = rc;
    }
}
static void cli_on_data_big(void *d, const uint8_t *data, size_t len) {
    (void)d;
    memcpy(g_big_recv + g_big_rlen, data, len);
    g_big_rlen += len;
    if(g_big_rlen >= g_big_len)
        g_ev_data = 1; /* 收齐 */
}

/* ---- 回调内 destroy 用例 (post 延迟释放, 回调栈安全) ---- */
static void cli_destroy_on_open(void *d) {
    g_ev_open = 1;
    (void)sevent_tcp_conn_write(d, "hello", 5);
}
static void cli_destroy_on_data(void *d, const uint8_t *data, size_t len) {
    (void)data;
    (void)len;
    g_ev_data = 1;
    sevent_tcp_conn_destroy(d); /* 回调内 destroy: free 推迟到 run_posts */
}
static int t_tcp_destroy_in_callback(void) {
    sevent_context *ev = sevent_create();
    if(!ev)
        return 1;
    g_ev                   = ev;
    g_srv_close_after_recv = 0;
    g_cli_close_on_data    = 0;
    int port               = start_server(ev);
    if(port < 0)
        return 1;
    g_ev_open = g_ev_data = g_ev_error = 0;
    sevent_tcp_conn *c                 = sevent_tcp_conn_create(ev);
    if(!c)
        return 1;
    sevent_stream_conn_init cb = {
            .user_data = c,
            .on_open   = cli_destroy_on_open,
            .on_data   = cli_destroy_on_data,
            .on_error  = cli_on_error,
    };
    if(sevent_tcp_conn_open(c, "127.0.0.1", (uint16_t)port, &cb) < 0)
        return 1;
    for(int i = 0; i < 200 && !g_ev_data && !g_ev_error; i++)
        sevent_run_once(ev);
    int ok = g_ev_data; /* 收到数据 + 回调内 destroy 未崩溃 */
    finish_case(ev);
    return ok ? 0 : 1;
}

/* ---- tcp 公开 API 用例 (直接使用 sevent_tcp_conn_*, 不经 stream 抽象) ---- */
static void tcp_api_on_open(void *d) {
    g_ev_open = 1;
    (void)sevent_tcp_conn_write(d, "hello", 5);
}
static void tcp_api_on_data(void *d, const uint8_t *data, size_t len) {
    if(g_rlen + len <= sizeof(g_recv)) {
        memcpy(g_recv + g_rlen, data, len);
        g_rlen += len;
    }
    g_ev_data = 1;
}
static int t_tcp_api_echo(void) {
    /* sevent_tcp_conn_* 完整链路独立可用 (echo 往返) */
    sevent_context *ev = sevent_create();
    if(!ev)
        return 1;
    g_ev                   = ev;
    g_srv_close_after_recv = 0;
    g_cli_close_on_data    = 0;
    int port               = start_server(ev);
    if(port < 0)
        return 1;
    g_ev_open = g_ev_data = g_ev_error = 0;
    g_rlen                             = 0;
    sevent_tcp_conn *c                 = sevent_tcp_conn_create(ev);
    if(!c)
        return 1;
    sevent_stream_conn_init cb = {
            .user_data = c, .on_open = tcp_api_on_open, .on_data = tcp_api_on_data, .on_error = cli_on_error};
    if(sevent_tcp_conn_open(c, "127.0.0.1", (uint16_t)port, &cb) < 0)
        return 1;
    for(int i = 0; i < 200 && !g_ev_data && !g_ev_error; i++)
        sevent_run_once(ev);
    int ok = g_ev_open && g_ev_data && !g_ev_error && g_rlen == 5 && memcmp(g_recv, "hello", 5) == 0;
    sevent_tcp_conn_destroy(c);
    finish_case(ev);
    return ok ? 0 : 1;
}

/* ---- 用例 ---- */

static int t_tcp_echo(void) {
    /* open → on_open → write → server echo → on_data 推送一致 */
    sevent_context *ev = sevent_create();
    if(!ev)
        return 1;
    g_ev                   = ev;
    g_srv_close_after_recv = 0;
    g_cli_close_on_data    = 0;
    int port               = start_server(ev);
    if(port < 0)
        return 1;
    g_ev_open = g_ev_data = g_ev_error = 0;
    g_rlen                             = 0;
    sevent_stream_conn_config cfg      = {0};
    sevent_stream_conn       *s        = sevent_stream_create(ev, &cfg);
    if(!s)
        return 1;
    sevent_stream_conn_init cb = {
            .user_data = s, .on_open = cli_on_open, .on_data = cli_on_data, .on_error = cli_on_error};
    if(sevent_stream_open(s, "127.0.0.1", (uint16_t)port, &cb) < 0)
        return 1;
    for(int i = 0; i < 200 && !g_ev_data && !g_ev_error; i++)
        sevent_run_once(ev);
    int ok = g_ev_open && g_ev_data && !g_ev_error && g_rlen == 5 && memcmp(g_recv, "hello", 5) == 0;
    sevent_stream_destroy(s);
    finish_case(ev);
    return ok ? 0 : 1;
}

static int t_tcp_eof(void) {
    /* server 收到后关闭 → client on_close (EOF, 覆盖 on_eof) */
    sevent_context *ev = sevent_create();
    if(!ev)
        return 1;
    g_ev                   = ev;
    g_srv_close_after_recv = 1;
    g_cli_close_on_data    = 0;
    int port               = start_server(ev);
    if(port < 0)
        return 1;
    g_ev_open = g_ev_data = g_ev_close = g_ev_error = 0;
    g_ev_close_count                                = 0;
    g_rlen                                          = 0;
    sevent_stream_conn_config cfg                   = {0};
    sevent_stream_conn       *s                     = sevent_stream_create(ev, &cfg);
    if(!s)
        return 1;
    sevent_stream_conn_init cb = {.user_data = s,
                                  .on_open   = cli_on_open,
                                  .on_data   = cli_on_data,
                                  .on_close  = cli_on_close,
                                  .on_error  = cli_on_error};
    if(sevent_stream_open(s, "127.0.0.1", (uint16_t)port, &cb) < 0)
        return 1;
    for(int i = 0; i < 200 && !g_ev_close && !g_ev_error; i++)
        sevent_run_once(ev);
    int ok = g_ev_open && g_ev_close && g_ev_close_count == 1 && !g_ev_error;
    sevent_stream_destroy(s);
    finish_case(ev);
    return ok ? 0 : 1;
}

static int t_tcp_close_no_cb(void) {
    /* 主动 close 不触发 on_close (上层自己发起的关闭, 状态已知) */
    sevent_context *ev = sevent_create();
    if(!ev)
        return 1;
    g_ev                   = ev;
    g_srv_close_after_recv = 0;
    g_cli_close_on_data    = 1; /* 收到 echo 后主动 close */
    int port               = start_server(ev);
    if(port < 0)
        return 1;
    g_ev_open = g_ev_data = g_ev_close = g_ev_error = 0;
    g_ev_close_count                                = 0;
    g_rlen                                          = 0;
    sevent_stream_conn_config cfg                   = {0};
    sevent_stream_conn       *s                     = sevent_stream_create(ev, &cfg);
    if(!s)
        return 1;
    sevent_stream_conn_init cb = {.user_data = s,
                                  .on_open   = cli_on_open,
                                  .on_data   = cli_on_data,
                                  .on_close  = cli_on_close,
                                  .on_error  = cli_on_error};
    if(sevent_stream_open(s, "127.0.0.1", (uint16_t)port, &cb) < 0)
        return 1;
    for(int i = 0; i < 200 && !g_ev_data && !g_ev_error; i++)
        sevent_run_once(ev);
    /* close 已在 on_data 内触发; 若 close 误触发 on_close, count 会变化 */
    int ok = g_ev_open && g_ev_data && g_ev_close_count == 0 && !g_ev_error;
    sevent_stream_destroy(s);
    finish_case(ev);
    return ok ? 0 : 1;
}

static int t_tcp_connect_refused(void) {
    /* 连接未监听端口: 立即失败 (open <0) 或异步 on_error(SEVENT_ERR_CONNECT) */
    sevent_context *ev = sevent_create();
    if(!ev)
        return 1;
    g_ev      = ev;
    g_ev_open = g_ev_error        = 0;
    g_ev_error_code               = 0;
    sevent_stream_conn_config cfg = {0};
    sevent_stream_conn       *s   = sevent_stream_create(ev, &cfg);
    if(!s)
        return 1;
    sevent_stream_conn_init cb = {
            .user_data = s, .on_open = cli_on_open, .on_data = cli_on_data, .on_error = cli_on_error};
    int rc = sevent_stream_open(s, "127.0.0.1", 1 /* 未监听 */, &cb);
    if(rc >= 0) {
        /* EINPROGRESS 路径: 等异步失败 (含连接超时定时器驱动) */
        for(int i = 0; i < 100 && !g_ev_error; i++)
            sevent_run_once(ev);
        if(!g_ev_error || g_ev_error_code != SEVENT_ERR_CONNECT) {
            sevent_stream_destroy(s);
            finish_case(ev);
            return 1;
        }
    } else if(rc != SEVENT_ERR_CONNECT) {
        sevent_stream_destroy(s);
        finish_case(ev);
        return 1;
    }
    sevent_stream_destroy(s);
    finish_case(ev);
    return 0;
}

static int t_tcp_reopen(void) {
    /* close 后同一对象重新 open → 再次 echo (重定向复用场景) */
    sevent_context *ev = sevent_create();
    if(!ev)
        return 1;
    g_ev                   = ev;
    g_srv_close_after_recv = 0;
    g_cli_close_on_data    = 0;
    int port               = start_server(ev);
    if(port < 0)
        return 1;
    sevent_stream_conn_config cfg = {0};
    sevent_stream_conn       *s   = sevent_stream_create(ev, &cfg);
    if(!s)
        return 1;
    /* 第一次 */
    g_ev_open = g_ev_data = g_ev_error = 0;
    g_rlen                             = 0;
    sevent_stream_conn_init cb         = {
                    .user_data = s, .on_open = cli_on_open, .on_data = cli_on_data, .on_error = cli_on_error};
    if(sevent_stream_open(s, "127.0.0.1", (uint16_t)port, &cb) < 0)
        return 1;
    for(int i = 0; i < 200 && !g_ev_data && !g_ev_error; i++)
        sevent_run_once(ev);
    if(!g_ev_data || g_rlen != 5 || memcmp(g_recv, "hello", 5) != 0)
        return 1;
    sevent_stream_close(s);
    /* 第二次 (同一对象, recv_buf_size 变化 → 触发接收缓冲重建) */
    g_ev_open = g_ev_data = g_ev_error = 0;
    g_rlen                             = 0;
    cb.recv_buf_size                   = 64;
    if(sevent_stream_open(s, "127.0.0.1", (uint16_t)port, &cb) < 0)
        return 1;
    for(int i = 0; i < 200 && !g_ev_data && !g_ev_error; i++)
        sevent_run_once(ev);
    int ok = g_ev_data && g_rlen == 5 && memcmp(g_recv, "hello", 5) == 0;
    sevent_stream_destroy(s);
    finish_case(ev);
    return ok ? 0 : 1;
}

static int t_tcp_accept_async(void) {
    /* accept 的 on_open 由事件循环触发 (accept 调用栈内不触发) */
    sevent_context *ev = sevent_create();
    if(!ev)
        return 1;
    g_ev                   = ev;
    g_srv_close_after_recv = 0;
    g_cli_close_on_data    = 0;
    int port               = start_server(ev);
    if(port < 0)
        return 1;
    g_accept_open = 0;
    g_ev_open = g_ev_error        = 0;
    sevent_stream_conn_config cfg = {0};
    sevent_stream_conn       *s   = sevent_stream_create(ev, &cfg);
    if(!s)
        return 1;
    sevent_stream_conn_init cb = {
            .user_data = s, .on_open = cli_on_open, .on_data = cli_on_data, .on_error = cli_on_error};
    if(sevent_stream_open(s, "127.0.0.1", (uint16_t)port, &cb) < 0)
        return 1;
    for(int i = 0; i < 50 && !g_accept_open; i++)
        sevent_run_once(ev); /* accept 由事件循环处理, on_open 经 on_first_ready */
    int ok = g_accept_open == 1;
    sevent_stream_destroy(s);
    finish_case(ev);
    return ok ? 0 : 1;
}

static int t_tcp_order(void) {
    /* 连续 write 三次: 写队列 FIFO, server 回显顺序一致 */
    sevent_context *ev = sevent_create();
    if(!ev)
        return 1;
    g_ev                   = ev;
    g_srv_close_after_recv = 0;
    g_cli_close_on_data    = 0;
    int port               = start_server(ev);
    if(port < 0)
        return 1;
    g_ev_open = g_ev_data = g_ev_error = 0;
    g_rlen                             = 0;
    sevent_stream_conn_config cfg      = {0};
    sevent_stream_conn       *s        = sevent_stream_create(ev, &cfg);
    if(!s)
        return 1;
    sevent_stream_conn_init cb = {
            .user_data = s, .on_open = cli_on_open_order, .on_data = cli_on_data, .on_error = cli_on_error};
    if(sevent_stream_open(s, "127.0.0.1", (uint16_t)port, &cb) < 0)
        return 1;
    for(int i = 0; i < 200 && !g_ev_error && g_rlen < 11; i++)
        sevent_run_once(ev);
    int ok = g_ev_open && g_rlen == 11 && memcmp(g_recv, "onetwothree", 11) == 0 && !g_ev_error;
    sevent_stream_destroy(s);
    finish_case(ev);
    return ok ? 0 : 1;
}

static int t_tcp_no_close_cb(void) {
    /* on_close=NULL: EOF 收尾路径不崩溃 (判空), 正常流不受影响 */
    sevent_context *ev = sevent_create();
    if(!ev)
        return 1;
    g_ev                   = ev;
    g_srv_close_after_recv = 1; /* server 收到后关闭 → client EOF */
    g_cli_close_on_data    = 0;
    int port               = start_server(ev);
    if(port < 0)
        return 1;
    g_ev_open = g_ev_data = g_ev_error = 0;
    g_rlen                             = 0;
    sevent_stream_conn_config cfg      = {0};
    sevent_stream_conn       *s        = sevent_stream_create(ev, &cfg);
    if(!s)
        return 1;
    sevent_stream_conn_init cb = {.user_data = s,
                                  .on_open   = cli_on_open,
                                  .on_data   = cli_on_data,
                                  .on_error  = cli_on_error /* on_close=NULL */};
    if(sevent_stream_open(s, "127.0.0.1", (uint16_t)port, &cb) < 0)
        return 1;
    /* EOF 收尾无崩溃即通过: 对端不回显 (无 on_data 事件), EOF 处理完无定时器 —
     * select 会无限阻塞, 用 wakeup 驱动固定轮次推进
     * connect→数据→server close→client EOF 全流程 */
    for(int i = 0; i < 200; i++) {
        sevent_wakeup(ev);
        sevent_run_once(ev);
    }
    int ok = g_ev_open && !g_ev_error; /* EOF 路径 (on_close=NULL) 无崩溃 */
    sevent_stream_destroy(s);
    finish_case(ev);
    return ok ? 0 : 1;
}

static int t_tcp_no_error_cb(void) {
    /* on_error=NULL: 建立失败路径不崩溃 (判空), 正常流不受影响 */
    sevent_context *ev = sevent_create();
    if(!ev)
        return 1;
    g_ev                   = ev;
    g_srv_close_after_recv = 0;
    g_cli_close_on_data    = 0;
    int port               = start_server(ev);
    if(port < 0)
        return 1;
    g_ev_open = g_ev_data         = 0;
    g_rlen                        = 0;
    sevent_stream_conn_config cfg = {0};
    sevent_stream_conn       *s   = sevent_stream_create(ev, &cfg);
    if(!s)
        return 1;
    sevent_stream_conn_init cb = {.user_data = s, .on_open = cli_on_open, .on_data = cli_on_data /* on_error=NULL */};
    if(sevent_stream_open(s, "127.0.0.1", (uint16_t)port, &cb) < 0)
        return 1;
    for(int i = 0; i < 200 && !g_ev_data; i++)
        sevent_run_once(ev);
    int ok = g_ev_open && g_ev_data && g_rlen == 5 && memcmp(g_recv, "hello", 5) == 0;
    sevent_stream_destroy(s);
    finish_case(ev);
    return ok ? 0 : 1;
}

static int t_tcp_large_echo(void) {
    /* 1MB 一次 write: 部分写/写兴趣续写路径, server 回显收齐验证 */
    sevent_context *ev = sevent_create();
    if(!ev)
        return 1;
    g_ev                   = ev;
    g_srv_close_after_recv = 0;
    g_cli_close_on_data    = 0;
    int port               = start_server(ev);
    if(port < 0)
        return 1;
    g_ev_open = g_ev_data = g_ev_error = 0;
    g_big_len                          = 8 << 20; /* 8MB: 双向部分写 + 写缓冲满 (EAGAIN) */
    g_big_rlen                         = 0;
    g_big                              = (uint8_t *)malloc(g_big_len);
    g_big_recv                         = (uint8_t *)malloc(g_big_len);
    if(!g_big || !g_big_recv) {
        free(g_big);
        free(g_big_recv);
        return 1;
    }
    unsigned int seed = 24680;
    for(size_t i = 0; i < g_big_len; i++) {
        seed     = seed * 1103515245u + 12345u;
        g_big[i] = (uint8_t)(seed >> 24);
    }
    sevent_stream_conn_config cfg = {0};
    sevent_stream_conn       *s   = sevent_stream_create(ev, &cfg);
    if(!s)
        return 1;
    sevent_stream_conn_init cb = {
            .user_data     = s,
            .on_open       = cli_on_open_big,
            .on_data       = cli_on_data_big,
            .on_error      = cli_on_error,
            .recv_buf_size = 1024, /* client 慢读 → server 回显写缓冲满 → 部分写/EAGAIN */
    };
    if(sevent_stream_open(s, "127.0.0.1", (uint16_t)port, &cb) < 0)
        return 1;
    for(int i = 0; i < 200000 && !g_ev_data && !g_ev_error; i++)
        sevent_run_once(ev);
    int ok = g_ev_data && g_big_rlen == g_big_len && memcmp(g_big, g_big_recv, g_big_len) == 0;
    sevent_stream_destroy(s);
    finish_case(ev);
    free(g_big);
    free(g_big_recv);
    return ok ? 0 : 1;
}

static int t_tcp_small_recv_buf(void) {
    /* recv_buf_size=64: on_data 分块推送 (≤64/轮) + compact 路径验证 */
    sevent_context *ev = sevent_create();
    if(!ev)
        return 1;
    g_ev                   = ev;
    g_srv_close_after_recv = 0;
    g_cli_close_on_data    = 0;
    int port               = start_server(ev);
    if(port < 0)
        return 1;
    g_ev_open = g_ev_data = g_ev_error = 0;
    g_big_len                          = 1000;
    g_big_rlen                         = 0;
    g_big                              = (uint8_t *)malloc(g_big_len);
    g_big_recv                         = (uint8_t *)malloc(g_big_len);
    if(!g_big || !g_big_recv) {
        free(g_big);
        free(g_big_recv);
        return 1;
    }
    unsigned int seed = 13579;
    for(size_t i = 0; i < g_big_len; i++) {
        seed     = seed * 1103515245u + 12345u;
        g_big[i] = (uint8_t)(seed >> 24);
    }
    sevent_stream_conn_config cfg = {0};
    sevent_stream_conn       *s   = sevent_stream_create(ev, &cfg);
    if(!s)
        return 1;
    sevent_stream_conn_init cb = {
            .user_data     = s,
            .on_open       = cli_on_open_big,
            .on_data       = cli_on_data_big,
            .on_error      = cli_on_error,
            .recv_buf_size = 64, /* 单次推送上限 64 字节 → 1000 字节分 ~16 轮 */
    };
    if(sevent_stream_open(s, "127.0.0.1", (uint16_t)port, &cb) < 0)
        return 1;
    for(int i = 0; i < 2000 && !g_ev_data && !g_ev_error; i++)
        sevent_run_once(ev);
    int ok = g_ev_data && g_big_rlen == g_big_len && memcmp(g_big, g_big_recv, g_big_len) == 0;
    sevent_stream_destroy(s);
    finish_case(ev);
    free(g_big);
    free(g_big_recv);
    return ok ? 0 : 1;
}

static int t_tcp_connect_timeout(void) {
    /* connect_timeout_ms=100: 连不可达地址 (TEST-NET, RFC 5737) 走 EINPROGRESS,
     * 100ms 超时定时器触发 on_error(SEVENT_ERR_CONNECT) */
    sevent_context *ev = sevent_create();
    if(!ev)
        return 1;
    g_ev      = ev;
    g_ev_open = g_ev_error        = 0;
    g_ev_error_code               = 0;
    sevent_stream_conn_config cfg = {0};
    sevent_stream_conn       *s   = sevent_stream_create(ev, &cfg);
    if(!s)
        return 1;
    sevent_stream_conn_init cb = {.user_data          = s,
                                  .on_open            = cli_on_open,
                                  .on_data            = cli_on_data,
                                  .on_error           = cli_on_error,
                                  .connect_timeout_ms = 100};
    int                     rc = sevent_stream_open(s, "192.0.2.1", 80, &cb);
    if(rc < 0) {
        /* 立即失败路径 (EINPROGRESS 未发生) */
        sevent_stream_destroy(s);
        finish_case(ev);
        return rc == SEVENT_ERR_CONNECT ? 0 : 1;
    }
    /* EINPROGRESS: 100ms 超时定时器在, select 带超时不会阻塞 */
    for(int i = 0; i < 200 && !g_ev_error; i++)
        sevent_run_once(ev);
    int ok = g_ev_error && g_ev_error_code == SEVENT_ERR_CONNECT;
    sevent_stream_destroy(s);
    finish_case(ev);
    return ok ? 0 : 1;
}

/* ---- 写致命错误用例 (对端关闭后写 → EPIPE → on_error(WRITE)) ----
 * raw server: accept 后立即 close(fd) — 等 RST 到达 (usleep) 后再写:
 * RST 后 send 立即 EPIPE (确定性, 不与 EOF 竞争).
 * MSG_NOSIGNAL 保证不 SIGPIPE 杀进程 (库内 send 用 MSG_NOSIGNAL). */
static int  g_srv_closed; /* raw server 已 accept+close */
static void on_accept_close(void *d, int fd) {
    (void)d;
    if(fd >= 0) {
        close(fd); /* 立即关闭 */
        g_srv_closed = 1;
    }
}
static int t_tcp_write_error(void) {
    sevent_context *ev = sevent_create();
    if(!ev)
        return 1;
    g_ev                   = ev;
    g_srv_close_after_recv = 0;
    g_cli_close_on_data    = 0;
    g_srv_closed           = 0;
    /* raw acceptor: 分发回调立即关闭连接 */
    g_acc                  = sevent_tcp_acceptor_create(ev);
    if(!g_acc)
        return 1;
    if(sevent_tcp_acceptor_listen(g_acc, "127.0.0.1", 0, 8, on_accept_close, NULL) < 0)
        return 1;
    int port  = sevent_tcp_acceptor_port(g_acc);
    g_ev_open = g_ev_error        = 0;
    g_ev_error_code               = 0;
    sevent_stream_conn_config cfg = {0};
    sevent_stream_conn       *s   = sevent_stream_create(ev, &cfg);
    if(!s)
        return 1;
    sevent_stream_conn_init cb = {
            .user_data = s, .on_open = cli_on_open, .on_data = cli_on_data, .on_error = cli_on_error};
    if(sevent_stream_open(s, "127.0.0.1", (uint16_t)port, &cb) < 0)
        return 1;
    /* 等 server accept+close 完成 (client on_open 已触发) */
    for(int i = 0; i < 100 && (!g_ev_open || !g_srv_closed); i++)
        sevent_run_once(ev);
    if(!g_ev_open || !g_srv_closed)
        return 1;
    struct timespec ts = {0, 50 * 1000 * 1000};
    (void)nanosleep(&ts, NULL); /* 等 RST 到达内核 (loopback 微秒级, 50ms 绰绰有余) */
    /* RST 后写: send 立即 EPIPE → flush 致命 → on_error(SEVENT_ERR_WRITE) */
    int rc = sevent_stream_write(s, "x", 1);
    int ok = rc == SEVENT_ERR_WRITE && g_ev_error && g_ev_error_code == SEVENT_ERR_WRITE;
    sevent_stream_destroy(s);
    finish_case(ev);
    return ok ? 0 : 1;
}

/* ---- OPENING 中 close 用例 (取消建立 + close 摘除 connect_timer) ---- */
static int t_tcp_close_opening(void) {
    sevent_context *ev = sevent_create();
    if(!ev)
        return 1;
    g_ev      = ev;
    g_ev_open = g_ev_error        = 0;
    g_ev_error_code               = 0;
    g_ev_close_count              = 0;
    sevent_stream_conn_config cfg = {0};
    sevent_stream_conn       *s   = sevent_stream_create(ev, &cfg);
    if(!s)
        return 1;
    sevent_stream_conn_init cb = {.user_data          = s,
                                  .on_open            = cli_on_open,
                                  .on_data            = cli_on_data,
                                  .on_close           = cli_on_close,
                                  .on_error           = cli_on_error,
                                  .connect_timeout_ms = 5000}; /* 5s 未到期即 close */
    int                     rc = sevent_stream_open(s, "192.0.2.1", 80, &cb);
    if(rc < 0) {
        /* 立即失败路径 (EINPROGRESS 未发生): 同样无回调, 对象可重开 */
        sevent_stream_destroy(s);
        finish_case(ev);
        return rc == SEVENT_ERR_CONNECT ? 0 : 1;
    }
    sevent_stream_close(s); /* 取消建立: on_open/on_error/on_close 均不触发 */
    for(int i = 0; i < 20; i++) {
        sevent_wakeup(ev);
        sevent_run_once(ev);
    }
    int ok = !g_ev_open && !g_ev_error && g_ev_close_count == 0;
    sevent_stream_destroy(s);
    finish_case(ev);
    return ok ? 0 : 1;
}

/* ---- 非法 host 用例 (inet_pton 失败 → 立即 CONNECT 错误) ---- */
static int t_tcp_bad_host(void) {
    sevent_context *ev = sevent_create();
    if(!ev)
        return 1;
    g_ev                          = ev;
    sevent_stream_conn_config cfg = {0};
    sevent_stream_conn       *s   = sevent_stream_create(ev, &cfg);
    if(!s)
        return 1;
    sevent_stream_conn_init cb = {
            .user_data = s, .on_open = cli_on_open, .on_data = cli_on_data, .on_error = cli_on_error};
    int rc = sevent_stream_open(s, "not-an-ip", 80, &cb);
    int ok = rc == SEVENT_ERR_CONNECT; /* inet_pton 失败 → 立即失败 */
    /* 失败后重开 (未监听端口): 立即失败或异步 on_error(CONNECT) 均可 */
    rc     = sevent_stream_open(s, "127.0.0.1", 1, &cb);
    if(rc == 0) {
        g_ev_error      = 0;
        g_ev_error_code = 0;
        for(int i = 0; i < 100 && !g_ev_error; i++)
            sevent_run_once(ev);
        ok = ok && g_ev_error && g_ev_error_code == SEVENT_ERR_CONNECT;
    } else {
        ok = ok && rc == SEVENT_ERR_CONNECT;
    }
    sevent_stream_destroy(s);
    finish_case(ev);
    return ok ? 0 : 1;
}

/* ---- 跨线程用例 (SEVENT_THREAD_SAFE=ON: write 与 loop 回调并发) ---- */
#ifdef SEVENT_THREAD_SAFE
#include <pthread.h>
static void *writer_thread(void *arg) {
    sevent_tcp_conn *c = (sevent_tcp_conn *)arg;
    char             msg[8];
    memset(msg, 'x', sizeof(msg));
    for(int i = 0; i < 200; i++)
        (void)sevent_tcp_conn_write(c, msg, sizeof(msg)); /* 工作线程跨线程 write */
    return NULL;
}
static int t_tcp_cross_thread(void) {
    /* 工作线程并发 write 与 loop 线程 IO 回调 — 锁正确性 (崩溃/竞态在 TSAN 下验证) */
    sevent_context *ev = sevent_create();
    if(!ev)
        return 1;
    g_ev                   = ev;
    g_srv_close_after_recv = 0;
    g_cli_close_on_data    = 0;
    int port               = start_server(ev);
    if(port < 0)
        return 1;
    g_ev_open = g_ev_data = g_ev_error = 0;
    g_rlen                             = 0;
    sevent_tcp_conn *c                 = sevent_tcp_conn_create(ev);
    if(!c)
        return 1;
    sevent_stream_conn_init cb = {
            .user_data = c, .on_open = tcp_api_on_open, .on_data = tcp_api_on_data, .on_error = cli_on_error};
    if(sevent_tcp_conn_open(c, "127.0.0.1", (uint16_t)port, &cb) < 0)
        return 1;
    for(int i = 0; i < 100 && !g_ev_open; i++)
        sevent_run_once(ev);
    if(!g_ev_open)
        return 1;
    pthread_t th;
    if(pthread_create(&th, NULL, writer_thread, c) != 0)
        return 1;
    /* loop 线程: IO 回调与 worker write 并发. worker 写完 200 次后队列可能清空
     * (无事件+无定时器 → select 无限阻塞), 用 wakeup 驱动每轮 */
    for(int i = 0; i < 500 && !g_ev_error; i++) {
        sevent_wakeup(ev);
        sevent_run_once(ev);
    }
    pthread_join(th, NULL);
    int ok = g_ev_open && !g_ev_error;
    sevent_tcp_conn_destroy(c);
    finish_case(ev);
    return ok ? 0 : 1;
}
#endif /* SEVENT_THREAD_SAFE */

/* ---- acceptor 专项用例 ---- */
static int  g_acc_count;
static void acc_on_accept(void *d, int fd) {
    (void)d;
    g_acc_count++;
    close(fd); /* 丢弃 */
}
static int acc_connect(sevent_context *ev, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if(fd < 0)
        return -1;
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port   = htons((uint16_t)port);
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    int rc = connect(fd, (struct sockaddr *)&a, sizeof(a));
    if(rc < 0 && errno != EINPROGRESS) {
        close(fd);
        return -1;
    }
    for(int i = 0; i < 100 && g_acc_count < 1; i++)
        sevent_run_once(ev); /* 等 acceptor 分发 */
    return fd;
}

static int t_acceptor_basic(void) {
    /* listen(随机端口) → port 查询 → client 连接 → 分发回调收到 fd */
    sevent_context *ev = sevent_create();
    if(!ev)
        return 1;
    g_ev  = ev;
    g_acc = sevent_tcp_acceptor_create(ev);
    if(!g_acc)
        return 1;
    if(sevent_tcp_acceptor_listen(g_acc, "127.0.0.1", 0, 8, acc_on_accept, NULL) < 0)
        return 1;
    int port = sevent_tcp_acceptor_port(g_acc);
    if(port <= 0)
        return 1;
    g_acc_count = 0;
    int fd      = acc_connect(ev, port);
    if(fd < 0)
        return 1;
    close(fd);
    int ok = g_acc_count == 1;
    finish_case(ev);
    return ok ? 0 : 1;
}

static int t_acceptor_relisten(void) {
    /* close 后重新 listen (端口变化) → 新连接分发 */
    sevent_context *ev = sevent_create();
    if(!ev)
        return 1;
    g_ev  = ev;
    g_acc = sevent_tcp_acceptor_create(ev);
    if(!g_acc)
        return 1;
    if(sevent_tcp_acceptor_listen(g_acc, "127.0.0.1", 0, 8, acc_on_accept, NULL) < 0)
        return 1;
    int port1 = sevent_tcp_acceptor_port(g_acc);
    sevent_tcp_acceptor_close(g_acc);
    if(sevent_tcp_acceptor_listen(g_acc, "127.0.0.1", 0, 8, acc_on_accept, NULL) < 0)
        return 1;
    int port2 = sevent_tcp_acceptor_port(g_acc);
    if(port1 <= 0 || port2 <= 0 || port1 == port2)
        return 1;
    g_acc_count = 0;
    int fd      = acc_connect(ev, port2);
    if(fd < 0)
        return 1;
    close(fd);
    int ok = g_acc_count == 1;
    finish_case(ev);
    return ok ? 0 : 1;
}

static int t_acceptor_listen_fail(void) {
    /* 端口占用 → SEVENT_ERR_LISTEN; 失败后可重新 listen */
    sevent_context *ev = sevent_create();
    if(!ev)
        return 1;
    g_ev  = ev;
    g_acc = sevent_tcp_acceptor_create(ev);
    if(!g_acc)
        return 1;
    if(sevent_tcp_acceptor_listen(g_acc, "127.0.0.1", 0, 8, acc_on_accept, NULL) < 0)
        return 1;
    int                  port = sevent_tcp_acceptor_port(g_acc);
    sevent_tcp_acceptor *a2   = sevent_tcp_acceptor_create(ev);
    if(!a2)
        return 1;
    int rc = sevent_tcp_acceptor_listen(a2, "127.0.0.1", (uint16_t)port, 8, acc_on_accept, NULL);
    int ok = rc == SEVENT_ERR_LISTEN; /* 同端口占用 */
    if(ok)
        ok = sevent_tcp_acceptor_listen(a2, "127.0.0.1", 0, 8, acc_on_accept, NULL) == 0; /* 失败后重 listen */
    sevent_tcp_acceptor_destroy(a2);
    finish_case(ev);
    return ok ? 0 : 1;
}

static int t_acceptor_inval(void) {
    /* on_accept NULL / 非法 bind_addr / 重复 listen → INVAL; create/destroy NULL 无害 */
    sevent_context *ev = sevent_create();
    if(!ev)
        return 1;
    g_ev  = ev;
    g_acc = sevent_tcp_acceptor_create(ev);
    if(!g_acc)
        return 1;
    int ok = 1;
    if(sevent_tcp_acceptor_listen(g_acc, "127.0.0.1", 0, 8, NULL, NULL) != SEVENT_ERR_INVAL)
        ok = 0; /* on_accept NULL */
    if(sevent_tcp_acceptor_listen(g_acc, "bad-addr", 0, 8, acc_on_accept, NULL) != SEVENT_ERR_INVAL)
        ok = 0; /* 非法 bind_addr */
    if(sevent_tcp_acceptor_listen(g_acc, "127.0.0.1", 0, 8, acc_on_accept, NULL) != 0)
        ok = 0; /* 正常监听 */
    if(sevent_tcp_acceptor_listen(g_acc, "127.0.0.1", 0, 8, acc_on_accept, NULL) != SEVENT_ERR_INVAL)
        ok = 0; /* 已在监听 */
    if(sevent_tcp_acceptor_create(NULL) != NULL)
        ok = 0;                        /* NULL ev */
    sevent_tcp_acceptor_destroy(NULL); /* 无害 */
    finish_case(ev);
    return ok ? 0 : 1;
}

static void acc_on_accept_destroy(void *d, int fd) {
    sevent_tcp_acceptor *a = (sevent_tcp_acceptor *)d;
    (void)fd;
    g_acc_count++;
    close(fd);
    sevent_tcp_acceptor_destroy(a); /* 回调内 destroy: 栈安全 */
}
static int t_acceptor_destroy_in_callback(void) {
    /* on_accept 回调内 destroy — 无 UAF (run_once 模式: 立即释放, 回调栈安全) */
    sevent_context *ev = sevent_create();
    if(!ev)
        return 1;
    g_ev  = ev;
    g_acc = sevent_tcp_acceptor_create(ev);
    if(!g_acc)
        return 1;
    if(sevent_tcp_acceptor_listen(g_acc, "127.0.0.1", 0, 8, acc_on_accept_destroy, g_acc) < 0)
        return 1;
    int port    = sevent_tcp_acceptor_port(g_acc);
    g_acc_count = 0;
    int fd      = acc_connect(ev, port);
    if(fd < 0)
        return 1;
    close(fd);
    int ok = g_acc_count == 1; /* 分发 + 回调内 destroy 无崩溃 */
    /* acceptor 已在回调内销毁 (post 已执行) — g_acc 作废, 置 NULL 防
     * 后续用例 finish_case 对悬空指针双销毁; 不经过 finish_case */
    g_acc  = NULL;
    sevent_destroy(ev);
    return ok ? 0 : 1;
}

static int t_tcp_inval(void) {
    /* 非法调用: open 前 write → INVAL; NULL host / NULL on_data → INVAL */
    sevent_context *ev = sevent_create();
    if(!ev)
        return 1;
    g_ev                          = ev;
    sevent_stream_conn_config cfg = {0};
    sevent_stream_conn       *s   = sevent_stream_create(ev, &cfg);
    if(!s)
        return 1;
    sevent_stream_conn_init cb = {
            .user_data = s, .on_open = cli_on_open, .on_data = cli_on_data, .on_error = cli_on_error};
    sevent_stream_conn_init cb_null_data = {.user_data = s, .on_open = cli_on_open}; /* on_data=NULL */
    sevent_stream_conn_init cb_null_open = {.user_data = s, .on_data = cli_on_data}; /* on_open=NULL */
    int                     ok           = 1;
    if(sevent_stream_write(s, "x", 1) != SEVENT_ERR_INVAL)
        ok = 0; /* 未 open, write 应 INVAL */
    if(sevent_stream_write(s, NULL, 1) != SEVENT_ERR_INVAL)
        ok = 0; /* NULL data */
    if(sevent_stream_open(s, NULL, 80, &cb) != SEVENT_ERR_INVAL)
        ok = 0; /* NULL host */
    if(sevent_stream_open(s, "127.0.0.1", 80, &cb_null_data) != SEVENT_ERR_INVAL)
        ok = 0; /* NULL on_data */
    if(sevent_stream_open(s, "127.0.0.1", 80, &cb_null_open) != SEVENT_ERR_INVAL)
        ok = 0; /* NULL on_open */
    if(sevent_stream_open(s, "127.0.0.1", 80, NULL) != SEVENT_ERR_INVAL)
        ok = 0; /* NULL init */
    if(sevent_tcp_conn_create(NULL) != NULL)
        ok = 0;                    /* NULL ev */
    sevent_tcp_conn_destroy(NULL); /* 无害 (NULL 判空) */
    sevent_tcp_conn *tc = sevent_tcp_conn_create(ev);
    if(!tc)
        ok = 0;
    if(tc) {
        if(sevent_tcp_conn_accept(tc, -1, &cb) != SEVENT_ERR_INVAL)
            ok = 0; /* fd < 0 */
        if(sevent_tcp_conn_accept(tc, 0, NULL) != SEVENT_ERR_INVAL)
            ok = 0; /* NULL init */
        sevent_tcp_conn_destroy(tc);
    }
    sevent_stream_destroy(s);
    finish_case(ev);
    return ok ? 0 : 1;
}

/* ---- 注册 ---- */
typedef struct {
    const char *n;
    int (*f)(void);
} test_entry;

static const test_entry tests[] = {
        {"tcp_echo", t_tcp_echo},
        {"tcp_eof", t_tcp_eof},
        {"tcp_close_no_cb", t_tcp_close_no_cb},
        {"tcp_connect_refused", t_tcp_connect_refused},
        {"tcp_reopen", t_tcp_reopen},
        {"tcp_accept_async", t_tcp_accept_async},
        {"tcp_order", t_tcp_order},
        {"tcp_no_close_cb", t_tcp_no_close_cb},
        {"tcp_no_error_cb", t_tcp_no_error_cb},
        {"tcp_large_echo", t_tcp_large_echo},
        {"tcp_api_echo", t_tcp_api_echo},
        {"tcp_destroy_in_callback", t_tcp_destroy_in_callback},
        {"tcp_small_recv_buf", t_tcp_small_recv_buf},
        {"tcp_connect_timeout", t_tcp_connect_timeout},
        {"tcp_write_error", t_tcp_write_error},
        {"tcp_close_opening", t_tcp_close_opening},
        {"tcp_bad_host", t_tcp_bad_host},
        {"acceptor_basic", t_acceptor_basic},
        {"acceptor_relisten", t_acceptor_relisten},
        {"acceptor_listen_fail", t_acceptor_listen_fail},
        {"acceptor_inval", t_acceptor_inval},
        {"acceptor_destroy_in_callback", t_acceptor_destroy_in_callback},
        {"tcp_inval", t_tcp_inval},
#ifdef SEVENT_THREAD_SAFE
        {"tcp_cross_thread", t_tcp_cross_thread},
#endif
        {NULL, NULL},
};

int main(void) {
    setbuf(stdout, NULL);
    printf("stream_conn tests\n");
    printf("=================\n");
    int ok = 0, fail = 0;
    for(int i = 0; tests[i].n; i++) {
        printf("  %-24s ", tests[i].n);
        if(tests[i].f()) {
            printf("×\n");
            fail++;
        } else {
            printf("✓\n");
            ok++;
        }
    }
    printf("%d/%d passed\n", ok, ok + fail);
    return fail ? 1 : 0;
}
