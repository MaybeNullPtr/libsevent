/* test_tcp_conn.c — tcp_conn 公开 API 独立单测
 *
 * 全部直接使用 sevent_tcp_conn_* (不经 stream 抽象), 验证公开接口契约:
 *  - create/open/accept/write/close/destroy 完整链路独立可用
 *  - open/accept 异步建连回调 (on_open 由事件循环触发)
 *  - on_data 推送模型 (无 read API), write 返回"已接受"自动 flush
 *  - EOF → on_close → 状态回 IDLE 可重开 (同一对象)
 *  - 主动 close 不触发 on_close
 *  - 建连失败 → on_error(SEVENT_ERR_CONNECT)
 *  - 非法调用 (前置条件/状态) → SEVENT_ERR_INVAL
 *  - 回调内 destroy 安全 (post 延迟释放)
 */
#include "sevent.h"
#include "sevent_tcp_conn.h"
#include "sevent_tcp_acceptor.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ---- 全局状态 ---- */
static int    g_ev_open;
static int    g_ev_data;
static int    g_ev_close;
static int    g_ev_close_count; /* 主动 close 不触发 on_close 断言用 */
static int    g_ev_error;
static int    g_ev_error_code;
static int    g_srv_close_after_recv; /* server 收到数据后立即关闭 (EOF 用例) */
static int    g_cli_close_on_data;    /* client 收到数据后主动 close (不触发 on_close) */
static char   g_recv[512];
static size_t g_rlen;

/* ---- 内嵌 echo server (acceptor 分发 → tcp_conn accept 包装) ---- */
static sevent_context      *g_ev;
static sevent_tcp_acceptor *g_acc;

static void srv_on_open(void *d) { (void)d; }
static void srv_on_data(void *d, const uint8_t *data, size_t len) {
    if(g_srv_close_after_recv) {
        sevent_tcp_conn_close(d); /* EOF 用例: 不回显直接关闭 */
        return;
    }
    (void)sevent_tcp_conn_write(d, data, len); /* 回显 (write 已拷贝, buffer 可随即复用) */
}
/* server 连接登记: 用例结束时统一销毁 (回调内销毁的置 NULL, 防双销毁) */
static sevent_tcp_conn *g_srv_conns[64];
static int              g_srv_conn_count;

static void srv_conn_drop(sevent_tcp_conn *c) {
    for(int i = 0; i < g_srv_conn_count; i++) {
        if(g_srv_conns[i] == c) {
            g_srv_conns[i] = NULL;
            break;
        }
    }
    sevent_tcp_conn_destroy(c);
}
static void srv_on_close(void *d) { srv_conn_drop((sevent_tcp_conn *)d); /* 对端关闭, 连接收尾 */ }
static void srv_on_error(void *d, int err) {
    (void)err;
    srv_conn_drop((sevent_tcp_conn *)d);
}
/* acceptor 分发: fd 已 accept, 包装成 tcp_conn 连接 (服务端入口) */
static void on_accept(void *d, int fd) {
    (void)d;
    sevent_tcp_conn *c = sevent_tcp_conn_create(g_ev);
    if(!c) {
        close(fd);
        return;
    }
    if(g_srv_conn_count < (int)(sizeof(g_srv_conns) / sizeof(g_srv_conns[0])))
        g_srv_conns[g_srv_conn_count++] = c;
    sevent_stream_conn_init cb = {.user_data = c,
                                  .on_open   = srv_on_open,
                                  .on_data   = srv_on_data,
                                  .on_close  = srv_on_close,
                                  .on_error  = srv_on_error};
    if(sevent_tcp_conn_accept(c, fd, &cb) < 0)
        sevent_tcp_conn_destroy(c); /* accept 失败: fd 已由本层关闭 */
}

/* 跑完 pending post: destroy 统一 post 后, 延迟 free 由 run_posts 执行 —
 * sevent_destroy 丢弃未执行的 post (不执行回调), 销毁 ev 前必须推进循环 */
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
            sevent_tcp_conn_destroy(g_srv_conns[i]);
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
    (void)sevent_tcp_conn_write(d, "hello", 5);
}
static void cli_on_data(void *d, const uint8_t *data, size_t len) {
    if(g_rlen + len <= sizeof(g_recv)) {
        memcpy(g_recv + g_rlen, data, len);
        g_rlen += len;
    }
    g_ev_data = 1;
    if(g_cli_close_on_data)
        sevent_tcp_conn_close(d); /* 主动 close: 不触发 on_close */
}
static void cli_on_close(void *d) {
    (void)d;
    g_ev_close = 1;
    g_ev_close_count++;
}
static void cli_on_error(void *d, int err) {
    (void)d;
    g_ev_error      = 1;
    g_ev_error_code = err;
}

/* ---- 大消息用例 (1MB 一次 write: 部分写/写兴趣续写路径) ---- */
static uint8_t *g_big;
static size_t   g_big_len;
static uint8_t *g_big_recv;
static size_t   g_big_rlen;

static void cli_on_open_big(void *d) {
    g_ev_open = 1;
    int rc    = sevent_tcp_conn_write(d, g_big, g_big_len);
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

/* ---- 用例 ---- */

static int t_echo(void) {
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
    sevent_tcp_conn *c                 = sevent_tcp_conn_create(ev);
    if(!c)
        return 1;
    sevent_stream_conn_init cb = {
            .user_data = c, .on_open = cli_on_open, .on_data = cli_on_data, .on_error = cli_on_error};
    if(sevent_tcp_conn_open(c, "127.0.0.1", (uint16_t)port, &cb) < 0)
        return 1;
    for(int i = 0; i < 200 && !g_ev_data && !g_ev_error; i++)
        sevent_run_once(ev);
    int ok = g_ev_open && g_ev_data && !g_ev_error && g_rlen == 5 && memcmp(g_recv, "hello", 5) == 0;
    sevent_tcp_conn_destroy(c);
    finish_case(ev);
    return ok ? 0 : 1;
}

static int t_large_msg(void) {
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
    g_big_len                          = 1 << 20; /* 1MB */
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
    sevent_tcp_conn *c = sevent_tcp_conn_create(ev);
    if(!c)
        return 1;
    sevent_stream_conn_init cb = {
            .user_data     = c,
            .on_open       = cli_on_open_big,
            .on_data       = cli_on_data_big,
            .on_error      = cli_on_error,
            .recv_buf_size = 1024, /* client 慢读 → server 回显写缓冲满 → 部分写/EAGAIN */
    };
    if(sevent_tcp_conn_open(c, "127.0.0.1", (uint16_t)port, &cb) < 0)
        return 1;
    for(int i = 0; i < 200000 && !g_ev_data && !g_ev_error; i++)
        sevent_run_once(ev);
    int ok = g_ev_data && g_big_rlen == g_big_len && memcmp(g_big, g_big_recv, g_big_len) == 0;
    sevent_tcp_conn_destroy(c);
    finish_case(ev);
    free(g_big);
    free(g_big_recv);
    return ok ? 0 : 1;
}

static int t_eof_reopen(void) {
    /* server 收到后关闭 → client on_close (EOF) → 状态回 IDLE → 直接重开成功 */
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
    sevent_tcp_conn *c                              = sevent_tcp_conn_create(ev);
    if(!c)
        return 1;
    sevent_stream_conn_init cb = {.user_data = c,
                                  .on_open   = cli_on_open,
                                  .on_data   = cli_on_data,
                                  .on_close  = cli_on_close,
                                  .on_error  = cli_on_error};
    if(sevent_tcp_conn_open(c, "127.0.0.1", (uint16_t)port, &cb) < 0)
        return 1;
    for(int i = 0; i < 200 && !g_ev_close && !g_ev_error; i++)
        sevent_run_once(ev);
    if(!g_ev_open || !g_ev_close || g_ev_close_count != 1 || g_ev_error)
        return 1;
    /* EOF 后直接重开 (tcp 层已回 IDLE, 无需先 close) */
    g_srv_close_after_recv = 0;
    g_ev_open = g_ev_data = g_ev_close = g_ev_error = 0;
    g_rlen                                          = 0;
    if(sevent_tcp_conn_open(c, "127.0.0.1", (uint16_t)port, &cb) < 0)
        return 1;
    for(int i = 0; i < 200 && !g_ev_data && !g_ev_error; i++)
        sevent_run_once(ev);
    int ok = g_ev_open && g_ev_data && !g_ev_error && g_rlen == 5 && memcmp(g_recv, "hello", 5) == 0;
    sevent_tcp_conn_destroy(c);
    finish_case(ev);
    return ok ? 0 : 1;
}

static int t_active_close(void) {
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
    sevent_tcp_conn *c                              = sevent_tcp_conn_create(ev);
    if(!c)
        return 1;
    sevent_stream_conn_init cb = {.user_data = c,
                                  .on_open   = cli_on_open,
                                  .on_data   = cli_on_data,
                                  .on_close  = cli_on_close,
                                  .on_error  = cli_on_error};
    if(sevent_tcp_conn_open(c, "127.0.0.1", (uint16_t)port, &cb) < 0)
        return 1;
    for(int i = 0; i < 200 && !g_ev_data && !g_ev_error; i++)
        sevent_run_once(ev);
    /* close 已在 on_data 内触发; 若 close 误触发 on_close, count 会变化 */
    int ok = g_ev_open && g_ev_data && g_ev_close_count == 0 && !g_ev_error;
    sevent_tcp_conn_destroy(c);
    finish_case(ev);
    return ok ? 0 : 1;
}

static int t_connect_refused(void) {
    /* 连接未监听端口: 立即失败 (open <0) 或异步 on_error(SEVENT_ERR_CONNECT) */
    sevent_context *ev = sevent_create();
    if(!ev)
        return 1;
    g_ev      = ev;
    g_ev_open = g_ev_error = 0;
    g_ev_error_code        = 0;
    sevent_tcp_conn *c     = sevent_tcp_conn_create(ev);
    if(!c)
        return 1;
    sevent_stream_conn_init cb = {
            .user_data = c, .on_open = cli_on_open, .on_data = cli_on_data, .on_error = cli_on_error};
    int rc = sevent_tcp_conn_open(c, "127.0.0.1", 1 /* 未监听 */, &cb);
    if(rc >= 0) {
        /* EINPROGRESS 路径: 等异步失败 */
        for(int i = 0; i < 100 && !g_ev_error; i++)
            sevent_run_once(ev);
        if(!g_ev_error || g_ev_error_code != SEVENT_ERR_CONNECT) {
            sevent_tcp_conn_destroy(c);
            finish_case(ev);
            return 1;
        }
    } else if(rc != SEVENT_ERR_CONNECT) {
        sevent_tcp_conn_destroy(c);
        finish_case(ev);
        return 1;
    }
    sevent_tcp_conn_destroy(c);
    finish_case(ev);
    return 0;
}

static int t_inval(void) {
    /* 非法调用: open 前 write → INVAL; NULL host/init/on_open/on_data → INVAL;
     * OPENING 中重复 open → INVAL; create(NULL) → NULL; destroy(NULL) 无害 */
    sevent_context *ev = sevent_create();
    if(!ev)
        return 1;
    g_ev               = ev;
    sevent_tcp_conn *c = sevent_tcp_conn_create(ev);
    if(!c)
        return 1;
    sevent_stream_conn_init cb = {
            .user_data = c, .on_open = cli_on_open, .on_data = cli_on_data, .on_error = cli_on_error};
    sevent_stream_conn_init cb_null_data = {.user_data = c, .on_open = cli_on_open}; /* on_data=NULL */
    sevent_stream_conn_init cb_null_open = {.user_data = c, .on_data = cli_on_data}; /* on_open=NULL */
    int                     ok           = 1;
    if(sevent_tcp_conn_write(c, "x", 1) != SEVENT_ERR_INVAL)
        ok = 0; /* 未 open, write 应 INVAL */
    if(sevent_tcp_conn_write(c, NULL, 1) != SEVENT_ERR_INVAL)
        ok = 0; /* NULL data */
    if(sevent_tcp_conn_open(c, NULL, 80, &cb) != SEVENT_ERR_INVAL)
        ok = 0; /* NULL host */
    if(sevent_tcp_conn_open(c, "127.0.0.1", 80, NULL) != SEVENT_ERR_INVAL)
        ok = 0; /* NULL init */
    if(sevent_tcp_conn_open(c, "127.0.0.1", 80, &cb_null_data) != SEVENT_ERR_INVAL)
        ok = 0; /* NULL on_data */
    if(sevent_tcp_conn_open(c, "127.0.0.1", 80, &cb_null_open) != SEVENT_ERR_INVAL)
        ok = 0; /* NULL on_open */
    if(sevent_tcp_conn_accept(c, -1, &cb) != SEVENT_ERR_INVAL)
        ok = 0; /* fd < 0 */
    if(sevent_tcp_conn_accept(c, 0, NULL) != SEVENT_ERR_INVAL)
        ok = 0; /* NULL init */
    if(sevent_tcp_conn_create(NULL) != NULL)
        ok = 0;                    /* NULL ev */
    sevent_tcp_conn_destroy(NULL); /* 无害 (NULL 判空) */
    /* OPENING 中重复 open → INVAL (不可达地址走 EINPROGRESS, 确定性) */
    sevent_stream_conn_init cb_to = {.user_data          = c,
                                     .on_open            = cli_on_open,
                                     .on_data            = cli_on_data,
                                     .on_error           = cli_on_error,
                                     .connect_timeout_ms = 5000};
    int                     rc    = sevent_tcp_conn_open(c, "192.0.2.1", 80, &cb_to);
    if(rc == 0) {
        if(sevent_tcp_conn_open(c, "127.0.0.1", 80, &cb) != SEVENT_ERR_INVAL)
            ok = 0;               /* OPENING 中重复 open */
        sevent_tcp_conn_close(c); /* 取消建立 */
    } else if(rc != SEVENT_ERR_CONNECT) {
        ok = 0; /* 立即失败只允许 CONNECT */
    }
    sevent_tcp_conn_destroy(c);
    finish_case(ev);
    return ok ? 0 : 1;
}

/* ---- 回调内 destroy 用例 (post 延迟释放, 回调栈安全) ---- */
static void cli_destroy_on_data(void *d, const uint8_t *data, size_t len) {
    (void)data;
    (void)len;
    g_ev_data = 1;
    sevent_tcp_conn_destroy(d); /* 回调内 destroy: free 推迟到 run_posts */
}
static int t_destroy_in_cb(void) {
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
            .on_open   = cli_on_open,
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

/* ---- 注册 ---- */
typedef struct {
    const char *n;
    int (*f)(void);
} test_entry;

static const test_entry tests[] = {
        {"tcp_echo", t_echo},
        {"tcp_large_msg", t_large_msg},
        {"tcp_eof_reopen", t_eof_reopen},
        {"tcp_active_close", t_active_close},
        {"tcp_connect_refused", t_connect_refused},
        {"tcp_inval", t_inval},
        {"tcp_destroy_in_cb", t_destroy_in_cb},
        {NULL, NULL},
};

int main(void) {
    setbuf(stdout, NULL);
    printf("tcp_conn tests (public API)\n");
    printf("===========================\n");
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
