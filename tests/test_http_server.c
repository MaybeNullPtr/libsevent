/* test_http_server.c — http server 服务器层单测
 *
 * 覆盖: 回调分发/keep-alive 多请求/关闭条件①②③/400/413/响应构造 (状态行/
 *       头遍历/CL/close 注入/body/查表)/辅助函数 (set 查重/add/del/clear)/
 *       状态机矩阵 (非法调用)/write 路径+write_end/半关 (shutdown)/空闲超时/
 *       on_accept 拒绝.
 *
 * 服务端: sevent_http_server (loop 线程, sevent_run_once 驱动).
 * 客户端: 裸 TCP 阻塞 socket, 手写 HTTP 请求.
 */
#include "sevent.h"
#include "sevent_http_server.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static int g_fail = 0;

#define CHECK(cond, ...)                                                                                               \
    do {                                                                                                               \
        if(cond) {                                                                                                     \
        } else {                                                                                                       \
            g_fail++;                                                                                                  \
            printf("  FAIL %s:%d: ", __FILE__, __LINE__);                                                              \
            printf(__VA_ARGS__);                                                                                       \
            printf("\n");                                                                                              \
        }                                                                                                              \
    } while(0)

/* ===== 服务端驱动 ===== */

static sevent_context     *g_ev;
static sevent_http_server *g_srv;

/* 收集回调事件 */
#define MAX_CB 64
static int    g_cb_count;
static int    g_cb_type[MAX_CB];  /* 0=accept 1=request 2=upgrade 3=conn_close */
static int    g_conn_close_count; /* 独立计数 (不受 MAX_CB 截断) */
static char   g_last_body[512];
static size_t g_last_body_len;
static int    g_last_req_keepalive;

static int g_reject_accept;           /* on_accept 里 close 拒绝 */
static int g_use_write_path;          /* on_request 走 write 路径 (全手写 + write_end) */
static int g_async_mode;              /* on_request 走异步 respond (post 延迟, 栈外调用) */
static int g_async_write_end;         /* 回调内 write 开始流式 → 栈外 write_end 收尾 */
static int g_try_respond_after_write; /* 回调内 write 后尝试 respond (互斥验证) */
static int g_write_respond_rc;
static int g_destroy_on_first; /* 首请求回调内 destroy server (UAF 回归) */
static int g_destroy_done;
static int g_respond_close; /* on_request 走 resp.close=true */
static int g_matrix_mode;   /* 矩阵非法调用: 回调内记录 rc */
static int g_no_upgrade;    /* listen 时 on_upgrade=NULL */
static int g_hang_mode;     /* 回调内挂起: 不 respond 不 post (AWAIT_RESP 永久窗口) */
static int g_resp_mode;     /* D5 头注入规则: 1=204 2=304 3=200空body 4=用户CL 5=用户Connection 6=204+body */
static int g_m_rc_respond_ok, g_m_rc_respond2, g_m_rc_write, g_m_rc_write_end;
static sevent_http_conn *g_async_conn;

static void async_respond_cb(void *data) {
    /* 栈外 respond: 启动残留处理 (AWAIT_RESP 态) */
    sevent_http_conn    *conn = (sevent_http_conn *)data;
    sevent_http_response resp = {0};
    resp.status               = 200;
    resp.body                 = "hello";
    resp.body_len             = 5;
    sevent_http_conn_respond(conn, &resp);
    g_async_conn = NULL;
}

static void async_write_end_cb(void *data) {
    /* 回调内 write 开始流式 → 回调返回 (REQUEST→RESPONDING) → 栈外 write_end 收尾.
     * 回归: 修复前回调返回落 AWAIT_RESP, write_end 报错 (RESPONDING 才合法). */
    sevent_http_conn *conn = (sevent_http_conn *)data;
    sevent_http_conn_write(conn, (const uint8_t *)"world", 5);
    g_async_conn = NULL;
    if(sevent_http_conn_write_end(conn) != 0)
        sevent_http_conn_close(conn);
}

static void on_accept(void *ud, sevent_http_conn *conn) {
    (void)ud;
    if(g_cb_count < MAX_CB) {
        g_cb_type[g_cb_count] = 0;
        g_cb_count++;
    }
    if(g_reject_accept)
        sevent_http_conn_close(conn);
}

static void on_request(void *ud, const sevent_http_msg *req, sevent_http_conn *conn) {
    (void)ud;
    if(g_cb_count < MAX_CB) {
        g_cb_type[g_cb_count] = 1;
        g_cb_count++;
    }
    g_last_req_keepalive = req->keep_alive;
    if(req->body_len < sizeof(g_last_body)) {
        memcpy(g_last_body, req->body, req->body_len);
        g_last_body[req->body_len] = 0;
    }
    g_last_body_len = req->body_len;
    if(g_hang_mode) {
        /* 挂起: 不 respond 不 post — AWAIT_RESP 永久窗口 (溢出契约测试用) */
        g_async_conn = conn;
        return;
    }
    if(g_resp_mode) {
        /* D5 头注入规则验证 (rc 记录到 g_m_rc_respond_ok) */
        sevent_http_response resp = {0};
        switch(g_resp_mode) {
        case 1: /* 204: 禁止 CL */
            resp.status = 204;
            break;
        case 2: /* 304: 禁止 CL */
            resp.status = 304;
            break;
        case 3: /* 200 空 body: 仍注入 CL:0 (keep-alive 终止边界) */
            resp.status = 200;
            break;
        case 4: /* 用户显式 CL: 库跳过注入 (不重复) */
            resp.status   = 200;
            resp.body     = "x";
            resp.body_len = 1;
            sevent_http_response_header_set(&resp, "Content-Length", "99");
            break;
        case 5: /* 用户显式 Connection: 库跳过 close 注入 */
            resp.status   = 200;
            resp.body     = "x";
            resp.body_len = 1;
            resp.close    = true;
            sevent_http_response_header_set(&resp, "Connection", "keep-alive");
            break;
        case 6: /* 204 + body: 协议禁止 → INVAL */
            resp.status       = 204;
            resp.body         = "x";
            resp.body_len     = 1;
            g_m_rc_respond_ok = sevent_http_conn_respond(conn, &resp);
            return;
        }
        g_m_rc_respond_ok = sevent_http_conn_respond(conn, &resp);
        return;
    }
    if(g_destroy_on_first && !g_destroy_done) {
        /* 首请求回调内 destroy server — 连接仍活跃 (srv_cleanup 排队中),
         * 主循环继续处理剩余粘包 → budget 耗尽让出 → 与 srv_cleanup 同轮 post */
        g_destroy_done = 1;
        sevent_http_server_destroy(g_srv);
        g_srv = NULL;
    }
    if(g_respond_close) {
        sevent_http_response resp = {0};
        resp.status               = 200;
        resp.body                 = "hello";
        resp.body_len             = 5;
        resp.close                = true; /* close 字段: 注入 Connection: close + 半关 */
        sevent_http_conn_respond(conn, &resp);
        return;
    }
    if(g_matrix_mode) {
        /* 状态机矩阵非法调用 (回调内断言 rc — 状态转换在 respond 内部完成) */
        sevent_http_response resp = {0};
        resp.status               = 200;
        resp.body                 = "hello";
        resp.body_len             = 5;
        g_m_rc_respond_ok         = sevent_http_conn_respond(conn, &resp);        /* 成功 → 回 PARSING */
        g_m_rc_respond2           = sevent_http_conn_respond(conn, &resp);        /* 重复 respond → INVAL */
        g_m_rc_write     = sevent_http_conn_write(conn, (const uint8_t *)"x", 1); /* 响应后 write → INVAL */
        g_m_rc_write_end = sevent_http_conn_write_end(conn);                      /* 响应后 write_end → INVAL */
        return;
    }
    if(g_async_mode) {
        /* 异步: 不 respond — post 到下一轮 run_posts 执行 respond (栈外调用,
         * 模拟异步响应; 期间粘包残留已攒在 recv_buf) */
        g_async_conn = conn;
        if(sevent_post(g_ev, async_respond_cb, conn) != 0)
            sevent_http_conn_close(conn);
        return;
    }
    if(g_async_write_end) {
        /* 回调内 write 头 + 部分 body (REQUEST 保持) → 回调返回 → 栈外续写收尾 */
        const char *hdr = "HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhello ";
        sevent_http_conn_write(conn, (const uint8_t *)hdr, strlen(hdr));
        g_async_conn = conn;
        if(sevent_post(g_ev, async_write_end_cb, conn) != 0)
            sevent_http_conn_close(conn);
        return;
    }
    if(g_try_respond_after_write) {
        /* write 后 respond: 应被拒 (互斥契约) — 回归: 修复前 REQUEST 态缺
         * "已写"区分, respond 成功 → 裸数据 + 完整响应头混入队列 */
        const char *hdr = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        sevent_http_conn_write(conn, (const uint8_t *)hdr, strlen(hdr));
        sevent_http_response resp = {0};
        resp.status               = 200;
        resp.body                 = "hello";
        resp.body_len             = 5;
        g_write_respond_rc        = sevent_http_conn_respond(conn, &resp);
        sevent_http_conn_write_end(conn);
        return;
    }
    if(g_use_write_path) {
        /* write 路径: 全手写响应 + write_end (回调内完成, 状态转换在 write_end 内部) */
        const char *hdr = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n";
        sevent_http_conn_write(conn, (const uint8_t *)hdr, strlen(hdr));
        sevent_http_conn_write(conn, (const uint8_t *)"hello", 5);
        sevent_http_conn_write_end(conn);
        return;
    }
    /* 默认: 同步 respond (回固定 "hello" — 测试期望 CL:5 + body) */
    sevent_http_response resp = {0};
    resp.status               = 200;
    resp.body                 = "hello";
    resp.body_len             = 5;
    sevent_http_response_header_set(&resp, "Content-Type", "text/plain");
    sevent_http_conn_respond(conn, &resp);
}

static sevent_http_upgrade_result_t on_upgrade(void *ud, const sevent_http_msg *req, sevent_http_conn *conn) {
    (void)ud;
    (void)req;
    if(g_cb_count < MAX_CB) {
        g_cb_type[g_cb_count] = 2;
        g_cb_count++;
    }
    /* 默认: 拒绝 (respond → DECLINED, 连接留 http server) */
    sevent_http_response resp = {0};
    resp.status               = 404;
    resp.close                = true;
    sevent_http_conn_respond(conn, &resp);
    return SEVENT_HTTP_UPGRADE_DECLINED;
}

static void on_conn_close(void *ud, sevent_http_conn *conn) {
    (void)ud;
    (void)conn;
    g_conn_close_count++;
    if(g_cb_count < MAX_CB) {
        g_cb_type[g_cb_count] = 3;
        g_cb_count++;
    }
}

static void on_error(void *ud, int err) {
    (void)ud;
    (void)err;
}

/* 启动 server (idle_timeout_ms 参数化) */
static int server_start(int idle_timeout_ms) {
    g_ev = sevent_create();
    if(!g_ev)
        return -1;
    sevent_http_server_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.idle_timeout_ms = idle_timeout_ms;
    g_srv               = sevent_http_server_create(g_ev, &cfg);
    if(!g_srv)
        return -1;
    if(sevent_http_server_listen(g_srv,
                                 "127.0.0.1",
                                 0,
                                 8,
                                 on_accept,
                                 on_request,
                                 g_no_upgrade ? NULL : on_upgrade,
                                 on_conn_close,
                                 on_error,
                                 NULL) < 0)
        return -1;
    /* 推进循环直到监听就绪 */
    for(int i = 0; i < 100 && sevent_http_server_port(g_srv) == 0; i++)
        sevent_run_once(g_ev);
    return sevent_http_server_port(g_srv);
}

static void server_stop(void) {
    if(g_srv)
        sevent_http_server_destroy(g_srv);
    if(g_ev) {
        for(int i = 0; i < 500; i++) {
            int pc = -1;
            sevent_get_counts(g_ev, NULL, NULL, &pc);
            if(pc <= 0)
                break;
            sevent_wakeup(g_ev);
            sevent_run_once(g_ev);
        }
        sevent_destroy(g_ev);
    }
    g_srv = NULL;
    g_ev  = NULL;
}

/* 推进事件循环直到条件满足 (确定性等待, 不依赖固定轮数) */
static void pump_until(int (*cond)(void)) {
    for(int i = 0; i < 400 && !cond(); i++) {
        if(g_ev)
            sevent_wakeup(g_ev); /* 打断 select: 不睡满 timer 剩余 */
        sevent_run_once(g_ev);
        struct timespec ts = {0, 1000 * 1000};
        nanosleep(&ts, NULL);
    }
}

/* 连接已建立 (on_accept 触发) */
static int conn_established(void) { return g_cb_count >= 1; }

/* 请求1 已分派 (hang_overflow: accept + request) */
static int req1_hung(void) { return g_cb_count >= 2; }

/* respond 返回值已记录 (header_rules) */
static int resp_rc_set(void) { return g_m_rc_respond_ok != 0; }

/* ===== 客户端工具 ===== */

static int tcp_connect_to(uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if(fd < 0)
        return -1;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(port);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    if(connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int send_all(int fd, const char *data, size_t len) {
    size_t off = 0;
    while(off < len) {
        ssize_t w = send(fd, data + off, len - off, 0);
        if(w <= 0)
            return -1;
        off += (size_t)w;
    }
    return 0;
}

/* 读到含 needle 为止 (pump 驱动服务端 + MSG_DONTWAIT, 带超时) */
static int recv_until(int fd, char *buf, size_t cap, const char *needle) {
    size_t n = 0;
    for(int i = 0; i < 400 && n < cap; i++) {
        if(g_ev) {
            sevent_wakeup(g_ev); /* 立即唤醒 select (run_once 无 timer 时最多等 50ms) */
            sevent_run_once(g_ev);
        }
        ssize_t r = recv(fd, buf + n, cap - n, MSG_DONTWAIT);
        if(r > 0) {
            n      += (size_t)r;
            buf[n] = 0;
            if(strstr(buf, needle))
                return (int)n;
        } else if(r < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            break; /* 错误 */
        }
        struct timespec ts = {0, 1000 * 1000};
        nanosleep(&ts, NULL);
    }
    buf[n] = 0;
    return (int)n;
}

/* 自然等待 EOF (无 wakeup): select 超时 = timer 剩余, timer 才能推进 (idle 超时测试用) */
static int wait_eof_natural(int fd) {
    char buf[16];
    for(int i = 0; i < 60; i++) {
        if(g_ev)
            sevent_run_once(g_ev);
        ssize_t r = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
        if(r == 0)
            return 1;
        if(r < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
            return 1;
    }
    return 0;
}

/* 等对端 EOF (pump 驱动) */
static int wait_eof(int fd) {
    char buf[16];
    for(int i = 0; i < 400; i++) {
        if(g_ev) {
            sevent_wakeup(g_ev);
            sevent_run_once(g_ev);
        }
        ssize_t r = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
        if(r == 0)
            return 1; /* EOF */
        if(r < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
            return 1; /* 连接错误也算关闭 */
        struct timespec ts = {0, 1000 * 1000};
        nanosleep(&ts, NULL);
    }
    return 0;
}

/* ===== 用例 ===== */

static void t_basic_request(void) {
    g_cb_count = 0;
    int port   = server_start(60000);
    CHECK(port > 0, "server listen");
    int fd = tcp_connect_to((uint16_t)port);
    CHECK(fd >= 0, "client connect");
    if(fd >= 0) {
        const char *req = "GET /hello HTTP/1.1\r\nHost: x\r\n\r\n";
        CHECK(send_all(fd, req, strlen(req)) == 0, "send request");
        char buf[1024];
        int  n = recv_until(fd, buf, sizeof(buf), "hello");
        CHECK(n > 0, "got response");
        CHECK(strstr(buf, "HTTP/1.1 200 OK\r\n") != NULL, "status line");
        CHECK(strstr(buf, "Content-Type: text/plain\r\n") != NULL, "header injected");
        CHECK(strstr(buf, "Content-Length: 5\r\n") != NULL, "auto Content-Length");
        CHECK(strstr(buf, "hello") != NULL, "body echoed");
        CHECK(g_cb_count >= 2 && g_cb_type[0] == 0 && g_cb_type[1] == 1, "on_accept then on_request");
        close(fd);
    }
    server_stop();
}

static void t_keepalive_multi(void) {
    g_cb_count = 0;
    int port   = server_start(60000);
    int fd     = tcp_connect_to((uint16_t)port);
    CHECK(fd >= 0, "connect");
    if(fd >= 0) {
        /* 两个请求同一连接 (keep-alive: 默认保持) */
        const char *req1 = "GET /one HTTP/1.1\r\nHost: x\r\n\r\n";
        const char *req2 = "GET /two HTTP/1.1\r\nHost: x\r\n\r\n";
        CHECK(send_all(fd, req1, strlen(req1)) == 0, "send req1");
        char buf1[2048];
        int  n = recv_until(fd, buf1, sizeof(buf1), "hello");
        CHECK(n > 0 && strstr(buf1, "hello") != NULL, "resp1");
        CHECK(strstr(buf1, "Connection: close") == NULL, "resp1 不带 close (保持)");
        CHECK(send_all(fd, req2, strlen(req2)) == 0, "send req2");
        char buf2[2048];
        n = recv_until(fd, buf2, sizeof(buf2), "hello");
        CHECK(n > 0 && strstr(buf2, "hello") != NULL, "resp2 同一连接");
        /* 验证 on_request 触发两次 */
        int req_count = 0;
        for(int i = 0; i < g_cb_count; i++)
            if(g_cb_type[i] == 1)
                req_count++;
        CHECK(req_count == 2, "on_request x2 (got %d)", req_count);
        close(fd);
    }
    server_stop();
}

static void t_close_conditions(void) {
    /* ① 请求带 Connection: close → 响应带 close + 连接关 */
    g_cb_count = 0;
    int port   = server_start(60000);
    int fd     = tcp_connect_to((uint16_t)port);
    CHECK(fd >= 0, "connect");
    if(fd >= 0) {
        const char *req = "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
        CHECK(send_all(fd, req, strlen(req)) == 0, "send");
        char buf[1024];
        int  n = recv_until(fd, buf, sizeof(buf), "200");
        CHECK(n > 0 && strstr(buf, "Connection: close\r\n") != NULL, "close 注入");
        /* 服务端半关 → 客户端读到 EOF */
        CHECK(wait_eof(fd), "EOF after close");
        close(fd);
    }

    /* ③ 用户 close(conn) → 响应后关 */
    server_stop();
    g_cb_count = 0;
    port       = server_start(60000);
    fd         = tcp_connect_to((uint16_t)port);
    if(fd >= 0) {
        const char *req = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        CHECK(send_all(fd, req, strlen(req)) == 0, "send");
        char buf[1024];
        int  n = recv_until(fd, buf, sizeof(buf), "200");
        CHECK(n > 0, "got response");
        close(fd);
    }
    server_stop();
}

static void t_http10_close(void) {
    g_cb_count = 0;
    int port   = server_start(60000);
    int fd     = tcp_connect_to((uint16_t)port);
    CHECK(fd >= 0, "connect");
    if(fd >= 0) {
        const char *req = "GET / HTTP/1.0\r\n\r\n";
        CHECK(send_all(fd, req, strlen(req)) == 0, "send");
        char buf[1024];
        int  n = recv_until(fd, buf, sizeof(buf), "200");
        CHECK(n > 0 && strstr(buf, "Connection: close\r\n") != NULL, "1.0 自动关 (close 注入)");
        CHECK(wait_eof(fd), "EOF after 1.0");
        close(fd);
    }
    server_stop();
}

static void t_respond_close_field(void) {
    /* 关闭条件②: respond close=true → Connection: close 注入 + 半关 (EOF) */
    server_stop();
    g_cb_count      = 0;
    g_respond_close = 1;
    int port        = server_start(60000);
    CHECK(port > 0, "server listen");
    int fd = tcp_connect_to((uint16_t)port);
    CHECK(fd >= 0, "connect");
    if(fd >= 0) {
        const char *req = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        CHECK(send_all(fd, req, strlen(req)) == 0, "send");
        char buf[1024];
        int  n = recv_until(fd, buf, sizeof(buf), "hello");
        CHECK(n > 0 && strstr(buf, "Connection: close\r\n") != NULL, "close 字段注入");
        CHECK(wait_eof(fd), "EOF after close 字段 (半关)");
        close(fd);
    }
    g_respond_close = 0;
    server_stop();
}

static void t_bad_request_400(void) {
    g_cb_count = 0;
    int port   = server_start(60000);
    int fd     = tcp_connect_to((uint16_t)port);
    CHECK(fd >= 0, "connect");
    if(fd >= 0) {
        const char *bad = "GARBAGE\r\n\r\n";
        CHECK(send_all(fd, bad, strlen(bad)) == 0, "send garbage");
        char buf[1024];
        int  n = recv_until(fd, buf, sizeof(buf), "400");
        CHECK(n > 0 && strstr(buf, "HTTP/1.1 400 Bad Request\r\n") != NULL, "400 响应");
        CHECK(wait_eof(fd), "EOF after 400");
        close(fd);
    }
    server_stop();
}

static void t_headers_helpers(void) {
    sevent_http_response resp = {0};
    sevent_http_response_init(&resp);
    CHECK(sevent_http_response_header_set(&resp, "Content-Type", "a") == 0, "set1");
    CHECK(sevent_http_response_header_set(&resp, "Content-Type", "b") == 0, "set 覆盖");
    CHECK(sevent_http_response_header_add(&resp, "Set-Cookie", "x=1") == 0, "add1");
    CHECK(sevent_http_response_header_add(&resp, "Set-Cookie", "y=2") == 0, "add2");
    /* 查重: Content-Type 只有一个且值为 b */
    int ct = 0, sc = 0;
    for(sevent_http_header *h = resp.headers; h; h = h->next) {
        if(strcmp(h->name, "Content-Type") == 0) {
            ct++;
            CHECK(strcmp(h->value, "b") == 0, "覆盖后值为 b");
        }
        if(strcmp(h->name, "Set-Cookie") == 0)
            sc++;
    }
    CHECK(ct == 1, "Content-Type 查重 (got %d)", ct);
    CHECK(sc == 2, "Set-Cookie 可重复 (got %d)", sc);
    CHECK(sevent_http_response_header_del(&resp, "Set-Cookie") == 2, "del 删除 2 条");
    sevent_http_response_clear(&resp);
    CHECK(resp.headers == NULL, "clear 后空");
}

static void t_state_machine(void) {
    /* 状态机矩阵非法调用 (回调内断言 rc — 状态转换在 respond 内部完成):
     * 首次 respond 成功 (回 PARSING) → 重复 respond / 响应后 write /
     * 响应后 write_end 全部报错 (矩阵: 非法状态返回 SEVENT_ERR_INVAL) */
    server_stop();
    g_cb_count        = 0;
    g_matrix_mode     = 1;
    g_m_rc_respond_ok = g_m_rc_respond2 = g_m_rc_write = g_m_rc_write_end = 0;
    int port                                                              = server_start(60000);
    CHECK(port > 0, "server listen");
    int fd = tcp_connect_to((uint16_t)port);
    CHECK(fd >= 0, "connect");
    if(fd >= 0) {
        const char *req = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        CHECK(send_all(fd, req, strlen(req)) == 0, "send");
        char buf[1024];
        CHECK(recv_until(fd, buf, sizeof(buf), "hello") > 0, "response");
        CHECK(g_m_rc_respond_ok == 0, "首次 respond 成功 (rc=%d)", g_m_rc_respond_ok);
        CHECK(g_m_rc_respond2 != 0, "重复 respond 报错 (rc=%d)", g_m_rc_respond2);
        CHECK(g_m_rc_write != 0, "响应后 write 报错 (rc=%d)", g_m_rc_write);
        CHECK(g_m_rc_write_end != 0, "响应后 write_end 报错 (rc=%d)", g_m_rc_write_end);
        close(fd);
    }
    g_matrix_mode = 0;
    server_stop();
}

static void t_write_stream_sticky(void) {
    /* F1 回归: 回调内 write 流式 + 粘包两请求 — RESPONDING 态必须停 (主循环
     * 不能覆写 state 继续分派下一请求). 修复前: req1 响应截断 (CL:11 只发
     * 6 字节), req2 提前分派, 栈外续写失败 → 连接被关, 协议流损坏. */
    server_stop();
    g_cb_count        = 0;
    g_async_write_end = 1;
    int port          = server_start(60000);
    CHECK(port > 0, "server listen");
    int fd = tcp_connect_to((uint16_t)port);
    CHECK(fd >= 0, "connect");
    if(fd >= 0) {
        const char *r1 = "GET /one HTTP/1.1\r\nHost: x\r\n\r\n";
        const char *r2 = "GET /two HTTP/1.1\r\nHost: x\r\n\r\n";
        char        pkt[256];
        size_t      n = 0;
        memcpy(pkt + n, r1, strlen(r1));
        n += strlen(r1);
        memcpy(pkt + n, r2, strlen(r2));
        n += strlen(r2);
        CHECK(send_all(fd, pkt, n) == 0, "send 2 sticky (stream)");
        /* 两个完整响应 ("hello world" 11 字节 CL) — 修复前只有 1 个完整.
         * 累积缓冲: 流式响应的两次 write 可能拆成多个 TCP 段到达 */
        char   buf[2048];
        size_t bn  = 0;
        int    got = 0;
        for(int i = 0; i < 400 && got < 2 && bn < sizeof(buf) - 1; i++) {
            if(g_ev) {
                sevent_wakeup(g_ev);
                sevent_run_once(g_ev);
            }
            ssize_t r = recv(fd, buf + bn, sizeof(buf) - 1 - bn, MSG_DONTWAIT);
            if(r > 0) {
                bn             += (size_t)r;
                buf[bn]        = 0;
                const char *p2 = buf;
                while((p2 = strstr(p2, "hello world"))) {
                    got++;
                    p2 += 11;
                }
            }
            struct timespec ts = {0, 1000 * 1000};
            nanosleep(&ts, NULL);
        }
        CHECK(got == 2, "2 个完整流式响应 (got %d)", got);
        close(fd);
    }
    g_async_write_end = 0;
    server_stop();
}

static void t_upgrade_no_callback(void) {
    /* F3 回归: listen 未注册 on_upgrade → upgrade 请求必须明确拒绝 (400),
     * 不能静默消费挂到空闲超时 (客户端永远等不到应答) */
    server_stop();
    g_cb_count   = 0;
    g_no_upgrade = 1;
    int port     = server_start(60000);
    CHECK(port > 0, "server listen");
    int fd = tcp_connect_to((uint16_t)port);
    CHECK(fd >= 0, "connect");
    if(fd >= 0) {
        const char *req = "GET /chat HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";
        CHECK(send_all(fd, req, strlen(req)) == 0, "send upgrade");
        char buf[1024];
        int  n = recv_until(fd, buf, sizeof(buf), "400");
        CHECK(n > 0 && strstr(buf, "HTTP/1.1 400") != NULL, "400 拒绝");
        CHECK(wait_eof(fd), "EOF after 400");
        close(fd);
    }
    g_no_upgrade = 0;
    server_stop();
}

static void t_idle_timeout(void) {
    g_cb_count = 0;
    int port   = server_start(150); /* 150ms 空闲超时 */
    int fd     = tcp_connect_to((uint16_t)port);
    CHECK(fd >= 0, "connect");
    if(fd >= 0) {
        /* 不发请求 → 超时关连接 (客户端读到 EOF) — 自然等待让 select 超时推进 timer */
        CHECK(wait_eof_natural(fd), "idle timeout → EOF");
        /* on_conn_close 触发 */
        int cc = 0;
        for(int i = 0; i < g_cb_count; i++)
            if(g_cb_type[i] == 3)
                cc++;
        CHECK(cc >= 1, "on_conn_close fired (got %d)", cc);
        close(fd);
    }
    server_stop();
}

static void t_on_accept_reject(void) {
    /* on_accept 里 close → 连接立即关 (客户端 EOF) */
    server_stop();
    g_cb_count      = 0;
    g_reject_accept = 1;
    int port        = server_start(60000);
    int fd          = tcp_connect_to((uint16_t)port);
    CHECK(fd >= 0, "connect");
    if(fd >= 0) {
        CHECK(wait_eof(fd), "EOF (无响应)");
        close(fd);
    }
    g_reject_accept = 0;
    server_stop();
}

static void t_write_path_keepalive(void) {
    /* 回调内 write 路径完成 (write_end 转 PARSING) 后, 下一请求数据必须被处理 */
    server_stop();
    g_cb_count       = 0;
    g_use_write_path = 1;
    int port         = server_start(60000);
    int fd           = tcp_connect_to((uint16_t)port);
    CHECK(fd >= 0, "connect");
    if(fd >= 0) {
        const char *req1 = "GET /one HTTP/1.1\r\nHost: x\r\n\r\n";
        const char *req2 = "GET /two HTTP/1.1\r\nHost: x\r\n\r\n";
        CHECK(send_all(fd, req1, strlen(req1)) == 0, "send req1");
        char buf1[2048];
        CHECK(recv_until(fd, buf1, sizeof(buf1), "hello") > 0, "resp1 (write 路径)");
        CHECK(strstr(buf1, "Content-Length: 5\r\n") != NULL, "write 路径头自管 (CL 用户拼)");
        CHECK(send_all(fd, req2, strlen(req2)) == 0, "send req2");
        char buf2[2048];
        CHECK(recv_until(fd, buf2, sizeof(buf2), "hello") > 0, "resp2 同一连接 (write_end 后处理)");
        close(fd);
    }
    g_use_write_path = 0;
    server_stop();
}

static void t_multi_requests(void) {
    /* 3 个请求一起发 (粘包) + 第 4 个后发 — 验证多轮 keep-alive 状态机 */
    server_stop();
    g_cb_count = 0;
    int port   = server_start(60000);
    int fd     = tcp_connect_to((uint16_t)port);
    CHECK(fd >= 0, "connect");
    if(fd >= 0) {
        const char *r1 = "GET /a HTTP/1.1\r\nHost: x\r\n\r\n";
        const char *r2 = "GET /b HTTP/1.1\r\nHost: x\r\n\r\n";
        const char *r3 = "GET /c HTTP/1.1\r\nHost: x\r\n\r\n";
        const char *r4 = "GET /d HTTP/1.1\r\nHost: x\r\n\r\n";
        /* 粘包: 前 3 个请求一次发送 */
        char        pkt[512];
        int         n = 0;
        n             += (int)strlen(r1);
        memcpy(pkt + n - (int)strlen(r1), r1, strlen(r1));
        n += (int)strlen(r2);
        memcpy(pkt + n - (int)strlen(r2), r2, strlen(r2));
        n += (int)strlen(r3);
        memcpy(pkt + n - (int)strlen(r3), r3, strlen(r3));
        CHECK(send_all(fd, pkt, (size_t)n) == 0, "send 3 requests (sticky)");
        /* 等 3 个响应 (累计出现 3 次 hello) */
        char buf[4096];
        int  got = 0;
        for(int i = 0; i < 400 && got < 3; i++) {
            if(g_ev) {
                sevent_wakeup(g_ev);
                sevent_run_once(g_ev);
            }
            ssize_t r = recv(fd, buf, sizeof(buf) - 1, MSG_DONTWAIT);
            if(r > 0) {
                buf[r]         = 0;
                const char *p2 = buf;
                while((p2 = strstr(p2, "hello"))) {
                    got++;
                    p2 += 5;
                }
            }
            struct timespec ts = {0, 1000 * 1000};
            nanosleep(&ts, NULL);
        }
        CHECK(got == 3, "3 sticky responses (got %d)", got);
        /* 第 4 个请求 */
        CHECK(send_all(fd, r4, strlen(r4)) == 0, "send req4");
        char buf2[1024];
        CHECK(recv_until(fd, buf2, sizeof(buf2), "hello") > 0, "resp4 (第 4 轮)");
        /* on_request 4 次 */
        int req_count = 0;
        for(int i = 0; i < g_cb_count; i++)
            if(g_cb_type[i] == 1)
                req_count++;
        CHECK(req_count == 4, "on_request x4 (got %d)", req_count);
        close(fd);
    }
    server_stop();
}

static void t_many_sticky(void) {
    /* 大量请求一次粘包发送 — 验证主循环迭代 (无递归爆栈, 恶意客户端场景) */
    server_stop();
    g_cb_count = 0;
    int port   = server_start(60000);
    int fd     = tcp_connect_to((uint16_t)port);
    CHECK(fd >= 0, "connect");
    if(fd >= 0) {
        /* 100 个请求拼一个包 */
        enum { N = 100 };
        char   pkt[32 * N];
        size_t n = 0;
        for(int i = 0; i < N; i++) {
            const char *r = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
            memcpy(pkt + n, r, strlen(r));
            n += strlen(r);
        }
        CHECK(send_all(fd, pkt, n) == 0, "send 100 sticky requests");
        /* 等 100 个响应 (累计 hello 出现 100 次) */
        char buf[8192];
        int  got = 0;
        for(int i = 0; i < 400 && got < N; i++) {
            if(g_ev) {
                sevent_wakeup(g_ev);
                sevent_run_once(g_ev);
            }
            ssize_t r = recv(fd, buf, sizeof(buf) - 1, MSG_DONTWAIT);
            if(r > 0) {
                buf[r]         = 0;
                const char *p2 = buf;
                while((p2 = strstr(p2, "hello"))) {
                    got++;
                    p2 += 5;
                }
            }
            struct timespec ts = {0, 1000 * 1000};
            nanosleep(&ts, NULL);
        }
        CHECK(got == N, "100 sticky responses (got %d)", got);
        close(fd);
    }
    server_stop();
}

static void t_async_sticky(void) {
    /* 异步响应 (栈外 post respond) + 粘包: 残留必须在异步 respond 时处理
     * (客户端不会再发数据 — 不处理则挂起). 两个请求粘包发送. */
    server_stop();
    g_cb_count   = 0;
    g_async_mode = 1;
    int port     = server_start(60000);
    int fd       = tcp_connect_to((uint16_t)port);
    CHECK(fd >= 0, "connect");
    if(fd >= 0) {
        const char *r1 = "GET /a HTTP/1.1\r\nHost: x\r\n\r\n";
        const char *r2 = "GET /b HTTP/1.1\r\nHost: x\r\n\r\n";
        char        pkt[256];
        int         n = 0;
        n             += (int)strlen(r1);
        memcpy(pkt, r1, strlen(r1));
        n += (int)strlen(r2);
        memcpy(pkt + strlen(r1), r2, strlen(r2));
        CHECK(send_all(fd, pkt, (size_t)n) == 0, "send 2 sticky (async)");
        char buf[2048];
        int  got = 0;
        for(int i = 0; i < 400 && got < 2; i++) {
            if(g_ev) {
                sevent_wakeup(g_ev);
                sevent_run_once(g_ev);
            }
            ssize_t r = recv(fd, buf, sizeof(buf) - 1, MSG_DONTWAIT);
            if(r > 0) {
                buf[r]         = 0;
                const char *p2 = buf;
                while((p2 = strstr(p2, "hello"))) {
                    got++;
                    p2 += 5;
                }
            }
            struct timespec ts = {0, 1000 * 1000};
            nanosleep(&ts, NULL);
        }
        CHECK(got == 2, "2 async responses (got %d) — 残留处理必须由异步 respond 启动", got);
        close(fd);
    }
    g_async_mode = 0;
    server_stop();
}

static void t_budget_yield_close(void) {
    /* budget 让出 (post 排队) 后连接立即关闭 — http_process_post 执行时
     * state==CLOSED → return, 无 UAF (post FIFO + free 也是 post) */
    server_stop();
    g_cb_count = 0;
    int port   = server_start(60000);
    int fd     = tcp_connect_to((uint16_t)port);
    CHECK(fd >= 0, "connect");
    if(fd >= 0) {
        /* 超 budget 的粘包请求 (>64) — 触发让出 */
        enum { N = 80 };
        char   pkt[32 * N];
        size_t n = 0;
        for(int i = 0; i < N; i++) {
            const char *r = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
            memcpy(pkt + n, r, strlen(r));
            n += strlen(r);
        }
        CHECK(send_all(fd, pkt, n) == 0, "send 80 sticky");
        close(fd); /* 立即断开 — 让出 post 排队期间连接关闭 */
        /* 推进事件循环: 让出 post 在 CLOSED 连接上执行 (不应崩溃) */
        for(int i = 0; i < 50; i++) {
            if(g_ev) {
                sevent_wakeup(g_ev);
                sevent_run_once(g_ev);
            }
            struct timespec ts = {0, 1000 * 1000};
            nanosleep(&ts, NULL);
        }
    }
    server_stop();
}

static void t_destroy_sticky_uaf(void) {
    /* UAF 回归: 回调内 destroy + 超 budget 粘包.
     * 时序: 首请求回调内 destroy → srv_cleanup 入队 → 主循环继续处理剩余请求
     * → budget(64) 耗尽 → http_process_post 入队 (排在 srv_cleanup 之后).
     * 同轮 run_posts FIFO: srv_cleanup (置 CLOSED + on_conn_close + 延迟释放)
     * → http_process_post (读到 CLOSED 直接返回) → conn_cleanup (free).
     * 修复前: srv_cleanup 同步 free → http_process_post 读已释放 state (UAF, ASAN 抓). */
    server_stop();
    g_cb_count         = 0;
    g_conn_close_count = 0;
    g_destroy_on_first = 1;
    g_destroy_done     = 0;
    int port           = server_start(60000);
    int fd             = tcp_connect_to((uint16_t)port);
    CHECK(fd >= 0, "connect");
    if(fd >= 0) {
        enum { N = 80 };
        char   pkt[32 * N];
        size_t n = 0;
        for(int i = 0; i < N; i++) {
            const char *r = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
            memcpy(pkt + n, r, strlen(r));
            n += strlen(r);
        }
        CHECK(send_all(fd, pkt, n) == 0, "send 80 sticky");
        CHECK(wait_eof(fd), "EOF after destroy (server 关闭连接)");
        CHECK(g_conn_close_count >= 1, "destroy → on_conn_close (got %d)", g_conn_close_count);
        close(fd);
    }
    g_destroy_on_first = 0;
    server_stop();
}

static void t_destroy_notify(void) {
    /* destroy server: 未完成连接逐个触发 on_conn_close (用户清理持有的引用) + 关闭.
     * 回归: 修复前 srv_cleanup 静默 free, 用户持有的 conn 引用悬垂无通知. */
    server_stop();
    g_cb_count         = 0;
    g_conn_close_count = 0;
    int port           = server_start(60000);
    int fd             = tcp_connect_to((uint16_t)port);
    CHECK(fd >= 0, "connect");
    if(fd >= 0) {
        /* 确定性等待: 连接建立 (on_accept 触发) 后再 destroy — 否则连接未入
         * 列表, srv_cleanup 扫不到 (泄漏) */
        pump_until(conn_established);
        sevent_http_server_destroy(g_srv);
        g_srv = NULL; /* 防 server_stop 重复 destroy */
        CHECK(wait_eof(fd), "EOF after destroy");
        CHECK(g_conn_close_count >= 1, "destroy → on_conn_close (got %d)", g_conn_close_count);
        close(fd);
    }
    server_stop();
}

static void t_write_end_async(void) {
    /* 回调内 write 开始流式 → 回调返回 (REQUEST→RESPONDING) → 栈外 write_end 收尾.
     * 回归: 修复前回调返回落 AWAIT_RESP, 栈外 write_end 报错 → 响应悬挂. */
    server_stop();
    g_cb_count        = 0;
    g_async_write_end = 1;
    int port          = server_start(60000);
    int fd            = tcp_connect_to((uint16_t)port);
    CHECK(fd >= 0, "connect");
    if(fd >= 0) {
        const char *req = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        CHECK(send_all(fd, req, strlen(req)) == 0, "send");
        char buf[1024];
        int  n = recv_until(fd, buf, sizeof(buf), "hello world");
        CHECK(n > 0, "跨回调 write_end 完整响应 (got %d)", n);
        /* keep-alive: write_end 后回 PARSING, 下一请求同连接 */
        const char *req2 = "GET /two HTTP/1.1\r\nHost: x\r\n\r\n";
        CHECK(send_all(fd, req2, strlen(req2)) == 0, "send req2");
        n = recv_until(fd, buf, sizeof(buf), "hello");
        CHECK(n > 0, "resp2 同一连接");
        close(fd);
    }
    g_async_write_end = 0;
    server_stop();
}

static void t_write_respond_mutex(void) {
    /* write 后 respond 互斥: 回调内先 write 再 respond → respond 报错.
     * 回归: 修复前 REQUEST 态缺"已写"区分 → respond 成功 → 裸数据 + 完整
     * 响应头混入队列 (协议损坏). */
    server_stop();
    g_cb_count                = 0;
    g_try_respond_after_write = 1;
    g_write_respond_rc        = 0;
    int port                  = server_start(60000);
    int fd                    = tcp_connect_to((uint16_t)port);
    CHECK(fd >= 0, "connect");
    if(fd >= 0) {
        const char *req = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        CHECK(send_all(fd, req, strlen(req)) == 0, "send");
        char buf[1024];
        CHECK(recv_until(fd, buf, sizeof(buf), "hello") > 0, "write 路径响应 (write_end 收尾)");
        CHECK(g_write_respond_rc != 0, "respond 被拒 (write 后互斥, rc=%d)", g_write_respond_rc);
        close(fd);
    }
    g_try_respond_after_write = 0;
    server_stop();
}

static void t_hang_overflow(void) {
    /* D1 行为契约: 异步挂起 (AWAIT_RESP) + 缓冲溢出 → 关连接, 不二次分派.
     * 构造: 请求1 (小, 回调挂起) + 请求2 (大, 完整) 粘包一次发送 (≤ 4096
     * 接收缓冲) → 请求1 挂起, 残留请求2 → 触发数据使缓冲溢出 → 溢出分支
     * state!=PARSING → 半关. 断言: 请求回调仅 1 次 + 连接 EOF. */
    int port = server_start(60000);
    CHECK(port > 0, "server listen");
    g_hang_mode = 1;
    g_cb_count  = 0;
    int fd      = tcp_connect_to((uint16_t)port);
    CHECK(fd >= 0, "connect");
    if(fd >= 0) {
        char req1[] = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        char req2[4100];
        int  n = snprintf(req2, sizeof(req2), "GET /big HTTP/1.1\r\nHost: x\r\n");
        for(int i = 0; i < 39; i++)
            n += snprintf(req2 + n, sizeof(req2) - (size_t)n, "X-Big-%02d: %-90s\r\n", i, "a");
        n            += snprintf(req2 + n, sizeof(req2) - (size_t)n, "\r\n");
        size_t s2    = (size_t)n;
        size_t total = sizeof(req1) - 1 + s2;
        CHECK(total <= 4096, "sticky fits recv buf (total=%zu)", total);
        char *pkt = (char *)malloc(total);
        CHECK(pkt != NULL, "pkt alloc");
        if(pkt) {
            memcpy(pkt, req1, sizeof(req1) - 1);
            memcpy(pkt + sizeof(req1) - 1, req2, s2);
            CHECK(send_all(fd, pkt, total) == 0, "send sticky");
            free(pkt);
        }
        /* 请求1 挂起 (AWAIT_RESP), 残留请求2 占缓冲 */
        pump_until(req1_hung);
        CHECK(g_cb_count == 2 && g_cb_type[1] == 1, "request1 dispatched once");
        /* 触发数据: 使残留+新数据溢出接收缓冲 */
        char trig[128];
        memset(trig, 't', sizeof(trig));
        CHECK(send_all(fd, trig, sizeof(trig)) == 0, "send trigger");
        /* 溢出 → 半关 → EOF; 请求2 不得被分派 */
        CHECK(wait_eof(fd) == 1, "connection closed by overflow");
        CHECK(g_cb_count == 2, "request2 NOT dispatched (count=%d)", g_cb_count);
        close(fd);
    }
    g_hang_mode = 0;
    server_stop();
}

static void t_header_rules(void) {
    /* D5: 自动头注入规则 —
     * 204/304 不注入 CL (RFC 9110 §8.6.1 MUST NOT); 200 空 body 仍注入 CL:0
     * (keep-alive 响应终止边界); 用户显式设置 CL/Connection → 库跳过注入
     * (不生成重复头, RFC 9112 §6.3); 204 + body → respond 返回 INVAL. */
    int port = server_start(60000);
    CHECK(port > 0, "server listen");
    static const char *req = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
    static const struct {
        int         mode;
        const char *has;
        const char *not_has;
    } cases[] = {
            {1, "HTTP/1.1 204 No Content", "Content-Length"},
            {2, "HTTP/1.1 304 Not Modified", "Content-Length"},
            {3, "Content-Length: 0", NULL},
            {4, "Content-Length: 99", "Content-Length: 1"},
            {5, "Connection: keep-alive", "Connection: close"},
    };
    for(size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        g_resp_mode = cases[i].mode;
        g_cb_count  = 0;
        int fd      = tcp_connect_to((uint16_t)port);
        CHECK(fd >= 0, "connect");
        if(fd >= 0) {
            CHECK(send_all(fd, req, strlen(req)) == 0, "send");
            char buf[1024];
            int  n = recv_until(fd, buf, sizeof(buf), "\r\n\r\n");
            CHECK(n > 0, "got response");
            CHECK(strstr(buf, cases[i].has) != NULL, "expect: %s", cases[i].has);
            if(cases[i].not_has)
                CHECK(strstr(buf, cases[i].not_has) == NULL, "not expect: %s", cases[i].not_has);
            close(fd);
        }
    }
    /* 204 + body → INVAL (协议禁止, 错误显性化) */
    g_resp_mode       = 6;
    g_cb_count        = 0;
    g_m_rc_respond_ok = 0;
    int fd            = tcp_connect_to((uint16_t)port);
    CHECK(fd >= 0, "connect 204+body");
    if(fd >= 0) {
        CHECK(send_all(fd, req, strlen(req)) == 0, "send");
        pump_until(resp_rc_set);
        CHECK(g_m_rc_respond_ok == SEVENT_ERR_INVAL, "204+body → INVAL (rc=%d)", g_m_rc_respond_ok);
        close(fd);
    }
    g_resp_mode = 0;
    server_stop();
}

/* ===== 注册 ===== */

typedef struct {
    const char *n;
    void (*f)(void);
} test_entry;

static const test_entry tests[] = {
        {"basic_request", t_basic_request},
        {"keepalive_multi", t_keepalive_multi},
        {"close_conditions", t_close_conditions},
        {"http10_close", t_http10_close},
        {"respond_close_field", t_respond_close_field},
        {"bad_request_400", t_bad_request_400},
        {"headers_helpers", t_headers_helpers},
        {"state_machine", t_state_machine},
        {"write_stream_sticky", t_write_stream_sticky},
        {"upgrade_no_callback", t_upgrade_no_callback},
        {"write_path_keepalive", t_write_path_keepalive},
        {"multi_requests", t_multi_requests},
        {"many_sticky", t_many_sticky},
        {"async_sticky", t_async_sticky},
        {"budget_yield_close", t_budget_yield_close},
        {"destroy_sticky_uaf", t_destroy_sticky_uaf},
        {"destroy_notify", t_destroy_notify},
        {"write_end_async", t_write_end_async},
        {"write_respond_mutex", t_write_respond_mutex},
        {"idle_timeout", t_idle_timeout},
        {"on_accept_reject", t_on_accept_reject},
        {"hang_overflow", t_hang_overflow},
        {"header_rules", t_header_rules},
        {NULL, NULL},
};

int main(void) {
    setbuf(stdout, NULL);
    printf("http_server tests (sevent_http_server 服务器层)\n");
    printf("===============================================\n");
    for(int i = 0; tests[i].n; i++) {
        printf("  %-24s ", tests[i].n);
        int             before = g_fail;
        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        tests[i].f();
        clock_gettime(CLOCK_MONOTONIC, &t1);
        double sec = (double)(t1.tv_sec - t0.tv_sec) + (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;
        printf("%s [%.1fs]\n", g_fail == before ? "✓" : "×", sec);
    }
    if(g_fail) {
        printf("%d FAILED\n", g_fail);
        return 1;
    }
    printf("all passed\n");
    return 0;
}
