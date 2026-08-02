/**
 *  http_server.c — HTTP 服务器 (sevent_http_server)
 *
 *  功能: 监听 8080 端口, 处理 GET 请求 — 演示 HTTP 服务器层 (keep-alive)
 *  用法: make example-http-server && ./example-http-server
 *        curl http://127.0.0.1:8080/
 *        curl http://127.0.0.1:8080/hello
 *        curl http://127.0.0.1:8080/async        # 异步响应: 1 秒后应答
 *        curl http://127.0.0.1:8080/{/,hello}    # 单连接连发 (keep-alive)
 *        curl http://127.0.0.1:8080/nope         # 404
 *        curl -X POST http://127.0.0.1:8080/     # 405
 *
 *  演示点:
 *    - 服务器类: create(配置) → listen(5 回调) → destroy — 与 tcp_acceptor 同构
 *    - 声明式响应: 结构体 + header_set 辅助函数, http 层自动 Content-Length /
 *      Connection: close 注入; text=NULL 时状态文本查表 (200→OK, 404→Not Found...)
 *    - keep-alive: 响应完成后自动处理下一请求 (HTTP/1.1 默认保持, 单连接多请求)
 *    - 异步响应: 回调返回不 respond → 连接进异步窗口, timer 到期后 respond
 *      完成 — 响应顺序仍与请求顺序一致 (同一连接请求串行)
 *    - 生命周期管理: 异步挂起中连接被关 → on_conn_close 清理挂起上下文
 *      (取消 timer + 释放) — 回调外持有的 conn 引用必须注销, 否则 UAF
 *    - on_accept 拒绝: 连接数上限 (黑名单/限流场景)
 */

#include "sevent.h"
#include "sevent_http_server.h"
#include "sevent_stream_conn.h" /* get_stream 返回类型 + set_no_delay */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PORT 8080
#define MAX_CONNS_DEFAULT 32

static sevent_context *g_ctx;
static int             g_conns;                         /* 活跃连接数 */
static int             g_max_conns = MAX_CONNS_DEFAULT; /* 连接数上限 (argv[1] 可调, 压测用) */

/* ---- 异步响应上下文 (演示回调外持有 conn 引用的生命周期管理) ---- */

struct async_ctx {
    sevent_http_conn *conn;  /* 连接引用 (respond 用) */
    sevent_timer     *timer; /* 响应定时器 */
    struct async_ctx *next;
};

static struct async_ctx *g_asyncs; /* example 全局链表; 真实服务可按 conn 哈希 */

static void async_detach(struct async_ctx *a) {
    /* 摘链表 + 注销 timer (防 timer 再触发持死引用) */
    struct async_ctx **pp = &g_asyncs;
    while(*pp && *pp != a)
        pp = &(*pp)->next;
    if(*pp)
        *pp = a->next;
    if(a->timer) {
        sevent_timer_unregister(g_ctx, a->timer);
        a->timer = NULL;
    }
    free(a);
}

static void on_async_timer(void *d) {
    struct async_ctx *a = (struct async_ctx *)d;

    static const char    body[] = "Hello, one second later!\n";
    sevent_http_response resp;
    sevent_http_response_init(&resp);
    resp.status   = 200;
    resp.body     = body;
    resp.body_len = sizeof(body) - 1;

    /* 连接可能已关闭 (用户 close / 空闲超时): respond 返回错误 — 静默即可.
     * 注意: 无论成败 resp 头节点都已释放 (调用后即弃), 无需再 clear. */
    (void)sevent_http_conn_respond(a->conn, &resp);
    async_detach(a);
}

/* ---- 连接回调 ---- */

static void on_accept(void *ud, sevent_http_conn *conn) {
    (void)ud;
    /* HTTP 小包请求-响应交替: 按需开 TCP_NODELAY (默认关).
     * 经 get_stream 取底层 stream 直接设置 (http 层不重复封装传输能力) */
    sevent_stream_set_no_delay(sevent_http_conn_get_stream(conn), true);
    if(g_conns >= g_max_conns) {
        /* 拒绝: 连接数上限 — 半关 (已入队数据发完 + FIN), 等对端 EOF */
        printf("[http] reject: too many conns\n");
        sevent_http_conn_close(conn);
        return;
    }
    g_conns++;
    printf("[http] accept (%d active)\n", g_conns);
}

static void respond_text(sevent_http_conn *conn, int status, const char *body) {
    sevent_http_response resp;
    sevent_http_response_init(&resp);
    resp.status   = status;
    resp.body     = body;
    resp.body_len = strlen(body);
    (void)sevent_http_conn_respond(conn, &resp);
}

static void on_request(void *ud, const sevent_http_msg *req, sevent_http_conn *conn) {
    (void)ud;
    /* 预解析字段 (语法层填好): method 枚举 / target / keep_alive... 其余头按需
     * sevent_http_find_header 惰性扫描. target 拆 path/query 用辅助函数. */
    if(req->method != HTTP_METHOD_GET) {
        respond_text(conn, 405, "Method Not Allowed\n");
        return;
    }

    const char *path;
    size_t      path_len;
    sevent_http_target_split(req->target, req->target_len, &path, &path_len, NULL, NULL);

    if(path_len == 1 && path[0] == '/') {
        const char          *body = "Hello from libsevent HTTP server!\n"
                                    "Try: curl http://127.0.0.1:8080/hello\n";
        sevent_http_response resp;
        sevent_http_response_init(&resp);
        resp.status   = 200;
        resp.body     = body;
        resp.body_len = strlen(body);
        /* 头辅助函数: 库管理链表, set 同名查重覆盖 */
        sevent_http_response_header_set(&resp, "Content-Type", "text/plain");
        sevent_http_response_header_set(&resp, "X-Powered-By", "libsevent");
        (void)sevent_http_conn_respond(conn, &resp);
        return;
    }
    if(sevent_http_str_eq(path, path_len, "/hello")) {
        respond_text(conn, 200, "Hello, World!\n");
        return;
    }
    if(sevent_http_str_eq(path, path_len, "/async")) {
        /* 异步响应: 不 respond, 挂 timer — 连接进异步窗口 (AWAIT_RESP).
         * 期间本连接请求串行: 下一请求等本响应完成后再处理. */
        struct async_ctx *a = (struct async_ctx *)calloc(1, sizeof(*a));
        if(!a) {
            respond_text(conn, 500, "Out of memory\n");
            return;
        }
        a->conn  = conn;
        a->timer = sevent_timer_register(g_ctx, 1000, on_async_timer, a);
        if(!a->timer) {
            free(a);
            respond_text(conn, 500, "Out of memory\n");
            return;
        }
        a->next  = g_asyncs;
        g_asyncs = a;
        printf("[http] async pending\n");
        return; /* 回调返回未响应 — http 层等 respond */
    }
    respond_text(conn, 404, "Not Found\n");
}

static void on_conn_close(void *ud, sevent_http_conn *conn) {
    (void)ud;
    /* 连接关闭: 清理挂起在该连接上的异步上下文 — 回调外引用必须注销 */
    struct async_ctx *a = g_asyncs;
    while(a) {
        struct async_ctx *next = a->next;
        if(a->conn == conn)
            async_detach(a);
        a = next;
    }
    if(g_conns > 0)
        g_conns--;
    printf("[http] conn closed (%d active)\n", g_conns);
}

static void on_error(void *ud, int err) {
    (void)ud;
    fprintf(stderr, "[http] transport error: %d\n", err);
}

/* ---- main ---- */

int main(int argc, char **argv) {
    if(argc > 1)
        g_max_conns = atoi(argv[1]); /* 连接数上限 (压测: 传大值放开) */
    g_ctx = sevent_create();
    if(!g_ctx) {
        fprintf(stderr, "sevent_create failed\n");
        return 1;
    }
    sevent_ignore_sigpipe();

    /* 配置: 全默认即可 — recv_buf_size 0=4096, idle_timeout_ms 0=60s.
     * TCP_NODELAY 在 on_accept 里按需设置 (见上) */
    sevent_http_server_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    /* TLS (wss): cfg.enable_tls = true + cert_path/key_path — 本例仅明文 */

    sevent_http_server *srv = sevent_http_server_create(g_ctx, &cfg);
    if(!srv) {
        fprintf(stderr, "create failed\n");
        sevent_destroy(g_ctx);
        return 1;
    }
    /* 回调组: on_request 必填其一 (on_upgrade 本例不提供 — ws 升级见 ws 示例) */
    if(sevent_http_server_listen(
               srv, "127.0.0.1", PORT, 8, on_accept, on_request, NULL, on_conn_close, on_error, NULL) < 0) {
        fprintf(stderr, "listen %d failed\n", PORT);
        return 1;
    }

    printf("HTTP server listening on 127.0.0.1:%d\n", PORT);
    printf("  try: curl http://127.0.0.1:%d/\n", PORT);
    printf("  try: curl http://127.0.0.1:%d/hello\n", PORT);
    printf("  try: curl http://127.0.0.1:%d/async   (1s 异步响应)\n", PORT);
    printf("  keep-alive: curl http://127.0.0.1:%d/{/,hello} 单连接连发\n", PORT);
    printf("  (Ctrl-C to stop)\n\n");

    sevent_run(g_ctx);

    sevent_http_server_destroy(srv);
    sevent_destroy(g_ctx);
    return 0;
}
