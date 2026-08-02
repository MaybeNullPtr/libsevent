/* test_ws_wss.c — wss 端到端 (ws 层 enable_tls → stream TLS 链路)
 *
 * 服务端: tls_conn 公开 API 做 TLS 回显 (不懂 ws 帧 — 回显明文, ws 帧在
 *         TLS 明文层原样往返, 客户端自行解析).
 * 客户端: sevent_ws_connect(enable_tls=true) 完整 ws 流程.
 * 验证: TLS 握手 + 证书验证失败 + hostname 不匹配 → ws 错误码映射.
 */
#include "sevent.h"
#include "sevent_ws.h"
#include "sevent_tcp_acceptor.h"
#include "sevent_tls_conn.h"
#include "websockets/ws_sha1.h"
#include "websockets/ws_base64.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef SEVENT_WS_TLS

#ifndef TEST_CERTS_DIR
#error "TEST_CERTS_DIR 未定义 (CMake 注入)"
#endif
#define CERT_DIR TEST_CERTS_DIR

/* ---- 全局状态 ---- */
static sevent_context      *g_ev;
static sevent_tcp_acceptor *g_acc;
static sevent_tls_conn     *g_srv_conn;
static int                  g_ev_open;
static int                  g_ev_msg;
static int                  g_ev_error;
static int                  g_ev_error_code;
static char                 g_msg[512];
static size_t               g_msg_len;

/* ---- TLS 回显服务端 (tls_conn 公开 API) ----
 * 首包是 ws HTTP 升级请求: 解析 Sec-WebSocket-Key → 回 101 响应;
 * 之后的数据是 ws 帧, 原样回显 (回显层不懂 ws 帧, 帧在明文层往返). */
static int  g_srv_http_done;
static void srv_on_open(void *d) { (void)d; }
static void srv_on_data(void *d, const uint8_t *data, size_t len) {
    sevent_tls_conn *c = (sevent_tls_conn *)d;
    if(!g_srv_http_done) {
        /* 等完整 HTTP 请求 (含空行) 再回 101 — 半包时只回 101 会把头残余
         * 当 ws 帧回显, 客户端帧解析错乱 */
        const char *end = strstr((const char *)data, "\r\n\r\n");
        if(!end)
            return;
        const char *p = strstr((const char *)data, "Sec-WebSocket-Key: ");
        if(!p)
            return;
        p             += 19;
        const char *e = strstr(p, "\r\n");
        if(!e || e >= end)
            return;
        char   key[64];
        size_t kl = (size_t)(e - p);
        if(kl >= sizeof(key))
            return;
        memcpy(key, p, kl);
        key[kl]                  = 0;
        /* accept = base64(sha1(key + GUID)) */
        static const char GUID[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        char              input[64 + sizeof(GUID) - 1];
        memcpy(input, key, kl);
        memcpy(input + kl, GUID, sizeof(GUID) - 1);
        uint8_t digest[WS_SHA1_DIGEST_SIZE];
        ws_sha1(input, kl + sizeof(GUID) - 1, digest);
        char   accept[64];
        size_t al = ws_base64_encode(digest, sizeof(digest), accept, sizeof(accept));
        if(al == 0)
            return;
        char resp[512];
        int  rn = snprintf(resp,
                          sizeof(resp),
                          "HTTP/1.1 101 Switching Protocols\r\n"
                           "Upgrade: websocket\r\n"
                           "Connection: Upgrade\r\n"
                           "Sec-WebSocket-Accept: %s\r\n\r\n",
                          accept);
        if(rn > 0)
            (void)sevent_tls_conn_write(c, resp, (size_t)rn);
        g_srv_http_done      = 1;
        /* 粘包: 请求头后的 ws 帧一并回显 */
        const uint8_t *after = (const uint8_t *)end + 4;
        if(after < data + len)
            (void)sevent_tls_conn_write(c, after, (size_t)(data + len - after));
        return;
    }
    (void)sevent_tls_conn_write(c, data, len); /* 回显 */
}
static void srv_on_close(void *d) { (void)d; }
static void srv_on_error(void *d, int err) {
    (void)d;
    (void)err;
    sevent_tls_conn_destroy((sevent_tls_conn *)d); /* 握手失败收尾 */
    g_srv_conn = NULL;
}
static void on_accept(void *d, int fd) {
    (void)d;
    static const sevent_stream_conn_config cfg = {
            .enable_tls = true,
            .cert_path  = CERT_DIR "/server.pem",
            .key_path   = CERT_DIR "/server.key",
    };
    g_srv_http_done = 0; /* 每连接重置升级状态 */
    g_srv_conn      = sevent_tls_conn_create(g_ev, &cfg);
    if(!g_srv_conn) {
        close(fd);
        return;
    }
    sevent_stream_conn_init init = {.user_data = g_srv_conn,
                                    .on_open   = srv_on_open,
                                    .on_data   = srv_on_data,
                                    .on_close  = srv_on_close,
                                    .on_error  = srv_on_error};
    if(sevent_tls_conn_accept(g_srv_conn, fd, &init) < 0)
        g_srv_conn = NULL;
}

static void flush_posts(sevent_context *ev) {
    for(int i = 0; i < 1000; i++) {
        int post_count = -1;
        sevent_get_counts(ev, NULL, NULL, &post_count);
        if(post_count <= 0)
            return;
        sevent_wakeup(ev);
        sevent_run_once(ev);
    }
}

/* ---- 客户端回调 ---- */
static sevent_ws_conn *g_ws;
static void            cli_on_open(void *d) {
    (void)d;
    g_ev_open = 1;
    if(sevent_ws_send_text(g_ws, "hello wss", 9) != SEVENT_SUCCESS)
        g_ev_error = 1;
}
static void cli_on_message(void *d, const void *m, size_t l, bool b, bool fin, uint64_t total) {
    (void)d;
    (void)b;
    (void)fin;
    (void)total;
    size_t c = l < sizeof(g_msg) ? l : sizeof(g_msg) - 1;
    memcpy(g_msg, m, c);
    g_msg_len = c;
    g_msg[c]  = 0;
    g_ev_msg  = 1;
}
static void cli_on_close(void *d, uint16_t code, const char *reason, size_t reason_len) {
    (void)d;
    (void)code;
    (void)reason;
    (void)reason_len;
}
static void cli_on_error(void *d, int err) {
    (void)d;
    g_ev_error      = 1;
    g_ev_error_code = err;
}

/* ---- 用例 ---- */

static int t_wss_echo(void) {
    /* 完整链路: TLS 握手 (证书链验证 + hostname) → ws 握手 → 消息往返 */
    sevent_context *ev = sevent_create();
    if(!ev)
        return 1;
    g_ev  = ev;
    g_acc = sevent_tcp_acceptor_create(ev);
    if(!g_acc)
        return 1;
    if(sevent_tcp_acceptor_listen(g_acc, "127.0.0.1", 0, 8, on_accept, NULL) < 0)
        return 1;
    int port  = sevent_tcp_acceptor_port(g_acc);
    g_ev_open = g_ev_msg = g_ev_error = 0;
    g_ev_error_code                   = 0;
    g_msg_len                         = 0;
    sevent_ws_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host                   = "127.0.0.1";
    cfg.port                   = (uint16_t)port;
    cfg.path                   = "/";
    cfg.enable_tls             = true;
    cfg.ca_path                = CERT_DIR "/ca.pem";
    cfg.enable_peer_verify     = true;
    cfg.enable_hostname_verify = true;
    cfg.tls_hostname           = "localhost"; /* TCP 目标 IP 与校验名分离 */
    cfg.on_open                = cli_on_open;
    cfg.on_message             = cli_on_message;
    cfg.on_close               = cli_on_close;
    cfg.on_error               = cli_on_error;
    g_ws                       = sevent_ws_connect(ev, &cfg);
    if(!g_ws)
        return 1;
    for(int i = 0; i < 500 && !g_ev_msg && !g_ev_error; i++)
        sevent_run_once(ev);
    int ok = g_ev_open && g_ev_msg && !g_ev_error && g_msg_len == 9 && memcmp(g_msg, "hello wss", 9) == 0;
    sevent_ws_destroy(g_ws);
    if(g_srv_conn)
        sevent_tls_conn_destroy(g_srv_conn);
    sevent_tcp_acceptor_destroy(g_acc);
    flush_posts(ev);
    sevent_destroy(ev);
    return ok ? 0 : 1;
}

static int t_wss_verify_fail(void) {
    /* 客户端 ca 用服务器证书冒充 → 链验证失败 → ws on_error(HANDSHAKE) */
    sevent_context *ev = sevent_create();
    if(!ev)
        return 1;
    g_ev  = ev;
    g_acc = sevent_tcp_acceptor_create(ev);
    if(!g_acc)
        return 1;
    if(sevent_tcp_acceptor_listen(g_acc, "127.0.0.1", 0, 8, on_accept, NULL) < 0)
        return 1;
    int port  = sevent_tcp_acceptor_port(g_acc);
    g_ev_open = g_ev_msg = g_ev_error = 0;
    g_ev_error_code                   = 0;
    sevent_ws_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host               = "127.0.0.1";
    cfg.port               = (uint16_t)port;
    cfg.path               = "/";
    cfg.enable_tls         = true;
    cfg.ca_path            = CERT_DIR "/server.pem"; /* 冒充 CA */
    cfg.enable_peer_verify = true;
    cfg.on_open            = cli_on_open;
    cfg.on_message         = cli_on_message;
    cfg.on_close           = cli_on_close;
    cfg.on_error           = cli_on_error;
    g_ws                   = sevent_ws_connect(ev, &cfg);
    if(!g_ws)
        return 1;
    for(int i = 0; i < 500 && !g_ev_error && !g_ev_open; i++)
        sevent_run_once(ev);
    int ok = g_ev_error && g_ev_error_code == SEVENT_WS_ERR_HANDSHAKE;
    sevent_ws_destroy(g_ws);
    if(g_srv_conn)
        sevent_tls_conn_destroy(g_srv_conn);
    sevent_tcp_acceptor_destroy(g_acc);
    flush_posts(ev);
    sevent_destroy(ev);
    return ok ? 0 : 1;
}

static int t_wss_hostname_mismatch(void) {
    /* ca 正确但 tls_hostname 不匹配 SAN → ws on_error(HANDSHAKE) */
    sevent_context *ev = sevent_create();
    if(!ev)
        return 1;
    g_ev  = ev;
    g_acc = sevent_tcp_acceptor_create(ev);
    if(!g_acc)
        return 1;
    if(sevent_tcp_acceptor_listen(g_acc, "127.0.0.1", 0, 8, on_accept, NULL) < 0)
        return 1;
    int port  = sevent_tcp_acceptor_port(g_acc);
    g_ev_open = g_ev_msg = g_ev_error = 0;
    g_ev_error_code                   = 0;
    sevent_ws_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host                   = "127.0.0.1";
    cfg.port                   = (uint16_t)port;
    cfg.path                   = "/";
    cfg.enable_tls             = true;
    cfg.ca_path                = CERT_DIR "/ca.pem";
    cfg.enable_peer_verify     = true;
    cfg.enable_hostname_verify = true;
    cfg.tls_hostname           = "wrong.example"; /* 证书 SAN 无此名 */
    cfg.on_open                = cli_on_open;
    cfg.on_message             = cli_on_message;
    cfg.on_close               = cli_on_close;
    cfg.on_error               = cli_on_error;
    g_ws                       = sevent_ws_connect(ev, &cfg);
    if(!g_ws)
        return 1;
    for(int i = 0; i < 500 && !g_ev_error && !g_ev_open; i++)
        sevent_run_once(ev);
    int ok = g_ev_error && g_ev_error_code == SEVENT_WS_ERR_HANDSHAKE;
    sevent_ws_destroy(g_ws);
    if(g_srv_conn)
        sevent_tls_conn_destroy(g_srv_conn);
    sevent_tcp_acceptor_destroy(g_acc);
    flush_posts(ev);
    sevent_destroy(ev);
    return ok ? 0 : 1;
}

/* ---- 注册 ---- */
typedef struct {
    const char *n;
    int (*f)(void);
} test_entry;

static const test_entry tests[] = {
        {"wss_echo", t_wss_echo},
        {"wss_verify_fail", t_wss_verify_fail},
        {"wss_hostname_mismatch", t_wss_hostname_mismatch},
        {NULL, NULL},
};

int main(void) {
    sevent_ignore_sigpipe();
    setbuf(stdout, NULL);
    printf("wss tests (ws + tls end-to-end)\n");
    printf("===============================\n");
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

#endif /* SEVENT_WS_TLS */
