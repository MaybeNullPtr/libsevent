#define _DEFAULT_SOURCE /* usleep (POSIX 2008 移除, glibc feature gate) */

/* test_ws_server.c — WebSocket 服务端入口测试 (ws_accept / ws_upgrade)
 *
 * 覆盖:
 *   - 握手单测: ws_parse_request 校验链 (GET/Upgrade/Connection/Key/Version)
 *     + ws_build_response (accept 与 ws_verify_accept 互验, PMD 确认, 容量)
 *   - 独立端口端到端: tcp_acceptor + ws_accept ↔ client 消息往返
 *   - 共用端口端到端: http_server + on_upgrade(ws_upgrade) ↔ client 往返
 *   - 共用端口粘包: 单 TCP 段发"升级请求 + mask 帧" → 残留帧处理
 *   - 掩码校验: 客户端发未 mask 帧 → 1002 (on_error)
 *   - 非法握手: 缺 key / 版本错 → 400/426 + on_error
 *   - wss (SEVENT_WS_TLS): accept/upgrade 带证书 + mTLS
 */

#include "sevent.h"
#include "sevent_ws.h"
#include "sevent_tcp_acceptor.h"
#include "sevent_http_server.h"
#include "sevent_stream_conn.h"
#include "websockets/ws_handshake.h" /* 单测: parse_request/build_response */
#include "websockets/ws_frame.h"     /* 裸帧构造 */
#include "websockets/ws_sha1.h"
#include "websockets/ws_base64.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef SEVENT_WS_TLS
#ifndef TEST_CERTS_DIR
#error "TEST_CERTS_DIR 未定义 (CMake 注入)"
#endif
#define CERT_DIR TEST_CERTS_DIR
#endif

#define WS_WRITE(fd, buf, len)                                                                                         \
    do {                                                                                                               \
        ssize_t _wr = write(fd, buf, len);                                                                             \
        (void)_wr;                                                                                                     \
    } while(0)

static sevent_context *g_ev;

/* ---- client 全局 (sevent_ws_connect 连接 server) ---- */
static sevent_ws_conn *g_cli;
static int             g_cli_open, g_cli_msg, g_cli_err, g_cli_err_code;
#ifdef SEVENT_WS_TLS
static int g_cli_close;
#endif
static char   g_cli_buf[512];
static size_t g_cli_len;

static void cli_on_open(void *d) {
    (void)d;
    g_cli_open = 1;
    (void)sevent_ws_send_text(g_cli, "hello server", 12);
}
static void cli_on_message(void *d, const void *m, size_t l, bool b, bool fin, uint64_t total) {
    (void)d;
    (void)b;
    (void)fin;
    (void)total;
    size_t c = l < sizeof(g_cli_buf) ? l : sizeof(g_cli_buf) - 1;
    memcpy(g_cli_buf, m, c);
    g_cli_len    = c;
    g_cli_buf[c] = 0;
    g_cli_msg    = 1;
}
#ifdef SEVENT_WS_TLS
static void cli_on_close(void *d, uint16_t code, const char *reason, size_t reason_len) {
    (void)d;
    (void)code;
    (void)reason;
    (void)reason_len;
    g_cli_close = 1;
}
#endif
static void cli_on_error(void *d, int err) {
    (void)d;
    g_cli_err      = 1;
    g_cli_err_code = err;
}

/* ---- server 全局 (ws_accept / ws_upgrade 回调组) ---- */
static sevent_ws_conn *g_srv;
static int             g_srv_open, g_srv_err, g_srv_err_code, g_srv_msg;

static void srv_on_open(void *d) {
    (void)d;
    g_srv_open = 1;
}
static void srv_on_message(void *d, const void *m, size_t l, bool b, bool fin, uint64_t total) {
    (void)b;
    (void)fin;
    (void)total;
    g_srv_msg++;
    /* 回显 — 注意: upgrade 栈内同步触发的粘包帧回调时句柄尚未返回 (NULL),
     * 此时跳过 (测试只验证残留帧处理; 发送路径由 upgrade_echo 覆盖) */
    if(g_srv && sevent_ws_send_text(g_srv, m, l) != 0)
        g_srv_err = 1;
}
static void srv_on_error(void *d, int err) {
    (void)d;
    g_srv_err      = 1;
    g_srv_err_code = err;
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

static void run_until(sevent_context *ev, int *cond, int rounds) {
    for(int i = 0; i < rounds && !*cond; i++)
        sevent_run_once(ev);
}

/* ---- 裸 socket 辅助 (构造请求/帧, 模拟客户端) ---- */

static int raw_connect(int port) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if(fd < 0)
        return -1;
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family      = AF_INET;
    a.sin_port        = htons((uint16_t)port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if(connect(fd, (struct sockaddr *)&a, sizeof(a)) < 0 && errno != EINPROGRESS) {
        close(fd);
        return -1;
    }
    /* 非阻塞 connect: 等可写 (连接完成), 检查 SO_ERROR */
    struct pollfd p = {.fd = fd, .events = POLLOUT};
    if(poll(&p, 1, 2000) <= 0) {
        close(fd);
        return -1;
    }
    int       so = 0;
    socklen_t sl = sizeof(so);
    if(getsockopt(fd, SOL_SOCKET, SO_ERROR, &so, &sl) < 0 || so != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* 构造升级请求 (key=NULL 时省略; version=NULL 时省略 — 非法请求路径) */
static int raw_build_upgrade(char *buf, size_t cap, const char *key, const char *version, const char *extras) {
    int n = snprintf(buf,
                     cap,
                     "GET /chat HTTP/1.1\r\n"
                     "Host: server.example.com\r\n"
                     "Upgrade: websocket\r\n"
                     "Connection: Upgrade\r\n");
    if(n < 0 || (size_t)n >= cap)
        return -1;
    if(key) {
        int m = snprintf(buf + n, cap - (size_t)n, "Sec-WebSocket-Key: %s\r\n", key);
        if(m < 0 || (size_t)m >= cap - (size_t)n)
            return -1;
        n += m;
    }
    if(version) {
        int m = snprintf(buf + n, cap - (size_t)n, "Sec-WebSocket-Version: %s\r\n", version);
        if(m < 0 || (size_t)m >= cap - (size_t)n)
            return -1;
        n += m;
    }
    if(extras) {
        int m = snprintf(buf + n, cap - (size_t)n, "%s", extras);
        if(m < 0 || (size_t)m >= cap - (size_t)n)
            return -1;
        n += m;
    }
    int m = snprintf(buf + n, cap - (size_t)n, "\r\n");
    if(m < 0 || (size_t)m >= cap - (size_t)n)
        return -1;
    return n + m;
}

/* 读响应头区 (等 \r\n\r\n), 返回读取总长或 -1; *head_end = 头区结束偏移
 * (含空行) — 同段粘包数据 (如回显帧) 保留在 buf[head_end..n), 调用方续用.
 * 单进程测试: 等待期间必须推进服务器事件循环 (sevent_run_once), 否则
 * 服务器不处理请求, 响应永远不来. */
static int raw_read_response(int fd, char *buf, size_t cap, size_t *head_end) {
    size_t n = 0;
    for(int i = 0; i < 2000; i++) {
        ssize_t r = read(fd, buf + n, cap - n);
        if(r > 0) {
            n += (size_t)r;
            for(size_t j = 0; j + 3 < n; j++) {
                if(buf[j] == '\r' && buf[j + 1] == '\n' && buf[j + 2] == '\r' && buf[j + 3] == '\n') {
                    *head_end = j + 4;
                    return (int)n;
                }
            }
        } else if(r < 0 && errno == EAGAIN) {
            if(g_ev)
                sevent_run_once(g_ev); /* 推进服务器事件循环 */
            usleep(1000);
        } else if(r == 0) {
            return -1; /* EOF */
        }
    }
    return -1;
}

/* 发 WS 帧 (mask=1 时按客户端语义 mask) */
static void raw_send_frame(int fd, int mask, uint8_t op, const void *payload, uint64_t len) {
    uint8_t key[4] = {1, 2, 3, 4};
    uint8_t hdr[16];
    int     hl = ws_frame_build_header(hdr, 1, 0, op, mask ? key : NULL, len);
    if(hl < 0)
        return;
    uint8_t *raw = (uint8_t *)malloc((size_t)hl + (size_t)len);
    memcpy(raw, hdr, (size_t)hl);
    if(payload && len) {
        memcpy(raw + hl, payload, (size_t)len);
        if(mask)
            ws_frame_apply_mask(raw + hl, len, key);
    }
    WS_WRITE(fd, raw, (size_t)hl + (size_t)len);
    free(raw);
}

/* ==================== 握手单测 ==================== */

static int t_handshake_parse(void) {
    /* ws_parse_request: 合法请求 → status==0 + key 提取 */
    char req[1024];
    int  n = raw_build_upgrade(req, sizeof(req), "dGhlIHNhbXBsZSBub25jZQ==", "13", NULL);
    if(n < 0)
        return 1;
    ws_handshake_request hr;
    memset(&hr, 0, sizeof(hr));
    if(ws_parse_request((const uint8_t *)req, (size_t)n, &hr) != n || hr.status != 0 ||
       strcmp(hr.key, "dGhlIHNhbXBsZSBub25jZQ==") != 0)
        return 1;

    /* 缺 key → 400 */
    n = raw_build_upgrade(req, sizeof(req), NULL, "13", NULL);
    if(n < 0 || ws_parse_request((const uint8_t *)req, (size_t)n, &hr) != n || hr.status != 400)
        return 1;
    /* 版本错 → 426 */
    n = raw_build_upgrade(req, sizeof(req), "dGhlIHNhbXBsZSBub25jZQ==", "12", NULL);
    if(n < 0 || ws_parse_request((const uint8_t *)req, (size_t)n, &hr) != n || hr.status != 426)
        return 1;
    /* 缺 version → 426 */
    n = raw_build_upgrade(req, sizeof(req), "dGhlIHNhbXBsZSBub25jZQ==", NULL, NULL);
    if(n < 0 || ws_parse_request((const uint8_t *)req, (size_t)n, &hr) != n || hr.status != 426)
        return 1;
    /* 非 GET → 400 */
    {
        const char *post = "POST /chat HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                           "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
        if(ws_parse_request((const uint8_t *)post, strlen(post), &hr) != (int)strlen(post) || hr.status != 400)
            return 1;
    }
    /* deflate offer 提取 (含 nct) */
    n = raw_build_upgrade(req,
                          sizeof(req),
                          "dGhlIHNhbXBsZSBub25jZQ==",
                          "13",
                          "Sec-WebSocket-Extensions: permessage-deflate; client_no_context_takeover\r\n");
    if(n < 0 || ws_parse_request((const uint8_t *)req, (size_t)n, &hr) != n || hr.status != 0)
        return 1;
    if(!hr.deflate_offered || !hr.client_no_context_takeover)
        return 1;
    /* 畸形扩展名不应误判 */
    n = raw_build_upgrade(
            req, sizeof(req), "dGhlIHNhbXBsZSBub25jZQ==", "13", "Sec-WebSocket-Extensions: xpermessage-deflatex\r\n");
    if(n < 0 || ws_parse_request((const uint8_t *)req, (size_t)n, &hr) != n || hr.status != 0)
        return 1;
    if(hr.deflate_offered)
        return 1;

    /* ws_build_response: accept 与 ws_verify_accept 互验 + PMD 确认 */
    char resp[512];
    int  rn = ws_build_response(resp, sizeof(resp), "dGhlIHNhbXBsZSBub25jZQ==", true);
    if(rn <= 0)
        return 1;
    ws_handshake_response rr;
    memset(&rr, 0, sizeof(rr));
    if(ws_parse_response((const uint8_t *)resp, (size_t)rn, &rr) != rn || rr.status_code != 101)
        return 1;
    if(ws_verify_accept("dGhlIHNhbXBsZSBub25jZQ==", rr.accept) != 0)
        return 1;
#ifdef SEVENT_WS_DEFLATE
    /* deflate 编译时: enable_deflate=true 必须确认 PMD (A 方案) */
    if(!rr.extensions[0] || strstr(rr.extensions, "permessage-deflate") == NULL)
        return 1;
#endif
    /* 容量不足 → <0 */
    if(ws_build_response(resp, 1, "dGhlIHNhbXBsZSBub25jZQ==", false) >= 0)
        return 1;
    return 0;
}

/* ==================== 独立端口端到端 (ws_accept) ==================== */

static sevent_tcp_acceptor *g_acc;

static void acc_on_accept(void *d, int fd) {
    (void)d;
    static const sevent_ws_config cfg = {
            .on_open    = srv_on_open,
            .on_message = srv_on_message,
            .on_error   = srv_on_error,
    };
    g_srv = sevent_ws_accept(g_ev, fd, &cfg);
    if(!g_srv)
        close(fd);
}

static int t_accept_echo(void) {
    /* tcp_acceptor + ws_accept ↔ client: 消息往返 */
    sevent_context *ev = sevent_create();
    if(!ev)
        return 1;
    g_ev  = ev;
    g_acc = sevent_tcp_acceptor_create(ev);
    if(!g_acc || sevent_tcp_acceptor_listen(g_acc, "127.0.0.1", 0, 8, acc_on_accept, NULL) < 0)
        return 1;
    int port = sevent_tcp_acceptor_port(g_acc);

    g_cli_open = g_cli_msg = g_cli_err = 0;
    g_srv_open = g_srv_err = 0;
    sevent_ws_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host       = "127.0.0.1";
    cfg.port       = (uint16_t)port;
    cfg.path       = "/";
    cfg.on_open    = cli_on_open;
    cfg.on_message = cli_on_message;
    cfg.on_error   = cli_on_error;
    g_cli          = sevent_ws_connect(ev, &cfg);
    if(!g_cli)
        return 1;
    run_until(ev, &g_cli_msg, 1000);
    int ok = g_cli_open && g_cli_msg && !g_cli_err && !g_srv_err && g_srv_open && g_cli_len == 12 &&
            memcmp(g_cli_buf, "hello server", 12) == 0;
    sevent_ws_destroy(g_cli);
    if(g_srv) {
        sevent_ws_destroy(g_srv);
        g_srv = NULL;
    }
    sevent_tcp_acceptor_destroy(g_acc);
    flush_posts(ev);
    sevent_destroy(ev);
    return ok ? 0 : 1;
}

/* client 连接 server (tls=1 时带证书链校验 — wss 用例用; 仅 TLS 构建引用) */
#ifdef SEVENT_WS_TLS
static int cli_connect(sevent_context *ev, int port, int tls, sevent_ws_conn **ws) {
    sevent_ws_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host       = "127.0.0.1";
    cfg.port       = (uint16_t)port;
    cfg.path       = "/";
    cfg.on_open    = cli_on_open;
    cfg.on_message = cli_on_message;
#ifdef SEVENT_WS_TLS
    cfg.on_close = cli_on_close;
#endif
    cfg.on_error = cli_on_error;
#ifdef SEVENT_WS_TLS
    if(tls) {
        cfg.enable_tls             = true;
        cfg.ca_path                = CERT_DIR "/ca.pem";
        cfg.enable_peer_verify     = true;
        cfg.enable_hostname_verify = true;
        cfg.tls_hostname           = "localhost"; /* TCP 目标 IP 与校验名分离 */
    }
#else
    (void)tls;
#endif
    *ws = sevent_ws_connect(ev, &cfg);
    return *ws ? 0 : 1;
}
#endif /* SEVENT_WS_TLS */


/* ==================== 共用端口端到端 (ws_upgrade) ==================== */

static sevent_http_server *g_hsrv;

static void http_on_upgrade(void *ud, const sevent_http_msg *req, sevent_http_conn *conn) {
    (void)ud;
    (void)req;
    static const sevent_ws_config cfg = {
            .on_open    = srv_on_open,
            .on_message = srv_on_message,
            .on_error   = srv_on_error,
    };
    g_srv = sevent_ws_upgrade(conn, &cfg);
}

/* ==================== wss (SEVENT_WS_TLS) ==================== */

#ifdef SEVENT_WS_TLS
static void acc_on_accept_tls(void *d, int fd) {
    (void)d;
    static const sevent_ws_config cfg = {
            .enable_tls = true,
            .cert_path  = CERT_DIR "/server.pem",
            .key_path   = CERT_DIR "/server.key",
            .on_open    = srv_on_open,
            .on_message = srv_on_message,
            .on_error   = srv_on_error,
    };
    g_srv = sevent_ws_accept(g_ev, fd, &cfg);
    if(!g_srv)
        close(fd);
}

static void acc_on_accept_mtls(void *d, int fd) {
    (void)d;
    static const sevent_ws_config cfg = {
            .enable_tls         = true,
            .cert_path          = CERT_DIR "/server.pem",
            .key_path           = CERT_DIR "/server.key",
            .enable_peer_verify = true, /* 服务端 mTLS: 要求客户端证书 */
            .ca_path            = CERT_DIR "/ca.pem",
            .on_open            = srv_on_open,
            .on_message         = srv_on_message,
            .on_error           = srv_on_error,
    };
    g_srv = sevent_ws_accept(g_ev, fd, &cfg);
    if(!g_srv)
        close(fd);
}

static int t_wss_accept_echo(void) {
    /* wss 独立端口: ws_accept 带证书 (TLS 服务端握手在 stream 层) ↔ client 往返 */
    sevent_context *ev = sevent_create();
    if(!ev)
        return 1;
    g_ev  = ev;
    g_acc = sevent_tcp_acceptor_create(ev);
    if(!g_acc || sevent_tcp_acceptor_listen(g_acc, "127.0.0.1", 0, 8, acc_on_accept_tls, NULL) < 0)
        return 1;
    int port = sevent_tcp_acceptor_port(g_acc);

    g_cli_open = g_cli_msg = g_cli_err = 0;
    g_srv_open = g_srv_err = 0;
    if(cli_connect(ev, port, 1, &g_cli) != 0)
        return 1;
    run_until(ev, &g_cli_msg, 2000);
    int ok = g_cli_open && g_cli_msg && !g_cli_err && !g_srv_err && g_srv_open && g_cli_len == 12 &&
            memcmp(g_cli_buf, "hello server", 12) == 0;
    if(!ok)
        fprintf(stderr,
                "  [wss_accept_echo] cli open=%d msg=%d err=%d(%d) srv open=%d err=%d(%d)\n",
                g_cli_open,
                g_cli_msg,
                g_cli_err,
                g_cli_err_code,
                g_srv_open,
                g_srv_err,
                g_srv_err_code);
    sevent_ws_destroy(g_cli);
    if(g_srv) {
        sevent_ws_destroy(g_srv);
        g_srv = NULL;
    }
    sevent_tcp_acceptor_destroy(g_acc);
    flush_posts(ev);
    sevent_destroy(ev);
    return ok ? 0 : 1;
}

static int t_wss_upgrade_echo(void) {
    /* wss 共用端口: http_server 带证书 (TLS 由 http server 完成) + ws_upgrade */
    sevent_context *ev = sevent_create();
    if(!ev)
        return 1;
    g_ev = ev;
    sevent_http_server_config hcfg;
    memset(&hcfg, 0, sizeof(hcfg));
    hcfg.enable_tls = true;
    hcfg.cert_path  = CERT_DIR "/server.pem";
    hcfg.key_path   = CERT_DIR "/server.key";
    g_hsrv          = sevent_http_server_create(ev, &hcfg);
    if(!g_hsrv ||
       sevent_http_server_listen(g_hsrv, "127.0.0.1", 0, 8, NULL, NULL, http_on_upgrade, NULL, NULL, NULL) < 0)
        return 1;
    int port = (int)sevent_http_server_port(g_hsrv);

    g_cli_open = g_cli_msg = g_cli_err = 0;
    g_srv_open = g_srv_err = 0;
    if(cli_connect(ev, port, 1, &g_cli) != 0)
        return 1;
    run_until(ev, &g_cli_msg, 2000);
    int ok = g_cli_open && g_cli_msg && !g_cli_err && !g_srv_err && g_srv_open && g_cli_len == 12 &&
            memcmp(g_cli_buf, "hello server", 12) == 0;
    sevent_ws_destroy(g_cli);
    if(g_srv) {
        sevent_ws_destroy(g_srv);
        g_srv = NULL;
    }
    sevent_http_server_destroy(g_hsrv);
    flush_posts(ev);
    sevent_destroy(ev);
    return ok ? 0 : 1;
}

static int t_wss_mtls(void) {
    /* mTLS: 服务端要求客户端证书 — 无证书 client 被拒 (on_error HANDSHAKE),
     * 带证书 client 通过 */
    sevent_context *ev = sevent_create();
    if(!ev)
        return 1;
    g_ev  = ev;
    g_acc = sevent_tcp_acceptor_create(ev);
    if(!g_acc || sevent_tcp_acceptor_listen(g_acc, "127.0.0.1", 0, 8, acc_on_accept_mtls, NULL) < 0)
        return 1;
    int port = sevent_tcp_acceptor_port(g_acc);

    /* 无证书 → 服务器拒绝 (TLS 握手失败) */
    g_cli_open = g_cli_msg = g_cli_err = g_cli_close = 0;
    g_srv_open = g_srv_err = 0;
    if(cli_connect(ev, port, 1, &g_cli) != 0)
        return 1;
    run_until(ev, &g_cli_err, 2000);
    if((!g_cli_err && !g_cli_close) || g_srv_err_code != SEVENT_WS_ERR_HANDSHAKE) {
        fprintf(stderr,
                "  [wss_mtls] 无证书未被拒: cli open=%d msg=%d err=%d(%d) close=%d srv open=%d err=%d(%d)\n",
                g_cli_open,
                g_cli_msg,
                g_cli_err,
                g_cli_err_code,
                g_cli_close,
                g_srv_open,
                g_srv_err,
                g_srv_err_code);
        sevent_ws_destroy(g_cli);
        if(g_srv)
            sevent_ws_destroy(g_srv);
        sevent_tcp_acceptor_destroy(g_acc);
        flush_posts(ev);
        sevent_destroy(ev);
        return 1;
    }
    sevent_ws_destroy(g_cli);
    if(g_srv) {
        sevent_ws_destroy(g_srv);
        g_srv = NULL;
    }

    /* 带证书 → 通过 */
    g_cli_open = g_cli_msg = g_cli_err = g_cli_close = 0;
    g_srv_open = g_srv_err = 0;
    sevent_ws_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host                   = "127.0.0.1";
    cfg.port                   = (uint16_t)port;
    cfg.path                   = "/";
    cfg.enable_tls             = true;
    cfg.ca_path                = CERT_DIR "/ca.pem";
    cfg.cert_path              = CERT_DIR "/client.pem";
    cfg.key_path               = CERT_DIR "/client.key";
    cfg.enable_peer_verify     = true;
    cfg.enable_hostname_verify = true;
    cfg.tls_hostname           = "localhost";
    cfg.on_open                = cli_on_open;
    cfg.on_message             = cli_on_message;
    cfg.on_error               = cli_on_error;
    g_cli                      = sevent_ws_connect(ev, &cfg);
    if(!g_cli)
        return 1;
    run_until(ev, &g_cli_msg, 2000);
    int ok = g_cli_open && g_cli_msg && !g_cli_err && !g_srv_err && g_cli_len == 12 &&
            memcmp(g_cli_buf, "hello server", 12) == 0;
    sevent_ws_destroy(g_cli);
    if(g_srv) {
        sevent_ws_destroy(g_srv);
        g_srv = NULL;
    }
    sevent_tcp_acceptor_destroy(g_acc);
    flush_posts(ev);
    sevent_destroy(ev);
    return ok ? 0 : 1;
}
#endif /* SEVENT_WS_TLS */
static int t_upgrade_echo(void) {
    /* http_server + on_upgrade(ws_upgrade) ↔ client 往返 */
    sevent_context *ev = sevent_create();
    if(!ev)
        return 1;
    g_ev = ev;
    sevent_http_server_config hcfg;
    memset(&hcfg, 0, sizeof(hcfg)); /* 全默认: 明文 4096 缓冲 / 60s 空闲超时 */
    g_hsrv = sevent_http_server_create(ev, &hcfg);
    if(!g_hsrv ||
       sevent_http_server_listen(g_hsrv, "127.0.0.1", 0, 8, NULL, NULL, http_on_upgrade, NULL, NULL, NULL) < 0)
        return 1;
    int port = (int)sevent_http_server_port(g_hsrv);

    g_cli_open = g_cli_msg = g_cli_err = 0;
    g_srv_open = g_srv_err = 0;
    sevent_ws_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host       = "127.0.0.1";
    cfg.port       = (uint16_t)port;
    cfg.path       = "/chat";
    cfg.on_open    = cli_on_open;
    cfg.on_message = cli_on_message;
    cfg.on_error   = cli_on_error;
    g_cli          = sevent_ws_connect(ev, &cfg);
    if(!g_cli)
        return 1;
    run_until(ev, &g_cli_msg, 1000);
    int ok = g_cli_open && g_cli_msg && !g_cli_err && !g_srv_err && g_srv_open && g_cli_len == 12 &&
            memcmp(g_cli_buf, "hello server", 12) == 0;
    if(!ok)
        fprintf(stderr,
                "  [upgrade_echo] cli open=%d msg=%d err=%d(%d) srv=%p open=%d err=%d(%d) len=%zu buf=%.12s\n",
                g_cli_open,
                g_cli_msg,
                g_cli_err,
                g_cli_err_code,
                (void *)g_srv,
                g_srv_open,
                g_srv_err,
                g_srv_err_code,
                g_cli_len,
                g_cli_buf);
    sevent_ws_destroy(g_cli);
    if(g_srv) {
        sevent_ws_destroy(g_srv);
        g_srv = NULL;
    }
    sevent_http_server_destroy(g_hsrv);
    flush_posts(ev);
    sevent_destroy(ev);
    return ok ? 0 : 1;
}

static int t_upgrade_sticky(void) {
    /* 共用端口粘包: 单 TCP 段发"升级请求 + mask 帧" → ws_upgrade 后残留帧处理 */
    sevent_context *ev = sevent_create();
    if(!ev)
        return 1;
    g_ev = ev;
    sevent_http_server_config hcfg;
    memset(&hcfg, 0, sizeof(hcfg)); /* 全默认: 明文 4096 缓冲 / 60s 空闲超时 */
    g_hsrv = sevent_http_server_create(ev, &hcfg);
    if(!g_hsrv ||
       sevent_http_server_listen(g_hsrv, "127.0.0.1", 0, 8, NULL, NULL, http_on_upgrade, NULL, NULL, NULL) < 0)
        return 1;
    int port = (int)sevent_http_server_port(g_hsrv);

    g_srv_open = g_srv_err = g_srv_msg = 0;
    int fd                             = raw_connect(port);
    if(fd < 0)
        return 1;
    /* 一次发送: 升级请求 + 粘包 TEXT 帧 (mask) */
    char req[1024];
    int  n = raw_build_upgrade(req, sizeof(req), "dGhlIHNhbXBsZSBub25jZQ==", "13", NULL);
    if(n < 0)
        return 1;
    uint8_t pay[]  = "sticky";
    uint8_t key[4] = {1, 2, 3, 4};
    uint8_t hdr[16];
    int     hl = ws_frame_build_header(hdr, 1, 0, WS_OPCODE_TEXT, key, sizeof(pay) - 1);
    if(hl < 0)
        return 1;
    uint8_t *raw = (uint8_t *)malloc((size_t)n + (size_t)hl + sizeof(pay) - 1);
    memcpy(raw, req, (size_t)n);
    memcpy(raw + n, hdr, (size_t)hl);
    memcpy(raw + n + hl, pay, sizeof(pay) - 1);
    ws_frame_apply_mask(raw + n + hl, sizeof(pay) - 1, key);
    WS_WRITE(fd, raw, (size_t)n + (size_t)hl + sizeof(pay) - 1);
    free(raw);
    /* 等 server 收到并回显 (回显经 101 后同连接 — 裸 socket 收未 mask 帧) */
    char   rbuf[512];
    size_t head_end = 0;
    int    rn       = raw_read_response(fd, rbuf, sizeof(rbuf), &head_end);
    if(rn < 0 || !strstr(rbuf, "101 Switching Protocols")) {
        fprintf(stderr,
                "  [upgrade_sticky] 101 未收到 rn=%d resp=%.60s srv=%p err=%d(%d)\n",
                rn,
                rn > 0 ? rbuf : "",
                (void *)g_srv,
                g_srv_err,
                g_srv_err_code);
        close(fd);
        if(g_srv)
            sevent_ws_destroy(g_srv);
        sevent_http_server_destroy(g_hsrv);
        flush_posts(ev);
        sevent_destroy(ev);
        return 1;
    }
    /* 验证: 粘包残留帧被 ws 层处理 (on_message 收到 "sticky") — 栈内回调
     * 句柄不可用是文档契约 (入口未返回), 发送路径由 upgrade_echo 覆盖 */
    close(fd);
    run_until(ev, &g_srv_err, 200);
    int ok = g_srv_open && g_srv_msg == 1 && !g_srv_err;
    if(!ok)
        fprintf(stderr,
                "  [upgrade_sticky] srv=%p open=%d msg=%d err=%d(%d)\n",
                (void *)g_srv,
                g_srv_open,
                g_srv_msg,
                g_srv_err,
                g_srv_err_code);
    if(g_srv)
        sevent_ws_destroy(g_srv);
    sevent_http_server_destroy(g_hsrv);
    flush_posts(ev);
    sevent_destroy(ev);
    return ok ? 0 : 1;
    close(fd);
    if(g_srv)
        sevent_ws_destroy(g_srv);
    sevent_http_server_destroy(g_hsrv);
    flush_posts(ev);
    sevent_destroy(ev);
    return 1;
}

/* ==================== 掩码校验 + 非法握手 (ws_accept 入口) ==================== */

static int t_accept_unmasked(void) {
    /* 客户端发未 mask 帧 → 1002 (server 必须拒绝, RFC 6455 §5.1) */
    sevent_context *ev = sevent_create();
    if(!ev)
        return 1;
    g_ev  = ev;
    g_acc = sevent_tcp_acceptor_create(ev);
    if(!g_acc || sevent_tcp_acceptor_listen(g_acc, "127.0.0.1", 0, 8, acc_on_accept, NULL) < 0)
        return 1;
    int port = sevent_tcp_acceptor_port(g_acc);

    g_srv_open = g_srv_err = 0;
    int fd                 = raw_connect(port);
    if(fd < 0)
        return 1;
    char req[1024];
    int  n = raw_build_upgrade(req, sizeof(req), "dGhlIHNhbXBsZSBub25jZQ==", "13", NULL);
    if(n < 0)
        return 1;
    WS_WRITE(fd, req, (size_t)n);
    char   rbuf[512];
    size_t he0 = 0;
    if(raw_read_response(fd, rbuf, sizeof(rbuf), &he0) < 0 || !strstr(rbuf, "101"))
        return 1;
    raw_send_frame(fd, 0, WS_OPCODE_TEXT, "bad", 3); /* mask=0 — 违规 */
    run_until(ev, &g_srv_err, 200);
    int ok = g_srv_err && g_srv_err_code == SEVENT_WS_ERR_PROTOCOL;
    close(fd);
    if(g_srv) {
        sevent_ws_destroy(g_srv);
        g_srv = NULL;
    }
    sevent_tcp_acceptor_destroy(g_acc);
    flush_posts(ev);
    sevent_destroy(ev);
    return ok ? 0 : 1;
}

static int t_accept_bad_request(void) {
    /* 缺 key 的升级请求 → 400 响应 + server on_error(HANDSHAKE) */
    sevent_context *ev = sevent_create();
    if(!ev)
        return 1;
    g_ev  = ev;
    g_acc = sevent_tcp_acceptor_create(ev);
    if(!g_acc || sevent_tcp_acceptor_listen(g_acc, "127.0.0.1", 0, 8, acc_on_accept, NULL) < 0)
        return 1;
    int port = sevent_tcp_acceptor_port(g_acc);

    g_srv_open = g_srv_err = 0;
    int fd                 = raw_connect(port);
    if(fd < 0)
        return 1;
    char req[1024];
    int  n = raw_build_upgrade(req, sizeof(req), NULL, "13", NULL); /* 缺 key */
    if(n < 0)
        return 1;
    WS_WRITE(fd, req, (size_t)n);
    char   rbuf[512];
    size_t he1 = 0;
    int    rn  = raw_read_response(fd, rbuf, sizeof(rbuf), &he1);
    run_until(ev, &g_srv_err, 200);
    int ok = rn > 0 && strstr(rbuf, "400") && g_srv_err && g_srv_err_code == SEVENT_WS_ERR_HANDSHAKE;
    if(!ok)
        fprintf(stderr,
                "  [bad_request] rn=%d resp=%.80s srv_err=%d code=%d\n",
                rn,
                rn > 0 ? rbuf : "",
                g_srv_err,
                g_srv_err_code);
    close(fd);
    if(g_srv) {
        sevent_ws_destroy(g_srv);
        g_srv = NULL;
    }
    sevent_tcp_acceptor_destroy(g_acc);
    flush_posts(ev);
    sevent_destroy(ev);
    return ok ? 0 : 1;
}

/* ==================== main ==================== */

int main(void) {
    sevent_ignore_sigpipe();
    setbuf(stdout, NULL);
    printf("ws server tests\n");
    printf("===============\n");
    struct {
        const char *n;
        int (*f)(void);
    } tests[] = {
            {"handshake_parse", t_handshake_parse},
            {"accept_echo", t_accept_echo},
            {"upgrade_echo", t_upgrade_echo},
            {"upgrade_sticky", t_upgrade_sticky},
            {"accept_unmasked", t_accept_unmasked},
            {"accept_bad_request", t_accept_bad_request},
#ifdef SEVENT_WS_TLS
            {"wss_accept_echo", t_wss_accept_echo},
            {"wss_upgrade_echo", t_wss_upgrade_echo},
            {"wss_mtls", t_wss_mtls},
#endif
            {NULL, NULL},
    };
    int ok = 0, fail = 0;
    for(int i = 0; tests[i].n; i++) {
        if(tests[i].f() == 0) {
            printf("  %-24s ✓\n", tests[i].n);
            ok++;
        } else {
            printf("  %-24s ✗\n", tests[i].n);
            fail++;
        }
    }
    printf("%d/%d passed\n", ok, ok + fail);
    return fail ? 1 : 0;
}
