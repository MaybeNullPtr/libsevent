/* test_tls_conn.c — tls_conn 公开 API 独立单测 (SEVENT_WS_TLS)
 *
 * 全部直接使用 sevent_tls_conn_* (不经 stream 抽象), 验证公开接口契约:
 *  - create/open/accept 完整链路独立可用 (握手完成才 on_open)
 *  - 证书链验证失败 / hostname 不匹配 → on_error(SEVENT_ERR_HANDSHAKE)
 *  - mTLS (服务端 enable_peer_verify: 带客户端证书成功 / 缺证书失败)
 *  - EOF → on_close → 状态回 IDLE 可重开 (同一对象)
 *  - 分离场景: TCP 目标 (IP) 与校验名 (tls_hostname 域名) 分离
 *  - 握手期对端关闭 → on_error(SEVENT_ERR_CONNECT)
 *
 * 证书: tests/gen_certs.sh 生成 (根 CA 签发 server/client 证书,
 *       server SAN = DNS:localhost, IP:127.0.0.1), 路径 TEST_CERTS_DIR 注入.
 */
#include "sevent.h"
#include "sevent_tcp_acceptor.h"
#include "sevent_tls_conn.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef SEVENT_WS_TLS

#ifndef TEST_CERTS_DIR
#error "TEST_CERTS_DIR 未定义 (CMake 注入)"
#endif
#define CERT_DIR TEST_CERTS_DIR

/* 证书 PEM 文件读取 (PEM 内存通道用例) */
static char *read_file(const char *path) {
    FILE *f = fopen(path, "rb");
    if(!f)
        return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc((size_t)sz + 1);
    if(fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        fclose(f);
        free(buf);
        return NULL;
    }
    fclose(f);
    buf[sz] = '\0';
    return buf;
}

/* ---- 全局状态 ---- */
static int    g_ev_open;
static int    g_ev_data;
static int    g_ev_close;
static int    g_ev_close_count; /* EOF 后重开断言用 */
static int    g_ev_error;
static int    g_ev_error_code;
static int    g_srv_close_after_recv; /* server 收到数据后立即关闭 (EOF 用例) */
static int    g_srv_mtls;             /* 服务端 enable_peer_verify (mTLS 用例) */
static int    g_srv_pem;              /* 服务端证书走 PEM 内存通道 (t_pem_config) */
static char  *g_srv_cert_pem;
static char  *g_srv_key_pem;
static int    g_srv_error; /* 服务端 on_error 记录 (mTLS 拒绝断言) */
static int    g_srv_error_code;
static char   g_recv[512];
static size_t g_rlen;

/* ---- 内嵌 TLS echo server (acceptor 分发 → tls_conn accept 包装) ---- */
static sevent_context      *g_ev;
static sevent_tcp_acceptor *g_acc;

static void srv_on_open(void *d) { (void)d; }
static void srv_on_data(void *d, const uint8_t *data, size_t len) {
    if(g_srv_close_after_recv) {
        sevent_tls_conn_close(d); /* EOF 用例: 不回显直接关闭 */
        return;
    }
    (void)sevent_tls_conn_write(d, data, len); /* 回显 */
}
/* server 连接登记: 用例结束时统一销毁 (回调内销毁的置 NULL, 防双销毁) */
static sevent_tls_conn *g_srv_conns[64];
static int              g_srv_conn_count;

static void srv_conn_drop(sevent_tls_conn *c) {
    for(int i = 0; i < g_srv_conn_count; i++) {
        if(g_srv_conns[i] == c) {
            g_srv_conns[i] = NULL;
            break;
        }
    }
    sevent_tls_conn_destroy(c);
}
static void srv_on_close(void *d) { srv_conn_drop((sevent_tls_conn *)d); /* 对端关闭, 连接收尾 */ }
static void srv_on_error(void *d, int err) {
    g_srv_error      = 1;
    g_srv_error_code = err;
    srv_conn_drop((sevent_tls_conn *)d);
}
/* acceptor 分发: fd 已 accept, 包装成 tls_conn 连接 (服务端入口) */
static void on_accept(void *d, int fd) {
    (void)d;
    sevent_stream_conn_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.enable_tls = true;
    cfg.ca_path    = CERT_DIR "/ca.pem";
    if(g_srv_pem) { /* PEM 内存通道 (D3) */
        cfg.cert_pem = g_srv_cert_pem;
        cfg.key_pem  = g_srv_key_pem;
    } else {
        cfg.cert_path = CERT_DIR "/server.pem";
        cfg.key_path  = CERT_DIR "/server.key";
    }
    cfg.enable_peer_verify = g_srv_mtls; /* 服务端: true=mTLS (要求客户端证书) */
    sevent_tls_conn *c     = sevent_tls_conn_create(g_ev, &cfg);
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
    if(sevent_tls_conn_accept(c, fd, &cb) < 0)
        sevent_tls_conn_destroy(c); /* accept 失败: fd 已由本层关闭 */
}

/* 跑完 pending post (destroy 延迟 free 由 run_posts 执行) */
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
static void finish_case(sevent_context *ev) {
    for(int i = 0; i < g_srv_conn_count; i++) {
        if(g_srv_conns[i])
            sevent_tls_conn_destroy(g_srv_conns[i]);
    }
    g_srv_conn_count = 0;
    sevent_tcp_acceptor_destroy(g_acc);
    g_acc = NULL;
    flush_posts(ev);
    sevent_destroy(ev);
}
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
    (void)sevent_tls_conn_write(d, "hello tls", 9);
}
static void cli_on_data(void *d, const uint8_t *data, size_t len) {
    if(g_rlen + len <= sizeof(g_recv)) {
        memcpy(g_recv + g_rlen, data, len);
        g_rlen += len;
    }
    g_ev_data = 1;
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

/* ---- 大消息用例 (1MB 一次 write: SSL_write 分片 + 写队列续写路径) ---- */
static uint8_t *g_big;
static size_t   g_big_len;
static uint8_t *g_big_recv;
static size_t   g_big_rlen;

static void cli_on_open_big(void *d) {
    g_ev_open = 1;
    int rc    = sevent_tls_conn_write(d, g_big, g_big_len);
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
    /* 握手 → on_open (明文可写) → write → server echo → on_data 推送明文一致.
     * 校验名 = tls_hostname 域名 (证书 SAN 含 localhost; mbedtls 不支持 IP 名校验) */
    sevent_context *ev = sevent_create();
    if(!ev)
        return 1;
    g_ev                   = ev;
    g_srv_close_after_recv = 0;
    g_srv_mtls             = 0;
    int port               = start_server(ev);
    if(port < 0)
        return 1;
    g_ev_open = g_ev_data = g_ev_error = 0;
    g_rlen                             = 0;
    sevent_stream_conn_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.enable_tls             = true;
    cfg.ca_path                = CERT_DIR "/ca.pem";
    cfg.enable_peer_verify     = true;
    cfg.enable_hostname_verify = true;
    cfg.tls_hostname           = "localhost";
    sevent_tls_conn *c         = sevent_tls_conn_create(ev, &cfg);
    if(!c)
        return 1;
    sevent_stream_conn_init cb = {
            .user_data = c, .on_open = cli_on_open, .on_data = cli_on_data, .on_error = cli_on_error};
    if(sevent_tls_conn_open(c, "127.0.0.1", (uint16_t)port, &cb) < 0)
        return 1;
    for(int i = 0; i < 200 && !g_ev_data && !g_ev_error; i++)
        sevent_run_once(ev);
    int ok = g_ev_open && g_ev_data && !g_ev_error && g_rlen == 9 && memcmp(g_recv, "hello tls", 9) == 0;
    sevent_tls_conn_destroy(c);
    finish_case(ev);
    return ok ? 0 : 1;
}

static int t_verify_fail(void) {
    /* 客户端 ca 用服务器自己的证书冒充 → 链验证必失败 → on_error(HANDSHAKE) */
    sevent_context *ev = sevent_create();
    if(!ev)
        return 1;
    g_ev                   = ev;
    g_srv_close_after_recv = 0;
    g_srv_mtls             = 0;
    int port               = start_server(ev);
    if(port < 0)
        return 1;
    g_ev_open = g_ev_data = g_ev_error = 0;
    g_ev_error_code                    = 0;
    sevent_stream_conn_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.enable_tls         = true;
    cfg.ca_path            = CERT_DIR "/server.pem"; /* 冒充 CA: 非 CA 证书 */
    cfg.enable_peer_verify = true;
    sevent_tls_conn *c     = sevent_tls_conn_create(ev, &cfg);
    if(!c)
        return 1;
    sevent_stream_conn_init cb = {
            .user_data = c, .on_open = cli_on_open, .on_data = cli_on_data, .on_error = cli_on_error};
    if(sevent_tls_conn_open(c, "127.0.0.1", (uint16_t)port, &cb) < 0)
        return 1;
    for(int i = 0; i < 200 && !g_ev_error && !g_ev_open; i++)
        sevent_run_once(ev);
    int ok = g_ev_error && g_ev_error_code == SEVENT_ERR_HANDSHAKE;
    sevent_tls_conn_destroy(c);
    finish_case(ev);
    return ok ? 0 : 1;
}

static int t_hostname_mismatch(void) {
    /* ca 正确但 tls_hostname 不匹配 SAN → 握手失败 (mbedtls 恒开校验) */
    sevent_context *ev = sevent_create();
    if(!ev)
        return 1;
    g_ev                   = ev;
    g_srv_close_after_recv = 0;
    g_srv_mtls             = 0;
    int port               = start_server(ev);
    if(port < 0)
        return 1;
    g_ev_open = g_ev_data = g_ev_error = 0;
    g_ev_error_code                    = 0;
    sevent_stream_conn_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.enable_tls             = true;
    cfg.ca_path                = CERT_DIR "/ca.pem";
    cfg.enable_peer_verify     = true;
    cfg.enable_hostname_verify = true;
    cfg.tls_hostname           = "wrong.example"; /* 证书 SAN 无此名 */
    sevent_tls_conn *c         = sevent_tls_conn_create(ev, &cfg);
    if(!c)
        return 1;
    sevent_stream_conn_init cb = {
            .user_data = c, .on_open = cli_on_open, .on_data = cli_on_data, .on_error = cli_on_error};
    if(sevent_tls_conn_open(c, "127.0.0.1", (uint16_t)port, &cb) < 0)
        return 1;
    for(int i = 0; i < 200 && !g_ev_error && !g_ev_open; i++)
        sevent_run_once(ev);
    int ok = g_ev_error && g_ev_error_code == SEVENT_ERR_HANDSHAKE;
    sevent_tls_conn_destroy(c);
    finish_case(ev);
    return ok ? 0 : 1;
}

static int t_mtls(void) {
    /* 服务端 mTLS: 客户端带证书 → 成功; 无证书 → on_error(HANDSHAKE) */
    sevent_context *ev = sevent_create();
    if(!ev)
        return 1;
    g_ev                   = ev;
    g_srv_close_after_recv = 0;
    g_srv_mtls             = 1; /* 服务端要求客户端证书 */
    g_srv_error            = 0;
    g_srv_error_code       = 0;
    int port               = start_server(ev);
    if(port < 0)
        return 1;
    /* 子用例 1: 客户端带证书 → 成功 */
    g_ev_open = g_ev_data = g_ev_error = 0;
    g_rlen                             = 0;
    sevent_stream_conn_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.enable_tls             = true;
    cfg.ca_path                = CERT_DIR "/ca.pem";
    cfg.cert_path              = CERT_DIR "/client.pem";
    cfg.key_path               = CERT_DIR "/client.key";
    cfg.enable_peer_verify     = true;
    cfg.enable_hostname_verify = true;
    cfg.tls_hostname           = "localhost";
    sevent_tls_conn *c         = sevent_tls_conn_create(ev, &cfg);
    if(!c)
        return 1;
    sevent_stream_conn_init cb = {
            .user_data = c, .on_open = cli_on_open, .on_data = cli_on_data, .on_error = cli_on_error};
    if(sevent_tls_conn_open(c, "127.0.0.1", (uint16_t)port, &cb) < 0)
        return 1;
    for(int i = 0; i < 200 && !g_ev_data && !g_ev_error; i++)
        sevent_run_once(ev);
    int ok = g_ev_open && g_ev_data && !g_ev_error && g_rlen == 9 && memcmp(g_recv, "hello tls", 9) == 0;
    sevent_tls_conn_destroy(c);
    if(!ok)
        goto out;
    /* 子用例 2: 客户端无证书 → 服务端要求 mTLS → 握手失败 */
    g_ev_open = g_ev_data = g_ev_error = 0;
    g_ev_error_code                    = 0;
    memset(&cfg, 0, sizeof(cfg));
    cfg.enable_tls             = true;
    cfg.ca_path                = CERT_DIR "/ca.pem";
    cfg.enable_peer_verify     = true;
    cfg.enable_hostname_verify = true;
    cfg.tls_hostname           = "localhost";
    c                          = sevent_tls_conn_create(ev, &cfg);
    if(!c) {
        ok = 0;
        goto out;
    }
    cb.user_data = c;
    if(sevent_tls_conn_open(c, "127.0.0.1", (uint16_t)port, &cb) < 0) {
        ok = 0;
        goto out;
    }
    /* TLS1.3 客户端乐观完成: on_open 先触发 (Finished 已发), 服务端随后拒绝
     * (mTLS) → alert → 客户端 on_error — 只等 on_error */
    for(int i = 0; i < 200 && !g_ev_error; i++)
        sevent_run_once(ev);
    ok = g_ev_error; /* 客户端连接失败即可 — 拒绝信号源头在服务端 (子用例 1 已证
                      * 客户端侧行为; 服务端先 HANDSHAKE 失败并关闭 TCP, 客户端
                      * 观察到 EOF → CONNECT) */
    if(ok)
        ok = g_srv_error && g_srv_error_code == SEVENT_ERR_HANDSHAKE; /* 服务端 mTLS 拒绝核心断言 */
    sevent_tls_conn_destroy(c);
out:
    finish_case(ev);
    return ok ? 0 : 1;
}

static int t_eof_reopen(void) {
    /* server 关闭 → client on_close (EOF) → 状态回 IDLE → 直接重开成功 */
    sevent_context *ev = sevent_create();
    if(!ev)
        return 1;
    g_ev                   = ev;
    g_srv_close_after_recv = 1;
    g_srv_mtls             = 0;
    int port               = start_server(ev);
    if(port < 0)
        return 1;
    g_ev_open = g_ev_data = g_ev_close = g_ev_error = 0;
    g_ev_close_count                                = 0;
    g_rlen                                          = 0;
    sevent_stream_conn_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.enable_tls             = true;
    cfg.ca_path                = CERT_DIR "/ca.pem";
    cfg.enable_peer_verify     = true;
    cfg.enable_hostname_verify = true;
    cfg.tls_hostname           = "localhost";
    sevent_tls_conn *c         = sevent_tls_conn_create(ev, &cfg);
    if(!c)
        return 1;
    sevent_stream_conn_init cb = {.user_data = c,
                                  .on_open   = cli_on_open,
                                  .on_data   = cli_on_data,
                                  .on_close  = cli_on_close,
                                  .on_error  = cli_on_error};
    if(sevent_tls_conn_open(c, "127.0.0.1", (uint16_t)port, &cb) < 0)
        return 1;
    for(int i = 0; i < 200 && !g_ev_close && !g_ev_error; i++)
        sevent_run_once(ev);
    if(!g_ev_open || !g_ev_close || g_ev_close_count != 1 || g_ev_error)
        return 1;
    /* EOF 后直接重开 (状态应已回 IDLE, 无需先 close) */
    g_srv_close_after_recv = 0;
    g_ev_open = g_ev_data = g_ev_close = g_ev_error = 0;
    g_rlen                                          = 0;
    if(sevent_tls_conn_open(c, "127.0.0.1", (uint16_t)port, &cb) < 0)
        return 1;
    for(int i = 0; i < 200 && !g_ev_data && !g_ev_error; i++)
        sevent_run_once(ev);
    int ok = g_ev_open && g_ev_data && !g_ev_error && g_rlen == 9 && memcmp(g_recv, "hello tls", 9) == 0;
    sevent_tls_conn_destroy(c);
    finish_case(ev);
    return ok ? 0 : 1;
}

static int t_large_msg(void) {
    /* 1MB 明文一次 write: SSL_write 加密 + tcp 写队列部分写, server 回显收齐 */
    sevent_context *ev = sevent_create();
    if(!ev)
        return 1;
    g_ev                   = ev;
    g_srv_close_after_recv = 0;
    g_srv_mtls             = 0;
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
    sevent_stream_conn_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.enable_tls             = true;
    cfg.ca_path                = CERT_DIR "/ca.pem";
    cfg.enable_peer_verify     = true;
    cfg.enable_hostname_verify = true;
    cfg.tls_hostname           = "localhost";
    sevent_tls_conn *c         = sevent_tls_conn_create(ev, &cfg);
    if(!c)
        return 1;
    sevent_stream_conn_init cb = {
            .user_data     = c,
            .on_open       = cli_on_open_big,
            .on_data       = cli_on_data_big,
            .on_error      = cli_on_error,
            .recv_buf_size = 1024, /* client 慢读 → server 回显写缓冲满 → 部分写/EAGAIN */
    };
    if(sevent_tls_conn_open(c, "127.0.0.1", (uint16_t)port, &cb) < 0)
        return 1;
    for(int i = 0; i < 200000 && !g_ev_data && !g_ev_error; i++)
        sevent_run_once(ev);
    int ok = g_ev_data && g_big_rlen == g_big_len && memcmp(g_big, g_big_recv, g_big_len) == 0;
    sevent_tls_conn_destroy(c);
    finish_case(ev);
    free(g_big);
    free(g_big_recv);
    return ok ? 0 : 1;
}

/* ---- 握手期对端关闭用例 (raw server: accept 后立即 close, 不做 TLS) ---- */
static void on_accept_close(void *d, int fd) {
    (void)d;
    if(fd >= 0)
        close(fd); /* 立即关闭: client 握手期收到 EOF */
}
static int t_handshake_peer_close(void) {
    sevent_context *ev = sevent_create();
    if(!ev)
        return 1;
    g_ev  = ev;
    /* raw acceptor: 分发回调立即关闭连接 */
    g_acc = sevent_tcp_acceptor_create(ev);
    if(!g_acc)
        return 1;
    if(sevent_tcp_acceptor_listen(g_acc, "127.0.0.1", 0, 8, on_accept_close, NULL) < 0)
        return 1;
    int port  = sevent_tcp_acceptor_port(g_acc);
    g_ev_open = g_ev_error = 0;
    g_ev_error_code        = 0;
    sevent_stream_conn_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.enable_tls             = true;
    cfg.ca_path                = CERT_DIR "/ca.pem";
    cfg.enable_peer_verify     = true;
    cfg.enable_hostname_verify = true;
    sevent_tls_conn *c         = sevent_tls_conn_create(ev, &cfg);
    if(!c)
        return 1;
    sevent_stream_conn_init cb = {
            .user_data = c, .on_open = cli_on_open, .on_data = cli_on_data, .on_error = cli_on_error};
    if(sevent_tls_conn_open(c, "127.0.0.1", (uint16_t)port, &cb) < 0)
        return 1;
    for(int i = 0; i < 200 && !g_ev_error && !g_ev_open; i++)
        sevent_run_once(ev);
    int ok = g_ev_error && g_ev_error_code == SEVENT_ERR_CONNECT;
    sevent_tls_conn_destroy(c);
    g_srv_conn_count = 0; /* 本用例无 tls 服务端连接 */
    sevent_tcp_acceptor_destroy(g_acc);
    g_acc = NULL;
    flush_posts(ev);
    sevent_destroy(ev);
    return ok ? 0 : 1;
}

/* ---- 非法调用 + 同步失败重试用例 ---- */
static int t_inval(void) {
    /* NULL host/init/on_open/on_data → INVAL; fd<0 → INVAL;
     * create(NULL ev) → NULL; destroy(NULL) 无害;
     * 同步失败 (非法 host 立即 CONNECT) 后 established 复位 → 可重试 */
    sevent_context *ev = sevent_create();
    if(!ev)
        return 1;
    g_ev                   = ev;
    g_srv_close_after_recv = 0;
    g_srv_mtls             = 0;
    int port               = start_server(ev);
    if(port < 0)
        return 1;
    int                       ok = 1;
    sevent_stream_conn_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.enable_tls     = true;
    sevent_tls_conn *c = sevent_tls_conn_create(ev, &cfg);
    if(!c)
        return 1;
    sevent_stream_conn_init cb = {
            .user_data = c, .on_open = cli_on_open, .on_data = cli_on_data, .on_error = cli_on_error};
    if(sevent_tls_conn_open(c, NULL, 80, &cb) != SEVENT_ERR_INVAL)
        ok = 0; /* NULL host (无 tls_hostname 时不得崩溃) */
    if(sevent_tls_conn_open(c, "127.0.0.1", 80, NULL) != SEVENT_ERR_INVAL)
        ok = 0; /* NULL init */
    sevent_stream_conn_init cb_no_data = {.user_data = c, .on_open = cli_on_open};
    sevent_stream_conn_init cb_no_open = {.user_data = c, .on_data = cli_on_data};
    if(sevent_tls_conn_open(c, "127.0.0.1", 80, &cb_no_data) != SEVENT_ERR_INVAL)
        ok = 0; /* NULL on_data */
    if(sevent_tls_conn_open(c, "127.0.0.1", 80, &cb_no_open) != SEVENT_ERR_INVAL)
        ok = 0; /* NULL on_open */
    if(sevent_tls_conn_accept(c, -1, &cb) != SEVENT_ERR_INVAL)
        ok = 0; /* fd < 0 */
    if(sevent_tls_conn_create(NULL, &cfg) != NULL)
        ok = 0;                    /* NULL ev */
    sevent_tls_conn_destroy(NULL); /* 无害 */
    /* 同步失败后可重试: 非法 host → tcp 立即 CONNECT 失败 → established 应复位 */
    int rc = sevent_tls_conn_open(c, "not-an-ip", 80, &cb);
    if(rc != SEVENT_ERR_CONNECT)
        ok = 0;
    g_ev_open = g_ev_data = g_ev_error = 0;
    g_rlen                             = 0;
    if(sevent_tls_conn_open(c, "127.0.0.1", (uint16_t)port, &cb) < 0)
        ok = 0;
    for(int i = 0; i < 200 && !g_ev_data && !g_ev_error; i++)
        sevent_run_once(ev);
    if(!g_ev_open || !g_ev_data || g_ev_error)
        ok = 0;
    sevent_tls_conn_destroy(c);
    finish_case(ev);
    return ok ? 0 : 1;
}

/* ---- 主动 close 后重开用例 (对象级 tls_hostname 保持) ---- */
static int t_close_reopen(void) {
    /* close → 同一对象重开: 校验名仍为 config 的 tls_hostname (对象级, 分离
     * 场景不退化) — mbedtls 下若丢失则校验 host=IP 必败, 用例即失败 */
    sevent_context *ev = sevent_create();
    if(!ev)
        return 1;
    g_ev                   = ev;
    g_srv_close_after_recv = 0;
    g_srv_mtls             = 0;
    int port               = start_server(ev);
    if(port < 0)
        return 1;
    sevent_stream_conn_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.enable_tls             = true;
    cfg.ca_path                = CERT_DIR "/ca.pem";
    cfg.enable_peer_verify     = true;
    cfg.enable_hostname_verify = true;
    cfg.tls_hostname           = "localhost";
    sevent_tls_conn *c         = sevent_tls_conn_create(ev, &cfg);
    if(!c)
        return 1;
    sevent_stream_conn_init cb = {
            .user_data = c, .on_open = cli_on_open, .on_data = cli_on_data, .on_error = cli_on_error};
    /* 第一次: echo */
    g_ev_open = g_ev_data = g_ev_error = 0;
    g_rlen                             = 0;
    if(sevent_tls_conn_open(c, "127.0.0.1", (uint16_t)port, &cb) < 0)
        return 1;
    for(int i = 0; i < 200 && !g_ev_data && !g_ev_error; i++)
        sevent_run_once(ev);
    if(!g_ev_open || !g_ev_data || g_ev_error || g_rlen != 9 || memcmp(g_recv, "hello tls", 9) != 0)
        return 1;
    sevent_tls_conn_close(c);
    /* 第二次: 同一对象重开 */
    g_ev_open = g_ev_data = g_ev_error = 0;
    g_rlen                             = 0;
    if(sevent_tls_conn_open(c, "127.0.0.1", (uint16_t)port, &cb) < 0)
        return 1;
    for(int i = 0; i < 200 && !g_ev_data && !g_ev_error; i++)
        sevent_run_once(ev);
    int ok = g_ev_open && g_ev_data && !g_ev_error && g_rlen == 9 && memcmp(g_recv, "hello tls", 9) == 0;
    sevent_tls_conn_destroy(c);
    finish_case(ev);
    return ok ? 0 : 1;
}

/* ---- path/PEM 双通道 (D3) 用例 ---- */
static int t_pem_config(void) {
    /* 客户端 ca_pem / 服务端 cert+key PEM 各验证一例;
     * 互斥 (path+PEM 同给 / cert 缺 key) → create 失败 */
    char *ca_pem     = read_file(CERT_DIR "/ca.pem");
    char *srv_cert_p = read_file(CERT_DIR "/server.pem");
    char *srv_key_p  = read_file(CERT_DIR "/server.key");
    if(!ca_pem || !srv_cert_p || !srv_key_p) {
        free(ca_pem);
        free(srv_cert_p);
        free(srv_key_p);
        return 1;
    }
    int ok = 1;

    /* 互斥/成对校验 (create 即失败, 无对象泄漏) */
    sevent_context *ev = sevent_create();
    if(!ev) {
        free(ca_pem);
        free(srv_cert_p);
        free(srv_key_p);
        return 1;
    }
    g_ev = ev;
    sevent_stream_conn_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.enable_tls = true;
    cfg.ca_path    = CERT_DIR "/ca.pem";
    cfg.ca_pem     = ca_pem;
    if(sevent_tls_conn_create(ev, &cfg) != NULL)
        ok = 0; /* ca path+PEM 互斥 */
    memset(&cfg, 0, sizeof(cfg));
    cfg.enable_tls = true;
    cfg.cert_path  = CERT_DIR "/server.pem";
    cfg.cert_pem   = srv_cert_p;
    if(sevent_tls_conn_create(ev, &cfg) != NULL)
        ok = 0; /* cert path+PEM 互斥 */
    memset(&cfg, 0, sizeof(cfg));
    cfg.enable_tls = true;
    cfg.cert_path  = CERT_DIR "/server.pem";
    if(sevent_tls_conn_create(ev, &cfg) != NULL)
        ok = 0;           /* cert 缺 key (成对) */
    g_srv_conn_count = 0; /* 本段无 acceptor */
    flush_posts(ev);
    sevent_destroy(ev);

    /* 子用例 1: 客户端 ca_pem + 服务端 path → 握手 echo */
    g_srv_pem              = 0;
    g_srv_cert_pem         = srv_cert_p;
    g_srv_key_pem          = srv_key_p;
    g_srv_close_after_recv = 0;
    g_srv_mtls             = 0;
    sevent_context *ev1    = sevent_create();
    if(!ev1) {
        ok = 0;
        goto out;
    }
    g_ev     = ev1;
    int port = start_server(ev1);
    if(port < 0) {
        ok = 0;
        goto out;
    }
    g_ev_open = g_ev_data = g_ev_error = 0;
    g_rlen                             = 0;
    memset(&cfg, 0, sizeof(cfg));
    cfg.enable_tls             = true;
    cfg.ca_pem                 = ca_pem; /* PEM 内存通道 */
    cfg.enable_peer_verify     = true;
    cfg.enable_hostname_verify = true;
    cfg.tls_hostname           = "localhost";
    sevent_tls_conn *c         = sevent_tls_conn_create(ev1, &cfg);
    if(!c) {
        ok = 0;
        goto out;
    }
    sevent_stream_conn_init cb = {
            .user_data = c, .on_open = cli_on_open, .on_data = cli_on_data, .on_error = cli_on_error};
    if(sevent_tls_conn_open(c, "127.0.0.1", (uint16_t)port, &cb) < 0) {
        ok = 0;
        goto out;
    }
    for(int i = 0; i < 200 && !g_ev_data && !g_ev_error; i++)
        sevent_run_once(ev1);
    if(!g_ev_open || !g_ev_data || g_ev_error || g_rlen != 9 || memcmp(g_recv, "hello tls", 9) != 0)
        ok = 0;
    sevent_tls_conn_destroy(c);
    finish_case(ev1);

    /* 子用例 2: 服务端 cert/key PEM + 客户端 ca_path → 握手 echo */
    g_srv_pem           = 1;
    sevent_context *ev2 = sevent_create();
    if(!ev2) {
        ok = 0;
        goto out;
    }
    g_ev = ev2;
    port = start_server(ev2);
    if(port < 0) {
        ok = 0;
        goto out;
    }
    g_ev_open = g_ev_data = g_ev_error = 0;
    g_rlen                             = 0;
    memset(&cfg, 0, sizeof(cfg));
    cfg.enable_tls             = true;
    cfg.ca_path                = CERT_DIR "/ca.pem"; /* 路径通道 */
    cfg.enable_peer_verify     = true;
    cfg.enable_hostname_verify = true;
    cfg.tls_hostname           = "localhost";
    c                          = sevent_tls_conn_create(ev2, &cfg);
    if(!c) {
        ok = 0;
        goto out;
    }
    cb.user_data = c;
    if(sevent_tls_conn_open(c, "127.0.0.1", (uint16_t)port, &cb) < 0) {
        ok = 0;
        goto out;
    }
    for(int i = 0; i < 200 && !g_ev_data && !g_ev_error; i++)
        sevent_run_once(ev2);
    if(!g_ev_open || !g_ev_data || g_ev_error || g_rlen != 9 || memcmp(g_recv, "hello tls", 9) != 0)
        ok = 0;
    sevent_tls_conn_destroy(c);
    finish_case(ev2);
out:
    g_srv_pem = 0;
    free(ca_pem);
    free(srv_cert_p);
    free(srv_key_p);
    return ok ? 0 : 1;
}

/* ---- 注册 ---- */
typedef struct {
    const char *n;
    int (*f)(void);
} test_entry;

static const test_entry tests[] = {
        {"tls_echo", t_echo},
        {"tls_verify_fail", t_verify_fail},
        {"tls_hostname_mismatch", t_hostname_mismatch},
        {"tls_mtls", t_mtls},
        {"tls_eof_reopen", t_eof_reopen},
        {"tls_large_msg", t_large_msg},
        {"tls_handshake_peer_close", t_handshake_peer_close},
        {"tls_inval", t_inval},
        {"tls_close_reopen", t_close_reopen},
        {"tls_pem_config", t_pem_config},
        {NULL, NULL},
};

int main(void) {
    sevent_ignore_sigpipe(); /* 契约: 对端关闭后写不发 SIGPIPE (应用层处理) */
    setbuf(stdout, NULL);
    printf("tls_conn tests (public API)\n");
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

#endif /* SEVENT_WS_TLS */
