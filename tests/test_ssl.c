/* =========================================================================
 *  test_ssl.c — ssl 抽象层单测 (openssl / mbedtls 双后端)
 *
 *  独立于 sevent_ws (直链 src/ssl/ssl.c + 选中后端), 数据通道回环:
 *  两端 (client/server) 各建 ssl 对象, xfer 搬运密文 (drain→feed),
 *  交替 pump 完成握手与数据交换.
 *
 *  证书: tests/gen_certs.sh 生成 (根 CA + 服务器证书 SAN=localhost/127.0.0.1
 *        + 客户端证书), 路径经 TEST_CERTS_DIR 编译定义注入.
 *
 *  用例:
 *    config 校验 (互斥/成对) / 路径与 PEM 双通道加载 / 握手+数据往返 /
 *    verify 失败 (无 CA) / hostname 不匹配 / mTLS / EOF / pending
 *  ========================================================================= */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "sevent.h" /* sevent_ignore_sigpipe: 库契约 (TCP 使用方应屏蔽 SIGPIPE) */
#include "ssl.h"

#ifndef TEST_CERTS_DIR
#error "TEST_CERTS_DIR 未定义 (CMake 注入)"
#endif

static int g_fail;

#define CHECK(cond, ...)                                                                                               \
    do {                                                                                                               \
        if(!(cond)) {                                                                                                  \
            printf("FAIL %s:%d: ", __FILE__, __LINE__);                                                                \
            printf(__VA_ARGS__);                                                                                       \
            printf("\n");                                                                                              \
            g_fail++;                                                                                                  \
            return;                                                                                                    \
        }                                                                                                              \
    } while(0)

/* ===== 辅助 ===== */

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

static char *errbuf(sevent_ssl *s) {
    static char b[200];
    sevent_ssl_error(s, b, sizeof(b));
    return b;
}

/* 把 from 产出的密文全部搬给 to (drain → feed) */
static void xfer(sevent_ssl *from, sevent_ssl *to) {
    char    buf[65536];
    ssize_t n;
    while((n = sevent_ssl_drain(from, buf, sizeof(buf))) > 0)
        sevent_ssl_feed(to, (const uint8_t *)buf, (size_t)n);
}

/* 交替 pump 直到双方握手完成; 返回 false=握手失败 */
static bool pump_handshake(sevent_ssl *cli, sevent_ssl *srv) {
    for(int i = 0; i < 200; i++) {
        int ra = sevent_ssl_handshake(cli);
        if(ra != 0 && ra != SEVENT_SSL_WANT_READ && ra != SEVENT_SSL_WANT_WRITE)
            return false;
        xfer(cli, srv);
        int rb = sevent_ssl_handshake(srv);
        if(rb != 0 && rb != SEVENT_SSL_WANT_READ && rb != SEVENT_SSL_WANT_WRITE)
            return false;
        xfer(srv, cli);
        if(ra == 0 && rb == 0)
            return true;
    }
    return false;
}

/* 尽力写入 len 字节明文 (WANT 时清空密文通道后重试) */
static bool pump_write(sevent_ssl *s, const void *data, size_t len, sevent_ssl *peer) {
    const unsigned char *p   = (const unsigned char *)data;
    size_t               off = 0;
    for(int i = 0; i < 200 && off < len; i++) {
        ssize_t r = sevent_ssl_write(s, p + off, len - off);
        if(r > 0) {
            off += (size_t)r;
            xfer(s, peer); /* 密文 → 对端 */
            continue;
        }
        if(r == 0) {
            xfer(s, peer); /* WANT (通道满): 清空后重试 */
            continue;
        }
        return false;
    }
    return off == len;
}

/* 读足 len 字节明文 (WANT 时从对端搬密文再试) */
static bool pump_read_exact(sevent_ssl *s, void *buf, size_t len, sevent_ssl *peer) {
    unsigned char *p   = (unsigned char *)buf;
    size_t         off = 0;
    for(int i = 0; i < 200 && off < len; i++) {
        ssize_t r = sevent_ssl_read(s, p + off, len - off);
        if(r > 0) {
            off += (size_t)r;
            continue;
        }
        if(r == 0)
            return false; /* EOF 提前 */
        if(r < 0 && peer) {
            xfer(peer, s); /* 对端可能还有密文: 搬过来再试 */
            continue;
        }
        return false;
    }
    return off == len;
}

/* ===== 用例 ===== */

/* 1. 配置校验: path+pem 互斥 / cert-key 不成对 */
static void t_config_conflict(void) {
    sevent_ssl_config cfg = {.ca_path = "a.pem", .ca_pem = "b.pem"};
    CHECK(sevent_ssl_ctx_new(&cfg) == NULL, "ca_path+ca_pem 应互斥失败");

    cfg = (sevent_ssl_config){.cert_path = "c.pem"}; /* 无 key */
    CHECK(sevent_ssl_ctx_new(&cfg) == NULL, "cert_path 无 key_path 应失败");

    cfg = (sevent_ssl_config){.key_path = "k.pem"}; /* 无 cert */
    CHECK(sevent_ssl_ctx_new(&cfg) == NULL, "key_path 无 cert_path 应失败");

    /* cert_pem+key_pem 成对 (缺 ca): 应通过 — enable_peer_verify 的 CA 检查在
     * ssl_new/握手期做 (mbedtls fail fast / openssl 握手失败), 不属 ctx 校验 */
    char *cp = read_file(TEST_CERTS_DIR "/server.pem");
    char *kp = read_file(TEST_CERTS_DIR "/server.key");
    CHECK(cp && kp, "证书文件缺失 (先跑 tests/gen_certs.sh)");
    cfg             = (sevent_ssl_config){.cert_pem = cp, .key_pem = kp, .enable_peer_verify = true};
    sevent_ssl *ctx = sevent_ssl_ctx_new(&cfg);
    CHECK(ctx != NULL, "cert_pem+key_pem 成对应通过: %s", errbuf(ctx));
    sevent_ssl_ctx_free(ctx);
    free(cp);
    free(kp);
}

/* 2. 路径通道加载 + 握手 + 数据往返 (enable_peer_verify + hostname 匹配) */
static void t_handshake_echo(void) {
    char *ca    = read_file(TEST_CERTS_DIR "/ca.pem");
    char *srv_c = read_file(TEST_CERTS_DIR "/server.pem");
    char *srv_k = read_file(TEST_CERTS_DIR "/server.key");
    CHECK(ca && srv_c && srv_k, "证书文件缺失 (先跑 tests/gen_certs.sh)");

    sevent_ssl_config ccfg = {
            .ca_path = TEST_CERTS_DIR "/ca.pem", .enable_peer_verify = true, .enable_hostname_verify = true};
    sevent_ssl_config scfg = {.cert_path = TEST_CERTS_DIR "/server.pem", .key_path = TEST_CERTS_DIR "/server.key"};
    sevent_ssl       *cctx = sevent_ssl_ctx_new(&ccfg);
    sevent_ssl       *sctx = sevent_ssl_ctx_new(&scfg);
    CHECK(cctx && sctx, "ctx_new 失败: %s / %s", cctx ? "" : errbuf(cctx), sctx ? "" : errbuf(sctx));

    sevent_ssl *cli = sevent_ssl_new(cctx, false, "localhost");
    sevent_ssl *srv = sevent_ssl_new(sctx, true, NULL);
    CHECK(cli && srv, "ssl_new 失败: %s / %s", cli ? "" : errbuf(cctx), srv ? "" : errbuf(sctx));

    CHECK(pump_handshake(cli, srv), "握手失败 (enable_peer_verify=true + CA 正确): %s", errbuf(cli));

    const char *msg = "hello ssl layer";
    CHECK(pump_write(cli, msg, strlen(msg), srv), "client 写入失败");
    char out[64] = {0};
    CHECK(pump_read_exact(srv, out, strlen(msg), cli), "server 读取失败");
    CHECK(memcmp(out, msg, strlen(msg)) == 0, "数据不一致: %s", out);

    sevent_ssl_free(cli);
    sevent_ssl_free(srv);
    sevent_ssl_ctx_free(cctx);
    sevent_ssl_ctx_free(sctx);
    free(ca);
    free(srv_c);
    free(srv_k);
}

/* 3. PEM 内存通道加载 (与路径通道等价) */
static void t_ctx_load_pem(void) {
    char *ca = read_file(TEST_CERTS_DIR "/ca.pem");
    char *c  = read_file(TEST_CERTS_DIR "/server.pem");
    char *k  = read_file(TEST_CERTS_DIR "/server.key");
    CHECK(ca && c && k, "证书文件缺失");

    sevent_ssl_config cfg = {.ca_pem = ca, .cert_pem = c, .key_pem = k, .enable_peer_verify = true};
    sevent_ssl       *ctx = sevent_ssl_ctx_new(&cfg);
    CHECK(ctx != NULL, "PEM 通道 ctx_new 失败: %s", errbuf(ctx));
    sevent_ssl_ctx_free(ctx);
    free(ca);
    free(c);
    free(k);
}

/* 4. enable_peer_verify=true 无 CA → 必须失败 (mbedtls: ssl_new fail fast;
 *    openssl: 握手失败) */
static void t_verify_fail_no_ca(void) {
    sevent_ssl_config ccfg = {.enable_peer_verify = true}; /* 无 ca */
    sevent_ssl_config scfg = {.cert_path = TEST_CERTS_DIR "/server.pem", .key_path = TEST_CERTS_DIR "/server.key"};
    sevent_ssl       *cctx = sevent_ssl_ctx_new(&ccfg);
    sevent_ssl       *sctx = sevent_ssl_ctx_new(&scfg);
    CHECK(cctx && sctx, "ctx_new 失败");

    sevent_ssl *cli = sevent_ssl_new(cctx, false, "localhost");
    sevent_ssl *srv = sevent_ssl_new(sctx, true, NULL);
    CHECK(srv != NULL, "server ssl_new 失败");
    /* 客户端必须失败: ssl_new 拒绝 或 握手失败 */
    bool rejected = (cli == NULL);
    bool hs_fail  = cli && !pump_handshake(cli, srv);
    CHECK(rejected || hs_fail, "无 CA 验证应失败 (rejected=%d)", rejected);
    if(cli)
        sevent_ssl_free(cli);
    sevent_ssl_free(srv);
    sevent_ssl_ctx_free(cctx);
    sevent_ssl_ctx_free(sctx);
}

/* 5. hostname 不匹配 (证书 SAN=localhost, 连 wrong.example.com) → 失败 */
static void t_hostname_mismatch(void) {
    sevent_ssl_config ccfg = {
            .ca_path = TEST_CERTS_DIR "/ca.pem", .enable_peer_verify = true, .enable_hostname_verify = true};
    sevent_ssl_config scfg = {.cert_path = TEST_CERTS_DIR "/server.pem", .key_path = TEST_CERTS_DIR "/server.key"};
    sevent_ssl       *cctx = sevent_ssl_ctx_new(&ccfg);
    sevent_ssl       *sctx = sevent_ssl_ctx_new(&scfg);
    CHECK(cctx && sctx, "ctx_new 失败");

    sevent_ssl *cli = sevent_ssl_new(cctx, false, "wrong.example.com");
    sevent_ssl *srv = sevent_ssl_new(sctx, true, NULL);
    CHECK(cli && srv, "ssl_new 失败 (hostname 校验在握手期)");
    CHECK(!pump_handshake(cli, srv), "hostname 不匹配应握手失败");

    sevent_ssl_free(cli);
    sevent_ssl_free(srv);
    sevent_ssl_ctx_free(cctx);
    sevent_ssl_ctx_free(sctx);
}

/* 6. mTLS: 服务端 enable_peer_verify=true (要求客户端证书) + 客户端带证书 → 成功 */
static void t_mtls(void) {
    sevent_ssl_config ccfg = {.ca_path                = TEST_CERTS_DIR "/ca.pem",
                              .cert_path              = TEST_CERTS_DIR "/client.pem",
                              .key_path               = TEST_CERTS_DIR "/client.key",
                              .enable_peer_verify     = true,
                              .enable_hostname_verify = true};
    sevent_ssl_config scfg = {.ca_path            = TEST_CERTS_DIR "/ca.pem",
                              .cert_path          = TEST_CERTS_DIR "/server.pem",
                              .key_path           = TEST_CERTS_DIR "/server.key",
                              .enable_peer_verify = true}; /* mTLS */
    sevent_ssl       *cctx = sevent_ssl_ctx_new(&ccfg);
    sevent_ssl       *sctx = sevent_ssl_ctx_new(&scfg);
    CHECK(cctx && sctx, "ctx_new 失败");

    sevent_ssl *cli = sevent_ssl_new(cctx, false, "localhost");
    sevent_ssl *srv = sevent_ssl_new(sctx, true, NULL);
    CHECK(cli && srv, "ssl_new 失败: %s / %s", cli ? "" : errbuf(cctx), srv ? "" : errbuf(sctx));
    CHECK(pump_handshake(cli, srv), "mTLS 握手失败: %s", errbuf(srv));

    const char *msg = "mtls ok";
    CHECK(pump_write(cli, msg, strlen(msg), srv), "client 写入失败");
    char out[32] = {0};
    CHECK(pump_read_exact(srv, out, strlen(msg), cli), "server 读取失败");
    CHECK(memcmp(out, msg, strlen(msg)) == 0, "数据不一致: %s", out);

    sevent_ssl_free(cli);
    sevent_ssl_free(srv);
    sevent_ssl_ctx_free(cctx);
    sevent_ssl_ctx_free(sctx);
}

/* 7. EOF: 对端关闭 (无 close_notify) — 先消费残留密文, 耗尽后 read 返回 0 */
static void t_eof(void) {
    sevent_ssl_config ccfg = {
            .ca_path = TEST_CERTS_DIR "/ca.pem", .enable_peer_verify = true, .enable_hostname_verify = true};
    sevent_ssl_config scfg = {.cert_path = TEST_CERTS_DIR "/server.pem", .key_path = TEST_CERTS_DIR "/server.key"};
    sevent_ssl       *cctx = sevent_ssl_ctx_new(&ccfg);
    sevent_ssl       *sctx = sevent_ssl_ctx_new(&scfg);
    CHECK(cctx && sctx, "ctx_new 失败");

    sevent_ssl *cli = sevent_ssl_new(cctx, false, "localhost");
    sevent_ssl *srv = sevent_ssl_new(sctx, true, NULL);
    CHECK(cli && srv, "ssl_new 失败");
    CHECK(pump_handshake(cli, srv), "握手失败");

    /* 模拟 tcp 层 on_close: 残留密文已搬完, 标记对端连接关闭 (无 close_notify) */
    xfer(srv, cli);
    sevent_ssl_peer_close(cli);
    char tmp[64];
    bool got_eof = false;
    for(int i = 0; i < 100 && !got_eof; i++) {
        ssize_t r = sevent_ssl_read(cli, tmp, sizeof(tmp));
        if(r == 0)
            got_eof = true;
        else if(r < 0 && sevent_ssl_want(cli) == 0)
            got_eof = true; /* 底层致命错误也视为连接终止 */
        /* WANT_*: 继续等 */
    }
    CHECK(got_eof, "对端关闭后应读到 EOF");

    sevent_ssl_free(cli);
    sevent_ssl_free(srv);
    sevent_ssl_ctx_free(cctx);
    sevent_ssl_ctx_free(sctx);
}

/* 8. pending: 一次记录读一半, 剩余经 pending 继续读 */
static void t_pending(void) {
    sevent_ssl_config ccfg = {
            .ca_path = TEST_CERTS_DIR "/ca.pem", .enable_peer_verify = true, .enable_hostname_verify = true};
    sevent_ssl_config scfg = {.cert_path = TEST_CERTS_DIR "/server.pem", .key_path = TEST_CERTS_DIR "/server.key"};
    sevent_ssl       *cctx = sevent_ssl_ctx_new(&ccfg);
    sevent_ssl       *sctx = sevent_ssl_ctx_new(&scfg);
    CHECK(cctx && sctx, "ctx_new 失败");

    sevent_ssl *cli = sevent_ssl_new(cctx, false, "localhost");
    sevent_ssl *srv = sevent_ssl_new(sctx, true, NULL);
    CHECK(cli && srv, "ssl_new 失败");
    CHECK(pump_handshake(cli, srv), "握手失败");

    const size_t total = 8000;
    char        *msg   = malloc(total);
    memset(msg, 'A', total);
    CHECK(pump_write(cli, msg, total, srv), "写入 %zu 字节失败", total);

    char    buf[4096];
    ssize_t r1 = sevent_ssl_read(srv, buf, sizeof(buf));
    CHECK(r1 == 4096, "第一次读应 4096, 实际 %zd", r1);
    CHECK(sevent_ssl_pending(srv) > 0, "读一半后 pending 应 >0");
    ssize_t r2 = sevent_ssl_read(srv, buf, sizeof(buf));
    CHECK(r2 == (ssize_t)(total - 4096), "第二次读应 %zu, 实际 %zd", total - 4096, r2);
    CHECK(memcmp(buf, msg + 4096, (size_t)r2) == 0, "数据不一致");

    free(msg);
    sevent_ssl_free(cli);
    sevent_ssl_free(srv);
    sevent_ssl_ctx_free(cctx);
    sevent_ssl_ctx_free(sctx);
}

/* ===== main ===== */

typedef void (*case_fn)(void);

static const case_fn g_cases[] = {
        t_config_conflict,
        t_handshake_echo,
        t_ctx_load_pem,
        t_verify_fail_no_ca,
        t_hostname_mismatch,
        t_mtls,
        t_eof,
        t_pending,
};

int main(void) {
    sevent_ignore_sigpipe(); /* 契约: 对端关闭后写不发 SIGPIPE (应用层处理) */
    printf("backend: %s\n", sevent_ssl_backend_name());

    const char *names[] = {"config_conflict",
                           "handshake_echo",
                           "ctx_load_pem",
                           "verify_fail_no_ca",
                           "hostname_mismatch",
                           "mtls",
                           "eof",
                           "pending"};
    size_t      n       = sizeof(g_cases) / sizeof(g_cases[0]);
    for(size_t i = 0; i < n; i++) {
        printf("[%zu/%zu] %s ... ", i + 1, n, names[i]);
        g_cases[i]();
        printf("%s\n", g_fail ? "" : "ok");
        if(g_fail)
            return 1; /* 首个失败即停 (fail 计数跨用例不重置) */
    }
    printf("test-ssl: 全部 %zu 用例通过\n", n);
    return 0;
}
