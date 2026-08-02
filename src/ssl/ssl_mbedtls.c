/* =========================================================================
 *  ssl_mbedtls.c — mbedtls 后端 (2.x API, 目标 2.25)
 *
 *  要点 (doc/ssl-design.md §6 + 注①②):
 *   - C1: endpoint (CLIENT/SERVER) 在 config_defaults 定死而角色在 ssl_new
 *         才知 → **config 于 ssl_new 创建**, ctx 只存材料 (CA/cert/pk) +
 *         entropy/ctr_drbg
 *   - 无系统信任库: enable_peer_verify=true 必须提供 CA (ca_path/ca_pem),
 *         ssl_new 时 fail fast (角色已知)
 *   - 主机名: set_hostname 同时做 SNI+校验 (enable_hostname_verify 恒开, 见设计 §7)
 *   - 数据通道 (F 方案): set_bio 回调改内存缓冲 (feed 入 / drain 出,
 *         不碰 fd — 网络 I/O 由上层 tcp_conn 负责)
 *   - 2.x 签名: pk_parse_keyfile 无 f_rng; 错误码只判 <0 与 WANT_* 特殊值
 *  ========================================================================= */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/pk.h>
#include <mbedtls/ssl.h>
#include <mbedtls/version.h> /* MBEDTLS_VERSION_STRING */
#include <mbedtls/x509_crt.h>

#include "sevent_i.h"
#include "ssl.h"
#include "ssl_i.h"

/* ===== 后端对象 ===== */

/* err 必须两个结构体同偏移 (最前): error_str 收到的是 impl (ctx 或 ssl),
 * 按统一前缀读错误文本 */
struct mbtls_ctx {
    char                     err[160]; /* 最近错误文本 (ssl_new 失败等) */
    mbedtls_x509_crt         ca;       /* 验证对端证书链 (客户端验证服务器 / 服务端 mTLS) */
    mbedtls_x509_crt         cert;     /* 本端证书 (含链) */
    mbedtls_pk_context       key;      /* 本端私钥 */
    mbedtls_entropy_context  entropy;
    mbedtls_ctr_drbg_context drbg;
    bool                     have_ca, have_cert, have_key;
    bool                     enable_peer_verify, enable_hostname_verify; /* 记录 cfg (ssl_new 按角色用) */
};

/* 密文通道缓冲: 单次 feed ≤ tcp recv_buf 4KB, TLS 记录 ≤16KB */
#define MBTLS_BUF_SIZE (64 * 1024)

struct mbtls_ssl {
    char                err[160]; /* 与 ctx 同偏移 (最前), error_str 统一读 */
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config  conf; /* setup 引用 conf, 须比 ssl_context 后释放 */
    /* 对端密文 (feed 追加, recv 回调消费) */
    uint8_t             recv_buf[MBTLS_BUF_SIZE];
    size_t              recv_len, recv_pos;
    /* 本端密文 (send 回调追加, drain 消费) */
    uint8_t             send_buf[MBTLS_BUF_SIZE];
    size_t              send_len;
    bool                peer_closed;
    int                 want;
};

/* ===== 错误文本 ===== */

static void mbtls_set_err(char *buf, size_t cap, int ret) {
    buf[0] = '\0';
    if(ret != 0)
        mbedtls_strerror(ret, buf, cap);
    buf[cap - 1] = '\0';
}

static void mbtls_error_str(void *obj, char *buf, size_t cap) {
    if(!buf || cap == 0)
        return;
    if(!obj) { /* ctx_new 失败 (无对象可取): 通用文本, 细节由调用方日志补 */
        snprintf(buf, cap, "mbedtls 初始化失败 (证书加载/私钥不匹配?)");
        return;
    }
    strncpy(buf, ((struct mbtls_ctx *)obj)->err, cap - 1);
    buf[cap - 1] = '\0';
}

/* ===== bio 回调 (内存缓冲 — 数据通道: 不碰 fd) ===== */

static int mbtls_bio_send(void *ctxp, const unsigned char *buf, size_t len) {
    struct mbtls_ssl *s    = (struct mbtls_ssl *)ctxp;
    size_t            free = sizeof(s->send_buf) - s->send_len;
    if(free == 0)
        return MBEDTLS_ERR_SSL_WANT_WRITE; /* 上层 drain 清空后重试 */
    size_t n = len < free ? len : free;
    memcpy(s->send_buf + s->send_len, buf, n);
    s->send_len += n;
    return (int)n;
}

static int mbtls_bio_recv(void *ctxp, unsigned char *buf, size_t len) {
    struct mbtls_ssl *s     = (struct mbtls_ssl *)ctxp;
    size_t            avail = s->recv_len - s->recv_pos;
    if(avail == 0) {
        if(s->peer_closed)
            return MBEDTLS_ERR_SSL_CONN_EOF; /* read 归一 0 (EOF) */
        return MBEDTLS_ERR_SSL_WANT_READ;    /* 等上层 feed */
    }
    size_t n = avail < len ? avail : len;
    memcpy(buf, s->recv_buf + s->recv_pos, n);
    s->recv_pos += n;
    if(s->recv_pos == s->recv_len)
        s->recv_pos = s->recv_len = 0; /* 整块消费完复位 */
    return (int)n;
}

/* ===== ctx_new (只解析材料 + 随机数源; 不建 config — C1) ===== */

static void *mbtls_ctx_new(const sevent_ssl_config *cfg) {
    struct mbtls_ctx *c = sevent_i_calloc(1, sizeof(*c));
    if(!c)
        return NULL;
    mbedtls_x509_crt_init(&c->ca);
    mbedtls_x509_crt_init(&c->cert);
    mbedtls_pk_init(&c->key);
    mbedtls_entropy_init(&c->entropy);
    mbedtls_ctr_drbg_init(&c->drbg);

    int ret = 0;
    do {
        if(mbedtls_ctr_drbg_seed(&c->drbg, mbedtls_entropy_func, &c->entropy, NULL, 0) != 0) {
            snprintf(c->err, sizeof(c->err), "ctr_drbg seed 失败");
            ret = -1;
            break;
        }

        /* CA (enable_peer_verify=true 必填; 无系统信任库概念) */
        if(cfg->ca_path) {
            if((ret = mbedtls_x509_crt_parse_file(&c->ca, cfg->ca_path)) != 0)
                break;
            c->have_ca = true;
        } else if(cfg->ca_pem) {
            if((ret = mbedtls_x509_crt_parse(&c->ca, (const unsigned char *)cfg->ca_pem, strlen(cfg->ca_pem) + 1)) != 0)
                break;
            c->have_ca = true;
        }

        /* 本端证书 + 私钥 (客户端 mTLS 可选; 服务端必填在 ssl_new 检查) */
        if(cfg->cert_path) {
            if((ret = mbedtls_x509_crt_parse_file(&c->cert, cfg->cert_path)) != 0)
                break;
            if((ret = mbedtls_pk_parse_keyfile(&c->key, cfg->key_path, NULL)) != 0)
                break; /* 2.x 签名: 无 f_rng 参数 */
            c->have_cert = c->have_key = true;
        } else if(cfg->cert_pem) {
            if((ret = mbedtls_x509_crt_parse(
                        &c->cert, (const unsigned char *)cfg->cert_pem, strlen(cfg->cert_pem) + 1)) != 0)
                break;
            if((ret = mbedtls_pk_parse_key(
                        &c->key, (const unsigned char *)cfg->key_pem, strlen(cfg->key_pem) + 1, NULL, 0)) != 0)
                break;
            c->have_cert = c->have_key = true;
        }
    } while(0);

    if(ret != 0) {
        mbtls_set_err(c->err, sizeof(c->err), ret);
        mbedtls_ctr_drbg_free(&c->drbg);
        mbedtls_entropy_free(&c->entropy);
        mbedtls_pk_free(&c->key);
        mbedtls_x509_crt_free(&c->cert);
        mbedtls_x509_crt_free(&c->ca);
        sevent_i_free(c);
        return NULL;
    }

    c->enable_peer_verify     = cfg->enable_peer_verify;
    c->enable_hostname_verify = cfg->enable_hostname_verify;
    return c;
}

static void mbtls_ctx_free(void *ctxp) {
    struct mbtls_ctx *c = (struct mbtls_ctx *)ctxp;
    if(!c)
        return;
    mbedtls_ctr_drbg_free(&c->drbg);
    mbedtls_entropy_free(&c->entropy);
    mbedtls_pk_free(&c->key);
    mbedtls_x509_crt_free(&c->cert);
    mbedtls_x509_crt_free(&c->ca);
    sevent_i_free(c);
}

/* ===== ssl_new (此时角色已知: 建 config + setup) ===== */

static void *mbtls_ssl_new(void *ctxp, bool is_server, const char *hostname) {
    struct mbtls_ctx *c = (struct mbtls_ctx *)ctxp;
    int               ret;

    /* 服务端必填检查 (C2) */
    if(is_server && !c->have_cert) {
        snprintf(c->err, sizeof(c->err), "服务端必须提供本端证书 (cert_path/cert_pem)");
        return NULL;
    }
    /* enable_peer_verify=true 无 CA → 验证必然失败, fail fast (无系统信任库) */
    if(c->enable_peer_verify && !c->have_ca) {
        snprintf(c->err, sizeof(c->err), "enable_peer_verify=true 必须提供 CA (ca_path/ca_pem) — mbedtls 无系统信任库");
        return NULL;
    }

    struct mbtls_ssl *s = sevent_i_calloc(1, sizeof(*s));
    if(!s)
        return NULL;
    mbedtls_ssl_init(&s->ssl);
    mbedtls_ssl_config_init(&s->conf);

    do {
        if((ret = mbedtls_ssl_config_defaults(&s->conf,
                                              is_server ? MBEDTLS_SSL_IS_SERVER : MBEDTLS_SSL_IS_CLIENT,
                                              MBEDTLS_SSL_TRANSPORT_STREAM,
                                              MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
            break;

        /* 安全基线: 最低 TLS1.2 (2.x 默认 TLS1.0, 必须显式设置) */
        mbedtls_ssl_conf_min_version(&s->conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);

        /* 验证模式 (enable_peer_verify: REQUIRED; 服务端 mTLS 与客户端同语义) */
        mbedtls_ssl_conf_authmode(&s->conf,
                                  c->enable_peer_verify ? MBEDTLS_SSL_VERIFY_REQUIRED : MBEDTLS_SSL_VERIFY_NONE);
        mbedtls_ssl_conf_rng(&s->conf, mbedtls_ctr_drbg_random, &c->drbg);

        if(c->have_ca)
            mbedtls_ssl_conf_ca_chain(&s->conf, &c->ca, NULL);
        if(c->have_cert)
            mbedtls_ssl_conf_own_cert(&s->conf, &c->cert, &c->key);

        if((ret = mbedtls_ssl_setup(&s->ssl, &s->conf)) != 0)
            break;
        mbedtls_ssl_set_bio(&s->ssl, s, mbtls_bio_send, mbtls_bio_recv, NULL); /* bio ctx = 连接对象 */
        /* 主机名 (两端通用): 客户端=SNI+校验服务器证书名; 服务端=校验客户端证书名.
         * mbedtls 恒开 — set_hostname 即触发校验, 无独立开关 (见设计 §7) */
        if(hostname)
            mbedtls_ssl_set_hostname(&s->ssl, hostname);
        return s;
    } while(0);

    mbtls_set_err(c->err, sizeof(c->err), ret);
    mbedtls_ssl_free(&s->ssl);
    mbedtls_ssl_config_free(&s->conf);
    sevent_i_free(s);
    return NULL;
}

static void mbtls_ssl_free(void *sslp) {
    struct mbtls_ssl *s = (struct mbtls_ssl *)sslp;
    if(!s)
        return;
    mbedtls_ssl_free(&s->ssl);
    mbedtls_ssl_config_free(&s->conf); /* 须在 ssl_free 后 (setup 引用 conf) */
    sevent_i_free(s);
}

/* ===== 操作 ===== */

static int mbtls_handshake(void *sslp) {
    struct mbtls_ssl *s = (struct mbtls_ssl *)sslp;
    s->want             = 0;
    int ret             = mbedtls_ssl_handshake(&s->ssl);
    if(ret == 0)
        return 0;
    if(ret == MBEDTLS_ERR_SSL_WANT_READ)
        return SEVENT_SSL_WANT_READ;
    if(ret == MBEDTLS_ERR_SSL_WANT_WRITE)
        return SEVENT_SSL_WANT_WRITE;
    mbtls_set_err(s->err, sizeof(s->err), ret); /* 含证书验证失败 */
    return -1;
}

static ssize_t mbtls_read(void *sslp, void *buf, size_t len) {
    struct mbtls_ssl *s = (struct mbtls_ssl *)sslp;
    s->want             = 0;
    int ret             = mbedtls_ssl_read(&s->ssl, (unsigned char *)buf, len);
    if(ret > 0)
        return ret;
    if(ret == 0 || ret == MBEDTLS_ERR_SSL_CONN_EOF)
        return 0; /* close_notify 或对端关闭 → EOF */
    if(ret == MBEDTLS_ERR_SSL_WANT_READ) {
        s->want = SEVENT_SSL_WANT_READ;
        return -1;
    }
    if(ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
        s->want = SEVENT_SSL_WANT_WRITE;
        return -1;
    }
    mbtls_set_err(s->err, sizeof(s->err), ret);
    return -1;
}

static ssize_t mbtls_write(void *sslp, const void *buf, size_t len) {
    struct mbtls_ssl *s = (struct mbtls_ssl *)sslp;
    s->want             = 0;
    int ret             = mbedtls_ssl_write(&s->ssl, (const unsigned char *)buf, len);
    if(ret > 0)
        return ret;
    if(ret == MBEDTLS_ERR_SSL_WANT_READ) {
        s->want = SEVENT_SSL_WANT_READ;
        return 0; /* 未写, 重试 */
    }
    if(ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
        s->want = SEVENT_SSL_WANT_WRITE;
        return 0;
    }
    mbtls_set_err(s->err, sizeof(s->err), ret);
    return -1;
}

static int mbtls_want(void *sslp) { return ((struct mbtls_ssl *)sslp)->want; }

static int mbtls_pending(void *sslp) { return mbedtls_ssl_get_bytes_avail(&((struct mbtls_ssl *)sslp)->ssl); }

/* ===== 数据通道 ===== */

static int mbtls_feed(void *sslp, const uint8_t *data, size_t len) {
    struct mbtls_ssl *s = (struct mbtls_ssl *)sslp;
    if(len > sizeof(s->recv_buf) - s->recv_len)
        return -1; /* 理论不发生: feed ≤ tcp recv_buf 4KB, 缓冲 64KB */
    memcpy(s->recv_buf + s->recv_len, data, len);
    s->recv_len += len;
    return 0;
}

static ssize_t mbtls_drain(void *sslp, void *buf, size_t cap) {
    struct mbtls_ssl *s = (struct mbtls_ssl *)sslp;
    size_t            n = s->send_len < cap ? s->send_len : cap;
    if(n == 0)
        return 0;
    memcpy(buf, s->send_buf, n);
    if(n < s->send_len)
        memmove(s->send_buf, s->send_buf + n, s->send_len - n);
    s->send_len -= n;
    return (ssize_t)n;
}

static void mbtls_peer_close(void *sslp) { ((struct mbtls_ssl *)sslp)->peer_closed = true; }

/* ===== ops 表 ===== */

const sevent_ssl_ops sevent_ssl_mbedtls_ops = {
        .name       = "mbedtls " MBEDTLS_VERSION_STRING, /* 如 "mbedtls 2.25.0" */
        .ctx_new    = mbtls_ctx_new,
        .ctx_free   = mbtls_ctx_free,
        .ssl_new    = mbtls_ssl_new,
        .ssl_free   = mbtls_ssl_free,
        .feed       = mbtls_feed,
        .drain      = mbtls_drain,
        .peer_close = mbtls_peer_close,
        .handshake  = mbtls_handshake,
        .read       = mbtls_read,
        .write      = mbtls_write,
        .want       = mbtls_want,
        .pending    = mbtls_pending,
        .error_str  = mbtls_error_str,
};
