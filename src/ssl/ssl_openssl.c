/* =========================================================================
 *  ssl_openssl.c — openssl 后端 (impl = SSL_CTX / SSL + BIO pair)
 *
 *  要点 (doc/ssl-design.md §6):
 *   - TLS_method() 角色无关, verify 模式在 ssl_new 设置 (角色此时已知)
 *   - CA: 路径 SSL_CTX_load_verify_locations / PEM 内存经 cert_store
 *         / 全 NULL → SSL_CTX_set_default_verify_paths (系统信任库)
 *   - 证书: 路径 use_certificate_chain_file / PEM 内存 BIO 读入 (含链)
 *   - 数据通道 (F 方案): 不碰 fd — SSL 经 BIO pair 与上层交换密文
 *     (peer_rbio 收 tcp 密文 → SSL 读; SSL 写 → peer_wbio 取密文交 tcp)
 *   - 归一化: handshake WANT 直接返回; read/write 失败返回负值, WANT 经
 *     want() 查询; EOF=read 返回 0 (ZERO_RETURN / peer_close 后耗尽)
 *  ========================================================================= */

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "sevent_i.h"
#include "ssl.h"
#include "ssl_i.h"

/* ===== 后端对象 ===== */

struct ossl_ctx {
    SSL_CTX *ctx;
    bool     enable_peer_verify; /* 记录 cfg (ssl_new 时按角色用) */
    bool     enable_hostname_verify;
    bool     ca_available; /* CA 已加载或系统默认路径成功 */
};

/* 密文通道缓冲: pair 写端容量 (单次 feed ≤ tcp recv_buf 4KB, 记录 ≤16KB) */
#define OSSL_PAIR_SIZE (64 * 1024)

struct ossl_ssl {
    SSL *ssl;
    bool is_server;
    int  want;      /* 最近一次未完成操作的 WANT_* 状态 */
    BIO *peer_rbio; /* 外部读端: feed 写入 → SSL 读取 */
    BIO *peer_wbio; /* 外部写端: SSL 写入 → drain 读取 */
    bool peer_closed;
};

/* ===== 错误文本 (ERR 队列, 进程级; NULL impl 也适用) ===== */

static void ossl_error_str(void *obj, char *buf, size_t cap) {
    (void)obj;
    if(!buf || cap == 0)
        return;
    buf[0]          = '\0';
    unsigned long e = ERR_get_error();
    if(e)
        ERR_error_string_n(e, buf, cap);
    else
        snprintf(buf, cap, "%s", strerror(errno)); /* 队列空: errno 兜底 */
    ERR_clear_error();
    buf[cap - 1] = '\0';
}

/* ===== ctx_new ===== */

/* CA PEM 内存 → cert_store (验证对端证书链时查 issuer) */
static int ossl_load_ca_pem(SSL_CTX *ctx, const char *pem) {
    BIO        *bio   = BIO_new_mem_buf(pem, -1);
    X509       *x     = NULL;
    X509_STORE *store = SSL_CTX_get_cert_store(ctx);
    int         n     = 0;
    if(!bio)
        return -1;
    while((x = PEM_read_bio_X509(bio, NULL, NULL, NULL)) != NULL) {
        X509_STORE_add_cert(store, x); /* 内部持引用 */
        X509_free(x);
        n++;
    }
    BIO_free(bio);
    return n > 0 ? 0 : -1;
}

/* 本端证书 PEM 内存 (支持链: 第一张=leaf, 其余=extra chain) */
static int ossl_load_cert_pem(SSL_CTX *ctx, const char *pem) {
    BIO  *bio = BIO_new_mem_buf(pem, -1);
    X509 *x   = NULL;
    int   rc  = -1;
    if(!bio)
        return -1;
    x = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if(!x)
        goto out;
    if(SSL_CTX_use_certificate(ctx, x) != 1) /* 拷贝语义 */
        goto out;
    X509_free(x);
    x  = NULL;
    rc = 0;
    while((x = PEM_read_bio_X509(bio, NULL, NULL, NULL)) != NULL) {
        SSL_CTX_add_extra_chain_cert(ctx, x); /* 接管所有权 */
        x = NULL;
    }
out:
    if(x)
        X509_free(x);
    BIO_free(bio);
    return rc;
}

static void *ossl_ctx_new(const sevent_ssl_config *cfg) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_method()); /* 角色无关 method */
    if(!ctx)
        return NULL;

    /* 安全基线: 最低 TLS1.2 */
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    bool ca_ok = false;

    /* CA (验证对端证书链用; 全 NULL → 系统默认信任库) */
    if(cfg->ca_path) {
        if(SSL_CTX_load_verify_locations(ctx, cfg->ca_path, NULL) == 1)
            ca_ok = true;
        else
            goto fail;
    } else if(cfg->ca_pem) {
        if(ossl_load_ca_pem(ctx, cfg->ca_pem) == 0)
            ca_ok = true;
        else
            goto fail;
    } else {
        if(SSL_CTX_set_default_verify_paths(ctx) == 1)
            ca_ok = true; /* 失败仅表示系统 CA 目录缺失, 不影响后续加载 */
    }

    /* 本端证书 + 私钥 (客户端 mTLS 可选; 服务端必填在 ssl_new 检查) */
    if(cfg->cert_path) {
        if(SSL_CTX_use_certificate_chain_file(ctx, cfg->cert_path) != 1)
            goto fail;
        if(SSL_CTX_use_PrivateKey_file(ctx, cfg->key_path, SSL_FILETYPE_PEM) != 1)
            goto fail;
    } else if(cfg->cert_pem) {
        if(ossl_load_cert_pem(ctx, cfg->cert_pem) != 0)
            goto fail;
        BIO      *bio = BIO_new_mem_buf(cfg->key_pem, -1);
        EVP_PKEY *key = bio ? PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL) : NULL;
        if(!key) {
            if(bio)
                BIO_free(bio);
            goto fail;
        }
        if(SSL_CTX_use_PrivateKey(ctx, key) != 1) {
            EVP_PKEY_free(key);
            BIO_free(bio);
            goto fail;
        }
        EVP_PKEY_free(key);
        BIO_free(bio);
    }

    /* 私钥与证书必须匹配 (fail fast) */
    if(cfg->cert_path || cfg->cert_pem) {
        if(SSL_CTX_check_private_key(ctx) != 1)
            goto fail;
    }

    struct ossl_ctx *o = sevent_i_calloc(1, sizeof(*o));
    if(!o)
        goto fail;
    o->ctx                    = ctx;
    o->enable_peer_verify     = cfg->enable_peer_verify;
    o->enable_hostname_verify = cfg->enable_hostname_verify;
    o->ca_available           = ca_ok;
    return o;

fail:
    SSL_CTX_free(ctx);
    return NULL;
}

static void ossl_ctx_free(void *ctxp) {
    struct ossl_ctx *o = (struct ossl_ctx *)ctxp;
    if(!o)
        return;
    SSL_CTX_free(o->ctx);
    sevent_i_free(o);
}

/* ===== ssl_new ===== */

static void *ossl_ssl_new(void *ctxp, bool is_server, const char *hostname) {
    struct ossl_ctx *o = (struct ossl_ctx *)ctxp;

    /* 服务端必填检查 (C2): 证书未配 → 失败 (错误经 ERR 队列/errno) */
    if(is_server && !SSL_CTX_get0_certificate(o->ctx)) {
        errno = EINVAL;
        return NULL;
    }
    /* 服务端 mTLS 无 CA → 客户端证书验证必然失败, fail fast */
    if(is_server && o->enable_peer_verify && !o->ca_available) {
        errno = EINVAL;
        return NULL;
    }

    struct ossl_ssl *s = sevent_i_calloc(1, sizeof(*s));
    if(!s)
        return NULL;

    /* BIO pair 数据通道: 内部端交给 SSL, 外部端 (peer_*) 由上层 feed/drain */
    BIO *rbio = NULL, *wbio = NULL;
    if(BIO_new_bio_pair(&rbio, OSSL_PAIR_SIZE, &s->peer_rbio, OSSL_PAIR_SIZE) != 1)
        goto fail;
    if(BIO_new_bio_pair(&wbio, OSSL_PAIR_SIZE, &s->peer_wbio, OSSL_PAIR_SIZE) != 1)
        goto fail;
    s->ssl = SSL_new(o->ctx);
    if(!s->ssl)
        goto fail;

    /* verify 模式 (角色已知, 此处设置):
     *   客户端: enable_peer_verify → VERIFY_PEER (验证服务器证书链)
     *   服务端: enable_peer_verify → VERIFY_PEER|FAIL_IF_NO_PEER_CERT (mTLS) */
    int mode = SSL_VERIFY_NONE;
    if(o->enable_peer_verify)
        mode = is_server ? (SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT) : SSL_VERIFY_PEER;
    SSL_set_verify(s->ssl, mode, NULL);
    SSL_set_bio(s->ssl, rbio, wbio); /* SSL 接管内部端 */
    s->is_server = is_server;

    /* 主机名校验 (两端通用, enable_hostname_verify 开关):
     *   客户端: 校验服务器证书 SAN; 服务端 (mTLS): 校验客户端证书 SAN.
     *   SNI 仅客户端 (RFC 6066) */
    if(hostname) {
        if(!is_server)
            SSL_set_tlsext_host_name(s->ssl, hostname); /* SNI, 失败不致命 */
        if(o->enable_hostname_verify)
            SSL_set1_host(s->ssl, hostname); /* 证书 SAN 匹配 (仅 enable_peer_verify 时验证生效) */
    }
    return s;

fail:
    if(rbio)
        BIO_free(rbio);
    if(wbio)
        BIO_free(wbio);
    if(s->ssl)
        SSL_free(s->ssl);
    if(s->peer_rbio)
        BIO_free(s->peer_rbio);
    if(s->peer_wbio)
        BIO_free(s->peer_wbio);
    sevent_i_free(s);
    return NULL;
}

static void ossl_ssl_free(void *sslp) {
    struct ossl_ssl *s = (struct ossl_ssl *)sslp;
    if(!s)
        return;
    SSL_free(s->ssl); /* 同时释放内部端 BIO */
    BIO_free(s->peer_rbio);
    BIO_free(s->peer_wbio);
    sevent_i_free(s);
}

/* ===== 数据通道 ===== */

static int ossl_feed(void *sslp, const uint8_t *data, size_t len) {
    struct ossl_ssl *s = (struct ossl_ssl *)sslp;
    if(!s->peer_rbio)
        return -1;
    int n = BIO_write(s->peer_rbio, data, (int)len); /* 缓冲 64KB, 单次喂 ≤4KB, 不会部分写 */
    return n == (int)len ? 0 : -1;
}

static ssize_t ossl_drain(void *sslp, void *buf, size_t cap) {
    struct ossl_ssl *s = (struct ossl_ssl *)sslp;
    if(!s->peer_wbio || cap == 0)
        return 0;
    int n = BIO_read(s->peer_wbio, buf, (int)cap); /* 空: 0 或 -1(retry) → 归一 0 */
    return n > 0 ? n : 0;
}

static void ossl_peer_close(void *sslp) {
    struct ossl_ssl *s = (struct ossl_ssl *)sslp;
    /* 关闭外部读端写侧: SSL 读到缓冲耗尽后返回 EOF (read=0) */
    if(s->peer_rbio)
        BIO_shutdown_wr(s->peer_rbio);
    s->peer_closed = true;
}

/* ===== 操作 ===== */

static int ossl_handshake(void *sslp) {
    struct ossl_ssl *s = (struct ossl_ssl *)sslp;
    s->want            = 0;
    int r              = s->is_server ? SSL_accept(s->ssl) : SSL_connect(s->ssl);
    if(r == 1)
        return 0;
    int err = SSL_get_error(s->ssl, r);
    if(err == SSL_ERROR_WANT_READ)
        return SEVENT_SSL_WANT_READ;
    if(err == SSL_ERROR_WANT_WRITE)
        return SEVENT_SSL_WANT_WRITE;
    return -1; /* 握手/证书验证失败 (含 mTLS) */
}

static ssize_t ossl_read(void *sslp, void *buf, size_t len) {
    struct ossl_ssl *s = (struct ossl_ssl *)sslp;
    s->want            = 0;
    if(len > INT_MAX)
        len = INT_MAX; /* SSL_read 接受 int */
    int r = SSL_read(s->ssl, buf, (int)len);
    if(r > 0)
        return r;
    int err = SSL_get_error(s->ssl, r);
    switch(err) {
    case SSL_ERROR_ZERO_RETURN:
        return 0; /* close_notify → EOF */
    case SSL_ERROR_WANT_READ:
        s->want = SEVENT_SSL_WANT_READ;
        return -1;
    case SSL_ERROR_WANT_WRITE:
        s->want = SEVENT_SSL_WANT_WRITE;
        return -1;
    case SSL_ERROR_SYSCALL:
        if(errno == EINTR || errno == EAGAIN) {
            s->want = SEVENT_SSL_WANT_READ; /* 非阻塞空读 → 重试 */
            return -1;
        }
        if(errno == 0)
            return 0; /* 对端关闭且无 close_notify → EOF (openssl 2.x 路径) */
        return -1;
    case SSL_ERROR_SSL:
        /* openssl 3.x: 对端直接关闭 (无 close_notify) → "unexpected eof while
         * reading" — 归一化为 EOF (2.x 同场景为 SYSCALL+errno=0, 上分支;
         * 宏 3.0 才引入, 旧版本走默认分支) */
#ifdef SSL_R_UNEXPECTED_EOF_WHILE_READING
        if(ERR_GET_REASON(ERR_peek_error()) == SSL_R_UNEXPECTED_EOF_WHILE_READING)
            return 0;
#endif
        return -1; /* 真协议错误 → 致命 */
    default:
        return -1; /* 解密/协议错误 → 致命 */
    }
}

static ssize_t ossl_write(void *sslp, const void *buf, size_t len) {
    struct ossl_ssl *s = (struct ossl_ssl *)sslp;
    s->want            = 0;
    if(len > INT_MAX)
        len = INT_MAX;
    int r = SSL_write(s->ssl, buf, (int)len);
    if(r > 0)
        return r;
    int err = SSL_get_error(s->ssl, r);
    switch(err) {
    case SSL_ERROR_WANT_READ:
        s->want = SEVENT_SSL_WANT_READ;
        return 0; /* 未写, 重试 */
    case SSL_ERROR_WANT_WRITE:
        s->want = SEVENT_SSL_WANT_WRITE;
        return 0;
    case SSL_ERROR_SYSCALL:
        if(errno == EINTR || errno == EAGAIN) {
            s->want = SEVENT_SSL_WANT_WRITE;
            return 0;
        }
        return -1; /* 对端断开等 → 致命 */
    default:
        return -1;
    }
}

static int ossl_want(void *sslp) { return ((struct ossl_ssl *)sslp)->want; }

static int ossl_pending(void *sslp) { return SSL_pending(((struct ossl_ssl *)sslp)->ssl); }

/* ===== ops 表 ===== */

const sevent_ssl_ops sevent_ssl_openssl_ops = {
        .name       = OPENSSL_VERSION_TEXT, /* 如 "OpenSSL 3.0.2 15 Mar 2022" */
        .ctx_new    = ossl_ctx_new,
        .ctx_free   = ossl_ctx_free,
        .ssl_new    = ossl_ssl_new,
        .ssl_free   = ossl_ssl_free,
        .feed       = ossl_feed,
        .drain      = ossl_drain,
        .peer_close = ossl_peer_close,
        .handshake  = ossl_handshake,
        .read       = ossl_read,
        .write      = ossl_write,
        .want       = ossl_want,
        .pending    = ossl_pending,
        .error_str  = ossl_error_str,
};
