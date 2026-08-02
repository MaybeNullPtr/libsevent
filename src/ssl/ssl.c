/* =========================================================================
 *  ssl.c — TLS 抽象层: 壳 + 工厂 + 配置校验
 *
 *  公共函数 = 壳分配 + ops 转发; 后端选择编译期 (ssl_i.h 两 ops 实例,
 *  本文件 #ifdef 选定, 与 CMake SEVENT_WS_TLS_BACKEND 定义对应).
 *  ========================================================================= */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sevent_i.h"
#include "ssl.h"
#include "ssl_i.h"

/* ===== 配置校验 (U4/C2: 每对字段互斥 + cert/key 成对) ===== */

static bool both(const char *a, const char *b) { return a != NULL && b != NULL; }

/* 返回 true=通过; 失败时把原因写入 shell->err */
static bool ssl_config_check(const sevent_ssl_config *cfg, struct sevent_ssl *shell) {
    if(both(cfg->ca_path, cfg->ca_pem)) {
        snprintf(shell->err, sizeof(shell->err), "ca_path 与 ca_pem 互斥, 只能给一个");
        return false;
    }
    if(both(cfg->cert_path, cfg->cert_pem)) {
        snprintf(shell->err, sizeof(shell->err), "cert_path 与 cert_pem 互斥, 只能给一个");
        return false;
    }
    if(both(cfg->key_path, cfg->key_pem)) {
        snprintf(shell->err, sizeof(shell->err), "key_path 与 key_pem 互斥, 只能给一个");
        return false;
    }
    /* cert/key 必须成对 (同一来源通道内): 给了 cert 必须给 key, 反之亦然 */
    if(cfg->cert_path && !cfg->key_path) {
        snprintf(shell->err, sizeof(shell->err), "cert_path 已给但 key_path 缺失 (证书与私钥必须成对)");
        return false;
    }
    if(!cfg->cert_path && cfg->key_path) {
        snprintf(shell->err, sizeof(shell->err), "key_path 已给但 cert_path 缺失 (证书与私钥必须成对)");
        return false;
    }
    if(cfg->cert_pem && !cfg->key_pem) {
        snprintf(shell->err, sizeof(shell->err), "cert_pem 已给但 key_pem 缺失 (证书与私钥必须成对)");
        return false;
    }
    if(!cfg->cert_pem && cfg->key_pem) {
        snprintf(shell->err, sizeof(shell->err), "key_pem 已给但 cert_pem 缺失 (证书与私钥必须成对)");
        return false;
    }
    return true;
}

/* ===== 壳分配 ===== */

static struct sevent_ssl *shell_alloc(const sevent_ssl_ops *ops) {
    struct sevent_ssl *s = sevent_i_calloc(1, sizeof(*s));
    if(!s)
        return NULL;
    s->ops = ops;
    return s;
}

/* ===== 工厂: 编译期选后端 (CMake SEVENT_WS_TLS_BACKEND) ===== */

static const sevent_ssl_ops *backend_ops(void) {
#ifdef SEVENT_WS_TLS_MBEDTLS
    return &sevent_ssl_mbedtls_ops;
#else
    return &sevent_ssl_openssl_ops;
#endif
}

/* ===== 公共 API ===== */

const char *sevent_ssl_backend_name(void) { return backend_ops()->name; }

sevent_ssl *sevent_ssl_ctx_new(const sevent_ssl_config *cfg) {
    if(!cfg)
        return NULL;
    struct sevent_ssl *ctx = shell_alloc(backend_ops());
    if(!ctx)
        return NULL;
    if(!ssl_config_check(cfg, ctx)) {
        sevent_i_free(ctx);
        return NULL;
    }
    ctx->impl = ctx->ops->ctx_new(cfg);
    if(!ctx->impl) {
        /* 后端加载失败: 取后端错误文本 (如私钥不匹配) */
        ctx->ops->error_str(NULL, ctx->err, sizeof(ctx->err));
        sevent_i_free(ctx);
        return NULL;
    }
    return ctx;
}

void sevent_ssl_ctx_free(sevent_ssl *ctx) {
    if(!ctx)
        return;
    ctx->ops->ctx_free(ctx->impl);
    sevent_i_free(ctx);
}

sevent_ssl *sevent_ssl_new(sevent_ssl *ctx, bool is_server, const char *hostname) {
    if(!ctx)
        return NULL;
    struct sevent_ssl *ssl = shell_alloc(ctx->ops);
    if(!ssl)
        return NULL;
    ssl->impl = ssl->ops->ssl_new(ctx->impl, is_server, hostname);
    if(!ssl->impl) {
        /* 失败原因记入 ctx (调用方从 ctx 取错误文本) */
        ssl->ops->error_str(ctx->impl, ctx->err, sizeof(ctx->err));
        sevent_i_free(ssl);
        return NULL;
    }
    return ssl;
}

void sevent_ssl_free(sevent_ssl *ssl) {
    if(!ssl)
        return;
    ssl->ops->ssl_free(ssl->impl);
    sevent_i_free(ssl);
}

int sevent_ssl_feed(sevent_ssl *ssl, const uint8_t *data, size_t len) { return ssl->ops->feed(ssl->impl, data, len); }

ssize_t sevent_ssl_drain(sevent_ssl *ssl, void *buf, size_t cap) { return ssl->ops->drain(ssl->impl, buf, cap); }

void sevent_ssl_peer_close(sevent_ssl *ssl) { ssl->ops->peer_close(ssl->impl); }

int sevent_ssl_handshake(sevent_ssl *ssl) { return ssl->ops->handshake(ssl->impl); }

ssize_t sevent_ssl_read(sevent_ssl *ssl, void *buf, size_t len) { return ssl->ops->read(ssl->impl, buf, len); }

ssize_t sevent_ssl_write(sevent_ssl *ssl, const void *buf, size_t len) { return ssl->ops->write(ssl->impl, buf, len); }

int sevent_ssl_want(sevent_ssl *ssl) { return ssl->ops->want(ssl->impl); }

int sevent_ssl_pending(sevent_ssl *ssl) { return ssl->ops->pending(ssl->impl); }

void sevent_ssl_error(sevent_ssl *ssl, char *buf, size_t cap) {
    if(!ssl || !buf || cap == 0)
        return;
    buf[0] = '\0';
    if(ssl->err[0])
        strncpy(buf, ssl->err, cap - 1);
    else if(ssl->impl)
        ssl->ops->error_str(ssl->impl, buf, cap);
    buf[cap - 1] = '\0';
}
