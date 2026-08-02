/* =========================================================================
 *  ssl_i.h — 内部契约: ssl 壳结构 + ops 表 (仅 ssl.c / ssl_openssl.c /
 *  ssl_mbedtls.c 使用, 不对外稳定, 与 sevent_stream_conn_i.h 同级别)
 *
 *  组合模型 (has-a): 壳 { ops, impl, err }, impl 是后端对象指针
 *  (openssl: SSL_CTX / SSL; mbedtls: 自管结构体). ops 函数全部收后端
 *  impl 指针 (ctx 角色 / ssl 角色靠参数名区分), 与 stream 层 ops 收壳
 *  不同 — 本层全部内部使用, 无需经壳中转.
 *  ========================================================================= */

#ifndef SEVENT_SSL_I_H
#define SEVENT_SSL_I_H

#include "ssl.h"

typedef struct sevent_ssl_ops {
    const char *name; /* 后端名+版本 (调试日志用), 如 "mbedtls 2.25.0" */
    /* ctx 角色 (void *ctx) */
    void *(*ctx_new)(const sevent_ssl_config *cfg); /* 后端 ctx 对象, NULL=失败 */
    void (*ctx_free)(void *ctx);
    /* ssl 角色 (void *ssl) — 数据通道模型: 不碰 fd, 密文经 feed/drain 交换 */
    void *(*ssl_new)(void *ctx, bool is_server, const char *hostname);
    void (*ssl_free)(void *ssl);
    int (*feed)(void *ssl, const uint8_t *data, size_t len); /* 喂入对端密文, 0=接受 */
    ssize_t (*drain)(void *ssl, void *buf, size_t cap);      /* 取本端密文, >0 字节 */
    void (*peer_close)(void *ssl);                           /* 对端底层连接已关闭 */
    /* 操作 */
    int (*handshake)(void *ssl);                              /* 0 / WANT_READ / WANT_WRITE / <0 */
    ssize_t (*read)(void *ssl, void *buf, size_t len);        /* >0 / 0=EOF / <0 */
    ssize_t (*write)(void *ssl, const void *buf, size_t len); /* >0 / 0=重试 / <0 */
    int (*want)(void *ssl);                                   /* 0 / WANT_READ / WANT_WRITE */
    int (*pending)(void *ssl);                                /* 已解密待读字节数 */
    void (*error_str)(void *ssl, char *buf, size_t cap);      /* 错误文本 (ctx/ssl 均可) */
} sevent_ssl_ops;

/* 壳: ops 表 + 后端对象 + 错误文本缓冲 */
struct sevent_ssl {
    const sevent_ssl_ops *ops;
    void                 *impl;
    char                  err[160]; /* 最近错误文本 (ctx/ssl 共用), 首字节 0=空 */
};

/* 两后端 ops 实例 (ssl_openssl.c / ssl_mbedtls.c) */
extern const sevent_ssl_ops sevent_ssl_openssl_ops;
#ifdef SEVENT_WS_TLS_MBEDTLS
extern const sevent_ssl_ops sevent_ssl_mbedtls_ops;
#endif

#endif /* SEVENT_SSL_I_H */
