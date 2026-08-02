/* =========================================================================
 *  ssl.h — TLS 抽象层: openssl / mbedtls 双后端统一接口 (库内部)
 *
 *  设计依据: doc/ssl-design.md (2026-08-02 定稿)
 *  本层是 tls_conn 的实现细节, 不对外公开 (openssl/mbedtls 类型不泄露).
 *  后端选择编译期: CMake SEVENT_WS_TLS_BACKEND (默认 MBEDTLS), 工厂经
 *  #ifdef 选 ops 表 (见 ssl.c).
 *
 *  对象两段式 (两后端强制模型):
 *    ctx — 配置+证书材料 (每连接一个, 不跨连接共享)
 *    ssl — 单个连接 (绑定 fd + hostname, 握手/读写)
 *
 *  归一化语义 (各后端内部翻译, 调用方无感知):
 *    handshake: 0=完成 / WANT_READ / WANT_WRITE / <0=失败 (含证书验证失败)
 *    read:      >0 数据 / 0=EOF(对端 close_notify 或关闭) / <0=错误
 *    write:     >0 实际写 / 0=未写重试 / <0=致命错误
 *    want:      read/write 未完成操作的原因 (0=无, 真错误时也为 0)
 *    注意: read 0=EOF, write 0=重试 — 语义不同, 勿混淆
 *  ========================================================================= */

#ifndef SEVENT_SSL_H
#define SEVENT_SSL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h> /* ssize_t */

#ifdef __cplusplus
extern "C" {
#endif

/* 不透明句柄: 壳 (ops + impl), ctx 与 ssl 共用同一类型 */
typedef struct sevent_ssl sevent_ssl;

/* 当前编译后端的名字+版本 (调试日志用), 如 "mbedtls 2.25.0" /
 * "OpenSSL 3.0.2 15 Mar 2022". 编译期常量, 静态存储, 无需释放 */
const char *sevent_ssl_backend_name(void);

/* ===== 配置 (create 时一次性传入) =====
 * 证书三件套: 文件路径 + 内存 PEM 双通道, 每对字段互斥 (同时提供 → ctx_new 失败)
 * 均为 NULL: CA → openssl=系统默认信任库 / mbedtls=配置错误; cert/key → 配置错误
 * 格式: 仅 PEM 文本 (NUL 结尾), 私钥不支持加密 */
typedef struct sevent_ssl_config {
    const char *ca_path;
    const char *ca_pem;
    const char *cert_path;
    const char *cert_pem;
    const char *key_path;
    const char *key_pem;
    bool        enable_peer_verify;     /* 客户端=验证服务器证书链; 服务端=true=mTLS */
    bool        enable_hostname_verify; /* 客户端主机名校验, 默认 true; mbedtls 恒开 */
} sevent_ssl_config;

/* 握手/IO 状态 (handshake 直接返回; read/write 经 want() 查询) */
enum { SEVENT_SSL_OK = 0, SEVENT_SSL_WANT_READ = 1, SEVENT_SSL_WANT_WRITE = 2 };

/* ===== 两段式对象 ===== */

/* 创建配置上下文: 解析证书材料. NULL=失败 (错误文本经 sevent_ssl_error(ctx,..) 取,
 * 但 ctx 未创建时无对象可取 — 互斥/成对检查失败由 tls_conn 层打印 config 错误日志). */
sevent_ssl *sevent_ssl_ctx_new(const sevent_ssl_config *cfg);

/* 释放配置上下文 (须在 ssl_free 之后) */
void sevent_ssl_ctx_free(sevent_ssl *ctx);

/* 创建连接对象 (数据通道模型 — 不绑定 fd, 密文经 feed/drain 与上层交换,
 * 上层通常是组合的 tcp_conn 字节流). is_server 定角色 (open=client / accept=server).
 * hostname 两端通用 (enable_hostname_verify 时):
 *   客户端: SNI + 校验名 (NULL=不设 SNI 不校名, IP 直连)
 *   服务端: 期望的客户端证书主机名 (mTLS 时, NULL=不校验名)
 * 服务端 cert 必填检查在此做 (角色此时已知): is_server && cert/key 全 NULL → 失败.
 * NULL=失败 (错误文本经 sevent_ssl_error(ctx,..) 取). */
sevent_ssl *sevent_ssl_new(sevent_ssl *ctx, bool is_server, const char *hostname);

/* 释放连接对象 (不做 close_notify — WebSocket 场景 Close 帧已由 ws 层处理,
 * 底层连接由上层 (tcp_conn) 关闭) */
void sevent_ssl_free(sevent_ssl *ssl);

/* 喂入对端来的密文 (tcp_conn on_data 推送的数据). 全部接受后返回 0;
 * 缓冲不足返回 -1 (上层应增大喂入间隔 — 实际由内部缓冲容量保证, 正常不会发生).
 * 数据内部复制, 上层可随即复用缓冲. */
int sevent_ssl_feed(sevent_ssl *ssl, const uint8_t *data, size_t len);

/* 取走本端产出的密文 (握手消息/加密数据, 转交给 tcp_conn 发出).
 * >0 字节; 0=当前无. 调用方循环取空. */
ssize_t sevent_ssl_drain(sevent_ssl *ssl, void *buf, size_t cap);

/* 标记对端底层连接已关闭 (tcp_conn on_close/EOF 时调用, 无 close_notify).
 * 已喂入的密文先被消费, 耗尽后 read 返回 0 (EOF). */
void sevent_ssl_peer_close(sevent_ssl *ssl);

/* ===== 操作 ===== */

/* 握手: 0=完成 / WANT_READ / WANT_WRITE / <0=失败 (含证书验证失败、mTLS 缺客户端证书).
 * 调用方按 WANT_* 注册对应事件兴趣, 事件就绪后再次调用 (可反复). */
int sevent_ssl_handshake(sevent_ssl *ssl);

/* 读: >0 数据 / 0=EOF / <0=错误 (want() 区分 WANT_* 可重试与真错误) */
ssize_t sevent_ssl_read(sevent_ssl *ssl, void *buf, size_t len);

/* 写: >0 实际写 / 0=未写重试 (want() 查原因) / <0=致命错误.
 * 调用方须自己维护偏移 (部分写) — 与 tcp 层约定一致 */
ssize_t sevent_ssl_write(sevent_ssl *ssl, const void *buf, size_t len);

/* 最近一次未完成操作的原因: 0 / WANT_READ / WANT_WRITE (真错误时返回 0) */
int sevent_ssl_want(sevent_ssl *ssl);

/* 已解密可读字节数: fd 已无可读事件但 SSL 内部有数据时, 调用方据此继续读
 * (openssl SSL_pending / mbedtls get_bytes_avail) */
int sevent_ssl_pending(sevent_ssl *ssl);

/* 最近错误文本 (调试日志用, 尽力而为). ctx 与 ssl 壳均可调:
 * ssl_new 失败时从 ctx 取, 运行期错误从 ssl 取 */
void sevent_ssl_error(sevent_ssl *ssl, char *buf, size_t cap);

#ifdef __cplusplus
}
#endif
#endif /* SEVENT_SSL_H */
