/* =========================================================================
 *  sevent_tls_conn.h — TLS 传输层 (公开, 可独立使用)
 *
 *  定位:
 *   独立完整层 — 用户可直接用本 API 完成 TLS 客户端/服务端 (握手/SNI/
 *   证书验证/WANT_* 全部在内部消化), 不经过 stream_conn 抽象.
 *   ws 模块经 stream_conn 使用 (内部适配本层). 用法与 tcp_conn 完全一致,
 *   仅 create 多一个 TLS 配置.
 *
 *  编译: SEVENT_WS_TLS=ON (CMake SEVENT_WS_TLS_BACKEND 选后端, 默认 MBEDTLS).
 *
 *  接口约定 (与 tcp_conn 同风格的纯回调推送模型, 仅以下差异):
 *   - 建立: open = TCP connect → TLS 握手 → on_open (握手完成);
 *           accept = 包装已 accept 的 fd → TLS 握手 → on_open
 *   - 失败: 建连失败 on_error(SEVENT_ERR_CONNECT); 握手/证书验证失败
 *           on_error(SEVENT_ERR_HANDSHAKE)
 *   - 数据: on_data 推送的是 TLS 解密后的明文 (密文层由内部搬运)
 *   - 其余 (状态机/close 语义/destroy 延迟释放/线程) 与 tcp_conn 一致
 *  ========================================================================= */

#ifndef SEVENT_TLS_CONN_H
#define SEVENT_TLS_CONN_H

#include <stddef.h>
#include <stdint.h>
#include "sevent.h"
#include "sevent_stream_conn.h" /* 回调类型 + sevent_stream_conn_init + config */

#ifdef __cplusplus
extern "C" {
#endif

/* ===== 错误码 =====
 * 复用 sevent 核心错误码 (sevent.h) + stream 层:
 *   SEVENT_ERR_INVAL     — 参数/非法状态调用 (open 前置条件不满足等)
 *   SEVENT_ERR_NOMEM     — 内存不足
 *   SEVENT_ERR_CONNECT   — TCP 连接失败 (open 立即失败或 on_error 通知)
 *   SEVENT_ERR_HANDSHAKE — TLS 握手失败 (含证书链/主机名验证失败、mTLS 缺客户端证书)
 *   SEVENT_ERR_READ / SEVENT_ERR_WRITE — 读写致命错误 (on_error 通知) */

/* ===== 不透明句柄 ===== */
typedef struct tls_conn sevent_tls_conn; /* 实现: struct tls_conn (tls_conn.c) */

/* ===== 回调类型 + 连接初始化参数 =====
 * 复用 sevent_stream_conn.h (唯一一套定义): 回调类型 sevent_stream_*_fn 与
 * 结构体 sevent_stream_conn_init (回调组 + connect_timeout_ms/recv_buf_size).
 * 本层直接使用, 不重复定义. */

/* ===== API ===== */

/*
 * 创建 TLS 传输对象. cfg 必须非 NULL, TLS 字段 (D2/D3/D6):
 *   - ca_path/ca_pem          — CA 证书 (客户端 enable_peer_verify 时;
 *                                mbedtls 后端必填 — 无系统信任库概念;
 *                                openssl 可 NULL=系统默认信任库)
 *   - cert_path/key_path      — 本端证书/私钥 (服务端必填; 客户端 mTLS 可选)
 *   - enable_peer_verify      — 客户端: 验证服务器证书链 (默认 true);
 *                                服务端: 要求客户端证书 mTLS (默认 false)
 *   - enable_hostname_verify  — 校验对端证书名开关 (两端, 默认 true;
 *                                mbedtls 恒开 — set_hostname 即校验)
 *   - tls_hostname            — 本端期望的对端证书名 (对象级):
 *                                客户端: SNI+校验名 (NULL=用 open 的 host)
 *                                服务端: 校验客户端证书名 (mTLS 时, NULL=不校验)
 * 前置条件: ev 已通过 sevent_create 创建.
 * 返回:     句柄, 或 NULL (ev/cfg 非法 / 证书加载失败 / 内存不足).
 * 线程:     串行 (loop 线程).
 */
sevent_tls_conn *sevent_tls_conn_create(sevent_context *ev, const sevent_stream_conn_config *cfg);

/*
 * 客户端: 异步建立 TLS 连接 (TCP connect → TLS 握手 → on_open).
 * 行为:     TCP connect (非阻塞) → SO_ERROR → TLS 握手 (WANT_* 内部驱动)
 *           → 成功 on_open (握手完成) / 失败 on_error(SEVENT_ERR_CONNECT 或
 *           SEVENT_ERR_HANDSHAKE) (状态回 IDLE 可重开).
 * 前置条件: host 非 NULL; init 非 NULL 且 on_open/on_data 非 NULL; 状态为 IDLE
 *           (重复调用前必须先 close). DNS 是应用层工作 — host 传 IP,
 *           域名校验名经 config.tls_hostname.
 * 返回:     0 = 已启动 (结果经回调通知);
 *           <0 = SEVENT_ERR_INVAL / SEVENT_ERR_CONNECT / SEVENT_ERR_NOMEM.
 * 后置条件: 成功 → OPENING; on_open 后 → OPEN.
 * 回调:     init 各回调由事件循环触发; 回调内可调 write/close/destroy.
 * 线程:     [loop 线程].
 */
int sevent_tls_conn_open(sevent_tls_conn *c, const char *host, uint16_t port, const sevent_stream_conn_init *init);

/*
 * 服务端: 包装已 accept 的连接并做 TLS 握手.
 * 行为:     fd 置非阻塞 → 注册事件 → TLS 握手 (accept 路径) → on_open.
 * 前置条件: fd >= 0; init 非 NULL 且 on_open/on_data 非 NULL; 状态为 IDLE;
 *           create 时已提供 cert_path/key_path (服务端必填, 缺失则建立失败
 *           on_error(SEVENT_ERR_HANDSHAKE)).
 *           fd 所有权契约: 成功 → 移交本层; 失败 → 归还调用方 (本层不关闭,
 *           调用方负责 close — 谁拥有谁关闭).
 * 返回:     0 = 已接受; <0 = SEVENT_ERR_INVAL / SEVENT_ERR_NOMEM.
 * 回调:     同 open.
 * 线程:     [loop 线程].
 */
int sevent_tls_conn_accept(sevent_tls_conn *c, int fd, const sevent_stream_conn_init *init);

/*
 * 发送数据 (明文; 异步, 立即返回).
 * 行为:     明文经 SSL_write 加密 → 密文交内部 tcp_conn 写队列异步 flush;
 *           调用方数据可随即复用. 前置条件: 状态为 OPEN (on_open 之后).
 * 返回:     0 = 已接受; <0 = SEVENT_ERR_INVAL / SEVENT_ERR_NOMEM / SEVENT_ERR_WRITE.
 * 线程:     [loop 线程] (SEVENT_THREAD_SAFE=ON 时跨线程安全).
 */
int sevent_tls_conn_write(sevent_tls_conn *c, const void *data, size_t len);

/*
 * 关闭连接 (TLS 不做 close_notify, 直接 TCP close — WebSocket 场景 Close
 * 帧已由 ws 层处理). 行为: 释放 TLS 连接对象 + 关闭底层 TCP + 状态回 IDLE,
 * 可重新 open/accept. 不触发 on_close. 任意状态可调, 幂等.
 * 线程:     [loop 线程] (SEVENT_THREAD_SAFE=ON 时跨线程安全).
 */
void sevent_tls_conn_close(sevent_tls_conn *c);

/*
 * 释放对象内存 (含内部 tcp_conn/ssl 配置). free 推迟到 run_posts (sevent_post),
 * 回调栈安全展开 — 回调内可安全调用. 调用后对象作废 (含再次 destroy 为未定义
 * 行为). 注: 销毁 ev 前未推进循环则对象泄漏 (sevent_destroy 丢弃未执行 post).
 * 线程:     SEVENT_THREAD_SAFE=ON 时跨线程安全, OFF 时 [loop 线程].
 */
void sevent_tls_conn_destroy(sevent_tls_conn *c);

/*
 * 获取底层 SSL 对象 (供 ALPN/会话复用/证书信息等特殊需求; NULL=无).
 * 线程: [loop 线程].
 */
void *sevent_tls_conn_get_ssl(sevent_tls_conn *c);

#ifdef __cplusplus
}
#endif
#endif /* SEVENT_TLS_CONN_H */
