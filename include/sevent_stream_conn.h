/* =========================================================================
 *  sevent_stream_conn.h — 传输流抽象: tcp_conn / tls_conn 的统一接口
 *
 *  tcp_conn / tls_conn 均为公开传输层 (见 tcp_conn.h / tls_conn.h),
 *  ws 模块内部统一通过本接口使用, 不感知具体实现 — tls 用起来和 tcp 一样.
 *
 *  设计原则 (纯回调推送模型, 与 sevent_ws 同风格):
 *   - 对上层呈现"非阻塞流"语义: TLS 的握手/WANT_READ/WANT_WRITE/SNI/证书
 *     验证全部在 tls_conn 内部消化, 上层只感知创建时的 config
 *   - 建立流程 (客户端 TCP connect + TLS 握手 / 服务端 TLS 握手) 由
 *     stream 层全包, 完成/失败走回调, 事件注册权在 stream 层内部
 *   - 读由事件驱动: 数据经 on_data 推送 (本层持有接收缓冲), 上层收到即处理,
 *     不提供 read API, 不主动轮询
 *   - 写异步: write 返回"已接受", 数据拷贝进本层写队列自动 flush, 上层无感知
 *
 *  状态机:
 *     IDLE --open/accept--> OPENING --on_open--> OPEN --EOF--> IDLE(可重开)
 *     OPENING 中 close() = 取消建立 (on_open/on_error 不再触发)
 *     EOF → on_close (状态已回 IDLE, 可重新 open/accept)
 *     主动 close() 不触发 on_close; on_error 后同样回 IDLE 可重开
 *
 *  生命周期: create → open/accept → write → close (可重开)
 *            → destroy (free 推迟到 run_posts, 回调内可安全调用; 调用后对象作废)
 *
 *  线程: 编译时 SEVENT_THREAD_SAFE=ON 时, write/close/destroy 跨线程安全
 *        (各连接一把递归锁, 与 sevent_ws 同约定: IO 回调与公开 API 均持锁);
 *        open/accept 仍为 [loop 线程]. 默认 OFF 时与 sevent 一致 — 全部
 *        调用需在 loop 线程或启动前.
 *  ========================================================================= */

#ifndef SEVENT_STREAM_CONN_H
#define SEVENT_STREAM_CONN_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include "sevent.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 不透明句柄: 实现为 tcp_conn / tls_conn (create 后不可变) */
typedef struct sevent_stream_conn sevent_stream_conn;

/* 无效 fd 值 (各实现层内部 socket 字段初始值; tcp_conn/tls_conn 共用) */
#define SEVENT_INVALID_SOCKET (-1)

/* ===== 错误码 =====
 * 复用 sevent 核心错误码 (sevent.h SEVENT_ERR_*):
 *   SEVENT_ERR_INVAL     — 参数/非法状态调用
 *   SEVENT_ERR_NOMEM     — 内存不足
 *   SEVENT_ERR_CONNECT   — TCP 连接失败
 *   SEVENT_ERR_HANDSHAKE — TLS 握手失败 (含证书验证失败)
 *   SEVENT_ERR_READ / SEVENT_ERR_WRITE — 读写致命错误 */

/* ===== 配置 (create 时一次性传入) =====
 * 注: TCP_NODELAY 不做配置项 — 连接建立后 (on_open 回调内) 按需
 * sevent_stream_set_no_delay 设置 (见下).
 * 生命周期: create 后 config 即可释放 — TLS 字符串字段 (ca/cert/key/
 * tls_hostname) 库内部自有拷贝 (tls_conn 同步装载或 strdup), 无外部引用. */
typedef struct sevent_stream_conn_config {
    bool        enable_tls; /* false=tcp_conn, true=tls_conn (sevent_stream_create 分发用) */
    /* --- TLS 配置 (tls_conn 用; tcp_conn 忽略) ---
     * 证书路径与 PEM 内存双通道 (D3), 每对字段互斥 (同时给 → create 失败):
     *   ca_path/ca_pem, cert_path/cert_pem, key_path/key_pem */
    const char *ca_path;                /* CA 证书路径, NULL=系统默认信任库 */
    const char *ca_pem;                 /* CA 证书 PEM 内存 (NUL 结尾) */
    const char *cert_path;              /* 本端证书 (服务端必填; 客户端 mTLS 可选) */
    const char *cert_pem;               /* 本端证书 PEM 内存 (支持链, NUL 结尾) */
    const char *key_path;               /* 本端私钥 (PEM, 不支持加密) */
    const char *key_pem;                /* 本端私钥 PEM 内存 */
    bool        enable_peer_verify;     /* 客户端: 校验服务器证书链 (默认 true);
                                         * 服务端: 要求客户端证书 mTLS (默认 false) */
    bool        enable_hostname_verify; /* 校验对端证书名开关, 两端通用, 默认 true */
    const char *tls_hostname;           /* D2: 本端期望的对端证书名 (与开关同处, 对象级)
                                         *   客户端: SNI+校验名 (NULL=用 open 的 host, 校验连接目标)
                                         *   服务端: 校验客户端证书名 (mTLS 时, NULL=不校验名)
                                         * 应用负责 DNS — TCP 目标 (open 的 host) 传 IP, 域名校验名经此字段 */
} sevent_stream_conn_config;

/* ===== 回调类型 (唯一一套: tcp_conn/tls_conn 复用, 不重复定义) ===== */
typedef void (*sevent_stream_open_fn)(void *user_data); /* 建立完成 (TLS 模式=握手完成) */
typedef void (*sevent_stream_data_fn)(void *user_data, const uint8_t *data, size_t len); /* 数据推送 */
typedef void (*sevent_stream_close_fn)(void *user_data);          /* 对端关闭 (EOF), 状态已回 IDLE 可重开 */
typedef void (*sevent_stream_error_fn)(void *user_data, int err); /* 建立失败/数据期致命错误 */

/* ===== 连接初始化参数 (open/accept 时传入, 每轮建立重置) =====
 * 回调组 + 连接配置 (与 sevent_ws_config 同风格). 各实现层 (tcp/tls)
 * 复用本结构体与回调类型. */
typedef struct sevent_stream_conn_init {
    /* --- 回调组 --- */
    void                  *user_data;
    sevent_stream_open_fn  on_open;
    sevent_stream_data_fn  on_data;
    sevent_stream_close_fn on_close;
    sevent_stream_error_fn on_error;
    /* --- 连接配置 (0=默认) --- */
    int                    connect_timeout_ms; /* 建连超时: 0=默认 10s; <0=禁用 (无超时定时器) */
    size_t                 recv_buf_size;      /* 接收缓冲/on_data 单次推送上限: 0=默认 4096 */
} sevent_stream_conn_init;

/* ===== API ===== */

/* 统一工厂: cfg.enable_tls 决定 tls_conn (true) / tcp_conn (false).
 * 也可直接用 sevent_tcp_conn_create / sevent_tls_conn_create (见各自头文件).
 * 线程: [loop 线程] */
sevent_stream_conn *sevent_stream_create(sevent_context *ev, const sevent_stream_conn_config *cfg);

/* 客户端: 异步建立 — TCP connect(EINPROGRESS) → SO_ERROR 检查 → (TLS) 握手 → on_open.
 * 失败 → on_error(err) (状态回 IDLE 可重开). 返回 0=已启动, <0=SEVENT_ERR_*.
 * 重复调用前必须先 close. 前置: init 非 NULL 且 on_open/on_data 非 NULL.
 * 线程: [loop 线程] */
int sevent_stream_open(sevent_stream_conn *s, const char *host, uint16_t port, const sevent_stream_conn_init *init);

/* 服务端: 包装已 accept 的连接 (TCP 模式直接可读写; TLS 模式做服务端握手).
 * fd 所有权契约: 成功 → 移交本层; 失败 → 归还调用方 (本层不关闭, 调用方
 * 负责 close). 语义同 open: 回调由事件循环触发. */
int sevent_stream_accept(sevent_stream_conn *s, int fd, const sevent_stream_conn_init *init);

/* 发送数据 (异步, 立即返回).
 * 行为: 数据拷贝进本层写队列 → 立即尝试 flush (写就绪) → 未写完注册写兴趣
 * 由事件驱动续写 (TLS 模式内部消化 WANT_*); 队列空后自动撤写兴趣.
 * 前置条件: on_open 后 (OPEN); 之前返回 SEVENT_ERR_INVAL.
 * 返回: 0 = 已接受 (失败经 on_error 通知); <0 = SEVENT_ERR_* (见 tcp_conn.h). */
int sevent_stream_write(sevent_stream_conn *s, const void *data, size_t len);

/* 按需开启 TCP_NODELAY (关 Nagle): 小包请求-响应交替协议 (HTTP/WS) 建议开 —
 * Nagle+delayed ACK 交互引入 ~40ms/轮延迟. 连接建立后 (on_open 回调内) 调用.
 * 默认关 (框架不替应用决定延迟/吞吐权衡). 线程: [loop 线程]. */
void sevent_stream_set_no_delay(sevent_stream_conn *s, bool on);

/* 关闭底层连接 (TCP close; TLS 模式不做 close_notify, 直接关闭 — WebSocket
 * 场景 Close 帧已由 ws 层处理). 任意状态可调, 幂等; 回调内可安全调用;
 * 不触发 on_close; 关闭后可重新 open/accept. */
void sevent_stream_close(sevent_stream_conn *s);

/* ===== 半关 (shutdown) ===== */
#define SEVENT_SHUT_RD 0x1 /* 关闭读方向 (后续读 → EOF) */
#define SEVENT_SHUT_WR 0x2 /* 关闭写方向 (发完数据 + FIN; 后续写报错) */

/* 半关连接: shutdown(fd, flag).
 * SHUT_WR 语义: 本层写队列先 flush 进内核 (内核保证已入队数据发完 + FIN),
 *               队列非空时标记待执行 — flush 完成后自动执行. 之后写报错.
 * 用途: http server 响应后优雅关闭 (响应 close=true → shutdown(WR) →
 *       发完响应 + FIN → 等对端 EOF). 半关后读方向继续 (可读对端剩余数据).
 * flag: SEVENT_SHUT_RD / SEVENT_SHUT_WR / 两者.
 * 返回: 0=已执行或已标记; <0=SEVENT_ERR_INVAL (未 OPEN/参数非法).
 * 线程: 同 write. */
int sevent_stream_shutdown(sevent_stream_conn *s, int flag);

/* 释放对象. free 一律推迟到事件循环 run_posts 阶段 (sevent_post, 不区分
 * sevent_run/run_once 模式), 回调栈安全展开 — 回调内可安全调用.
 * 约束: 调用后对象作废 — 不得再对 s 调用任何 API (含再次 destroy),
 *       违反为未定义行为. destroy 不允许幂等.
 * 注: free 由事件循环执行 — destroy 后须推进循环; sevent_destroy 丢弃
 *     未执行的 post, 销毁 ev 前未推进循环则对象泄漏.
 * 线程: SEVENT_THREAD_SAFE=ON 时跨线程安全, OFF 时 [loop 线程]. */
void sevent_stream_destroy(sevent_stream_conn *s);

#ifdef __cplusplus
}
#endif
#endif /* SEVENT_STREAM_CONN_H */
