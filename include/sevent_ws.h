/* =========================================================================
 *  sevent_ws.h — WebSocket 客户端 (RFC 6455) 公开 API
 *
 *  基于 libsevent 事件循环构建.
 *
 *  用法:
 *    1. 配置 sevent_ws_config
 *    2. 调用 sevent_ws_connect(ctx, &cfg)
 *    3. 在 on_open / on_message / on_close / on_error 回调中处理事件
 *    4. 使用 sevent_ws_send_text/binary/ping 发送数据
 *    5. 使用 sevent_ws_shutdown 发起关闭或 sevent_ws_close 立即销毁
 *
 *  线程安全:
 *    编译时 SEVENT_THREAD_SAFE=ON 时, send_text/binary/ping/shutdown/
 *    close/get_state/destroy 跨线程安全 (各连接一把递归锁). connect 仍为
 *    [loop 线程]. destroy 完成后不得再对 c 调用任何 API.
 *    默认 OFF 时与 sevent 一致 — 所有调用需在 loop 线程或启动前.
 *  ========================================================================= */

#ifndef SEVENT_WS_H
#define SEVENT_WS_H

#include "sevent.h"
#include "sevent_http_server.h" /* SEVENT_HTTP_UPGRADE_TAKEN (upgrade 回调返回契约) */
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ===== 错误码 ===== */
/* SEVENT_SUCCESS(0) / SEVENT_ERR_INVAL(-1) / SEVENT_ERR_NOMEM(-2) 沿用 */
#define SEVENT_WS_ERR_HANDSHAKE 0x3001 /* 服务器返回非 101 或握手头缺失 */
#define SEVENT_WS_ERR_PROTOCOL 0x3002  /* 协议违例 (非法帧/分片错) */
#define SEVENT_WS_ERR_CLOSE 0x3003     /* 收到 Close 帧 */
#define SEVENT_WS_ERR_CONNECT 0x3004   /* TCP 连接失败 */
#define SEVENT_WS_ERR_WRITE 0x3005     /* 写错误 */

/* ===== WebSocket Close 码 (RFC 6455 §7.4.1) ===== */
#define SEVENT_WS_CLOSE_NORMAL 1000          /* 正常关闭 */
#define SEVENT_WS_CLOSE_GOING_AWAY 1001      /* 服务端关闭/客户端离开 */
#define SEVENT_WS_CLOSE_PROTOCOL_ERR 1002    /* 协议错误 */
#define SEVENT_WS_CLOSE_UNSUPPORTED 1003     /* 收到不支持的数据类型 */
#define SEVENT_WS_CLOSE_INVALID_PAYLOAD 1007 /* 非法 payload (如 UTF-8 错误) */
#define SEVENT_WS_CLOSE_POLICY 1008          /* 策略违反 */
#define SEVENT_WS_CLOSE_TOO_BIG 1009         /* 消息太大 */
#define SEVENT_WS_CLOSE_EXTENSION 1010       /* 缺少强制扩展协商 */
#define SEVENT_WS_CLOSE_SERVER_ERR 1011      /* 服务端内部错误 */
/* 以下为保留/内部使用码, 应用不应主动发送 */
#define SEVENT_WS_CLOSE_ABNORMAL 1006 /* 异常断开 (仅内部, 不可发送) */
/* 1012-1015 为 TLS 握手等保留 */

/* ===== 连接超时默认值 ===== */
#define SEVENT_WS_CONNECT_TIMEOUT_MS 10000 /* 默认连接超时 10 秒 */

/* ===== 连接状态 (用于 sevent_ws_get_state) ===== */
#define SEVENT_WS_STATE_CONNECTING 0
#define SEVENT_WS_STATE_OPEN 1
#define SEVENT_WS_STATE_CLOSING 2
#define SEVENT_WS_STATE_CLOSED 3

/* ===== 不透明句柄 ===== */
typedef struct sevent_ws_conn   sevent_ws_conn;
typedef struct sevent_http_conn sevent_http_conn; /* 升级转移参数 (前置声明, 不 include http 头) */

/* ===== 回调类型 ===== */
typedef void (*sevent_ws_on_open_fn)(void *user_data);
typedef void (*sevent_ws_on_message_fn)(
        void *user_data, const void *msg, size_t len, bool binary, bool fin, uint64_t total);
typedef void (*sevent_ws_on_close_fn)(void *user_data, uint16_t code, const char *reason, size_t reason_len);
typedef void (*sevent_ws_on_error_fn)(void *user_data, int err);
typedef void (*sevent_ws_on_pong_fn)(void *user_data, const void *payload, size_t len);
typedef void (*sevent_ws_on_http_response_fn)(
        void *user_data, int status_code, const char *headers, size_t headers_len, const char *body, size_t body_len);

/* ===== 发送压缩等级 (permessage-deflate, 本端发送侧) =====
 * 值 1-9 与 zlib deflate level 对应 (1=最快, 9=最大压缩).
 * DEFAULT=0: 零初始化即默认 (level 6, 发送压缩).
 * NONE=10: 显式关闭发送压缩 (RFC 7692 允许逐条消息不压缩, RSV1=0). */
typedef enum {
    SEVENT_WS_DEFLATE_LEVEL_DEFAULT  = 0,
    SEVENT_WS_DEFLATE_LEVEL_1        = 1,
    SEVENT_WS_DEFLATE_LEVEL_2        = 2,
    SEVENT_WS_DEFLATE_LEVEL_3        = 3,
    SEVENT_WS_DEFLATE_LEVEL_4        = 4,
    SEVENT_WS_DEFLATE_LEVEL_5        = 5,
    SEVENT_WS_DEFLATE_LEVEL_6        = 6,
    SEVENT_WS_DEFLATE_LEVEL_7        = 7,
    SEVENT_WS_DEFLATE_LEVEL_8        = 8,
    SEVENT_WS_DEFLATE_LEVEL_9        = 9,
    SEVENT_WS_DEFLATE_LEVEL_NONE     = 10, /* 发送不压缩 */
    /* 语义别名 */
    SEVENT_WS_DEFLATE_LEVEL_FAST     = SEVENT_WS_DEFLATE_LEVEL_1,
    SEVENT_WS_DEFLATE_LEVEL_BALANCED = SEVENT_WS_DEFLATE_LEVEL_6,
    SEVENT_WS_DEFLATE_LEVEL_MAX      = SEVENT_WS_DEFLATE_LEVEL_9,
} sevent_ws_deflate_level;

/* ===== 配置结构体 =====
 * 生命周期: 调用 sevent_ws_connect 后 config 即可释放 — 库内部自有拷贝
 * 所有字符串字段 (host/path/sub_protocol/TLS 系列, 无任何外部引用). */
typedef struct sevent_ws_config {
    const char             *host;                               /* 服务器 IP 地址 ("127.0.0.1") */
    uint16_t                port;                               /* 端口 (80) */
    const char             *path;                               /* 路径 ("/ws") */
    const char             *sub_protocol;                       /* 子协议, NULL=不协商 */
    int                     ping_interval_ms;                   /* 心跳间隔(ms), 0=不启用 */
    int                     connect_timeout_ms;                 /* 连接超时(ms), 0=默认10s, -1=不超时 */
    size_t                  recv_buf_size;                      /* 接收缓冲区初始大小, 0=默认 4096 */
    bool                    enable_deflate;                     /* 启用 permessage-deflate 压缩 (RFC 7692) */
    sevent_ws_deflate_level deflate_level;                      /* 发送压缩等级, 默认 DEFAULT(6) */
    bool                    request_client_no_context_takeover; /* 自我承诺: 每条消息重置本端压缩上下文
                                                                 * (错误隔离: 单条消息损坏不影响后续) */
    bool    request_server_no_context_takeover; /* 请求对端每条消息重置 (服务器同意才生效) */
    uint8_t request_client_max_window_bits;     /* 0=默认无值 offer (服务器可指定, 现状);
                                                 * 8-15=offer 带值自我承诺本端发送窗口
                                                 * ≤N (省发送侧内存, 服务器不响应也生效) */
    uint8_t request_server_max_window_bits;     /* 0=不请求; 8-15=请求服务器压缩窗口 ≤N
                                                 * (省接收侧内存, 服务器拒绝则保持默认) */

    /* ---- TLS (wss; enable_tls=false 行为与现状完全一致) ----
     * 证书路径与 PEM 内存双通道 (D3), 每对字段互斥 (同时给 → connect 失败):
     *   ca_path/ca_pem, cert_path/cert_pem, key_path/key_pem */
    bool        enable_tls;             /* false=ws, true=wss (TLS 握手在传输层完成) */
    const char *ca_path;                /* CA 证书路径, NULL=系统默认信任库 */
    const char *ca_pem;                 /* CA 证书 PEM 内存 (NUL 结尾) */
    const char *cert_path;              /* 本端证书 (客户端 mTLS 可选) */
    const char *cert_pem;               /* 本端证书 PEM 内存 (支持链, NUL 结尾) */
    const char *key_path;               /* 本端私钥 (PEM, 不支持加密) */
    const char *key_pem;                /* 本端私钥 PEM 内存 */
    bool        enable_peer_verify;     /* 校验服务器证书链, 默认 true */
    bool        enable_hostname_verify; /* 校验对端证书名, 默认 true */
    const char *tls_hostname;           /* 校验名 (NULL=用连接 host; 应用负责 DNS —
                                         * host 传 IP, 域名校验名经此字段) */

    /* ---- 用户回调 ---- */
    sevent_ws_on_open_fn          on_open;
    sevent_ws_on_message_fn       on_message;
    sevent_ws_on_close_fn         on_close;
    sevent_ws_on_error_fn         on_error;
    sevent_ws_on_pong_fn          on_pong;          /* 收到 PONG 时触发, NULL=忽略 */
    sevent_ws_on_http_response_fn on_http_response; /* HTTP 升级响应, 含非 101 */

    void *user_data; /* 透传给回调的参数 */
} sevent_ws_config;

/* ===== API ===== */

/*
 * 异步连接 WebSocket 服务器.
 * 连接建立/失败通过 on_open/on_error 通知.
 * 返回: 句柄 (需调用 sevent_ws_close 释放), 或 NULL (参数错误/内存不足).
 * 线程: [loop 线程] (IO 注册内部有锁, 但配置副本写入无保护).
 */
sevent_ws_conn *sevent_ws_connect(sevent_context *ev, const sevent_ws_config *cfg);

/*
 * 服务端入口①: 包装已 accept 的 fd (来自 tcp_acceptor 的 on_accept).
 * 流程: stream 建连 (enable_tls 时含 TLS 服务端握手, 证书来自 cfg cert/key —
 *       必填) → 收升级请求回 101 → on_open; 请求非法 → 回 400/426 + on_error.
 * 返回: 句柄 (失败经 on_error 通知), NULL=参数错误/内存不足.
 * fd 所有权契约: 成功 → 移交本层 (调用方不得再使用); 失败 → 归还调用方,
 * 调用方负责 close (谁拥有谁关闭 — 失败后库不关闭 fd).
 * 线程: [loop 线程].
 */
sevent_ws_conn *sevent_ws_accept(sevent_context *ev, int fd, const sevent_ws_config *cfg);

/*
 * 服务端入口②: 共用端口升级转移 — 在 http_server 的 on_upgrade 回调内调用,
 * 调用即升级决定 (内部完成释放摘除, 无两段式): stream + 解析缓冲移交
 * (含完整升级请求 + 粘包残留 — ws 层自行解析), 同步完成握手 —
 * 101 入队 → OPEN + on_open (本调用栈内触发, 无等待期).
 * 返回: 句柄 (已 OPEN; 握手失败经 on_error 通知 — 连接半关, 按失败态处理),
 *       NULL=参数错误/非法状态 (连接留 http server)/内存不足 — 资源已
 *       移交时库负责关闭底层连接, 用户无需善后.
 * 约束: 仅 on_upgrade 回调内调用 (REQUEST 态); cfg 中 host/port/path/TLS
 *       字段忽略 (连接已建立); on_http_response 不触发; 成功后 http_conn
 *       句柄作废 (壳由库延迟释放). on_upgrade 回调返回契约: 调用了本函数
 *       一律返回 SEVENT_HTTP_UPGRADE_TAKEN (调用即接管 — 无论句柄是否
 *       NULL, 连接已脱离 http 管理).
 * 线程: [loop 线程].
 */
sevent_ws_conn *sevent_ws_upgrade(sevent_http_conn *conn, const sevent_ws_config *cfg);

/*
 * 发送文本消息 (自动掩码).
 * 返回: SEVENT_SUCCESS 或 SEVENT_ERR_*.
 * 线程: SEVENT_THREAD_SAFE=ON 时跨线程安全, OFF 时 [loop 线程].
 */
int sevent_ws_send_text(sevent_ws_conn *c, const void *data, size_t len);

/*
 * 发送二进制消息 (自动掩码).
 * 返回: SEVENT_SUCCESS 或 SEVENT_ERR_*.
 * 线程: 同 send_text.
 */
int sevent_ws_send_binary(sevent_ws_conn *c, const void *data, size_t len);

/*
 * 发送 Ping (自动掩码).
 * 返回: SEVENT_SUCCESS 或 SEVENT_ERR_*.
 * 线程: 同 send_text.
 */
int sevent_ws_ping(sevent_ws_conn *c, const void *payload, size_t len);

/*
 * 主动发起 Close 握手 (正常关闭流程).
 * code: RFC 6455 关闭码 (如 1000), reason: 关闭原因 (可为 "").
 * 关闭完成通过 on_close 通知.
 * 返回: SEVENT_SUCCESS 或 SEVENT_ERR_*.
 * 线程: 同 send_text.
 */
int sevent_ws_shutdown(sevent_ws_conn *c, uint16_t code, const char *reason);

/*
 * 立即关闭连接 (不发送 Close 帧).
 * 注意: 不释放内存 — 调用后对象仍可安全访问 (get_state 等,
 *       用于在回调内提前终止连接), 最终须调用 sevent_ws_destroy 释放.
 * 回调内可安全调用 (on_message / on_pong / on_open / on_error /
 *       on_http_response; 事件已摘除, 不会重入).
 * 重复调用安全 (幂等).
 * 线程: SEVENT_THREAD_SAFE=ON 时跨线程安全, OFF 时 [loop 线程].
 */
void sevent_ws_close(sevent_ws_conn *c);

/*
 * 释放连接内存.
 * 回调内可安全调用 (on_open / on_message / on_error / on_close).
 * 线程: SEVENT_THREAD_SAFE=ON 时跨线程安全, OFF 时 [loop 线程].
 * 约束: 调用后对象作废 — 不得再对 c 调用任何 API (含再次 destroy),
 *       违反为未定义行为 (对象可能已释放). destroy 不允许幂等.
 * 注:   free 一律推迟到事件循环 run_posts 阶段 (sevent_post, 不区分
 *       sevent_run/run_once 模式) — destroy 后须推进循环让 run_posts
 *       执行 cleanup; sevent_destroy 丢弃未执行的 post (不执行回调),
 *       销毁 ev 前未推进循环则对象泄漏.
 */
void sevent_ws_destroy(sevent_ws_conn *c);

/*
 * 获取当前连接状态.
 * 返回: SEVENT_WS_STATE_CONNECTING / OPEN / CLOSING / CLOSED.
 * 用于上层超时管理: 在 CONNECTING/CLOSING 停留过久可自行 destroy.
 * 线程: SEVENT_THREAD_SAFE=ON 时跨线程安全, OFF 时 [loop 线程].
 */
int sevent_ws_get_state(const sevent_ws_conn *c);

#ifdef __cplusplus
}
#endif

#endif /* SEVENT_WS_H */
