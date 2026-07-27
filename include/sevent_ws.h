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
 *    编译时 SEVENT_WS_THREAD_SAFE=ON 时, send_text/binary/ping/close/get_state
 *    跨线程安全 (各连接一把递归锁). connect/destroy 仍为 [loop 线程].
 *    默认 OFF 时与 sevent 一致 — 所有调用需在 loop 线程或启动前.
 *  ========================================================================= */

#ifndef SEVENT_WS_H
#define SEVENT_WS_H

#include "sevent.h"
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
typedef struct sevent_ws_conn sevent_ws_conn;

/* ===== 回调类型 ===== */
typedef void (*sevent_ws_on_open_fn)(void *user_data);
typedef void (*sevent_ws_on_message_fn)(
        void *user_data, const void *msg, size_t len, bool binary, bool fin, uint64_t total);
typedef void (*sevent_ws_on_close_fn)(void *user_data, uint16_t code, const char *reason, size_t reason_len);
typedef void (*sevent_ws_on_error_fn)(void *user_data, int err);
typedef void (*sevent_ws_on_pong_fn)(void *user_data, const void *payload, size_t len);
typedef void (*sevent_ws_on_http_response_fn)(
        void *user_data, int status_code, const char *headers, size_t headers_len, const char *body, size_t body_len);

/* ===== 配置结构体 ===== */
typedef struct sevent_ws_config {
    const char *host;               /* 服务器 IP 地址 ("127.0.0.1") */
    uint16_t    port;               /* 端口 (80) */
    const char *path;               /* 路径 ("/ws") */
    const char *sub_protocol;       /* 子协议, NULL=不协商 */
    int         ping_interval_ms;   /* 心跳间隔(ms), 0=不启用 */
    int         connect_timeout_ms; /* 连接超时(ms), 0=默认10s, -1=不超时 */
    size_t      recv_buf_size;      /* 接收缓冲区初始大小, 0=默认 4096 */

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
 * 发送文本消息 (自动掩码).
 * 返回: SEVENT_SUCCESS 或 SEVENT_ERR_*.
 * 线程: SEVENT_WS_THREAD_SAFE=ON 时跨线程安全, OFF 时 [loop 线程].
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
 * 关闭 socket + IO + 写队列, 但不释放内存.
 * 可在 on_message / on_pong / on_open / on_http_response 中安全调用.
 * 线程: [loop 线程].
 *
 * 调用后连接仍可安全访问 (用于在回调内提前终止连接),
 * 最终需调用 sevent_ws_destroy 释放内存.
 */
void sevent_ws_close(sevent_ws_conn *c);

/*
 * 释放连接内存.
 * 内部先调 sevent_ws_close, 再释放所有内存.
 * 应在 loop 结束后调用.
 * 注: on_error 中可调, 但 on_close 中推荐用 sevent_ws_close 而非此函数,
 *     因为 CLOSE 帧处理完成后库可能还需访问连接状态.
 * 线程: [loop 线程].
 */
void sevent_ws_destroy(sevent_ws_conn *c);

/*
 * 获取当前连接状态.
 * 返回: SEVENT_WS_STATE_CONNECTING / OPEN / CLOSING / CLOSED.
 * 用于上层超时管理: 在 CONNECTING/CLOSING 停留过久可自行 destroy.
 * 线程: SEVENT_WS_THREAD_SAFE=ON 时跨线程安全, OFF 时 [loop 线程].
 */
int sevent_ws_get_state(const sevent_ws_conn *c);

#ifdef __cplusplus
}
#endif

#endif /* SEVENT_WS_H */
