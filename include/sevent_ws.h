/* =========================================================================
 *  sevent_ws.h — WebSocket 客户端 (RFC 6455) 公开 API
 *
 *  基于 libsevent 事件循环构建.
 *
 *  用法:
 *    1. 配置 struct sevent_ws_config
 *    2. 调用 sevent_ws_connect(ctx, &cfg)
 *    3. 在 on_open / on_message / on_close / on_error 回调中处理事件
 *    4. 使用 sevent_ws_send_text/binary/ping 发送数据
 *    5. 使用 sevent_ws_close 发起关闭或 sevent_ws_destroy 立即销毁
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
        void *user_data, const void *msg, size_t len, int binary, int fin, uint64_t total);
typedef void (*sevent_ws_on_close_fn)(void *user_data, uint16_t code, const char *reason, size_t reason_len);
typedef void (*sevent_ws_on_error_fn)(void *user_data, int err);
typedef void (*sevent_ws_on_http_response_fn)(
        void *user_data, int status_code, const char *headers, size_t headers_len, const char *body, size_t body_len);

/* ===== 配置结构体 ===== */
struct sevent_ws_config {
    const char *host;             /* 服务器主机名/IP ("127.0.0.1") */
    uint16_t    port;             /* 端口 (80) */
    const char *path;             /* 路径 ("/ws") */
    const char *sub_protocol;     /* 子协议, NULL=不协商 */
    int         ping_interval_ms; /* 心跳间隔(ms), 0=不启用 */
    size_t      recv_buf_size;    /* 接收缓冲区初始大小, 0=默认 4096 */

    /* ---- 用户回调 ---- */
    sevent_ws_on_open_fn          on_open;
    sevent_ws_on_message_fn       on_message;
    sevent_ws_on_close_fn         on_close;
    sevent_ws_on_error_fn         on_error;
    sevent_ws_on_http_response_fn on_http_response; /* HTTP 升级响应, 含非 101 */

    void *user_data; /* 透传给回调的参数 */
};

/* ===== API ===== */

/*
 * 异步连接 WebSocket 服务器.
 * 连接建立/失败通过 on_open/on_error 通知.
 * 返回: 句柄 (需调用 sevent_ws_destroy 释放), 或 NULL (参数错误/内存不足).
 * 线程: [loop 线程] (IO 注册内部有锁, 但配置副本写入无保护).
 */
sevent_ws_conn *sevent_ws_connect(sevent_context *ev, const struct sevent_ws_config *cfg);

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
 * 主动发起 Close 握手.
 * code: RFC 6455 关闭码 (如 1000), reason: 关闭原因 (可为 "").
 * 关闭完成通过 on_close 通知.
 * 返回: SEVENT_SUCCESS 或 SEVENT_ERR_*.
 * 线程: 同 send_text.
 */
int sevent_ws_close(sevent_ws_conn *c, uint16_t code, const char *reason);

/*
 * 立即销毁连接 (不发送 Close 帧, 立即释放资源).
 * 回调内可安全调用.
 * 线程: [loop 线程] (不参与线程安全锁, 调用者需确保无其他线程并行访问).
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
