/* =========================================================================
 *  ws_conn.h — WebSocket 连接状态机 (内部定义)
 *
 *  不对外暴露.
 *  ========================================================================= */

#ifndef SEVENT_WS_CONN_H
#define SEVENT_WS_CONN_H

#include "../../include/sevent_ws.h"
#include "../../include/sevent_stream_conn.h"
#include <stdbool.h>
#include <stdint.h>

#include "ws_deflate.h"

#ifdef SEVENT_THREAD_SAFE
#include "../../include/sevent_platform.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* 内部状态枚举 */
enum ws_state {
    WS_STATE_CONNECTING = 0,
    WS_STATE_HANDSHAKE, /* TCP 已连, 等 HTTP 101 响应 */
    WS_STATE_OPEN,
    WS_STATE_CLOSING,
    WS_STATE_CLOSED
};

/* ---- 消息接收状态机 (RFC 6455 §5.4 分片 + 大帧流式) ----
 * 消息级状态跨帧保持, 状态转换:
 *   MSG_NONE   --首帧 TEXT/BINARY (fin=0)--> MSG_FRAG (小帧) / MSG_STREAM (大帧)
 *   MSG_FRAG / MSG_STREAM --CONT 帧--> 保持
 *   MSG_FRAG / MSG_STREAM --fin 帧--> MSG_NONE (msg_end 统一收尾)
 * opcode/compressed 由首帧决定, CONT 帧不覆盖. */
enum ws_msg_mode {
    WS_MSG_NONE,   /* 无消息进行中 */
    WS_MSG_FRAG,   /* 分片累积路径 (frag_append/frag_flush) */
    WS_MSG_STREAM, /* 大帧流式路径 (stream_consume) */
};

struct ws_msg_state {
    enum ws_msg_mode mode;       /* 当前接收路径 */
    uint8_t          opcode;     /* 消息级 opcode (首帧 TEXT/BINARY) */
    bool             compressed; /* 消息级压缩 (首帧 rsv1, CONT 帧沿用) */
    uint64_t         total;      /* 消息总字节, fin 回调传给 on_message */
    bool             fin_sent;   /* fin 回调已发 → msg_end 保证"恰好一次" */
};

/* 内部连接结构 */
struct sevent_ws_conn {
    sevent_context *ev;

    /* ---- 传输层 (stream_conn: tcp_conn 或 tls_conn, enable_tls 分发) ---- */
    sevent_stream_conn       *stream;     /* 底层字节流 (组合) */
    sevent_stream_conn_config stream_cfg; /* stream 配置副本 (建连/重定向复用) */

    /* ---- 状态 ---- */
    int  state;     /* enum ws_state */
    bool destroyed; /* 回调重入守卫: on_error/on_close 中 destroy 后不再访问 */
    bool is_client; /* 角色: true=客户端 (connect) / false=服务端 (accept/upgrade).
                     * 掩码方向 (RFC 6455 §5.1): 客户端帧必须 mask, 服务器帧必须
                     * 不 mask — 发送 mask 标志 + 接收校验均按此角色. */
#ifdef SEVENT_THREAD_SAFE
    sevent_mutex_t lock; /* 跨线程锁 (递归) */
#endif

    /* ---- 用户配置副本 ---- */
    char          host[256];
    uint16_t      port;
    char          path[256];
    int           redirect_count; /* 已跟随重定向次数, 超限报错 */
    char          sub_protocol[64];
    int           ping_interval_ms;
    int           connect_timeout_ms; /* 传给 stream init (连接超时) */
    sevent_timer *ping_timer;

    /* ---- 压缩 (permessage-deflate) ---- */
    bool                    enable_deflate;
    sevent_ws_deflate_level deflate_level;                      /* 发送压缩等级 */
    bool                    request_client_no_context_takeover; /* 自我承诺 (offer + 本地生效) */
    bool                    request_server_no_context_takeover; /* 请求对端 (offer, 响应同意才生效) */
    uint8_t                 request_client_max_window_bits;     /* 0=无值 offer; 8-15=带值自我承诺 */
    uint8_t                 request_server_max_window_bits;     /* 0=不请求; 8-15=请求服务器降窗 */
    ws_deflate             *deflate;

    /* ---- 用户回调 ---- */
    void                         *user_data;
    sevent_ws_on_open_fn          on_open;
    sevent_ws_on_message_fn       on_message;
    sevent_ws_on_close_fn         on_close;
    sevent_ws_on_error_fn         on_error;
    sevent_ws_on_pong_fn          on_pong;
    sevent_ws_on_http_response_fn on_http_response;

    /* ---- 握手状态 ---- */
    char sec_ws_key[25]; /* base64 key */

    /* ---- 接收缓冲 (固定大小, 从 config->recv_buf_size) ---- */
    uint8_t *recv_buf;
    size_t   recv_cap; /* 固定值, 初始化后不变 */
    size_t   recv_len; /* 有效数据长度 */
    size_t   recv_pos; /* 已消费偏移 */

    /* ---- 消息接收状态机 (定义见文件顶部) ---- */
    struct ws_msg_state msg;

    /* ---- 大帧流式读取 (帧级状态, 单帧 > recv_cap 时分块) ---- */
    uint64_t stream_remaining;   /* 当前流式帧剩余未消费字节 */
    bool     stream_fin;         /* 当前流式帧 FIN 位 */
    bool     stream_mask;        /* 当前流式帧是否 mask (客户端帧, 消费前解掩码) */
    uint8_t  stream_mask_key[4]; /* 当前流式帧掩码密钥 */
    uint64_t stream_mask_off;    /* 当前流式帧掩码偏移游标 (chunk 在 payload 内
                                  * 的起始偏移 — 解掩码 XOR 周期按此推进) */

    /* ---- 分片累积 (RFC 6455 §5.4, frag_buf 大小 = recv_cap) ---- */
    uint8_t *frag_buf;
    size_t   frag_len;

    uint32_t mask_seed; /* gen_mask_key 用, 连接初始化时播种 */
};

#ifdef __cplusplus
}
#endif

#endif /* SEVENT_WS_CONN_H */
