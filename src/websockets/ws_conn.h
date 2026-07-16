/* =========================================================================
 *  ws_conn.h — WebSocket 连接状态机 (内部定义)
 *
 *  不对外暴露.
 *  ========================================================================= */

#ifndef SEVENT_WS_CONN_H
#define SEVENT_WS_CONN_H

#include "../../include/sevent_ws.h"
#include <stdint.h>

#ifdef SEVENT_WS_THREAD_SAFE
#include "../../include/sevent_platform.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* 内部状态枚举 */
enum ws_state {
    WS_STATE_CONNECTING = 0,
    WS_STATE_HANDSHAKE,   /* TCP 已连, 等 HTTP 101 响应 */
    WS_STATE_OPEN,
    WS_STATE_CLOSING,
    WS_STATE_CLOSED
};

/* 写缓冲节点 (Round 5 启用) */
struct ws_write_node {
    struct ws_write_node *next;
    uint8_t              *data;      /* 完整帧 (含帧头) */
    size_t                len;       /* 总长度 */
    size_t                offset;    /* 已写入偏移 */
    int                   is_ctrl;   /* 控制帧, 优先发送 */
};

/* 内部连接结构 */
struct sevent_ws_conn {
    sevent_context   *ev;

    /* ---- socket ---- */
    int               fd;
    sevent_io_t       io_handle;

    /* ---- 状态 ---- */
    int               state;       /* enum ws_state */
    int               destroyed;   /* 回调重入守卫: on_error/on_close 中 destroy 后不再访问 */
#ifdef SEVENT_WS_THREAD_SAFE
    sevent_mutex_t    lock;        /* 跨线程锁 (递归) */
#endif

    /* ---- 用户配置副本 ---- */
    char              host[256];
    uint16_t          port;
    char              path[256];
    char              sub_protocol[64];
    int               ping_interval_ms;

    /* ---- 用户回调 ---- */
    void             *user_data;
    sevent_ws_on_open_fn     on_open;
    sevent_ws_on_message_fn  on_message;
    sevent_ws_on_close_fn    on_close;
    sevent_ws_on_error_fn    on_error;

    /* ---- 握手状态 ---- */
    char              sec_ws_key[25];     /* base64 key */

    /* ---- 接收缓冲 (固定大小, 从 config->recv_buf_size) ---- */
    uint8_t          *recv_buf;
    size_t            recv_cap;      /* 固定值, 初始化后不变 */
    size_t            recv_len;      /* 有效数据长度 */
    size_t            recv_pos;      /* 已消费偏移 */

    /* ---- 大帧流式读取 (单帧 > recv_cap 时分块) ---- */
    int               stream_active;
    uint8_t           stream_opcode;
    uint64_t          stream_remaining;
    uint64_t          stream_total;  /* 原始帧 payload 总长, 传给 on_message */
    int               stream_fin;    /* 原始帧 FIN 位 */

    /* ---- 分片累积 (RFC 6455 §5.4, frag_buf 大小 = recv_cap) ---- */
    int               frag_pending;     /* 1=正在接收分片序列 */
    uint8_t           frag_opcode;      /* 原始 opcode (TEXT/BINARY) */
    uint8_t          *frag_buf;
    size_t            frag_len;
    uint64_t          frag_total;    /* 分片累积总字节, 传给 on_message */

    /* ---- 写队列 (Round 5 启用) ---- */
    struct ws_write_node *write_head;
    struct ws_write_node *write_tail;
    int               write_count;

    /* ---- 关闭状态 ---- */
    uint16_t          close_code;
    char              close_reason[128];
    size_t            close_reason_len;
};

#ifdef __cplusplus
}
#endif

#endif /* SEVENT_WS_CONN_H */
