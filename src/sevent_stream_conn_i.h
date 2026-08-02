/* =========================================================================
 *  sevent_stream_conn_i.h — 内部契约: stream_conn 结构布局 + ops 表
 *
 *  仅 stream_conn.c / tcp_conn.c / tls_conn.c 使用, 不对外稳定
 *  (与 sevent_i.h 同级别: 库内部实现细节).
 *
 *  组合模型 (has-a): stream_conn 是统一壳, 持有具体实现指针 (impl →
 *  struct tcp_conn / struct tls_conn). 具体实现层不感知 stream 结构 —
 *  ops 适配函数在各实现文件内, 经 s->impl 强转调用公开 API.
 *  ========================================================================= */

#ifndef SEVENT_STREAM_CONN_I_H
#define SEVENT_STREAM_CONN_I_H

#include "sevent_stream_conn.h"

/* ops 表: tcp_conn.c / tls_conn.c 各自实现.
 * 纯回调模型: open/accept 传回调组; write 入队异步 flush; 无 read/update. */
typedef struct sevent_stream_ops {
    int (*open)(sevent_stream_conn *s, const char *host, uint16_t port, const sevent_stream_conn_init *cb);
    int (*accept)(sevent_stream_conn *s, int fd, const sevent_stream_conn_init *cb);
    int (*write)(sevent_stream_conn *s, const void *data, size_t len);
    int (*shutdown)(sevent_stream_conn *s, int flag); /* 半关: 队列 flush 后 shutdown(fd, flag) */
    void (*close)(sevent_stream_conn *s);
    void (*destroy)(sevent_stream_conn *s);
    void (*set_no_delay)(sevent_stream_conn *s, bool on); /* 按需 TCP_NODELAY (tcp 直接/tls 转发) */
} sevent_stream_ops;

/* 统一壳: ops 表 + 具体实现指针 (tcp_conn / tls_conn) */
struct sevent_stream_conn {
    const sevent_stream_ops *ops;
    void                    *impl;
};

#endif /* SEVENT_STREAM_CONN_I_H */
