/* =========================================================================
 *  http_server_i.h — http server 内部接口 (仅供 ws_upgrade 消费已释放连接)
 *
 *  两段式升级出口 (设计定稿 doc/http-layer-design.md §4.4):
 *    段 1: sevent_http_conn_release (http 层, 公开) — 摘除管理
 *    段 2: sevent_ws_upgrade (ws 层) — 经本内部接口取走底层资源:
 *          stream 所有权 + 解析缓冲 (含粘包残留) + Sec-WebSocket-Key.
 *  调用后 conn 作废 (http_conn 壳由库销毁) — 不得再访问.
 *  ========================================================================= */

#ifndef SEVENT_HTTP_SERVER_I_H
#define SEVENT_HTTP_SERVER_I_H

#include "sevent_http_server.h"
#include "sevent_stream_conn.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 取走 stream 所有权 (RELEASED 态; 调用后 conn->stream 归 ws). */
sevent_stream_conn *sevent_http_conn_i_detach_stream(sevent_http_conn *conn);

/* 取走解析缓冲所有权 (指针移交 ws, 含粘包残留; len/cap 输出). 返回 NULL=无残留. */
uint8_t *sevent_http_conn_i_take_recv(sevent_http_conn *conn, size_t *len, size_t *cap);

/* 升级请求的 Sec-WebSocket-Key (on_upgrade 分派时保存). 返回 NULL=无. */
const char *sevent_http_conn_i_upgrade_key(sevent_http_conn *conn);

/* 消费完毕释放壳 (ws_upgrade 内三件套取走后调用): post 延迟释放 —
 * 调用在 on_upgrade 回调栈内, 返回后 http_process 仍读 conn. 仅 RELEASED 态. */
void sevent_http_conn_i_destroy(sevent_http_conn *conn);

#ifdef __cplusplus
}
#endif

#endif /* SEVENT_HTTP_SERVER_I_H */
