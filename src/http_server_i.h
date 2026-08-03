/* =========================================================================
 *  http_server_i.h — http server 内部接口 (仅供 ws_upgrade 消费连接)
 *
 *  升级出口 (设计定稿 doc/http-layer-design.md §4.4):
 *    sevent_ws_upgrade (ws 层) 一步完成 — 内部先 i_release 摘除管理,
 *    再经本接口取走资源: stream 所有权 + 解析缓冲 (含完整升级请求 +
 *    粘包残留 — ws 层自行解析, http 零 ws 感知).
 *  调用后 conn 作废 (http_conn 壳由库延迟销毁) — 不得再访问.
 *  ========================================================================= */

#ifndef SEVENT_HTTP_SERVER_I_H
#define SEVENT_HTTP_SERVER_I_H

#include "sevent_http_server.h"
#include "sevent_stream_conn.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 内部释放 (ws_upgrade 调用 — 升级决定 = 调用本函数, 用户无需两段式):
 * 置 RELEASED + 摘列表 + 停空闲超时. 仅 on_upgrade 回调内合法 (REQUEST 态);
 * 失败返回 SEVENT_ERR_INVAL (连接留 http server). 调用后 conn 脱离 http 管理. */
int sevent_http_conn_i_release(sevent_http_conn *conn);

/* 取走 stream 所有权 (RELEASED 态; 调用后 conn->stream 归 ws). */
sevent_stream_conn *sevent_http_conn_i_detach_stream(sevent_http_conn *conn);

/* 取走解析缓冲所有权 (指针移交 ws, 含完整升级请求 + 粘包残留; len/cap 输出).
 * 返回 NULL=无缓冲. 请求在 on_upgrade 栈内未消费 — ws 层自行解析 (零 ws 感知). */
uint8_t *sevent_http_conn_i_take_recv(sevent_http_conn *conn, size_t *len, size_t *cap);

/* 消费完毕释放壳 (ws_upgrade 内取走资源后调用): post 延迟释放 —
 * 调用在 on_upgrade 回调栈内, 返回后 http_process 仍读 conn. 仅 RELEASED 态. */
void sevent_http_conn_i_destroy(sevent_http_conn *conn);

/* 事件循环上下文 (ws_upgrade 建 ws_conn 用). 仅 RELEASED 态 (消费中). */
sevent_context *sevent_http_conn_i_ev(sevent_http_conn *conn);

#ifdef __cplusplus
}
#endif

#endif /* SEVENT_HTTP_SERVER_I_H */
