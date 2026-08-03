/* =========================================================================
 *  sevent_http_server.h — HTTP 服务器层 (连接管理 + 响应构造 + 升级出口)
 *
 *  设计定稿 (doc/http-layer-design.md §4):
 *    - 服务器类 (acceptor 同构): create(带传输配置) → listen(5 回调) → destroy
 *    - 连接管理: 8 态状态机 + keep-alive + 空闲超时 + 响应后优雅关闭
 *      (stream_shutdown(WR): 发完响应 + FIN, 半双工)
 *    - 响应构造: 声明式结构体 + 辅助函数 (set 查重/add/del), http 层自己
 *      构造发送 (自动 Content-Length / Connection: close 注入)
 *    - 升级出口: on_upgrade 内调用 ws_upgrade (升级决定 = 调用), 返回值
 *      TAKEN/DECLINED 告知 http 层是否继续管理连接 (回调后 http 层零访问)
 *
 *  线程: 全部 [loop 线程] — 连接对象 API 仅事件循环线程调用
 *        (回调内外均可, 跨线程调用无保护).
 *  ========================================================================= */

#ifndef SEVENT_HTTP_SERVER_H
#define SEVENT_HTTP_SERVER_H

#include "sevent.h"
#include "sevent_http_parse.h"
#include "sevent_stream_conn.h" /* get_stream 返回类型 */
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ===== 服务器 ===== */
typedef struct sevent_http_server sevent_http_server;
typedef struct sevent_http_conn   sevent_http_conn; /* 连接对象: 用户可持有 (回调外有效) */

/* 配置 (create 一次性传入; 与 stream 层同构).
 * 生命周期: create 后 config 即可释放 — TLS 字符串字段 (cert/ca/key) 库内部
 * 自有拷贝, 存到 server 生命周期, 无任何外部引用. */
typedef struct sevent_http_server_config {
    /* 传输 (stream 同构): wss 时 enable_tls + cert/key 必填 */
    bool        enable_tls;
    const char *cert_path, *cert_pem, *key_path, *key_pem;
    bool        verify_peer; /* mTLS, 默认 false */
    const char *ca_path, *ca_pem;
    size_t      recv_buf_size;   /* 解析缓冲 = 单请求上限 (头+body), 0=默认 4096 */
    int         idle_timeout_ms; /* keep-alive 空闲超时: 0=默认 60s, <0=禁用 */
} sevent_http_server_config;

/* 回调 (listen 一次性传入, 注释均在其 typedef 之前) */
/* 连接就绪 (stream/TLS 完成, 解析前): 可 close 拒绝 (黑名单/连接数超限), 可持有引用 */
typedef void (*sevent_http_on_accept_fn)(void *ud, sevent_http_conn *conn);
typedef void (*sevent_http_on_request_fn)(void *ud, const sevent_http_msg *req, sevent_http_conn *conn);

/* 升级回调返回: 连接是否已由回调处理完毕 (http 层不再触碰).
 * 契约: 调用了 sevent_ws_upgrade → 无论返回句柄是否非 NULL 一律 TAKEN
 * (调用即接管 — 升级决定已下, 连接成功归 ws / 失败已销毁, 均脱离 http 管理);
 * 仅未调用 (respond 拒绝等) → DECLINED (http 层继续管理). 误用返回
 * DECLINED 而连接已移交 = 编程错误 (对已脱离管理的连接操作). */
typedef enum {
    SEVENT_HTTP_UPGRADE_TAKEN = 0, /* 已接管: 连接归 ws (或已销毁) — http 层零访问 */
    SEVENT_HTTP_UPGRADE_DECLINED,  /* 未接管: 连接仍在 http 管理下, 正常流程继续 */
} sevent_http_upgrade_result_t;

typedef sevent_http_upgrade_result_t (*sevent_http_on_upgrade_fn)(void                  *ud,
                                                                  const sevent_http_msg *req,
                                                                  sevent_http_conn      *conn);
/* 连接将销毁 (用户清理引用); 升级转交的连接不走本回调 */
typedef void (*sevent_http_on_conn_close_fn)(void *ud, sevent_http_conn *conn);
/* 传输层错误 (stream accept/TLS 握手失败): 连接从未建立 — 无 conn 参数.
 * err 为 stream 层错误码 (SEVENT_ERR_CONNECT/HANDSHAKE 等). NULL=静默. */
typedef void (*sevent_http_on_error_fn)(void *ud, int err);

sevent_http_server *sevent_http_server_create(sevent_context *ev, const sevent_http_server_config *cfg);

int      sevent_http_server_listen(sevent_http_server       *s,
                                   const char               *host,
                                   uint16_t                  port,
                                   int                       backlog,
                                   sevent_http_on_accept_fn  on_accept,  /* 可选 */
                                   sevent_http_on_request_fn on_request, /* 必填其一 */
                                   sevent_http_on_upgrade_fn on_upgrade, /* 必填其一; 返回 TAKEN=已接管/DECLINED=继续 */
                                   sevent_http_on_conn_close_fn on_conn_close, /* 可选 */
                                   sevent_http_on_error_fn      on_error,      /* 可选 */
                                   void                        *ud);
uint16_t sevent_http_server_port(const sevent_http_server *s);
void     sevent_http_server_destroy(sevent_http_server *s);
/* 关闭全部未完成连接: 逐个触发 on_conn_close (用户清理持有的引用) 后销毁;
 * 已升级转交的 ws 连接不受影响.
 * 回调内调用需延迟 (与 ws destroy 纪律一致: post, 回调栈安全展开) */

/* ===== 连接状态 (sevent_http_conn_state 返回) ===== */
typedef enum {
    HTTP_CONN_NEW = 0,    /* stream+TLS 建连 (on_accept 前) */
    HTTP_CONN_PARSING,    /* 累积+分帧, 等完整请求 */
    HTTP_CONN_REQUEST,    /* 回调中 (on_request/on_upgrade) */
    HTTP_CONN_AWAIT_RESP, /* 回调返回未响应 (异步窗口, 空闲超时适用) */
    HTTP_CONN_RESPONDING, /* write 路径流式中 (异步窗口 write 后; 回调内 write 保持 REQUEST) */
    HTTP_CONN_RELEASED,   /* release 后, 等 ws_upgrade 消费 */
    HTTP_CONN_CLOSING,    /* 关闭收尾 (半关: shutdown WR 发完+FIN, 等对端 EOF) */
    HTTP_CONN_CLOSED,     /* 已销毁 (on_conn_close 已回调) */
} sevent_http_conn_state_t;

/* ===== 响应构造 (声明式: 用户填结构体 + 辅助函数, http 层自己构造 + 发送) ===== */
typedef struct sevent_http_header { /* 头链表节点: 库管理 (堆分配, 无槽位上限).
                                     * name/value 库内部拷贝持有 (自有内存) —
                                     * set/add 后调用方字符串可自由释放 */
    const char                *name;
    const char                *value;
    struct sevent_http_header *next;
} sevent_http_header;

typedef struct sevent_http_response {
    int                 status; /* 状态码 */
    const char         *text;   /* NULL=库查表 (常见码), 未知码必填 */
    bool                close;  /* true=响应后关: 注入 Connection: close + 半关 (shutdown WR); false=保持 */
    const void         *body;   /* NULL=无 body */
    size_t              body_len;
    sevent_http_header *headers; /* 库管理链表, 用户经辅助函数操作 */
} sevent_http_response;

void sevent_http_response_init(sevent_http_response *resp); /* 清零 */
int  sevent_http_response_header_set(sevent_http_response *resp, const char *name, const char *value);
/* 查重: 同名覆盖 (后一个生效); 返回 0=OK, <0=非法/内存不足 */
int  sevent_http_response_header_add(sevent_http_response *resp, const char *name, const char *value);
/* 追加: 允许重复 (Set-Cookie 多值等); 返回 0=OK, <0=非法/内存不足 */
int  sevent_http_response_header_del(sevent_http_response *resp, const char *name);
/* 删除: 按名删全部同名; 返回删除条数 */
void sevent_http_response_clear(sevent_http_response *resp); /* 释放节点, 可复用 */

/* ===== 连接对象 API (回调外可调用 — 支持异步响应) =====
 * 状态机矩阵 (设计定稿 §4.2): 非法状态调用返回 SEVENT_ERR_INVAL. */
int  sevent_http_conn_respond(sevent_http_conn *conn, sevent_http_response *resp);
/* 构造状态行 + 遍历头 + 自动 Content-Length + close 注入 → 入写队列.
 * 返回: 0=已接受; <0=错误 (状态非法/已响应/NOMEM/头区溢出/连接已关).
 *     无论成败 resp 头节点都已释放 (调用后 resp 即弃 — 头节点归库管,
 *     重试场景用户重新 set). 一请求一响应: 重复 respond 报错. */
int  sevent_http_conn_write(sevent_http_conn *conn, const uint8_t *buf, size_t len);
/* 原始写 (write 路径): 用户全手写响应 (含所有头) + 多次 write 流式 + write_end/close 结束.
 * 不含任何头注入. 与 respond 互斥: 本请求 write 过数据后 respond 报错 (反之 respond 后
 * 回 PARSING, write 也报错). 回调内 write 后返回 → 连接转 RESPONDING (流式中, 空闲超时豁免),
 * 回调外可继续 write + write_end 收尾. */
int  sevent_http_conn_write_end(sevent_http_conn *conn);
/* write 路径专用: 声明"响应已完整写完" → 可处理下一请求 (keep-alive).
 * 未写过数据 (AWAIT_RESP) / respond 路径 → 报错. */
void sevent_http_conn_close(sevent_http_conn *conn);
/* 关闭: 已入队数据发完 + FIN (半关) → 等对端 EOF → on_conn_close.
 * 关闭后 write/respond 报错 (半双工). 幂等. */
int  sevent_http_conn_state(const sevent_http_conn *conn); /* 返回 sevent_http_conn_state_t 枚举值 */
sevent_stream_conn *sevent_http_conn_get_stream(sevent_http_conn *conn);
/* 获取底层 stream (借用, 所有权仍归 http 连接): 用户按需设置传输属性,
 * 如 on_accept 内 sevent_stream_set_no_delay(conn_stream, true) (TCP_NODELAY).
 * 约束: 不得 close/destroy/接管; 连接关闭 (on_conn_close) 后指针失效.
 * 连接未建立/已关闭 → NULL. 线程: [loop 线程]. */

#ifdef __cplusplus
}
#endif

#endif /* SEVENT_HTTP_SERVER_H */
