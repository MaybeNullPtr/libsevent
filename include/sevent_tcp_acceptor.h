/* =========================================================================
 *  sevent_tcp_acceptor.h — TCP 监听器 (服务端入口封装, 公开)
 *
 *  封装服务端样板: socket + bind + listen + 读事件注册 + accept 循环.
 *  新连接就绪 → on_accept(fd) 回调 (fd 已 accept 且非阻塞, 所有权移交上层 —
 *  典型用法 sevent_tcp_conn_accept 包装, 或 close(fd) 丢弃).
 *
 *  生命周期: create → listen → (on_accept 分发) → close (可重 listen)
 *            → destroy (free 推迟到 run_posts, 回调内可安全调用; 调用后对象作废)
 *
 *  回调安全: on_accept 内可调 close/destroy (回调前事件已摘除/守卫置位,
 *            回调返回后不再访问对象 — 与 tcp_conn 同模式).
 *  线程: 编译时 SEVENT_THREAD_SAFE=ON 时, close/destroy 跨线程安全;
 *        listen 仍为 [loop 线程]. 默认 OFF 时全部调用需在 loop 线程或启动前.
 *  错误码: sevent 核心 SEVENT_ERR_* (sevent.h)
 *  ========================================================================= */

#ifndef SEVENT_TCP_ACCEPTOR_H
#define SEVENT_TCP_ACCEPTOR_H

#include <stddef.h>
#include <stdint.h>
#include "sevent.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ===== 错误码 =====
 *   SEVENT_ERR_INVAL    — 参数/状态非法 (on_accept 为 NULL / 已监听)
 *   SEVENT_ERR_NOMEM    — 内存不足
 *   SEVENT_ERR_LISTEN   — 监听失败 (socket/bind/listen, 含端口占用) */

/* ===== 不透明句柄 ===== */
typedef struct tcp_acceptor sevent_tcp_acceptor; /* 实现: struct tcp_acceptor (tcp_acceptor.c) */

/* 新连接回调: fd 已 accept (非阻塞), 所有权移交上层.
 * 回调内可调 close/destroy; 回调返回后不得再使用 acceptor 句柄 (可能已销毁). */
typedef void (*sevent_tcp_accept_fn)(void *user_data, int fd);

/* ===== API ===== */

/*
 * 创建监听器.
 * 前置条件: ev 已通过 sevent_create 创建.
 * 返回:     句柄, 或 NULL (ev 为 NULL / 内存不足).
 * 线程:     串行 (loop 线程).
 */
sevent_tcp_acceptor *sevent_tcp_acceptor_create(sevent_context *ev);

/*
 * 开始监听: socket + SO_REUSEADDR + bind + listen + 注册读事件.
 * 前置条件: on_accept 非 NULL; 未在监听 (先 close 再重新 listen).
 * 参数:     bind_addr=NULL=INADDR_ANY; port=0=随机端口 (sevent_tcp_acceptor_port 查询);
 *           backlog=0 用默认 (8).
 * 返回:     0 = 已监听 (事件循环就绪后分发 on_accept);
 *           <0 = SEVENT_ERR_INVAL (参数/状态非法), SEVENT_ERR_NOMEM,
 *                SEVENT_ERR_LISTEN (socket/bind/listen 失败, 含端口占用).
 * 失败时监听 fd 已由本层关闭, 对象可重新 listen.
 * 线程:     [loop 线程].
 */
int sevent_tcp_acceptor_listen(sevent_tcp_acceptor *a,
                               const char          *bind_addr,
                               uint16_t             port,
                               int                  backlog,
                               sevent_tcp_accept_fn on_accept,
                               void                *user_data);

/*
 * 实际监听端口 (port=0 随机端口时查询).
 * 返回: >=0 = 端口; <0 = 未在监听.
 * 线程: [loop 线程].
 */
int sevent_tcp_acceptor_port(sevent_tcp_acceptor *a);

/*
 * 停止监听 (摘事件 + 关闭监听 fd). 对象可重新 listen.
 * 前置条件: 无 (幂等 — 未监听时调用安全).
 * 回调:     回调内可安全调用 (事件已摘除, 不会重入).
 * 线程:     SEVENT_THREAD_SAFE=ON 时跨线程安全, OFF 时 [loop 线程].
 */
void sevent_tcp_acceptor_close(sevent_tcp_acceptor *a);

/*
 * 释放对象内存.
 * 行为:     先 close, 再释放; free 一律推迟到事件循环 run_posts 阶段
 *           (sevent_post), 保证回调栈安全展开 — on_accept 回调内可安全调用
 *           (与 tcp_conn 同模式; 不区分 sevent_run/run_once 模式).
 * 约束:     调用后对象作废 — 不得再对 a 调用任何 API (含再次 destroy),
 *           违反为未定义行为. destroy 不允许幂等.
 * 注:       free 由事件循环执行 — destroy 后须推进循环让 run_posts 执行
 *           cleanup; sevent_destroy 会丢弃未执行的 post, 销毁 ev 前未推进
 *           循环则对象泄漏.
 * 线程:     SEVENT_THREAD_SAFE=ON 时跨线程安全, OFF 时 [loop 线程].
 */
void sevent_tcp_acceptor_destroy(sevent_tcp_acceptor *a);

#ifdef __cplusplus
}
#endif
#endif /* SEVENT_TCP_ACCEPTOR_H */
