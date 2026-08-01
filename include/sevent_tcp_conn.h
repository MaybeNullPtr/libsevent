/* =========================================================================
 *  sevent_tcp_conn.h — TCP 传输层 (公开, 可独立使用)
 *
 *  定位:
 *   独立完整层 — 用户可直接用本 API 完成 TCP 客户端/服务端, 不经过
 *   stream_conn 抽象. ws 模块经 stream_conn 使用 (内部适配本层).
 *
 *  接口约定 (与 sevent_ws 同风格的纯回调推送模型):
 *   - 状态机: IDLE --open/accept--> OPENING --on_open--> OPEN --EOF--> IDLE
 *     OPENING 中 close() = 取消建立 (连接中止, 回调不再触发)
 *   - 数据推送: 数据到达由事件循环驱动, 经 on_data 推送 (本层持有接收缓冲,
 *     上层收到即处理, 不提供 read API, 不主动轮询)
 *   - 发送: write 返回"已接受" — 数据拷贝进本层写队列, 异步自动 flush
 *     (写就绪续写, 上层无感知); 队列空后自动撤写兴趣
 *   - 生命周期通知: on_open (建立完成) / on_data (数据) / on_close (对端
 *     关闭 EOF, 之后状态回 IDLE 可重开) / on_error (建立失败或数据期致命错误)
 *   - 主动 close() 不触发 on_close (上层自己发起的关闭, 状态已知);
 *     on_error 后状态同样回 IDLE, 可重新 open/accept
 *   - 生命周期: create → open/accept → write → close (可重开)
 *     → destroy (free 推迟到 run_posts, 回调内可安全调用; 调用后对象作废)
 *   - 回调安全: 所有回调内可调 write/close/destroy; destroy 后回调栈安全
 *     展开 (对象 free 延迟到 run_posts)
 *   - 线程: 编译时 SEVENT_THREAD_SAFE=ON 时, write/close/destroy 跨线程
 *     安全 (各连接一把递归锁, 与 sevent_ws 同约定: IO 回调与公开 API 均持锁);
 *     open/accept 仍为 [loop 线程]. 默认 OFF 时与 sevent 一致 — 全部调用
 *     需在 loop 线程或启动前.
 *   - 错误码: sevent 核心 SEVENT_ERR_* (sevent.h)
 *  ========================================================================= */

#ifndef SEVENT_TCP_CONN_H
#define SEVENT_TCP_CONN_H

#include <stddef.h>
#include <stdint.h>
#include "sevent.h"
#include "sevent_stream_conn.h" /* 回调类型 + sevent_stream_conn_init */

#ifdef __cplusplus
extern "C" {
#endif

/* ===== 错误码 =====
 * 复用 sevent 核心错误码 (sevent.h):
 *   SEVENT_ERR_INVAL    — 参数/非法状态调用 (open 前置条件不满足等)
 *   SEVENT_ERR_NOMEM    — 内存不足
 *   SEVENT_ERR_CONNECT  — TCP 连接失败 (open 立即失败或 on_error 通知)
 *   SEVENT_ERR_READ     — 读致命错误 (on_error 通知)
 *   SEVENT_ERR_WRITE    — 写致命错误 (write 返回或 on_error 通知) */

/* ===== 不透明句柄 ===== */
typedef struct tcp_conn sevent_tcp_conn; /* 实现: struct tcp_conn (tcp_conn.c) */

/* ===== 回调类型 + 连接初始化参数 =====
 * 复用 sevent_stream_conn.h (唯一一套定义): 回调类型 sevent_stream_*_fn 与
 * 结构体 sevent_stream_conn_init (回调组 + connect_timeout_ms/recv_buf_size).
 * 本层直接使用, 不重复定义. */

/* ===== API ===== */

/*
 * 创建 TCP 传输对象.
 * 前置条件: ev 已通过 sevent_create 创建.
 * 返回:     句柄, 或 NULL (ev 为 NULL / 内存不足).
 * 线程:     串行 (loop 线程).
 */
sevent_tcp_conn *sevent_tcp_conn_create(sevent_context *ev);

/*
 * 客户端: 异步建立连接.
 * 行为:     TCP connect (非阻塞, EINPROGRESS 容忍) → 写就绪 → SO_ERROR 检查
 *           → 成功 on_open / 失败 on_error(SEVENT_ERR_CONNECT) (均自行收尾,
 *           状态回 IDLE 可重开).
 * 前置条件: host 非 NULL; init 非 NULL 且 on_open/on_data 非 NULL; 状态为 IDLE
 *           (重复调用前必须先 close).
 * 返回:     0 = 已启动 (结果经回调通知);
 *           <0 = 未启动: SEVENT_ERR_INVAL (参数/状态非法),
 *                SEVENT_ERR_CONNECT (立即失败), SEVENT_ERR_NOMEM.
 * 后置条件: 成功 → OPENING; on_open 后 → OPEN.
 * 回调:     init 各回调由事件循环触发; 回调内可调 write/close/destroy.
 * 线程:     [loop 线程].
 */
int sevent_tcp_conn_open(sevent_tcp_conn *c, const char *host, uint16_t port, const sevent_stream_conn_init *init);

/*
 * 服务端: 包装已 accept 的连接.
 * 行为:     fd 置非阻塞 → 注册首次就绪事件 → 事件循环触发 on_open (异步,
 *           与 open 语义一致); TCP 无握手, on_open 后连接即可读写.
 * 前置条件: fd >= 0; init 非 NULL 且 on_open/on_data 非 NULL; 状态为 IDLE.
 *           fd 所有权移交本层 (失败时 fd 已由本层关闭, 调用方不得再使用).
 * 返回:     0 = 已接受; <0 = SEVENT_ERR_INVAL (参数/状态/fcntl 失败) /
 *           SEVENT_ERR_NOMEM.
 * 后置条件: 成功 → OPEN; on_open 在事件循环中触发 (回调内可 write).
 * 回调:     同 open.
 * 线程:     [loop 线程].
 */
int sevent_tcp_conn_accept(sevent_tcp_conn *c, int fd, const sevent_stream_conn_init *init);

/*
 * 发送数据 (异步, 立即返回).
 * 行为:     数据拷贝进本层写队列 → 立即尝试 flush (写就绪) → 未写完注册写
 *           兴趣由事件驱动续写; 队列空后自动撤写兴趣. 调用方数据可随即复用.
 * 前置条件: 状态为 OPEN (on_open 之后); 之前返回 SEVENT_ERR_INVAL.
 * 返回:     0 = 已接受 (数据已入队, 失败会经 on_error(SEVENT_ERR_WRITE) 通知);
 *           <0 = SEVENT_ERR_INVAL (参数/状态非法) / SEVENT_ERR_NOMEM (入队失败,
 *           数据未接受) / SEVENT_ERR_WRITE (flush 致命写错误, on_error 已通知).
 * 线程:     [loop 线程] (SEVENT_THREAD_SAFE=ON 时跨线程安全).
 */
int sevent_tcp_conn_write(sevent_tcp_conn *c, const void *data, size_t len);

/*
 * 关闭底层连接 (TCP close, 不等待对端).
 * 行为:     摘除事件 + 关闭 fd + 清写队列 + 状态回 IDLE; 对象可重新 open/accept.
 *           不触发 on_close (主动关闭, 上层状态已知).
 * 前置条件: 无 (任意状态可调, 幂等 — 已关闭/EOF 后调用安全).
 * 回调:     回调内可安全调用 (事件已摘除, 不会重入).
 * 线程:     [loop 线程] (SEVENT_THREAD_SAFE=ON 时跨线程安全).
 */
void sevent_tcp_conn_close(sevent_tcp_conn *c);

/*
 * 释放对象内存.
 * 行为:     先 close, 再释放; 对象内存的 free 一律推迟到事件循环 run_posts
 *           阶段 (sevent_post), 保证回调栈安全展开 — 回调内可安全调用
 *           (与 sevent_ws_destroy 同模式; 不区分 sevent_run/run_once 模式).
 * 约束:     调用后对象作废 — 不得再对 c 调用任何 API (含再次 destroy),
 *           违反为未定义行为 (对象可能已释放). destroy 不允许幂等.
 * 注:       free 由事件循环执行 — destroy 后须推进循环 (run_once/sevent_run)
 *           让 run_posts 执行 cleanup; sevent_destroy 会丢弃未执行的 post
 *           (不执行回调), 销毁 ev 前未推进循环则对象泄漏.
 * 线程:     SEVENT_THREAD_SAFE=ON 时跨线程安全, OFF 时 [loop 线程].
 */
void sevent_tcp_conn_destroy(sevent_tcp_conn *c);

#ifdef __cplusplus
}
#endif
#endif /* SEVENT_TCP_CONN_H */
