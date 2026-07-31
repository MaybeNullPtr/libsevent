/* =========================================================================
 *  ws_deflate.h — WebSocket permessage-deflate (RFC 7692)
 *
 *  封装 zlib deflate/inflate, 提供消息级压缩/解压.
 *  只在 SEVENT_WS_DEFLATE 编译时真正链接, 否则为无操作桩.
 *  ========================================================================= */

#ifndef SEVENT_WS_DEFLATE_H
#define SEVENT_WS_DEFLATE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef SEVENT_WS_DEFLATE
#include <zlib.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* ===== 参数 ===== */
typedef struct {
    bool    server_no_context_takeover; /* 默认 false */
    bool    client_no_context_takeover; /* 默认 false */
    uint8_t server_max_window_bits;     /* 0=默认 15 */
    uint8_t client_max_window_bits;     /* 0=默认 15 */
} ws_deflate_params;

/* ===== 公开结构 =====
 * 压缩侧 (deflate) 由 ws_deflate 封装管理;
 * 解压侧 (inflate) 由协议层 (ws_conn.c) 直接操作:
 * 解压输出大小不可预判, 协议层用固定缓冲分批循环 inflate,
 * 无法封装成"一次调用"的独立层. */
typedef struct ws_deflate {
#ifdef SEVENT_WS_DEFLATE
    z_stream deflate;
    z_stream inflate;
#endif
    bool     server_no_context_takeover;
    bool     client_no_context_takeover;
    uint8_t  server_window_bits;
    uint8_t  client_window_bits;
} ws_deflate;

/* ===== API ===== */

/* 创建/销毁 (内部 malloc/free). */
bool ws_deflate_create(ws_deflate **out, const ws_deflate_params *params);
void ws_deflate_destroy(ws_deflate *df);

/* 查询压缩所需最大输出大小 (deflateBound). */
size_t ws_deflate_compress_maxlen(ws_deflate *df, size_t in_len);

/* 压缩一条消息. out_cap 传入容量, 传出实际长度.
 * 确保 out_cap >= ws_deflate_compress_maxlen(df, in_len). */
bool ws_deflate_compress(ws_deflate *df, const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_cap);

/* ===== 流式压缩 ===== */

/* 重置压缩流，准备压缩新消息. */
void ws_deflate_compress_reset(ws_deflate *df);

/* 压缩一段数据，同一消息可多次调用. out_cap 传入容量, 传出实际输出长度.
 * 返回 false 表示输出缓冲不足，调用方应增大缓冲重试（当前输入已丢弃）. */
bool ws_deflate_compress_stream(ws_deflate *df, const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_cap);

/* 结束压缩，Z_SYNC_FLUSH 收尾并去掉尾部 4 字节.
 * out_cap 不足时返回 false，调用方应增大缓冲重试. */
bool ws_deflate_compress_end(ws_deflate *df, uint8_t *out, size_t *out_cap);

/* ===== 解压 =====
 * 解压侧不提供封装: 协议层直接操作 df->inflate (z_stream),
 * 用固定缓冲分批循环调用 inflate. 见 struct ws_deflate 注释. */

#ifdef __cplusplus
}
#endif

#endif /* SEVENT_WS_DEFLATE_H */
