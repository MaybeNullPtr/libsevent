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

/* ===== 不透明句柄 ===== */
typedef struct ws_deflate ws_deflate;

/* ===== API ===== */

/* 创建/销毁 (内部 malloc/free). */
bool ws_deflate_create(ws_deflate **out, const ws_deflate_params *params);
void ws_deflate_destroy(ws_deflate *df);

/* 查询压缩所需最大输出大小 (deflateBound). */
size_t ws_deflate_compress_maxlen(ws_deflate *df, size_t in_len);

/* 压缩一条消息. out_cap 传入容量, 传出实际长度.
 * 确保 out_cap >= ws_deflate_compress_maxlen(df, in_len). */
bool ws_deflate_compress(ws_deflate *df, const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_cap);

/* 解压一条消息. out_cap 不足时返回 false. */
bool ws_deflate_decompress(ws_deflate *df, const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_cap);

#ifdef __cplusplus
}
#endif

#endif /* SEVENT_WS_DEFLATE_H */
