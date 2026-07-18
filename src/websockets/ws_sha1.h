/* =========================================================================
 *  ws_sha1.h — SHA-1 实现 (FIPS 180-4)
 *
 *  自包含, 零外部依赖, 仅供 sevent WebSocket 模块内部使用.
 *  ========================================================================= */

#ifndef SEVENT_WS_SHA1_H
#define SEVENT_WS_SHA1_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WS_SHA1_DIGEST_SIZE 20 /* 160 bits */

typedef struct {
    uint32_t state[5];
    uint64_t count;
    uint8_t  buffer[64];
} ws_sha1_ctx;

void ws_sha1_init(ws_sha1_ctx *ctx);
void ws_sha1_update(ws_sha1_ctx *ctx, const void *data, size_t len);
void ws_sha1_final(ws_sha1_ctx *ctx, uint8_t digest[WS_SHA1_DIGEST_SIZE]);

/* 全量单拍接口 */
void ws_sha1(const void *data, size_t len, uint8_t digest[WS_SHA1_DIGEST_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* SEVENT_WS_SHA1_H */
