/* =========================================================================
 *  ws_sha1.c — SHA-1 实现 (FIPS 180-4)
 *
 *  自包含标准 C99, 无外部依赖.
 *  参考 RFC 3174 / FIPS 180-4.
 *  ========================================================================= */

#include "ws_sha1.h"
#include <string.h>

/* ---- 循环左移 ---- */
#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

/* ---- 四轮逻辑函数 ---- */
#define F0(b, c, d) (((b) & (c)) | ((~(b)) & (d)))
#define F1(b, c, d) ((b) ^ (c) ^ (d))
#define F2(b, c, d) (((b) & (c)) | ((b) & (d)) | ((c) & (d)))
#define F3(b, c, d) ((b) ^ (c) ^ (d))

/* ---- 四轮常量 ---- */
#define K0 0x5A827999
#define K1 0x6ED9EBA1
#define K2 0x8F1BBCDC
#define K3 0xCA62C1D6

/* ---- Combine ROTL(A,5) + f(B,C,D) + E + K + W into one step.
 *      After the macro, the standard rotate-shift happens. ---- */
#define SHA1_STEP(a, b, c, d, e, f, k, w)  \
    do {                                    \
        e += ROTL(a, 5) + f(b, c, d) + k + w; \
        b  = ROTL(b, 30);                   \
    } while (0)

static void sha1_transform(ws_sha1_ctx *ctx, const uint8_t block[64])
{
    uint32_t w[80];
    uint32_t a, b, c, d, e;
    int      i;

    /* 字节序: big-endian → host */
    for (i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i * 4]     << 24)
             | ((uint32_t)block[i * 4 + 1] << 16)
             | ((uint32_t)block[i * 4 + 2] <<  8)
             | ((uint32_t)block[i * 4 + 3]);
    }
    for (i = 16; i < 80; i++) {
        w[i] = ROTL(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];

    for (i = 0; i < 80; i++) {
        if (i < 20) {
            SHA1_STEP(a, b, c, d, e, F0, K0, w[i]);
        } else if (i < 40) {
            SHA1_STEP(a, b, c, d, e, F1, K1, w[i]);
        } else if (i < 60) {
            SHA1_STEP(a, b, c, d, e, F2, K2, w[i]);
        } else {
            SHA1_STEP(a, b, c, d, e, F3, K3, w[i]);
        }
        /* 标准 rotate-shift: A→B→C→D→E→A */
        uint32_t t = a;
        a = e; e = d; d = c; c = b; b = t;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
}

void ws_sha1_init(ws_sha1_ctx *ctx)
{
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xC3D2E1F0;
    ctx->count = 0;
}

void ws_sha1_update(ws_sha1_ctx *ctx, const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    size_t idx = (size_t)(ctx->count & 0x3F);
    ctx->count += len;

    /* 缓冲中有残余, 先填满一个块 */
    if (idx > 0 && idx + len >= 64) {
        size_t fill = 64 - idx;
        memcpy(ctx->buffer + idx, p, fill);
        sha1_transform(ctx, ctx->buffer);
        p  += fill;
        len -= fill;
        idx = 0;
    }

    /* 逐块处理 */
    while (len >= 64) {
        sha1_transform(ctx, p);
        p  += 64;
        len -= 64;
    }

    /* 剩余数据入缓冲 */
    if (len > 0) {
        memcpy(ctx->buffer + idx, p, len);
    }
}

void ws_sha1_final(ws_sha1_ctx *ctx, uint8_t digest[WS_SHA1_DIGEST_SIZE])
{
    uint64_t bits  = ctx->count * 8;
    size_t   idx   = (size_t)(ctx->count & 0x3F);
    size_t   pad   = (idx < 56) ? (56 - idx) : (120 - idx);

    /* 追加 0x80 + 填充 zero */
    uint8_t padding[128];
    padding[0] = 0x80;
    memset(padding + 1, 0, pad - 1);
    ws_sha1_update(ctx, padding, pad);

    /* 追加 64-bit 长度 (big-endian) */
    uint8_t len_buf[8];
    len_buf[0] = (uint8_t)(bits >> 56);
    len_buf[1] = (uint8_t)(bits >> 48);
    len_buf[2] = (uint8_t)(bits >> 40);
    len_buf[3] = (uint8_t)(bits >> 32);
    len_buf[4] = (uint8_t)(bits >> 24);
    len_buf[5] = (uint8_t)(bits >> 16);
    len_buf[6] = (uint8_t)(bits >> 8);
    len_buf[7] = (uint8_t)(bits);
    ws_sha1_update(ctx, len_buf, 8);

    /* 输出 (big-endian) */
    for (int i = 0; i < 5; i++) {
        digest[i * 4]     = (uint8_t)(ctx->state[i] >> 24);
        digest[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        digest[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        digest[i * 4 + 3] = (uint8_t)(ctx->state[i]);
    }
}

void ws_sha1(const void *data, size_t len, uint8_t digest[WS_SHA1_DIGEST_SIZE])
{
    ws_sha1_ctx ctx;
    ws_sha1_init(&ctx);
    ws_sha1_update(&ctx, data, len);
    ws_sha1_final(&ctx, digest);
}
