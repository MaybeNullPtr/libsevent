/* =========================================================================
 *  ws_deflate.c — WebSocket permessage-deflate (RFC 7692)
 *
 *  只在 SEVENT_WS_DEFLATE 编译时链接 zlib, 否则为无操作桩.
 *  ========================================================================= */

#include "ws_deflate.h"
#include "sevent_i.h"

#include <stdio.h>
#include <string.h>

#ifdef SEVENT_WS_DEFLATE
#include <zlib.h>

/* 转义层: sevent_ws_deflate_level → zlib deflate level.
 * 枚举值 1-9 与 zlib 字面对应, DEFAULT(0)=默认 6, NONE(10)=不压缩,
 * 未知值一律安全回退默认 6. */
static int deflate_level_to_zlib(sevent_ws_deflate_level lvl) {
    switch(lvl) {
    case SEVENT_WS_DEFLATE_LEVEL_NONE: return Z_NO_COMPRESSION;       /* 0 */
    case SEVENT_WS_DEFLATE_LEVEL_1:    return 1;
    case SEVENT_WS_DEFLATE_LEVEL_2:    return 2;
    case SEVENT_WS_DEFLATE_LEVEL_3:    return 3;
    case SEVENT_WS_DEFLATE_LEVEL_4:    return 4;
    case SEVENT_WS_DEFLATE_LEVEL_5:    return 5;
    case SEVENT_WS_DEFLATE_LEVEL_6:    return 6;
    case SEVENT_WS_DEFLATE_LEVEL_7:    return 7;
    case SEVENT_WS_DEFLATE_LEVEL_8:    return 8;
    case SEVENT_WS_DEFLATE_LEVEL_9:    return 9;
    default:                           return Z_DEFAULT_COMPRESSION;  /* DEFAULT(0)/未知 */
    }
}

bool ws_deflate_create(ws_deflate **out, const ws_deflate_params *params) {
    if(!out)
        return false;
    ws_deflate *df = (ws_deflate *)sevent_i_calloc(1, sizeof(ws_deflate));
    if(!df)
        return false;

    int cbw = 15, sbw = 15;
    int level = Z_DEFAULT_COMPRESSION;
    if(params) {
        cbw                            = params->client_max_window_bits ? params->client_max_window_bits : 15;
        sbw                            = params->server_max_window_bits ? params->server_max_window_bits : 15;
        df->client_no_context_takeover = params->client_no_context_takeover;
        df->server_no_context_takeover = params->server_no_context_takeover;
        level = deflate_level_to_zlib(params->compression_level);
    }
    df->client_window_bits = (uint8_t)cbw;
    df->server_window_bits = (uint8_t)sbw;

    df->deflate.zalloc = Z_NULL;
    df->deflate.zfree  = Z_NULL;
    df->deflate.opaque = Z_NULL;
    if(deflateInit2(&df->deflate, level, Z_DEFLATED, -cbw, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
        sevent_i_free(df);
        return false;
    }

    df->inflate.zalloc = Z_NULL;
    df->inflate.zfree  = Z_NULL;
    df->inflate.opaque = Z_NULL;
    if(inflateInit2(&df->inflate, -sbw) != Z_OK) {
        deflateEnd(&df->deflate);
        sevent_i_free(df);
        return false;
    }

    *out = df;
    return true;
}

void ws_deflate_destroy(ws_deflate *df) {
    if(!df)
        return;
    deflateEnd(&df->deflate);
    inflateEnd(&df->inflate);
    sevent_i_free(df);
}

size_t ws_deflate_compress_maxlen(ws_deflate *df, size_t in_len) {
    if(!df || in_len > UINT_MAX)
        return 0;
    return deflateBound(&df->deflate, (uLong)in_len) + 4; /* +4 尾部 */
}

bool ws_deflate_compress(ws_deflate *df, const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_cap) {
    if(!df || !in || !out || !out_cap)
        return false;
    if(in_len > UINT_MAX || *out_cap > UINT_MAX)
        return false;

    df->deflate.next_in   = (uint8_t *)in;
    df->deflate.avail_in  = (uInt)in_len;
    df->deflate.next_out  = out;
    df->deflate.avail_out = (uInt)*out_cap;

    if(deflate(&df->deflate, Z_SYNC_FLUSH) != Z_OK) {
        deflateReset(&df->deflate);
        return false;
    }

    size_t used = *out_cap - df->deflate.avail_out;
    if(used < 4) {
        deflateReset(&df->deflate);
        return false; /* 尾部都放不下, 不可能 */
    }

    /* RFC 7692 §6: 去掉尾部 0x00 0x00 0xff 0xff (Z_SYNC_FLUSH 固定输出) */
    *out_cap = used - 4;

    if(df->client_no_context_takeover)
        deflateReset(&df->deflate);
    return true;
}

/* ===== 流式压缩 ===== */

void ws_deflate_compress_reset(ws_deflate *df) {
    if(df)
        deflateReset(&df->deflate);
}

bool ws_deflate_compress_stream(ws_deflate *df, const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_cap) {
    if(!df || !in || !out || !out_cap)
        return false;
    if(in_len > UINT_MAX || *out_cap > UINT_MAX)
        return false;

    df->deflate.next_in   = (uint8_t *)in;
    df->deflate.avail_in  = (uInt)in_len;
    df->deflate.next_out  = out;
    df->deflate.avail_out = (uInt)*out_cap;

    int rc = deflate(&df->deflate, Z_NO_FLUSH);
    if(rc != Z_OK) {
        deflateReset(&df->deflate);
        return false;
    }

    *out_cap = *out_cap - df->deflate.avail_out;
    return true;
}

bool ws_deflate_compress_end(ws_deflate *df, uint8_t *out, size_t *out_cap) {
    if(!df || !out || !out_cap)
        return false;
    if(*out_cap > UINT_MAX)
        return false;

    df->deflate.next_in   = NULL;
    df->deflate.avail_in  = 0;
    df->deflate.next_out  = out;
    df->deflate.avail_out = (uInt)*out_cap;

    /* Z_SYNC_FLUSH 刷出所有积压数据 + 尾部 0x0000FFFF */
    if(deflate(&df->deflate, Z_SYNC_FLUSH) != Z_OK) {
        deflateReset(&df->deflate);
        return false;
    }

    size_t used = *out_cap - df->deflate.avail_out;
    if(used < 4) {
        deflateReset(&df->deflate);
        return false;
    }
    *out_cap = used - 4;

    if(df->client_no_context_takeover)
        deflateReset(&df->deflate);
    return true;
}

#else /* !SEVENT_WS_DEFLATE */

bool ws_deflate_create(ws_deflate **out, const ws_deflate_params *params) {
    (void)params;
    if(out)
        *out = NULL;
    return false;
}

void ws_deflate_destroy(ws_deflate *df) { (void)df; }

size_t ws_deflate_compress_maxlen(ws_deflate *df, size_t in_len) {
    (void)df;
    (void)in_len;
    return 0;
}

bool ws_deflate_compress(ws_deflate *df, const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_cap) {
    (void)df;
    (void)in;
    (void)in_len;
    (void)out;
    (void)out_cap;
    return false;
}

/* stub: 流式操作 */

void ws_deflate_compress_reset(ws_deflate *df) { (void)df; }

bool ws_deflate_compress_stream(ws_deflate *df, const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_cap) {
    (void)df; (void)in; (void)in_len; (void)out; (void)out_cap;
    return false;
}

bool ws_deflate_compress_end(ws_deflate *df, uint8_t *out, size_t *out_cap) {
    (void)df; (void)out; (void)out_cap;
    return false;
}

#endif /* SEVENT_WS_DEFLATE */
