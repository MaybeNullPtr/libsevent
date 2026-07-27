/* =========================================================================
 *  ws_deflate.c — WebSocket permessage-deflate (RFC 7692)
 *
 *  只在 SEVENT_WS_DEFLATE 编译时链接 zlib, 否则为无操作桩.
 *  ========================================================================= */

#include "ws_deflate.h"
#include "sevent_i.h"

#include <string.h>

#ifdef SEVENT_WS_DEFLATE
#include <zlib.h>

struct ws_deflate {
    z_stream deflate;
    z_stream inflate;
    bool     server_no_context_takeover;
    bool     client_no_context_takeover;
    uint8_t  server_window_bits;
    uint8_t  client_window_bits;
};

bool ws_deflate_create(ws_deflate **out, const ws_deflate_params *params) {
    if(!out)
        return false;
    ws_deflate *df = (ws_deflate *)sevent_i_calloc(1, sizeof(ws_deflate));
    if(!df)
        return false;

    int cbw = 15, sbw = 15;
    if(params) {
        cbw                            = params->client_max_window_bits ? params->client_max_window_bits : 15;
        sbw                            = params->server_max_window_bits ? params->server_max_window_bits : 15;
        df->client_no_context_takeover = params->client_no_context_takeover;
        df->server_no_context_takeover = params->server_no_context_takeover;
    }
    df->client_window_bits = (uint8_t)cbw;
    df->server_window_bits = (uint8_t)sbw;

    df->deflate.zalloc = Z_NULL;
    df->deflate.zfree  = Z_NULL;
    df->deflate.opaque = Z_NULL;
    if(deflateInit2(&df->deflate, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -cbw, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
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

bool ws_deflate_decompress(ws_deflate *df, const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_cap) {
    if(!df || !in || !out || !out_cap)
        return false;
    if(in_len > UINT_MAX || *out_cap > UINT_MAX)
        return false;

    /* 拼接尾部 0x00 0x00 0xff 0xff (RFC 7692 §6) 后一次性解压 */
    uint8_t *buf = (uint8_t *)sevent_i_malloc(in_len + 4);
    if(!buf)
        return false;
    memcpy(buf, in, in_len);
    buf[in_len]     = 0x00;
    buf[in_len + 1] = 0x00;
    buf[in_len + 2] = 0xFF;
    buf[in_len + 3] = 0xFF;

    df->inflate.next_in   = buf;
    df->inflate.avail_in  = (uInt)(in_len + 4);
    df->inflate.next_out  = out;
    df->inflate.avail_out = (uInt)*out_cap;

    int rc = inflate(&df->inflate, Z_SYNC_FLUSH);
    sevent_i_free(buf);

    if(rc != Z_OK && rc != Z_STREAM_END) {
        inflateReset(&df->inflate);
        return false;
    }

    size_t used = *out_cap - df->inflate.avail_out;
    *out_cap    = used;

    if(df->server_no_context_takeover)
        inflateReset(&df->inflate);
    return true;
}

#else /* !SEVENT_WS_DEFLATE */

struct ws_deflate {
    int _placeholder;
};

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

bool ws_deflate_decompress(ws_deflate *df, const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_cap) {
    (void)df;
    (void)in;
    (void)in_len;
    (void)out;
    (void)out_cap;
    return false;
}

#endif /* SEVENT_WS_DEFLATE */
