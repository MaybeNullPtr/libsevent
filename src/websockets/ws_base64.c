/* =========================================================================
 *  ws_base64.c — Base64 编码 (RFC 4648 §4)
 *
 *  仅实现编码方向. 使用标准 alphabet:
 *    A-Z a-z 0-9 + /
 *  ========================================================================= */

#include "ws_base64.h"

static const char b64_tab[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

size_t ws_base64_encode_size(size_t raw_len) {
    /* 每 3 字节 → 4 字符, 向上取整, 加 NUL */
    return ((raw_len + 2) / 3) * 4 + 1;
}

int ws_base64_encode(const void *raw, size_t raw_len, char *dst, size_t dst_cap) {
    const uint8_t *in      = (const uint8_t *)raw;
    size_t         out_len = ((raw_len + 2) / 3) * 4;

    if(dst_cap < out_len + 1)
        return -1;

    size_t i = 0, o = 0;
    while(i < raw_len) {
        uint8_t a = in[i++];
        uint8_t b = (i < raw_len) ? in[i++] : 0;
        uint8_t c = (i < raw_len) ? in[i++] : 0;

        dst[o++] = b64_tab[a >> 2];
        dst[o++] = b64_tab[((a & 0x03) << 4) | (b >> 4)];
        dst[o++] = b64_tab[((b & 0x0F) << 2) | (c >> 6)];
        dst[o++] = b64_tab[c & 0x3F];
    }

    /* padding: raw 长度非 3 倍数的替换末尾字符为 '=' */
    size_t pad = 3 - (raw_len % 3);
    if(pad != 3) {
        for(size_t j = 0; j < pad; j++)
            dst[out_len - 1 - j] = '=';
    }

    dst[out_len] = '\0';
    return (int)out_len;
}
