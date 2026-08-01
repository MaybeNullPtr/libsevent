/* =========================================================================
 *  ws_handshake.c — WebSocket HTTP Upgrade 握手 (RFC 6455 §4)
 *
 *  客户端侧: 构建请求 + 验证响应.
 *  ========================================================================= */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <unistd.h>

#include "ws_handshake.h"
#include "ws_sha1.h"
#include "ws_base64.h"

/* ---- 可移植的 case-insensitive 比较 (避免 strncasecmp 的平台差异) ---- */
static int ci_eq(const char *a, size_t a_len, const char *b) {
    for(size_t i = 0; i < a_len; i++) {
        if(b[i] == '\0')
            return 0;
        char ca = a[i], cb = b[i];
        if(ca >= 'A' && ca <= 'Z')
            ca += 0x20;
        if(cb >= 'A' && cb <= 'Z')
            cb += 0x20;
        if(ca != cb)
            return 0;
    }
    return (b[a_len] == '\0');
}

/* ---- 辅助: 从 /dev/urandom 读取, 失败返回 -1 ---- */
static int read_random(void *buf, size_t len) {
    FILE *f = fopen("/dev/urandom", "rb");
    if(!f)
        return -1;
    size_t r = fread(buf, 1, len, f);
    fclose(f);
    return (r == len) ? 0 : -1;
}

/* ---- 辅助: fallback PRNG ---- */
static unsigned int xorshift32(unsigned int *seed) {
    unsigned int x = *seed;
    x              ^= x << 13;
    x              ^= x >> 17;
    x              ^= x << 5;
    *seed          = x;
    return x;
}

void ws_gen_key(char key[WS_KEY_BASE64_LEN]) {
    uint8_t raw[16];
    if(read_random(raw, sizeof(raw)) != 0) {
        /* fallback: time + PID 种子 */
        unsigned int seed = (unsigned int)(time(NULL) ^ (getpid() << 16));
        for(size_t i = 0; i < sizeof(raw); i++) {
            raw[i] = (uint8_t)xorshift32(&seed);
        }
    }
    ws_base64_encode(raw, sizeof(raw), key, WS_KEY_BASE64_LEN);
}

int ws_build_request(char                   *buf,
                     size_t                  cap,
                     const char             *host,
                     uint16_t                port,
                     const char             *path,
                     const char             *key,
                     const char             *sub_protocol,
                     bool                    enable_deflate,
                     const ws_deflate_params *pmd_offer) {
    (void)enable_deflate;
    (void)pmd_offer;
    /* 固定头部 (不含子协议行和最后的空行) */
    int n = snprintf(buf,
                     cap,
                     "GET %s HTTP/1.1\r\n"
                     "Host: %s:%u\r\n"
                     "Upgrade: websocket\r\n"
                     "Connection: Upgrade\r\n"
                     "Sec-WebSocket-Key: %s\r\n"
                     "Sec-WebSocket-Version: 13\r\n",
                     path,
                     host,
                     (unsigned)port,
                     key);
    if(n < 0 || (size_t)n >= cap)
        return -1;

    /* 条件追加 Sec-WebSocket-Protocol */
    if(sub_protocol && sub_protocol[0]) {
        int m = snprintf(buf + n, cap - (size_t)n, "Sec-WebSocket-Protocol: %s\r\n", sub_protocol);
        if(m < 0 || (size_t)m >= cap - (size_t)n)
            return -1;
        n += m;
    }

#ifdef SEVENT_WS_DEFLATE
    /* permessage-deflate 压缩扩展协商 (RFC 7692 §7.1.2) */
    if(enable_deflate) {
        char ext[192];
        int  e = snprintf(ext, sizeof(ext), WS_EXT_PMD);
        if(e < 0 || (size_t)e >= sizeof(ext))
            return -1;
        if(pmd_offer) {
            /* client_max_window_bits: 自我承诺发送窗口上限 (0=无值 offer) */
            if(pmd_offer->client_max_window_bits)
                e += snprintf(ext + e, sizeof(ext) - (size_t)e, "; " WS_EXT_CLIENT_MAX_WB "=%u",
                              (unsigned)pmd_offer->client_max_window_bits);
            else
                e += snprintf(ext + e, sizeof(ext) - (size_t)e, "; " WS_EXT_CLIENT_MAX_WB);
            /* server_max_window_bits: 请求对端窗口上限 (0=不请求) */
            if(pmd_offer->server_max_window_bits)
                e += snprintf(ext + e, sizeof(ext) - (size_t)e, "; " WS_EXT_SERVER_MAX_WB "=%u",
                              (unsigned)pmd_offer->server_max_window_bits);
            /* no_context_takeover: 自我承诺/请求对端每条消息重置压缩上下文 */
            if(pmd_offer->client_no_context_takeover)
                e += snprintf(ext + e, sizeof(ext) - (size_t)e, "; " WS_EXT_CLIENT_NO_CTX);
            if(pmd_offer->server_no_context_takeover)
                e += snprintf(ext + e, sizeof(ext) - (size_t)e, "; " WS_EXT_SERVER_NO_CTX);
        } else {
            /* 默认 offer: 无值 client_max_window_bits (向后兼容) */
            e += snprintf(ext + e, sizeof(ext) - (size_t)e, "; " WS_EXT_CLIENT_MAX_WB);
        }
        if(e < 0 || (size_t)e >= sizeof(ext))
            return -1;
        int m = snprintf(buf + n, cap - (size_t)n, "Sec-WebSocket-Extensions: %s\r\n", ext);
        if(m < 0 || (size_t)m >= cap - (size_t)n)
            return -1;
        n += m;
    }
#endif

    /* 末尾空行 */
    if((size_t)n + 2 > cap)
        return -1;
    memcpy(buf + n, "\r\n", 2);
    buf[n + 2] = '\0';
    return n + 2;
}

/* ---- HTTP 响应解析状态机 ---- */

#define WS_HTTP_STATUS_LINE 0
#define WS_HTTP_HEADERS 1
#define WS_HTTP_DONE 2

int ws_parse_response(const uint8_t *buf, size_t len, ws_handshake_response *resp) {
    /* 最小长度: "HTTP/1.1 XXX\r\n" = 14 字节 */
    if(len < 14)
        return 0;

    /* 初始化 */
    resp->status_code   = 0;
    resp->accept[0]     = '\0';
    resp->protocol[0]   = '\0';
    resp->location[0]   = '\0';
    resp->extensions[0] = '\0';

    /* ---- 查找 HTTP 响应结尾 (\r\n\r\n) ---- */
    const uint8_t *end = NULL;
    for(size_t i = 0; i + 3 < len; i++) {
        if(buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n') {
            end = buf + i;
            break;
        }
    }
    if(!end) {
        /* 数据不足 */
        if(len >= 4096)
            return -1; /* 响应头过长 */
        return 0;
    }

    size_t header_len = (size_t)(end - buf) + 4;

    /* ---- 解析状态行: "HTTP/1.1 XXX ...\r\n" ---- */
    const uint8_t *p        = buf;
    const uint8_t *line_end = (const uint8_t *)memchr(p, '\n', header_len - (size_t)(p - buf));
    if(!line_end)
        return -1;

    /* 跳过 "HTTP/" */
    if(header_len - (size_t)(p - buf) < 8 || p[0] != 'H' || p[1] != 'T' || p[2] != 'T' || p[3] != 'P' || p[4] != '/')
        return -1;

    /* 找到状态码: 空格后的前 3 个数字 */
    const uint8_t *sp = (const uint8_t *)memchr(p, ' ', header_len - (size_t)(p - buf));
    if(!sp)
        return -1;
    sp++;
    if(header_len - (size_t)(sp - buf) < 3)
        return -1;
    if(sp[0] >= '0' && sp[0] <= '9' && sp[1] >= '0' && sp[1] <= '9' && sp[2] >= '0' && sp[2] <= '9') {
        resp->status_code = (sp[0] - '0') * 100 + (sp[1] - '0') * 10 + (sp[2] - '0');
    }

    /* ---- 逐行解析头 (无论 101 还是非 101, 都要解 header 长度用于提取 body) ---- */
    p = line_end + 1;
    while((size_t)(p - buf) < header_len - 2) {
        line_end = (const uint8_t *)memchr(p, '\n', header_len - (size_t)(p - buf));
        if(!line_end)
            break;

        size_t line_len = (size_t)(line_end - p);
        /* 去掉尾部 \r */
        if(line_len > 0 && p[line_len - 1] == '\r')
            line_len--;

        if(line_len == 0) {
            p = line_end + 1;
            break; /* 空行 = 头结束 */
        }

        /* 查找冒号分割 */
        const uint8_t *colon = (const uint8_t *)memchr(p, ':', line_len);
        if(colon) {
            size_t         name_len = (size_t)(colon - p);
            const uint8_t *val      = colon + 1;
            size_t         val_len  = line_len - name_len - 1;

            /* 跳过值前空格 */
            while(val_len > 0 && (*val == ' ' || *val == '\t')) {
                val++;
                val_len--;
            }

            /* 大小写不敏感比较头名 */
            if(ci_eq((const char *)p, name_len, WS_HDR_ACCEPT)) {
                size_t copy = val_len;
                if(copy >= WS_ACCEPT_BASE64_LEN)
                    copy = WS_ACCEPT_BASE64_LEN - 1;
                memcpy(resp->accept, val, copy);
                resp->accept[copy] = '\0';
            } else if(ci_eq((const char *)p, name_len, WS_HDR_PROTOCOL)) {
                size_t copy = val_len;
                if(copy >= sizeof(resp->protocol))
                    copy = sizeof(resp->protocol) - 1;
                memcpy(resp->protocol, val, copy);
                resp->protocol[copy] = '\0';
            } else if(ci_eq((const char *)p, name_len, WS_HDR_LOCATION)) {
                size_t copy = val_len;
                if(copy >= sizeof(resp->location))
                    copy = sizeof(resp->location) - 1;
                memcpy(resp->location, val, copy);
                resp->location[copy] = '\0';
            } else if(ci_eq((const char *)p, name_len, WS_HDR_EXTENSIONS)) {
                size_t copy = val_len;
                if(copy >= sizeof(resp->extensions))
                    copy = sizeof(resp->extensions) - 1;
                memcpy(resp->extensions, val, copy);
                resp->extensions[copy] = '\0';
            }
        }

        p = line_end + 1;
    }

    /* 101 响应必须带 Sec-WebSocket-Accept */
    if(resp->status_code == WS_HTTP_STATUS_SWITCHING && resp->accept[0] == '\0')
        return -1;

    return (int)header_len;
}

int ws_verify_accept(const char *key, const char *accept) {
    /* SHA1(key + GUID) */
    char concat[256];
    int  n = snprintf(concat, sizeof(concat), "%s%s", key, WS_GUID);
    if(n < 0 || (size_t)n >= sizeof(concat))
        return -1;

    uint8_t digest[WS_SHA1_DIGEST_SIZE];
    ws_sha1(concat, (size_t)n, digest);

    /* Base64 编码 (栈数组, 免堆分配) */
    char b64[WS_ACCEPT_BASE64_LEN];
    int  b64_len = ws_base64_encode(digest, WS_SHA1_DIGEST_SIZE, b64, sizeof(b64));
    if(b64_len < 0)
        return -1;
    return (strcmp(b64, accept) == 0) ? 0 : -1;
}
