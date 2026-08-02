/* =========================================================================
 *  ws_handshake.c — WebSocket HTTP Upgrade 握手 (RFC 6455 §4)
 *
 *  双端 (纯函数, 无连接状态, 可并发):
 *    客户端: Key 生成 / 构建升级请求 / 解析 101 响应 + 验证 accept
 *    服务端: 解析升级请求 (校验链) / 构建 101 响应 (计算 accept)
 *  HTTP 语法层 (行/头解析/分帧/骨架构建) 由 sevent_http_parse 提供 (doc/
 *  http-layer-design.md §3) — 本文件只保留 ws 专有语义:
 *    Key 生成 / accept 计算校验 / 扩展协商头 / 子协议头 / token 级校验.
 *  ========================================================================= */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <unistd.h>

#include "sevent_http_parse.h"
#include "ws_handshake.h"
#include "ws_sha1.h"
#include "ws_base64.h"

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

int ws_build_request(char                    *buf,
                     size_t                   cap,
                     const char              *host,
                     uint16_t                 port,
                     const char              *path,
                     const char              *key,
                     const char              *sub_protocol,
                     bool                     enable_deflate,
                     const ws_deflate_params *pmd_offer) {
    (void)enable_deflate;
    (void)pmd_offer;
    /* ws 升级头 (请求行/Host/结尾由 sevent_http_build_request 骨架提供) */
    char   extra[512];
    size_t n = (size_t)snprintf(extra,
                                sizeof(extra),
                                "Upgrade: websocket\r\n"
                                "Connection: Upgrade\r\n"
                                "Sec-WebSocket-Key: %s\r\n"
                                "Sec-WebSocket-Version: 13\r\n",
                                key);
    if(n >= sizeof(extra))
        return -1;

    /* 条件追加 Sec-WebSocket-Protocol */
    if(sub_protocol && sub_protocol[0]) {
        int m = snprintf(extra + n, sizeof(extra) - n, "Sec-WebSocket-Protocol: %s\r\n", sub_protocol);
        if(m < 0 || (size_t)m >= sizeof(extra) - n)
            return -1;
        n += (size_t)m;
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
                e += snprintf(ext + e,
                              sizeof(ext) - (size_t)e,
                              "; " WS_EXT_CLIENT_MAX_WB "=%u",
                              (unsigned)pmd_offer->client_max_window_bits);
            else
                e += snprintf(ext + e, sizeof(ext) - (size_t)e, "; " WS_EXT_CLIENT_MAX_WB);
            /* server_max_window_bits: 请求对端窗口上限 (0=不请求) */
            if(pmd_offer->server_max_window_bits)
                e += snprintf(ext + e,
                              sizeof(ext) - (size_t)e,
                              "; " WS_EXT_SERVER_MAX_WB "=%u",
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
        int m = snprintf(extra + n, sizeof(extra) - n, "Sec-WebSocket-Extensions: %s\r\n", ext);
        if(m < 0 || (size_t)m >= sizeof(extra) - n)
            return -1;
        n += (size_t)m;
    }
#endif

    return sevent_http_build_request(buf, cap, "GET", path, host, port, extra);
}

int ws_parse_response(const uint8_t *buf, size_t len, ws_handshake_response *resp) {
    /* 全量清零: 纯函数确定性 (fuzz 断言同输入同输出) + 防调用方误读垃圾 */
    memset(resp, 0, sizeof(*resp));

    /* 最小长度: "HTTP/1.1 XXX\r\n" = 14 字节 */
    if(len < 14)
        return 0;

    /* 语法解析交给 sevent_http_parse (行/头/半包语义一致) */
    sevent_http_msg m;
    int             r = sevent_http_parse((const char *)buf, len, &m);
    if(r < 0)
        return -1;
    if(r > 0 && !m.is_response)
        return -1; /* 服务端回了请求行 (非响应) — 协议错误 */
    if(r == 0) {
        /* 头区完整但 body 未收齐 (非 101 响应带 CL body) — ws 握手只需头区:
         * 旧实现头区完整即返回; http_parse 按完整分帧语义等 body 会挂起
         * (3xx/4xx 错误页 body 可超 4096 上限). 恢复"仅头区"语义 — 手动
         * 构造 msg (headers 指向头区) 供 find_header 提取, body 不消费. */
        const char *hdr_end = NULL;
        for(size_t i = 0; i + 3 < len; i++) {
            if(buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n') {
                hdr_end = (const char *)buf + i;
                break;
            }
        }
        if(!hdr_end)
            return 0; /* 头区也未完整 — 等更多 */
        if((size_t)(hdr_end - (const char *)buf) >= 4096)
            return -1; /* 响应头过长 */

        /* 首行状态码 (仅头区部分): "HTTP/x.y XXX ..." */
        const char *sp = (const char *)memchr(buf, ' ', (size_t)(hdr_end - (const char *)buf));
        if(!sp)
            return -1;
        sp = (const char *)memchr(sp + 1, ' ', (size_t)(hdr_end - sp - 1));
        if(!sp)
            return -1;
        const char *st = sp + 1;
        const char *p;
        int         code = 0;
        /* 位数上限 5: 状态码理论范围 100-599; 畸形超长数字串会溢出 int (UB) */
        for(p = st; p < hdr_end && *p >= '0' && *p <= '9' && p - st < 5; p++)
            code = code * 10 + (*p - '0');
        if(p == st || (p < hdr_end && *p != ' ' && *p != '\r'))
            return -1;
        m.status_code        = code;
        m.is_response        = 1;
        const char *line_end = (const char *)memchr(buf, '\n', (size_t)(hdr_end - (const char *)buf));
        m.headers_start      = line_end + 1;
        m.headers_len        = (size_t)(hdr_end + 2 - m.headers_start);
        /* 头区完整即完成 — 返回完整头区长度 (空行 + 4, 粘包偏移语义与完整解析一致) */
        return (int)(hdr_end + 4 - (const char *)buf);
    }

    resp->status_code = m.status_code;

    /* 提取 ws 专有头 (按需查找) */
    size_t      vl;
    const char *v;
    if((v = sevent_http_find_header(&m, WS_HDR_ACCEPT, &vl))) {
        size_t copy = vl;
        if(copy >= WS_ACCEPT_BASE64_LEN)
            copy = WS_ACCEPT_BASE64_LEN - 1;
        memcpy(resp->accept, v, copy);
        resp->accept[copy] = '\0';
    }
    if((v = sevent_http_find_header(&m, WS_HDR_PROTOCOL, &vl))) {
        size_t copy = vl;
        if(copy >= sizeof(resp->protocol))
            copy = sizeof(resp->protocol) - 1;
        memcpy(resp->protocol, v, copy);
        resp->protocol[copy] = '\0';
    }
    if((v = sevent_http_find_header(&m, WS_HDR_LOCATION, &vl))) {
        size_t copy = vl;
        if(copy >= sizeof(resp->location))
            copy = sizeof(resp->location) - 1;
        memcpy(resp->location, v, copy);
        resp->location[copy] = '\0';
    }
    if((v = sevent_http_find_header(&m, WS_HDR_EXTENSIONS, &vl))) {
        size_t copy = vl;
        if(copy >= sizeof(resp->extensions))
            copy = sizeof(resp->extensions) - 1;
        memcpy(resp->extensions, v, copy);
        resp->extensions[copy] = '\0';
    }

    /* 101 响应必须带 Sec-WebSocket-Accept */
    if(resp->status_code == WS_HTTP_STATUS_SWITCHING && resp->accept[0] == '\0')
        return -1;

    /* 返回完整消息长度 (m.body 起点 = 空行后 = 已消费字节, 粘包偏移语义保持) */
    return (int)(m.body - (const char *)buf);
}

/* ---- 辅助: 计算 Sec-WebSocket-Accept = base64(sha1(key + GUID)) (RFC 6455 §4.2.2) ---- */
static void ws_compute_accept(const char *key, char out[WS_ACCEPT_BASE64_LEN]) {
    char concat[256];
    int  n = snprintf(concat, sizeof(concat), "%s%s", key, WS_GUID);
    if(n < 0 || (size_t)n >= sizeof(concat)) {
        out[0] = '\0'; /* 理论上不可达 (key ≤ 24 字符) */
        return;
    }

    uint8_t digest[WS_SHA1_DIGEST_SIZE];
    ws_sha1(concat, (size_t)n, digest);

    /* Base64 编码 (栈数组, 免堆分配) */
    if(ws_base64_encode(digest, WS_SHA1_DIGEST_SIZE, out, WS_ACCEPT_BASE64_LEN) < 0)
        out[0] = '\0';
}

int ws_verify_accept(const char *key, const char *accept) {
    char b64[WS_ACCEPT_BASE64_LEN];
    ws_compute_accept(key, b64);
    return (strcmp(b64, accept) == 0) ? 0 : -1;
}

/* ---- 服务端握手 ---- */

/* token 比较 (RFC 7230 §3.2.6: HTTP token 大小写不敏感) */
static bool token_eq(const char *v, size_t len, const char *token) {
    size_t tl = strlen(token);
    if(len != tl)
        return false;
    for(size_t i = 0; i < tl; i++) {
        char a = v[i], b = token[i];
        if(a >= 'A' && a <= 'Z')
            a = (char)(a + 32);
        if(b >= 'A' && b <= 'Z')
            b = (char)(b + 32);
        if(a != b)
            return false;
    }
    return true;
}

/* token 列表包含: "Upgrade, keep-alive" 逗号分隔, 各项去 OWS (RFC 7230 §3.2.6) */
static bool token_list_has(const char *v, size_t len, const char *token) {
    const char *p = v, *end = v + len;
    while(p < end) {
        while(p < end && (*p == ' ' || *p == '\t'))
            p++; /* 跳前导空白 */
        const char *s = p;
        while(p < end && *p != ',')
            p++;
        const char *e = p;
        while(e > s && (e[-1] == ' ' || e[-1] == '\t'))
            e--; /* 去尾空白 */
        if(token_eq(s, (size_t)(e - s), token))
            return true;
        if(p < end)
            p++; /* 跳逗号 */
    }
    return false;
}

/* 扩展列表 token 检查 (Sec-WebSocket-Extensions): 逗号分隔的扩展/参数名,
 * 各 token 间允许 OWS; 与 client 侧 ws_extensions_ok 的 token 扫描同构 —
 * 子串匹配会误判 "xpermessage-deflate" 这类畸形 offer (响应未请求的扩展
 * 会让标准客户端 Fail the Connection, RFC 6455 §9). */
static bool ext_token_has(const char *v, size_t len, const char *token) {
    const char *p = v, *end = v + len;
    while(p < end) {
        while(p < end && (*p == ' ' || *p == '\t' || *p == ','))
            p++; /* 跳分隔空白/逗号 */
        const char *s = p;
        while(p < end && *p != ';' && *p != ',')
            p++;
        const char *e = p;
        while(e > s && (e[-1] == ' ' || e[-1] == '\t'))
            e--; /* 去尾空白 */
        if(token_eq(s, (size_t)(e - s), token))
            return true;
        if(p < end && *p == ';')
            p++; /* 跳过参数分隔符 (参数名也按 token 匹配, 循环继续) */
    }
    return false;
}

int ws_parse_request(const uint8_t *buf, size_t len, ws_handshake_request *req) {
    memset(req, 0, sizeof(*req));
    req->status = -1; /* 默认: 语法错 (HTTP 解析失败时返回) */
    /* 最小长度: "GET / HTTP/1.1\r\n" = 16 字节 */
    if(len < 16)
        return 0;

    /* 语法解析交给 sevent_http_parse (行/头/半包语义一致) */
    sevent_http_msg m;
    int             r = sevent_http_parse((const char *)buf, len, &m);
    if(r < 0)
        return -1;
    if(r == 0)
        return 0;
    if(m.is_response)
        return -1; /* 客户端发来响应行 — 协议错误 */
    size_t consumed = (size_t)(m.body - (const char *)buf) + m.body_len;

    /* RFC 6455 §4.1: 升级请求必须 GET */
    if(m.method != HTTP_METHOD_GET) {
        req->status = 400;
        return (int)consumed;
    }

    /* Upgrade: websocket (token 大小写不敏感) */
    size_t      vl;
    const char *v;
    if(!(v = sevent_http_find_header(&m, "upgrade", &vl)) || !token_eq(v, vl, "websocket")) {
        req->status = 400;
        return (int)consumed;
    }
    /* Connection 含 upgrade */
    if(!(v = sevent_http_find_header(&m, "connection", &vl)) || !token_list_has(v, vl, "upgrade")) {
        req->status = 400;
        return (int)consumed;
    }
    /* Sec-WebSocket-Key 必须恰好 24 字符 (RFC 6455 §4.2.1: 16 字节随机数的
     * base64; 长度不符按普通非法请求处理 — 宽松会通过 Autobahn 坏 key 用例) */
    if(!(v = sevent_http_find_header(&m, WS_HDR_KEY, &vl)) || vl != WS_KEY_BASE64_LEN - 1) {
        req->status = 400;
        return (int)consumed;
    }
    memcpy(req->key, v, vl);
    req->key[vl] = '\0';
    /* Sec-WebSocket-Version: 13 (RFC 6455 §4.4: 不支持的版本必须回 426) */
    if(!(v = sevent_http_find_header(&m, "sec-websocket-version", &vl)) || !token_eq(v, vl, "13")) {
        req->status = 426;
        return (int)consumed;
    }

    /* deflate offer (A 方案): 扩展含 permessage-deflate 即接受; nct 提取为
     * server 解压方向参数 (RFC 7692 §7.1.1.1 单方面承诺, 响应省略也生效).
     * token 级匹配 (ext_token_has) — 防子串误判畸形扩展名 */
    if((v = sevent_http_find_header(&m, WS_HDR_EXTENSIONS, &vl))) {
        req->deflate_offered = ext_token_has(v, vl, WS_EXT_PMD);
        if(req->deflate_offered)
            req->client_no_context_takeover = ext_token_has(v, vl, WS_EXT_CLIENT_NO_CTX);
    }

    req->status = 0;
    return (int)consumed;
}

int ws_build_response(char *buf, size_t cap, const char *key, bool enable_deflate) {
    char accept[WS_ACCEPT_BASE64_LEN];
    ws_compute_accept(key, accept);
    char   extra[256];
    size_t n = (size_t)snprintf(extra,
                                sizeof(extra),
                                "Upgrade: websocket\r\n"
                                "Connection: Upgrade\r\n"
                                "Sec-WebSocket-Accept: %s\r\n",
                                accept);
    if(n >= sizeof(extra))
        return -1;
#ifdef SEVENT_WS_DEFLATE
    if(enable_deflate) {
        int m = snprintf(extra + n, sizeof(extra) - n, "Sec-WebSocket-Extensions: " WS_EXT_PMD "\r\n");
        if(m < 0 || (size_t)m >= sizeof(extra) - n)
            return -1;
        n += (size_t)m;
    }
#endif
    return sevent_http_build_response(buf, cap, WS_HTTP_STATUS_SWITCHING, "Switching Protocols", extra);
}
