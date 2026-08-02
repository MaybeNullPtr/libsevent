/* fuzz_ws_handshake.c — ws_handshake 变异 fuzzer (零外部依赖: gcc + ASAN 可跑)
 *
 * 对象: ws_parse_request (服务端解析请求) / ws_parse_response (客户端解析
 *   响应, 含 headers-only 分支) / build→parse roundtrip 自洽.
 * 方式: 从种子集合 (合法/半合法握手样本) 做字节级变异 (同 fuzz_http_parse 模式).
 * 断言:
 *   - 永不崩溃 (ASAN 抓越界/UAF)
 *   - 解析成功 (r>0) 时结果自洽: consumed ≤ 输入长度、输出数组 NUL 结尾、
 *     status 枚举范围、status==0 时 key 恰好 24 字符
 *   - 确定性: 同一输入两次调用结果一致 (纯函数)
 *   - roundtrip: build_response → parse → verify_accept 匹配;
 *     build_request → parse_request → 可升级 (status==0)
 *   - 发现违反 → 打印输入 hex + 迭代号 → 退出 1 (可复现)
 *
 * 用法: ./fuzz-ws-handshake [iterations] [seed]   (默认 100 万次, seed 默认 1)
 */

#include "ws_handshake.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- 确定性 PRNG (xorshift64*, 与 fuzz_http_parse 同) ---- */
static uint64_t g_rng;

static uint64_t rng_next(void) {
    uint64_t x = g_rng;
    x          ^= x >> 12;
    x          ^= x << 25;
    x          ^= x >> 27;
    g_rng      = x;
    return x * 0x2545F4914F6CDD1DULL;
}

static uint32_t rng_below(uint32_t n) { return (uint32_t)(rng_next() % n); }

/* ---- 种子集合: 握手各路径的合法/半合法样本 (RFC 6455 §1.3 例子为基) ---- */
static const char *g_seeds[] = {
        /* 合法升级请求 (标准例子) */
        "GET /chat HTTP/1.1\r\nHost: server.example.com\r\nUpgrade: websocket\r\n"
        "Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n",
        /* deflate offer (无参数) */
        "GET /chat HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n"
        "Sec-WebSocket-Extensions: permessage-deflate\r\n\r\n",
        /* deflate offer (nct + max_window_bits 参数) */
        "GET /chat HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n"
        "Sec-WebSocket-Extensions: permessage-deflate; client_no_context_takeover; "
        "client_max_window_bits=10\r\n\r\n",
        /* 畸形扩展名 (token 级匹配回归: 不应误判为 offer) */
        "GET /chat HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n"
        "Sec-WebSocket-Extensions: xpermessage-deflatex\r\n\r\n",
        /* 小写/混合大小写头 */
        "get /chat http/1.1\r\nhost: a\r\nupgrade: WebSocket\r\nconnection: keep-alive, upgrade\r\n"
        "sec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\r\nsec-websocket-version: 13\r\n\r\n",
        /* 畸形: 各类拒绝路径 */
        "POST /chat HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
        "GET /chat HTTP/1.1\r\nHost: a\r\nUpgrade: h2c\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
        "GET /chat HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
        "GET /chat HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Key: abc\r\nSec-WebSocket-Version: 13\r\n\r\n",
        "GET /chat HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 12\r\n\r\n",
        "GET /chat HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
        /* 合法 101 响应 (标准例子) */
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
        /* 101 + deflate 确认 */
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
        "Sec-WebSocket-Extensions: permessage-deflate\r\n\r\n",
        /* 3xx 重定向 (headers-only 分支: CL body 不消费) */
        "HTTP/1.1 301 Moved Permanently\r\nLocation: ws://server.example.com/chat\r\n"
        "Content-Length: 9999\r\n\r\n",
        /* 200 OK (非 101) */
        "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc",
        /* 101 缺 accept (应拒绝) */
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n",
        /* 半包 */
        "HTTP/1.1 101 Switch",
        "GET /chat HTTP/1.1\r\nHost: a\r\nUp",
        /* 畸形 HTTP */
        "GARBAGE\r\n\r\n",
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\nGARBAGE",
        "",
};

static const int g_n_seeds = (int)(sizeof(g_seeds) / sizeof(g_seeds[0]));

/* ---- 变异: 对种子做 1..8 次随机操作 (同 fuzz_http_parse) ---- */
static void mutate(uint8_t *out, size_t *out_len) {
    static const uint8_t special[] = {'\0', '\r', '\n', ' ', ':', ';', ',', '\t', 0xFF, 0x80, '\''};
    const char          *seed      = g_seeds[rng_below((uint32_t)g_n_seeds)];
    size_t               len       = strlen(seed);
    size_t               ops       = 1 + rng_below(8);

    memcpy(out, seed, len);
    for(size_t k = 0; k < ops && len < 4096; k++) {
        switch(rng_below(6)) {
        case 0: /* 翻转单字节 */
            if(len > 0)
                out[rng_below((uint32_t)len)] ^= (uint8_t)(1u << rng_below(8));
            break;
        case 1: /* 截断 */
            len = rng_below((uint32_t)len + 1);
            break;
        case 2: /* 插入特殊字节 */
            out[len++] = (rng_below(3) == 0) ? special[rng_below(sizeof(special))] : (uint8_t)rng_below(256);
            break;
        case 3: /* 插入随机串 */
        {
            uint32_t n = 1 + rng_below(16);
            while(n-- > 0 && len < 4096)
                out[len++] = (uint8_t)rng_below(256);
        } break;
        case 4: /* 复制片段膨胀 */
            if(len > 0) {
                uint32_t from = rng_below((uint32_t)len);
                uint32_t n    = 1 + rng_below(64);
                while(n-- > 0 && len < 4096) {
                    out[len] = out[from];
                    len++;
                }
            }
            break;
        case 5: /* 整体随机覆盖 */
            len = rng_below(512);
            for(size_t i = 0; i < len; i++)
                out[i] = (uint8_t)rng_below(256);
            break;
        }
    }
    *out_len = len;
}

static void dump_hex(const uint8_t *buf, size_t len) {
    for(size_t i = 0; i < len; i++)
        printf("%02x ", buf[i]);
    printf("\n");
}

/* ---- 断言组 ---- */

/* 确定性: 纯函数 — 同一输入两次调用结果必须一致 */
static int check_deterministic_req(const uint8_t *buf, size_t len, uint64_t iter) {
    ws_handshake_request a, b;
    int                  ra = ws_parse_request(buf, len, &a);
    int                  rb = ws_parse_request(buf, len, &b);
    if(ra != rb || memcmp(&a, &b, sizeof(a)) != 0) {
        printf("iter %llu: ws_parse_request 非确定性 (r=%d/%d)\n", (unsigned long long)iter, ra, rb);
        dump_hex(buf, len);
        return -1;
    }
    return 0;
}

static int check_deterministic_resp(const uint8_t *buf, size_t len, uint64_t iter) {
    ws_handshake_response a, b;
    int                   ra = ws_parse_response(buf, len, &a);
    int                   rb = ws_parse_response(buf, len, &b);
    if(ra != rb || memcmp(&a, &b, sizeof(a)) != 0) {
        printf("iter %llu: ws_parse_response 非确定性 (r=%d/%d)\n", (unsigned long long)iter, ra, rb);
        dump_hex(buf, len);
        return -1;
    }
    return 0;
}

static int verify_req(const uint8_t *buf, size_t len, int r, const ws_handshake_request *req, uint64_t iter) {
    if(r > 0) {
        if((size_t)r > len) {
            printf("iter %llu: consumed 越界 (%d > %zu)\n", (unsigned long long)iter, r, len);
            return -1;
        }
        if(req->status != 0 && req->status != 400 && req->status != 426) {
            printf("iter %llu: status 枚举越界 (%d)\n", (unsigned long long)iter, req->status);
            return -1;
        }
        if(req->status == 0) {
            /* 可升级请求: key 必须恰好 24 字符且 NUL 结尾 */
            if(strlen(req->key) != WS_KEY_BASE64_LEN - 1) {
                printf("iter %llu: 可升级但 key 长度错 (%zu)\n", (unsigned long long)iter, strlen(req->key));
                return -1;
            }
        }
    } else if(r < 0 && req->status != -1) {
        printf("iter %llu: 语法错但 status=%d (应为 -1)\n", (unsigned long long)iter, req->status);
        return -1;
    }
    return 0;
}

static int verify_resp(const uint8_t *buf, size_t len, int r, const ws_handshake_response *resp, uint64_t iter) {
    if(r > 0) {
        if((size_t)r > len) {
            printf("iter %llu: consumed 越界 (%d > %zu)\n", (unsigned long long)iter, r, len);
            return -1;
        }
        if(resp->status_code < 0 || resp->status_code > 99999) {
            printf("iter %llu: status_code 越界 (%d)\n", (unsigned long long)iter, resp->status_code);
            return -1;
        }
        /* 提取缓冲 NUL 结尾保证 */
        if(resp->accept[WS_ACCEPT_BASE64_LEN - 1] != '\0' || resp->protocol[63] != '\0' ||
           resp->location[255] != '\0' || resp->extensions[255] != '\0') {
            printf("iter %llu: 提取缓冲未 NUL 结尾\n", (unsigned long long)iter);
            return -1;
        }
        if(resp->status_code == WS_HTTP_STATUS_SWITCHING && resp->accept[0] == '\0') {
            printf("iter %llu: 101 但 accept 为空 (解析应已拒绝)\n", (unsigned long long)iter);
            return -1;
        }
    }
    return 0;
}

/* roundtrip: build_response → parse → verify_accept */
static int roundtrip_response(uint64_t iter) {
    char key[WS_KEY_BASE64_LEN];
    ws_gen_key(key);
    char   buf[1024];
    int    r = ws_build_response(buf, sizeof(buf), key, true);
    if(r <= 0) {
        printf("iter %llu: build_response 失败 (r=%d)\n", (unsigned long long)iter, r);
        return -1;
    }
    ws_handshake_response resp;
    int rp = ws_parse_response((const uint8_t *)buf, (size_t)r, &resp);
    if(rp != r) {
        printf("iter %llu: roundtrip 解析长度不匹配 (%d != %d)\n", (unsigned long long)iter, rp, r);
        return -1;
    }
    if(resp.status_code != WS_HTTP_STATUS_SWITCHING || ws_verify_accept(key, resp.accept) != 0) {
        printf("iter %llu: roundtrip accept 校验失败\n", (unsigned long long)iter);
        return -1;
    }
    /* deflate=true 的响应必须确认 PMD (A 方案) */
    if(strlen(resp.extensions) == 0 || strstr(resp.extensions, WS_EXT_PMD) == NULL) {
        printf("iter %llu: roundtrip 缺 PMD 确认\n", (unsigned long long)iter);
        return -1;
    }
    /* 容量不足路径: 返回 <0 且不写 buf */
    uint8_t small[8] = {0};
    if(ws_build_response((char *)small, 1, key, false) >= 0) {
        printf("iter %llu: build_response cap=1 未拒绝\n", (unsigned long long)iter);
        return -1;
    }
    return 0;
}

/* roundtrip: build_request → parse_request → 可升级 */
static int roundtrip_request(uint64_t iter) {
    char key[WS_KEY_BASE64_LEN];
    ws_gen_key(key);
    char              buf[1024];
    ws_deflate_params pmd = {0};
    pmd.client_no_context_takeover = true;
    pmd.server_max_window_bits     = 10;
    int r = ws_build_request(buf, sizeof(buf), "server.example.com", 8080, "/chat", key, NULL, true, &pmd);
    if(r <= 0) {
        printf("iter %llu: build_request 失败 (r=%d)\n", (unsigned long long)iter, r);
        return -1;
    }
    ws_handshake_request req;
    int rp = ws_parse_request((const uint8_t *)buf, (size_t)r, &req);
    if(rp != r || req.status != 0) {
        printf("iter %llu: roundtrip 请求不可升级 (r=%d/%d, status=%d)\n",
               (unsigned long long)iter,
               rp,
               r,
               req.status);
        return -1;
    }
    if(strcmp(req.key, key) != 0) {
        printf("iter %llu: roundtrip key 不匹配\n", (unsigned long long)iter);
        return -1;
    }
    if(!req.deflate_offered || !req.client_no_context_takeover) {
        printf("iter %llu: roundtrip deflate offer 丢失\n", (unsigned long long)iter);
        return -1;
    }
    return 0;
}

int main(int argc, char **argv) {
    uint64_t iterations = (argc > 1) ? strtoull(argv[1], NULL, 10) : 1000000ULL;
    g_rng               = (argc > 2) ? strtoull(argv[2], NULL, 10) : 1ULL;

    printf("fuzz-ws-handshake: %llu iterations, seed %llu\n",
           (unsigned long long)iterations,
           (unsigned long long)g_rng);

    for(uint64_t iter = 0; iter < iterations; iter++) {
        uint8_t buf[4096];
        size_t  len;
        mutate(buf, &len);

        switch(rng_below(4)) {
        case 0: { /* 服务端解析请求 */
            ws_handshake_request req;
            int r = ws_parse_request(buf, len, &req);
            if(verify_req(buf, len, r, &req, iter) != 0)
                return 1;
            if(check_deterministic_req(buf, len, iter) != 0)
                return 1;
        } break;
        case 1: { /* 客户端解析响应 */
            ws_handshake_response resp;
            int r = ws_parse_response(buf, len, &resp);
            if(verify_resp(buf, len, r, &resp, iter) != 0)
                return 1;
            if(check_deterministic_resp(buf, len, iter) != 0)
                return 1;
        } break;
        case 2: /* build_response roundtrip */
            if(roundtrip_response(iter) != 0)
                return 1;
            break;
        case 3: /* build_request roundtrip */
            if(roundtrip_request(iter) != 0)
                return 1;
            break;
        }
    }
    printf("done: no crash, no inconsistency\n");
    return 0;
}
