/* fuzz_http_parse.c — HTTP 语法层变异 fuzzer (零外部依赖: gcc + ASAN 可跑)
 *
 * 方式: 从种子集合 (合法/半合法 HTTP 请求/响应样本) 出发做字节级变异
 *   (翻转/截断/插入随机字节含 \0 \r \n/复制片段膨胀/整体随机), 喂给 sevent_http_parse.
 * 断言:
 *   - 永不崩溃 (ASAN 抓越界/UAF; 纯线性扫描无死循环风险)
 *   - 解析成功 (r>0) 时结果自洽: body/headers 指针在输入范围内,
 *     body_len == content_length, consumed ≤ 输入长度
 *   - 发现违反 → 打印输入 hex + 种子/迭代号 → 退出 1 (可复现)
 *
 * 用法: ./fuzz-http-parse [iterations] [seed]   (默认 100 万次, seed 默认 1)
 * 说明: 确定性 PRNG — 同参数同序列, 失败可复现.
 */

#include "sevent_http_parse.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- 确定性 PRNG (xorshift64*, 零依赖) ---- */
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

/* ---- 种子集合: 解析器各路径的合法/半合法样本 ---- */
static const char *g_seeds[] = {
        /* 合法请求 */
        "GET / HTTP/1.1\r\nHost: a\r\n\r\n",
        "POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\nhello",
        "GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: a\r\nConnection: keep-alive\r\n\r\n",
        "GET / HTTP/1.0\r\n\r\n",
        "HEAD / HTTP/1.1\r\nHost: a\r\n\r\n",
        /* 升级请求 (upgrade 预解析路径) */
        "GET /chat HTTP/1.1\r\nHost: a\r\nConnection: upgrade\r\nUpgrade: websocket\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
        /* 响应 (is_response 路径) */
        "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc",
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
        /* 畸形: 应被拒 (<0) */
        "GARBAGE\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: a\r\nContent-Length: 99999999999999999999\r\n\r\n",
        "GET /\r\n\r\n",
        "GET  HTTP/1.1\r\n\r\n",
        "\r\n\r\n",
        /* 边界: 无任何头行的请求 (首行后直接空行) */
        "GET / HTTP/1.1\r\n\r\n",
        /* 控制字符/空字节 */
        "GET / HTTP/1.1\r\nHost: a\r\nX-Bad: \x01\x02\x7f\r\n\r\n",
        "",
};

static const int g_n_seeds = (int)(sizeof(g_seeds) / sizeof(g_seeds[0]));

/* ---- 变异: 对种子做 1..8 次随机操作 ---- */
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
        case 1: /* 截断到随机长度 */
            len = rng_below((uint32_t)len + 1);
            break;
        case 2: /* 插入随机字节 (含特殊字符) */
            out[len++] = (rng_below(3) == 0) ? special[rng_below(sizeof(special))] : (uint8_t)rng_below(256);
            break;
        case 3: /* 插入一段随机字节串 */
        {
            uint32_t n = 1 + rng_below(16);
            while(n-- > 0 && len < 4096)
                out[len++] = (uint8_t)rng_below(256);
        } break;
        case 4: /* 复制片段 (膨胀长度, 超长行路径) */
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

/* ---- 解析结果自洽性校验 (r>0 时) ---- */
static int verify_ok(const char *buf, size_t len, const sevent_http_msg *m, uint64_t iter) {
    /* 引用字段 (method_ref/target/body/headers) 必须在输入范围内 */
    if(m->method < HTTP_METHOD_UNKNOWN || m->method > HTTP_METHOD_TRACE) {
        printf("iter %llu: method 枚举越界 (%d)\n", (unsigned long long)iter, m->method);
        return -1;
    }
    if(m->method_ref && (m->method_ref < buf || m->method_ref > buf + len)) {
        printf("iter %llu: method_ref 指针越界\n", (unsigned long long)iter);
        return -1;
    }
    if(m->method_ref && m->method_len > len - (size_t)(m->method_ref - buf)) {
        printf("iter %llu: method_len 越界 (%zu)\n", (unsigned long long)iter, m->method_len);
        return -1;
    }
    if(m->target && (m->target < buf || m->target > buf + len)) {
        printf("iter %llu: target 指针越界\n", (unsigned long long)iter);
        return -1;
    }
    if(m->target && m->target_len > len - (size_t)(m->target - buf)) {
        printf("iter %llu: target_len 越界 (%zu)\n", (unsigned long long)iter, m->target_len);
        return -1;
    }
    /* 请求 (is_response=0) 时 method_ref/target 必须有效; 响应时可为 NULL */
    if(!m->is_response && (!m->method_ref || !m->target)) {
        printf("iter %llu: 请求缺 method_ref/target\n", (unsigned long long)iter);
        return -1;
    }
    if(m->body && (m->body < buf || m->body > buf + len)) {
        printf("iter %llu: body 指针越界 (body-%p buf+len-%p)\n",
               (unsigned long long)iter,
               (const void *)m->body,
               (const void *)(buf + len));
        return -1;
    }
    if(m->body_len > len - (size_t)(m->body - buf)) {
        printf("iter %llu: body_len 越界 (%zu > %zu)\n",
               (unsigned long long)iter,
               m->body_len,
               len - (size_t)(m->body - buf));
        return -1;
    }
    if(m->body_len != m->content_length) {
        printf("iter %llu: body_len != content_length (%zu != %zu)\n",
               (unsigned long long)iter,
               m->body_len,
               m->content_length);
        return -1;
    }
    if(m->headers_start && (m->headers_start < buf || m->headers_start > buf + len)) {
        printf("iter %llu: headers_start 越界\n", (unsigned long long)iter);
        return -1;
    }
    if(m->headers_len > len - (size_t)(m->headers_start - buf)) {
        printf("iter %llu: headers_len 越界 (%zu)\n", (unsigned long long)iter, m->headers_len);
        return -1;
    }
    /* consumed = body 起点 - buf + body_len ≤ len (http_server 的分帧消费公式) */
    size_t consumed = (size_t)(m->body - buf) + m->body_len;
    if(consumed > len) {
        printf("iter %llu: consumed 越界 (%zu > %zu)\n", (unsigned long long)iter, consumed, len);
        return -1;
    }
    return 0;
}

static void dump_hex(const char *buf, size_t len) {
    for(size_t i = 0; i < len; i++)
        printf("%02x ", buf[i]);
    printf("\n");
}

int main(int argc, char **argv) {
    uint64_t iterations = (argc > 1) ? strtoull(argv[1], NULL, 10) : 1000000ULL;
    g_rng               = (argc > 2) ? strtoull(argv[2], NULL, 10) : 1ULL;

    printf("fuzz-http-parse: %llu iterations, seed %llu\n", (unsigned long long)iterations, (unsigned long long)g_rng);

    for(uint64_t iter = 0; iter < iterations; iter++) {
        uint8_t buf[4096];
        size_t  len;
        mutate(buf, &len);

        sevent_http_msg m;
        int             r = sevent_http_parse((const char *)buf, len, &m);
        if(r > 0 && verify_ok((const char *)buf, len, &m, iter) != 0) {
            printf("FAIL: 解析成功但结果不自洽 (iter %llu, r=%d)\n", (unsigned long long)iter, r);
            dump_hex((const char *)buf, len);
            return 1;
        }
        /* r < 0 (拒绝) 与 r == 0 (等更多) 均合法 — 无额外断言 */
    }
    printf("done: no crash, no inconsistency\n");
    return 0;
}
