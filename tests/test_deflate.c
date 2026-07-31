/**
 *  test_deflate.c — permessage-deflate 单元测试
 *
 *  不依赖事件循环, 只测试 ws_deflate 压缩/解压正确性.
 *  SEVENT_WS_DEFLATE=ON 时才编译有效代码, OFF 时仅验证桩函数.
 *
 *  解压侧说明: ws_deflate 不再提供解压封装 (解压在协议层 ws_conn.c
 *  直接操作 df->inflate, 见 doc/deflate-decompress-fix.md).
 *  本测试用 test_decompress() 复现协议层的分批循环, 仅用于验证
 *  压缩侧正确性 (压缩 → 解压 → 比对原文).
 *  ================================================================ */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../src/websockets/ws_deflate.h"

#ifdef SEVENT_WS_DEFLATE
#include <zlib.h>
#endif

static int g_pass;
static int g_total;

#define TEST(name)                                                                                                     \
    do {                                                                                                               \
        g_total++;                                                                                                     \
        printf("  %s ... ", name);                                                                                     \
        fflush(stdout);                                                                                                \
    } while(0)

#define PASS()                                                                                                         \
    do {                                                                                                               \
        printf("PASS\n");                                                                                              \
        g_pass++;                                                                                                      \
    } while(0)

#define FAIL(msg)                                                                                                      \
    do {                                                                                                               \
        printf("FAIL: %s\n", msg);                                                                                     \
    } while(0)

/* ====================================================================
 *  解压 helper: 复现协议层的分批循环 (Z_SYNC_FLUSH + 拼 tail)
 *  返回解压长度; 0 表示错误或输出不足.
 * ==================================================================== */
#ifdef SEVENT_WS_DEFLATE
static size_t test_decompress(ws_deflate *df, const uint8_t *in, size_t in_len,
                              uint8_t *out, size_t out_cap) {
    uint8_t *buf = (uint8_t *)malloc(in_len + 4);
    if(!buf)
        return 0;
    memcpy(buf, in, in_len);
    buf[in_len]     = 0x00;
    buf[in_len + 1] = 0x00;
    buf[in_len + 2] = 0xFF;
    buf[in_len + 3] = 0xFF;

    z_stream *z = &df->inflate;
    z->next_in  = buf;
    z->avail_in = (uInt)(in_len + 4);

    size_t used = 0;
    for(;;) {
        if(used >= out_cap) {
            free(buf);
            return 0; /* 输出不足 */
        }
        z->next_out  = out + used;
        z->avail_out = (uInt)(out_cap - used);
        int rc = inflate(z, Z_SYNC_FLUSH);
        if(rc != Z_OK && rc != Z_STREAM_END && rc != Z_BUF_ERROR) {
            inflateReset(z);
            free(buf);
            return 0;
        }
        used = out_cap - z->avail_out;
        if(z->avail_out > 0)
            break; /* 到达 sync 点 */
    }
    free(buf);
    if(df->server_no_context_takeover)
        inflateReset(z);
    return used;
}
#endif

/* ====================================================================
 *  测试: 压缩 → 解压, 验证原文一致
 * ==================================================================== */
static void test_roundtrip(void) {
    const char *texts[] = {
            "",
            "Hello",
            "Hello World! Hello World! Hello World! Hello World!",
            "{\"json\": true, \"numbers\": [1,2,3,4,5], \"nested\": {\"a\":1}}",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    };
    size_t n = sizeof(texts) / sizeof(texts[0]);

    for(size_t i = 0; i < n; i++) {
        char label[64];
        snprintf(label, sizeof(label), "roundtrip [%zu] len=%zu", i, strlen(texts[i]));

#ifdef SEVENT_WS_DEFLATE
        TEST(label);
        ws_deflate *df = NULL;
        int         rc = ws_deflate_create(&df, NULL);
        if(!rc || !df) {
            FAIL("create");
            continue;
        }

        size_t in_len  = strlen(texts[i]);
        size_t out_max = ws_deflate_compress_maxlen(df, in_len);
        if(out_max == 0) {
            FAIL("compress_maxlen=0");
            ws_deflate_destroy(df);
            continue;
        }

        uint8_t *comp = (uint8_t *)malloc(out_max);
        if(!comp) {
            FAIL("malloc");
            ws_deflate_destroy(df);
            continue;
        }

        size_t comp_len = out_max;
        if(!ws_deflate_compress(df, (const uint8_t *)texts[i], in_len, comp, &comp_len)) {
            FAIL("compress");
            free(comp);
            ws_deflate_destroy(df);
            continue;
        }

        /* 小消息压缩后不应过度膨胀 */
        if(comp_len > (in_len > 0 ? in_len + 16 : 32)) {
            FAIL("compression expanded");
            free(comp);
            ws_deflate_destroy(df);
            continue;
        }

        size_t   decomp_cap = in_len + 64;
        uint8_t *decomp     = (uint8_t *)malloc(decomp_cap ? decomp_cap : 1);
        if(!decomp) {
            FAIL("malloc decomp");
            free(comp);
            ws_deflate_destroy(df);
            continue;
        }

        size_t decomp_len = test_decompress(df, comp, comp_len, decomp, decomp_cap);
        if(decomp_len != in_len || memcmp(decomp, texts[i], in_len) != 0) {
            FAIL("mismatch");
            free(decomp);
            free(comp);
            ws_deflate_destroy(df);
            continue;
        }

        PASS();
        free(decomp);
        free(comp);
        ws_deflate_destroy(df);
#else
        TEST(label);
        ws_deflate *df = NULL;
        if(ws_deflate_create(&df, NULL)) {
            FAIL("stub create should fail");
            continue;
        }
        if(df) {
            FAIL("stub create should set *out=NULL");
            continue;
        }
        ws_deflate_destroy(df);
        PASS();
#endif
    }
}

/* ====================================================================
 *  测试: 1024 字节重复数据 (压缩率高的场景)
 * ==================================================================== */
static void test_compressible(void) {
#ifdef SEVENT_WS_DEFLATE
    TEST("compressible 1KB data");
    ws_deflate *df = NULL;
    if(!ws_deflate_create(&df, NULL)) {
        FAIL("create");
        return;
    }

    char buf[1024];
    memset(buf, 'A', sizeof(buf));

    size_t out_max = ws_deflate_compress_maxlen(df, sizeof(buf));
    if(out_max == 0) {
        FAIL("compress_maxlen=0");
        ws_deflate_destroy(df);
        return;
    }

    uint8_t *comp = (uint8_t *)malloc(out_max);
    if(!comp) {
        FAIL("malloc");
        ws_deflate_destroy(df);
        return;
    }

    size_t comp_len = out_max;
    if(!ws_deflate_compress(df, (const uint8_t *)buf, sizeof(buf), comp, &comp_len)) {
        FAIL("compress");
        free(comp);
        ws_deflate_destroy(df);
        return;
    }

    if(comp_len >= sizeof(buf)) {
        FAIL("compressible data expanded");
        free(comp);
        ws_deflate_destroy(df);
        return;
    }

    size_t   decomp_cap = sizeof(buf) + 64;
    uint8_t *decomp     = (uint8_t *)malloc(decomp_cap);
    if(!decomp) {
        FAIL("malloc decomp");
        free(comp);
        ws_deflate_destroy(df);
        return;
    }

    size_t decomp_len = test_decompress(df, comp, comp_len, decomp, decomp_cap);
    if(decomp_len != sizeof(buf) || memcmp(decomp, buf, sizeof(buf)) != 0) {
        FAIL("mismatch");
        free(decomp);
        free(comp);
        ws_deflate_destroy(df);
        return;
    }

    PASS();
    free(decomp);
    free(comp);
    ws_deflate_destroy(df);
#else
    TEST("compressible 1KB data (stub)");
    PASS();
#endif
}

/* ====================================================================
 *  测试: NULL/异常参数
 * ==================================================================== */
static void test_errors(void) {
    TEST("NULL out pointer");
#ifdef SEVENT_WS_DEFLATE
    if(ws_deflate_create(NULL, NULL)) {
        FAIL("should return false");
        return;
    }
#else
    if(ws_deflate_create(NULL, NULL)) {
        FAIL("stub should return false");
        return;
    }
#endif
    PASS();

    TEST("compress with NULL df");
    size_t dummy = 64;
#ifdef SEVENT_WS_DEFLATE
    if(ws_deflate_compress(NULL, (const uint8_t *)"x", 1, (uint8_t *)&dummy, &dummy)) {
        FAIL("should return false");
        return;
    }
#else
    if(ws_deflate_compress(NULL, (const uint8_t *)"x", 1, (uint8_t *)&dummy, &dummy)) {
        FAIL("stub should return false");
        return;
    }
#endif
    PASS();
}

/* ====================================================================
 *  测试: 带参数的创建 (no_context_takeover)
 * ==================================================================== */
static void test_params(void) {
#ifdef SEVENT_WS_DEFLATE
    TEST("params: client_no_context_takeover");
    ws_deflate_params p  = {.client_no_context_takeover = true};
    ws_deflate       *df = NULL;
    if(!ws_deflate_create(&df, &p)) {
        FAIL("create");
        return;
    }
    char buf[64];
    memset(buf, 'B', sizeof(buf));
    size_t out_max = ws_deflate_compress_maxlen(df, sizeof(buf));
    if(out_max == 0) {
        FAIL("compress_maxlen=0");
        ws_deflate_destroy(df);
        return;
    }
    uint8_t *comp = (uint8_t *)malloc(out_max);
    size_t   cl   = out_max;
    if(!ws_deflate_compress(df, (const uint8_t *)buf, sizeof(buf), comp, &cl)) {
        FAIL("compress");
        free(comp);
        ws_deflate_destroy(df);
        return;
    }
    uint8_t dec[128];
    size_t  dl = test_decompress(df, comp, cl, dec, sizeof(dec));
    if(dl != sizeof(buf) || memcmp(dec, buf, sizeof(buf)) != 0) {
        FAIL("mismatch");
        free(comp);
        ws_deflate_destroy(df);
        return;
    }

    /* 第二轮: 不同数据, 验证 no_context_takeover 重置有效 */
    {
        char buf2[32];
        memset(buf2, 'C', sizeof(buf2));
        size_t om2 = ws_deflate_compress_maxlen(df, sizeof(buf2));
        if(om2 == 0) {
            FAIL("compress_maxlen=0 (2nd)");
            free(comp);
            ws_deflate_destroy(df);
            return;
        }
        uint8_t *c2 = (uint8_t *)realloc(comp, om2);
        if(!c2) {
            FAIL("realloc (2nd)");
            free(comp);
            ws_deflate_destroy(df);
            return;
        }
        comp     = c2;
        size_t cl2 = om2;
        if(!ws_deflate_compress(df, (const uint8_t *)buf2, sizeof(buf2), comp, &cl2)) {
            FAIL("compress (2nd)");
            free(comp);
            ws_deflate_destroy(df);
            return;
        }
        uint8_t dec2[64];
        size_t  dl2 = test_decompress(df, comp, cl2, dec2, sizeof(dec2));
        if(dl2 != sizeof(buf2) || memcmp(dec2, buf2, sizeof(buf2)) != 0) {
            FAIL("mismatch (2nd)");
            free(comp);
            ws_deflate_destroy(df);
            return;
        }
    }

    PASS();
    free(comp);
    ws_deflate_destroy(df);
#else
    TEST("params (stub)");
    PASS();
#endif
}

/* ====================================================================
 *  测试: 流式压缩
 * ==================================================================== */

/* 将 (in,in_len) 分 nchunks 段, 每段依次压缩 → 合著 total_comp。返回 comp 长度。 */
static size_t stream_compress(ws_deflate *df, const uint8_t *in, size_t in_len,
                               uint8_t *comp, size_t comp_cap, int nchunks) {
    size_t chunk = in_len / (size_t)nchunks;
    size_t pos   = 0;
    size_t total = 0;

    while(pos < in_len) {
        size_t sz = (pos + chunk < in_len) ? chunk : (in_len - pos);
        size_t out_sz = comp_cap - total;
        if(out_sz == 0)
            return 0;
        if(!ws_deflate_compress_stream(df, in + pos, sz, comp + total, &out_sz))
            return 0;
        total += out_sz;
        pos   += sz;
    }

    size_t end_sz = comp_cap - total;
    if(end_sz == 0)
        return 0;
    if(!ws_deflate_compress_end(df, comp + total, &end_sz))
        return 0;
    total += end_sz;
    return total;
}

static void test_stream_roundtrip(void) {
#ifdef SEVENT_WS_DEFLATE
    TEST("stream roundtrip 8KB x4 chunks");
    ws_deflate *df = NULL;
    if(!ws_deflate_create(&df, NULL)) {
        FAIL("create");
        return;
    }

    char src[8192];
    /* 用可预测但非完全重复的数据填充 */
    for(size_t i = 0; i < sizeof(src); i++)
        src[i] = (uint8_t)(i * 73 + 17);

    size_t cmax = ws_deflate_compress_maxlen(df, sizeof(src));
    uint8_t *comp = (uint8_t *)malloc(cmax);
    if(!comp) { FAIL("malloc"); ws_deflate_destroy(df); return; }

    size_t cl = stream_compress(df, (const uint8_t *)src, sizeof(src), comp, cmax, 4);
    if(cl == 0) { FAIL("stream_compress"); free(comp); ws_deflate_destroy(df); return; }

    uint8_t *dec = (uint8_t *)malloc(sizeof(src) + 64);
    if(!dec) { FAIL("malloc dec"); free(comp); ws_deflate_destroy(df); return; }

    size_t dl = test_decompress(df, comp, cl, dec, sizeof(src) + 64);
    if(dl != sizeof(src) || memcmp(dec, src, sizeof(src)) != 0) {
        FAIL("mismatch");
    } else {
        PASS();
    }

    free(dec);
    free(comp);
    ws_deflate_destroy(df);
#else
    TEST("stream roundtrip (stub)");
    PASS();
#endif
}

static void test_stream_chunked(void) {
#ifdef SEVENT_WS_DEFLATE
    TEST("stream byte-by-byte");
    ws_deflate *df = NULL;
    if(!ws_deflate_create(&df, NULL)) {
        FAIL("create");
        return;
    }

    const char *msg = "Streaming deflate test message!";
    size_t      len = strlen(msg);

    /* 逐字节压缩 */
    size_t cmax = ws_deflate_compress_maxlen(df, len);
    uint8_t *comp = (uint8_t *)malloc(cmax);
    if(!comp) { FAIL("malloc"); ws_deflate_destroy(df); return; }

    ws_deflate_compress_reset(df);
    size_t cpos = 0;
    for(size_t i = 0; i < len; i++) {
        size_t sz = cmax - cpos;
        if(sz == 0) { FAIL("comp full"); free(comp); ws_deflate_destroy(df); return; }
        if(!ws_deflate_compress_stream(df, (const uint8_t *)(msg + i), 1, comp + cpos, &sz))
            { FAIL("compress_stream"); free(comp); ws_deflate_destroy(df); return; }
        cpos += sz;
    }
    size_t esz = cmax - cpos;
    if(esz == 0 || !ws_deflate_compress_end(df, comp + cpos, &esz))
        { FAIL("compress_end"); free(comp); ws_deflate_destroy(df); return; }
    cpos += esz;

    /* 解压验证 */
    uint8_t dec[256];
    size_t  dl = test_decompress(df, comp, cpos, dec, sizeof(dec));
    if(dl != len || memcmp(dec, msg, len) != 0) {
        FAIL("mismatch");
    } else {
        PASS();
    }

    free(comp);
    ws_deflate_destroy(df);
#else
    TEST("stream byte-by-byte (stub)");
    PASS();
#endif
}

static void test_stream_compression(void) {
#ifdef SEVENT_WS_DEFLATE
    TEST("stream compressible 1KB");
    ws_deflate *df = NULL;
    if(!ws_deflate_create(&df, NULL)) {
        FAIL("create");
        return;
    }

    char buf[1024];
    memset(buf, 'A', sizeof(buf));

    size_t cmax = ws_deflate_compress_maxlen(df, sizeof(buf));
    uint8_t *comp = (uint8_t *)malloc(cmax);
    if(!comp) { FAIL("malloc"); ws_deflate_destroy(df); return; }

    size_t cl = stream_compress(df, (const uint8_t *)buf, sizeof(buf), comp, cmax, 4);
    if(cl == 0 || cl >= sizeof(buf)) {
        FAIL("no compression");
        free(comp);
        ws_deflate_destroy(df);
        return;
    }

    uint8_t dec[1024 + 64];
    size_t  dl = test_decompress(df, comp, cl, dec, sizeof(dec));
    if(dl != sizeof(buf) || memcmp(dec, buf, sizeof(buf)) != 0) {
        FAIL("mismatch");
    } else {
        PASS();
    }
    free(comp);
    ws_deflate_destroy(df);
#else
    TEST("stream compressible 1KB (stub)");
    PASS();
#endif
}

static void test_stream_params(void) {
#ifdef SEVENT_WS_DEFLATE
    TEST("stream params: client_no_context_takeover");
    ws_deflate_params p  = {.client_no_context_takeover = true};
    ws_deflate       *df = NULL;
    if(!ws_deflate_create(&df, &p)) {
        FAIL("create");
        return;
    }

    char buf[64];
    memset(buf, 'B', sizeof(buf));

    size_t cmax = ws_deflate_compress_maxlen(df, sizeof(buf));
    uint8_t *comp = (uint8_t *)malloc(cmax);
    if(!comp) { FAIL("malloc"); ws_deflate_destroy(df); return; }

    size_t cl = stream_compress(df, (const uint8_t *)buf, sizeof(buf), comp, cmax, 2);
    if(cl == 0) { FAIL("compress"); free(comp); ws_deflate_destroy(df); return; }

    uint8_t dec[128];
    size_t  dl = test_decompress(df, comp, cl, dec, sizeof(dec));
    if(dl != sizeof(buf) || memcmp(dec, buf, sizeof(buf)) != 0) {
        FAIL("mismatch");
        free(comp);
        ws_deflate_destroy(df);
        return;
    }

    /* 第二轮: 不同数据，验证 reset 有效 */
    char buf2[32];
    memset(buf2, 'C', sizeof(buf2));
    ws_deflate_compress_reset(df);
    inflateReset(&df->inflate);

    cl = stream_compress(df, (const uint8_t *)buf2, sizeof(buf2), comp, cmax, 2);
    if(cl == 0) { FAIL("compress (2nd)"); free(comp); ws_deflate_destroy(df); return; }

    dl = test_decompress(df, comp, cl, dec, sizeof(dec));
    if(dl != sizeof(buf2) || memcmp(dec, buf2, sizeof(buf2)) != 0) {
        FAIL("mismatch (2nd)");
    } else {
        PASS();
    }

    free(comp);
    ws_deflate_destroy(df);
#else
    TEST("stream params (stub)");
    PASS();
#endif
}

/* ====================================================================
 *  main
 * ==================================================================== */
int main(void) {
    setbuf(stdout, NULL);
    printf("test_deflate ...\n");

    test_roundtrip();
    test_compressible();
    test_errors();
    test_params();
    test_stream_roundtrip();
    test_stream_chunked();
    test_stream_compression();
    test_stream_params();

    int ok = (g_pass == g_total);
    printf("%s: %d/%d passed\n", ok ? "PASS" : "FAIL", g_pass, g_total);
    return ok ? 0 : 1;
}
