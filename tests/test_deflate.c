/**
 *  test_deflate.c — permessage-deflate 单元测试
 *
 *  不依赖事件循环, 只测试 ws_deflate 压缩/解压正确性.
 *  SEVENT_WS_DEFLATE=ON 时才编译有效代码, OFF 时仅验证桩函数.
 *  ================================================================ */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../src/websockets/ws_deflate.h"

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

        /* 小消息压缩后不可能膨胀到超过原文+16 */
        if(in_len > 0 && comp_len > in_len + 16) {
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

        size_t decomp_len = decomp_cap;
        if(!ws_deflate_decompress(df, comp, comp_len, decomp, &decomp_len)) {
            FAIL("decompress");
            free(decomp);
            free(comp);
            ws_deflate_destroy(df);
            continue;
        }

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

    size_t decomp_len = decomp_cap;
    if(!ws_deflate_decompress(df, comp, comp_len, decomp, &decomp_len)) {
        FAIL("decompress");
        free(decomp);
        free(comp);
        ws_deflate_destroy(df);
        return;
    }

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

    TEST("decompress with NULL df");
#ifdef SEVENT_WS_DEFLATE
    if(ws_deflate_decompress(NULL, (const uint8_t *)"x", 1, (uint8_t *)&dummy, &dummy)) {
        FAIL("should return false");
        return;
    }
#else
    if(ws_deflate_decompress(NULL, (const uint8_t *)"x", 1, (uint8_t *)&dummy, &dummy)) {
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
    size_t  dl = sizeof(dec);
    if(!ws_deflate_decompress(df, comp, cl, dec, &dl)) {
        FAIL("decompress");
        free(comp);
        ws_deflate_destroy(df);
        return;
    }
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
        size_t  dl2 = sizeof(dec2);
        if(!ws_deflate_decompress(df, comp, cl2, dec2, &dl2)) {
            FAIL("decompress (2nd)");
            free(comp);
            ws_deflate_destroy(df);
            return;
        }
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
 *  main
 * ==================================================================== */
int main(void) {
    setbuf(stdout, NULL);
    printf("test_deflate ...\n");

    test_roundtrip();
    test_compressible();
    test_errors();
    test_params();

    int ok = (g_pass == g_total);
    printf("%s: %d/%d passed\n", ok ? "PASS" : "FAIL", g_pass, g_total);
    return ok ? 0 : 1;
}
