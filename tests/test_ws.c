/* =========================================================================
 *  test_ws.c — WebSocket 模块单元测试
 *
 *  编译: see CMakeLists.txt, 或手动:
 *    gcc -Wall -Werror -std=c99 -Iinclude -o test_ws \
 *        tests/test_ws.c src/websockets/ws_sha1.c src/websockets/ws_base64.c
 * ========================================================================= */

#include "sevent.h"
#include "../src/websockets/ws_sha1.h"
#include "../src/websockets/ws_base64.h"
#include "../src/websockets/ws_frame.h"
#include "../src/websockets/ws_handshake.h"
#include "../src/websockets/ws_conn.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* ==================== 简易测试框架 ==================== */

struct test_entry {
    const char *label;
    void (*fn)(void);
    struct test_entry *next;
};

static int fail_count;

#define TEST(t) static void test_##t(void)

#define ASSERT(cond)                                                                                                   \
    do {                                                                                                               \
        if(!(cond)) {                                                                                                  \
            fprintf(stderr, "      [FAIL] %s:%d: %s\n", __FILE__, __LINE__, #cond);                                    \
            fail_count++;                                                                                              \
        }                                                                                                              \
    } while(0)

#define ASSERT_EQ(a, b)                                                                                                \
    do {                                                                                                               \
        long _a = (long)(a);                                                                                           \
        long _b = (long)(b);                                                                                           \
        if(_a != _b) {                                                                                                 \
            fprintf(stderr,                                                                                            \
                    "      [FAIL] %s:%d: \n"                                                                           \
                    "        left:  %ld  (%s)\n"                                                                       \
                    "        right: %ld  (%s)\n",                                                                      \
                    __FILE__,                                                                                          \
                    __LINE__,                                                                                          \
                    _a,                                                                                                \
                    #a,                                                                                                \
                    _b,                                                                                                \
                    #b);                                                                                               \
            fail_count++;                                                                                              \
        }                                                                                                              \
    } while(0)

#define ASSERT_GT(a, b)                                                                                                \
    do {                                                                                                               \
        long _a = (long)(a);                                                                                           \
        long _b = (long)(b);                                                                                           \
        if(!(_a > _b)) {                                                                                               \
            fprintf(stderr,                                                                                            \
                    "      [FAIL] %s:%d: \n"                                                                           \
                    "        left:  %ld  (%s)\n"                                                                       \
                    "        right: %ld  (%s)\n"                                                                       \
                    "        expected: %ld > %ld\n",                                                                   \
                    __FILE__,                                                                                          \
                    __LINE__,                                                                                          \
                    _a,                                                                                                \
                    #a,                                                                                                \
                    _b,                                                                                                \
                    #b,                                                                                                \
                    _a,                                                                                                \
                    _b);                                                                                               \
            fail_count++;                                                                                              \
        }                                                                                                              \
    } while(0)

#define ASSERT_LT(a, b)                                                                                                \
    do {                                                                                                               \
        long _a = (long)(a);                                                                                           \
        long _b = (long)(b);                                                                                           \
        if(!(_a < _b)) {                                                                                               \
            fprintf(stderr,                                                                                            \
                    "      [FAIL] %s:%d: \n"                                                                           \
                    "        left:  %ld  (%s)\n"                                                                       \
                    "        right: %ld  (%s)\n"                                                                       \
                    "        expected: %ld < %ld\n",                                                                   \
                    __FILE__,                                                                                          \
                    __LINE__,                                                                                          \
                    _a,                                                                                                \
                    #a,                                                                                                \
                    _b,                                                                                                \
                    #b,                                                                                                \
                    _a,                                                                                                \
                    _b);                                                                                               \
            fail_count++;                                                                                              \
        }                                                                                                              \
    } while(0)

/* 十六进制转储比较辅助 */
static int hex_cmp(const uint8_t *got, const char *expected_hex) {
    size_t hex_len = strlen(expected_hex);
    if(hex_len != WS_SHA1_DIGEST_SIZE * 2)
        return -1;
    for(size_t i = 0; i < WS_SHA1_DIGEST_SIZE; i++) {
        char    hi = expected_hex[i * 2];
        char    lo = expected_hex[i * 2 + 1];
        uint8_t b  = 0;
        if(hi >= '0' && hi <= '9')
            b = (hi - '0') << 4;
        else if(hi >= 'A' && hi <= 'F')
            b = (hi - 'A' + 10) << 4;
        else if(hi >= 'a' && hi <= 'f')
            b = (hi - 'a' + 10) << 4;
        if(lo >= '0' && lo <= '9')
            b |= (lo - '0');
        else if(lo >= 'A' && lo <= 'F')
            b |= (lo - 'A' + 10);
        else if(lo >= 'a' && lo <= 'f')
            b |= (lo - 'a' + 10);
        if(got[i] != b)
            return -1;
    }
    return 0;
}

/* ====================================================================
 *  SHA-1 测试
 * ==================================================================== */

TEST(sha1_empty) {
    uint8_t d[WS_SHA1_DIGEST_SIZE];
    ws_sha1("", 0, d);
    ASSERT_EQ(0, hex_cmp(d, "da39a3ee5e6b4b0d3255bfef95601890afd80709"));
}

TEST(sha1_abc) {
    uint8_t d[WS_SHA1_DIGEST_SIZE];
    ws_sha1("abc", 3, d);
    ASSERT_EQ(0, hex_cmp(d, "a9993e364706816aba3e25717850c26c9cd0d89d"));
}

TEST(sha1_len_448) {
    /* "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" */
    const char *msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    uint8_t     d[WS_SHA1_DIGEST_SIZE];
    ws_sha1(msg, strlen(msg), d);
    ASSERT_EQ(0, hex_cmp(d, "84983e441c3bd26ebaae4aa1f95129e5e54670f1"));
}

TEST(sha1_streaming) {
    /* 分两次 update, 验证中间状态正确 */
    ws_sha1_ctx ctx;
    ws_sha1_init(&ctx);
    ws_sha1_update(&ctx, "ab", 2);
    ws_sha1_update(&ctx, "c", 1);
    uint8_t d[WS_SHA1_DIGEST_SIZE];
    ws_sha1_final(&ctx, d);
    ASSERT_EQ(0, hex_cmp(d, "a9993e364706816aba3e25717850c26c9cd0d89d"));
}

TEST(sha1_million_a) {
    /* 1,000,000 个 'a' — 验证长消息和大计数 */
    ws_sha1_ctx ctx;
    ws_sha1_init(&ctx);
    char block[1024];
    memset(block, 'a', 1024);
    for(int i = 0; i < 1000000 / 1024; i++)
        ws_sha1_update(&ctx, block, 1024);
    ws_sha1_update(&ctx, block, 1000000 % 1024);
    uint8_t d[WS_SHA1_DIGEST_SIZE];
    ws_sha1_final(&ctx, d);
    ASSERT_EQ(0, hex_cmp(d, "34aa973cd4c4daa4f61eeb2bdbad27316534016f"));
}

TEST(sha1_ws_key) {
    /* RFC 6455 §4.2.2 示例:
     *   key    = "dGhlIHNhbXBsZSBub25jZQ=="
     *   GUID   = "258EAFA5-E914-47DA-95CA-5AB5DC2EA936"
     *   accept = SHA1(key + GUID) → base64 = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
     */
    const char *key  = "dGhlIHNhbXBsZSBub25jZQ==";
    const char *guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    char        concat[128];
    int         n = snprintf(concat, sizeof(concat), "%s%s", key, guid);
    (void)n;

    uint8_t d[WS_SHA1_DIGEST_SIZE];
    ws_sha1(concat, strlen(concat), d);

    /* 验证 SHA1 摘要 (供 base64 编码后应为 "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") */
    ASSERT_EQ(0, hex_cmp(d, "b37a4f2cc0624f1690f64606cf385945b2bec4ea"));

    /* 编码为 base64 */
    char b64[64];
    int  len = ws_base64_encode(d, WS_SHA1_DIGEST_SIZE, b64, sizeof(b64));
    ASSERT_EQ((int)strlen("s3pPLMBiTxaQ9kYGzzhZRbK+xOo="), len);
    ASSERT_EQ(0, strcmp(b64, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));
}

/* ====================================================================
 *  Base64 测试
 * ==================================================================== */

TEST(base64_empty) {
    char dst[8];
    int  len = ws_base64_encode("", 0, dst, sizeof(dst));
    ASSERT_EQ(0, len);
    ASSERT_EQ(0, strcmp(dst, ""));
}

TEST(base64_single) {
    char dst[8];
    int  len = ws_base64_encode("f", 1, dst, sizeof(dst));
    ASSERT_EQ(4, len);
    ASSERT_EQ(0, strcmp(dst, "Zg=="));
}

TEST(base64_double) {
    char dst[8];
    int  len = ws_base64_encode("fo", 2, dst, sizeof(dst));
    ASSERT_EQ(4, len);
    ASSERT_EQ(0, strcmp(dst, "Zm8="));
}

TEST(base64_triple) {
    char dst[8];
    int  len = ws_base64_encode("foo", 3, dst, sizeof(dst));
    ASSERT_EQ(4, len);
    ASSERT_EQ(0, strcmp(dst, "Zm9v"));
}

TEST(base64_4bytes) {
    char dst[16];
    int  len = ws_base64_encode("foob", 4, dst, sizeof(dst));
    ASSERT_EQ(8, len);
    ASSERT_EQ(0, strcmp(dst, "Zm9vYg=="));
}

TEST(base64_5bytes) {
    char dst[16];
    int  len = ws_base64_encode("fooba", 5, dst, sizeof(dst));
    ASSERT_EQ(8, len);
    ASSERT_EQ(0, strcmp(dst, "Zm9vYmE="));
}

TEST(base64_6bytes) {
    char dst[16];
    int  len = ws_base64_encode("foobar", 6, dst, sizeof(dst));
    ASSERT_EQ(8, len);
    ASSERT_EQ(0, strcmp(dst, "Zm9vYmFy"));
}

TEST(base64_binary) {
    /* 0x00 0x01 0x02 0x03 ... */
    uint8_t buf[256];
    for(int i = 0; i < 256; i++)
        buf[i] = (uint8_t)i;
    size_t cap = ws_base64_encode_size(256);
    char  *dst = (char *)malloc(cap);
    ASSERT(dst != NULL);
    int len = ws_base64_encode(buf, 256, dst, cap);
    ASSERT_EQ((int)(cap - 1), len);
    /* 解码验证: 只需检查 padding 和字符表范围 */
    ASSERT(len > 0);
    ASSERT_EQ('=', dst[len - 1]);
    ASSERT_EQ('=', dst[len - 2]);
    for(int i = 0; i < len; i++) {
        if(dst[i] == '=')
            continue;
        /* Base64 字符范围 */
        int ok = (dst[i] >= 'A' && dst[i] <= 'Z') || (dst[i] >= 'a' && dst[i] <= 'z') ||
                (dst[i] >= '0' && dst[i] <= '9') || dst[i] == '+' || dst[i] == '/';
        ASSERT(ok);
    }
    free(dst);
}

TEST(base64_insufficient_buffer) {
    char dst[4]; /* encode "foobar" (6 bytes) → needs 9 bytes incl NUL */
    int  len = ws_base64_encode("foobar", 6, dst, sizeof(dst));
    ASSERT_EQ(-1, len); /* 容量不足 */
}

TEST(base64_just_fit) {
    /* "foo" (3 bytes) → base64 "Zm9v" (4 chars + NUL = 5 bytes) */
    char dst[5];
    int  len = ws_base64_encode("foo", 3, dst, sizeof(dst));
    ASSERT_EQ(4, len);
    ASSERT_EQ(0, strcmp(dst, "Zm9v"));
}

TEST(base64_encode_size) {
    /* 公式: ((raw_len + 2) / 3) * 4 + 1 (NUL) */
    ASSERT_EQ(1, (int)ws_base64_encode_size(0));
    ASSERT_EQ(5, (int)ws_base64_encode_size(1));
    ASSERT_EQ(5, (int)ws_base64_encode_size(2));
    ASSERT_EQ(5, (int)ws_base64_encode_size(3));
    ASSERT_EQ(9, (int)ws_base64_encode_size(4));
    ASSERT_EQ(9, (int)ws_base64_encode_size(5));
    ASSERT_EQ(9, (int)ws_base64_encode_size(6));
    ASSERT_EQ(13, (int)ws_base64_encode_size(7));
}

/* ====================================================================
 *  帧层帮助函数
 * ==================================================================== */

/* 构建一个完整的帧 (header + payload) 用于测试解析.
 * buf 必须足够大 (临时 buffer 即可). 返回总字节数. */
static int build_frame(uint8_t       *buf,
                       uint8_t        fin,
                       uint8_t        opcode,
                       const uint8_t  mask_key[4],
                       const uint8_t *payload,
                       uint64_t       payload_len) {
    int hdr_len = ws_frame_build_header(buf, fin, 0, opcode, mask_key, payload_len);
    if(hdr_len < 0)
        return -1;
    if(payload && payload_len > 0) {
        memcpy(buf + hdr_len, payload, payload_len);
    }
    return hdr_len + (int)payload_len;
}

/* ====================================================================
 *  帧层测试
 * ==================================================================== */

/* ---- 帧头解析: 小 payload ---- */

TEST(frame_parse_small_unmasked) {
    uint8_t         frame[] = {0x81, 0x05, 'H', 'e', 'l', 'l', 'o'};
    ws_frame_header hdr;
    int             n = ws_frame_parse_header(frame, sizeof(frame), &hdr);
    ASSERT_EQ(2, n); /* 帧头只有 2 字节 */
    ASSERT_EQ(1, hdr.fin);
    ASSERT_EQ(WS_OPCODE_TEXT, hdr.opcode);
    ASSERT_EQ(0, hdr.mask);
    ASSERT_EQ(5, hdr.payload_len);
}

TEST(frame_parse_small_masked) {
    uint8_t         frame[] = {0x89, 0x85, 0x01, 0x02, 0x03, 0x04, 0x50, 0x51, 0x52, 0x53, 0x54};
    /* PING(0x9) + mask + len=5 + mask_key + payload */
    ws_frame_header hdr;
    int             n = ws_frame_parse_header(frame, sizeof(frame), &hdr);
    ASSERT_EQ(6, n); /* 2 + 4(mask) */
    ASSERT_EQ(1, hdr.fin);
    ASSERT_EQ(WS_OPCODE_PING, hdr.opcode);
    ASSERT_EQ(1, hdr.mask);
    ASSERT_EQ(5, hdr.payload_len);
    ASSERT_EQ(1, hdr.mask_key[0]);
    ASSERT_EQ(2, hdr.mask_key[1]);
    ASSERT_EQ(3, hdr.mask_key[2]);
    ASSERT_EQ(4, hdr.mask_key[3]);
}

TEST(frame_parse_medium_length) {
    /* payload len = 200 (>=126, 需要 16-bit 扩展) */
    uint8_t buf[256];
    memset(buf, 0, sizeof(buf));
    buf[0] = 0x82; /* FIN + BINARY */
    buf[1] = 0x7E; /* mask=0, len7=126 => 16-bit 扩展 */
    buf[2] = 0x00; /* 扩展长度高字节 */
    buf[3] = 0xC8; /* 扩展长度低字节 = 200 */

    ws_frame_header hdr;
    int             n = ws_frame_parse_header(buf, sizeof(buf), &hdr);
    ASSERT_EQ(4, n); /* 2 + 2(ext) */
    ASSERT_EQ(WS_OPCODE_BINARY, hdr.opcode);
    ASSERT_EQ(0, hdr.mask);
    ASSERT_EQ(200, hdr.payload_len);
}

TEST(frame_parse_large_length) {
    /* payload len = 70000 (> 65535, 需要 64-bit 扩展) */
    uint8_t buf[20];
    memset(buf, 0, sizeof(buf));
    buf[0] = 0x82; /* FIN + BINARY */
    buf[1] = 0x7F; /* mask=0, len7=127 => 64-bit 扩展 */
    buf[2] = 0x00;
    buf[3] = 0x00; /* 64-bit 扩展 (Big-Endian) */
    buf[4] = 0x00;
    buf[5] = 0x00;
    buf[6] = 0x00;
    memset(buf + 2, 0, 8);
    uint64_t v = 70000;
    for(int i = 7; i >= 0; i--) {
        buf[2 + i] = (uint8_t)(v & 0xFF);
        v          >>= 8;
    }

    ws_frame_header hdr;
    int             n = ws_frame_parse_header(buf, sizeof(buf), &hdr);
    ASSERT_EQ(10, n); /* 2 + 8(ext) */
    ASSERT_EQ(70000, hdr.payload_len);
}

TEST(frame_parse_incomplete) {
    /* 只有 1 字节, 不足 2 字节帧头 */
    uint8_t         buf[] = {0x81};
    ws_frame_header hdr;
    ASSERT_EQ(0, ws_frame_parse_header(buf, 1, &hdr));
}

TEST(frame_parse_incomplete_ext16) {
    /* 有 ext16 标记, 但只有 3 字节 */
    uint8_t         buf[] = {0x81, 0x7E, 0x01};
    ws_frame_header hdr;
    ASSERT_EQ(0, ws_frame_parse_header(buf, 3, &hdr));
}

TEST(frame_parse_incomplete_ext64) {
    /* 有 ext64 标记, 但只有 5 字节 */
    uint8_t         buf[] = {0x81, 0x7F, 0x00, 0x00, 0x01};
    ws_frame_header hdr;
    ASSERT_EQ(0, ws_frame_parse_header(buf, 5, &hdr));
}

TEST(frame_parse_incomplete_mask) {
    /* 有 mask, 但只有 3 字节 */
    uint8_t         buf[] = {0x81, 0x85, 0x01, 0x02};
    ws_frame_header hdr;
    ASSERT_EQ(0, ws_frame_parse_header(buf, 4, &hdr));
}

TEST(frame_parse_rsv) {
    /* RSV1 = 1 (bit 6 of byte 0), 不再由底层 parser 拒绝,
     * 由上层协议 (如 permessage-deflate) 协商后检查. */
    uint8_t         buf[] = {0xC1, 0x00}; /* 0xC1 = 11000001: FIN=1, RSV1=1, TEXT */
    ws_frame_header hdr;
    int             n = ws_frame_parse_header(buf, 2, &hdr);
    ASSERT_GT(n, 0);
    ASSERT_EQ(1, hdr.rsv1);
    ASSERT_EQ(1, hdr.fin);
    ASSERT_EQ(WS_OPCODE_TEXT, hdr.opcode);
}

TEST(frame_parse_msb_length_error) {
    /* 64-bit 扩展长度 MSB 非零 (RFC 6455 禁止) */
    uint8_t buf[10];
    memset(buf, 0, sizeof(buf));
    buf[0] = 0x82;
    buf[1] = 0x7F;
    buf[2] = 0x80; /* MSB of 64-bit length = 1 => 非法 */
    ws_frame_header hdr;
    ASSERT_EQ(-1, ws_frame_parse_header(buf, 10, &hdr));
}

TEST(frame_parse_continuation) {
    /* FIN=0, opcode=CONT */
    uint8_t         buf[] = {0x00, 0x03, 'a', 'b', 'c'};
    ws_frame_header hdr;
    int             n = ws_frame_parse_header(buf, sizeof(buf), &hdr);
    ASSERT_EQ(2, n);
    ASSERT_EQ(0, hdr.fin);
    ASSERT_EQ(WS_OPCODE_CONT, hdr.opcode);
    ASSERT_EQ(3, hdr.payload_len);
}

/* ---- 帧头构建 ---- */

TEST(frame_build_small_unmasked) {
    uint8_t buf[16];
    int     n = ws_frame_build_header(buf, 1, 0, WS_OPCODE_TEXT, NULL, 5);
    ASSERT_EQ(2, n);
    ASSERT_EQ(0x81, buf[0]); /* FIN + TEXT */
    ASSERT_EQ(0x05, buf[1]); /* len=5, mask=0 */
}

TEST(frame_build_small_masked) {
    uint8_t key[4] = {0x01, 0x02, 0x03, 0x04};
    uint8_t buf[16];
    int     n = ws_frame_build_header(buf, 1, 0, WS_OPCODE_TEXT, key, 5);
    ASSERT_EQ(6, n);
    ASSERT_EQ(0x81, buf[0]);
    ASSERT_EQ(0x85, buf[1]); /* mask=1, len=5 */
    ASSERT_EQ(0x01, buf[2]);
    ASSERT_EQ(0x02, buf[3]);
    ASSERT_EQ(0x03, buf[4]);
    ASSERT_EQ(0x04, buf[5]);
}

TEST(frame_build_medium) {
    uint8_t buf[16];
    int     n = ws_frame_build_header(buf, 1, 0, WS_OPCODE_BINARY, NULL, 200);
    ASSERT_EQ(4, n);
    ASSERT_EQ(0x82, buf[0]);
    ASSERT_EQ(0x7E, buf[1]); /* 126 = 16-bit ext */
    ASSERT_EQ(0x00, buf[2]);
    ASSERT_EQ(0xC8, buf[3]); /* 200 */
}

TEST(frame_build_large) {
    uint8_t buf[16];
    int     n = ws_frame_build_header(buf, 1, 0, WS_OPCODE_BINARY, NULL, 70000);
    ASSERT_EQ(10, n);
    ASSERT_EQ(0x82, buf[0]);
    ASSERT_EQ(0x7F, buf[1]); /* 127 = 64-bit ext */
    uint64_t val = 0;
    for(int i = 0; i < 8; i++)
        val = (val << 8) | buf[2 + i];
    ASSERT_EQ(70000, val);
}

TEST(frame_build_invalid_opcode) {
    uint8_t buf[16];
    int     n = ws_frame_build_header(buf, 1, 0, 0x10, NULL, 0); /* opcode > 0x0F */
    ASSERT_EQ(-1, n);
}

/* ---- 帧头 roundtrip: 构建 → 解析 ---- */

TEST(frame_roundtrip_small) {
    uint8_t       key[4]      = {0x11, 0x22, 0x33, 0x44};
    const uint8_t payload[]   = "Hello!";
    int           payload_len = 6;
    uint8_t       frame[32];
    int           total = build_frame(frame, 1, WS_OPCODE_TEXT, key, payload, payload_len);
    ASSERT(total > 0);

    ws_frame_header hdr;
    int             n = ws_frame_parse_header(frame, (size_t)total, &hdr);
    ASSERT_EQ(n, total - payload_len); /* 帧头大小 */
    ASSERT_EQ(1, hdr.fin);
    ASSERT_EQ(WS_OPCODE_TEXT, hdr.opcode);
    ASSERT_EQ(1, hdr.mask);
    ASSERT_EQ(6, hdr.payload_len);
    ASSERT_EQ(0x11, hdr.mask_key[0]);
    ASSERT_EQ(0x22, hdr.mask_key[1]);
    ASSERT_EQ(0x33, hdr.mask_key[2]);
    ASSERT_EQ(0x44, hdr.mask_key[3]);
}

/* ---- 掩码 ---- */

TEST(frame_apply_mask) {
    uint8_t key[4] = {0x01, 0x02, 0x03, 0x04};
    uint8_t data[] = {0x10, 0x20, 0x30, 0x40, 0x50};
    uint8_t orig[] = {0x10, 0x20, 0x30, 0x40, 0x50};
    ws_frame_apply_mask(data, 5, key);
    /* 验证掩码 XOR */
    for(int i = 0; i < 5; i++)
        ASSERT_EQ(orig[i] ^ key[i & 3], data[i]);
    /* 再次应用应该恢复 */
    ws_frame_apply_mask(data, 5, key);
    for(int i = 0; i < 5; i++)
        ASSERT_EQ(orig[i], data[i]);
}

/* ====================================================================
 *  握手测试
 * ==================================================================== */

TEST(handshake_gen_key) {
    char key[WS_KEY_BASE64_LEN];
    ws_gen_key(key);
    ASSERT_EQ(24, (int)strlen(key)); /* 16 字节 → 24 base64 字符 */
    /* 验证 base64 字符集 */
    for(int i = 0; key[i]; i++) {
        int ok = (key[i] >= 'A' && key[i] <= 'Z') || (key[i] >= 'a' && key[i] <= 'z') ||
                (key[i] >= '0' && key[i] <= '9') || key[i] == '+' || key[i] == '/' || key[i] == '=';
        ASSERT(ok);
    }
}

TEST(handshake_build_request_basic) {
    char buf[512];
    char key[WS_KEY_BASE64_LEN];
    ws_gen_key(key);

    int n = ws_build_request(buf, sizeof(buf), "example.com", 80, "/ws", key, NULL, false, NULL);
    ASSERT_GT(n, 0);
    ASSERT_LT((size_t)n, sizeof(buf));

    /* 验证请求格式 */
    ASSERT(strstr(buf, "GET /ws HTTP/1.1\r\n") != NULL);
    ASSERT(strstr(buf, "Host: example.com:80\r\n") != NULL);
    ASSERT(strstr(buf, "Upgrade: websocket\r\n") != NULL);
    ASSERT(strstr(buf, "Connection: Upgrade\r\n") != NULL);
    ASSERT(strstr(buf, "Sec-WebSocket-Version: 13\r\n") != NULL);
    /* 验证 key 出现在请求中 */
    ASSERT(strstr(buf, key) != NULL);
    /* 验证无子协议 */
    ASSERT(strstr(buf, "Sec-WebSocket-Protocol:") == NULL);
    /* 验证以 \r\n\r\n 结尾 */
    size_t blen = strlen(buf);
    ASSERT(blen >= 4);
    ASSERT_EQ(0, memcmp(buf + blen - 4, "\r\n\r\n", 4));
}

TEST(handshake_build_request_with_protocol) {
    char buf[512];
    char key[WS_KEY_BASE64_LEN];
    ws_gen_key(key);

    int n = ws_build_request(buf, sizeof(buf), "chat.example.com", 9000, "/chat", key, "myprotocol", false, NULL);
    ASSERT_GT(n, 0);

    ASSERT(strstr(buf, "Sec-WebSocket-Protocol: myprotocol\r\n") != NULL);
}

TEST(handshake_build_request_buffer_too_small) {
    char buf[10];
    char key[WS_KEY_BASE64_LEN] = "dGhlIHNhbXBsZSBub25jZQ==";
    int  n                      = ws_build_request(buf, sizeof(buf), "h", 1, "/", key, NULL, false, NULL);
    ASSERT_EQ(-1, n);
}

TEST(handshake_build_request_pmd_offer) {
#ifdef SEVENT_WS_DEFLATE
    char buf[512];
    char key[WS_KEY_BASE64_LEN];
    ws_gen_key(key);

    /* 默认 offer (pmd_offer=NULL): 无值 client_max_window_bits */
    int n = ws_build_request(buf, sizeof(buf), "h", 1, "/", key, NULL, true, NULL);
    ASSERT_GT(n, 0);
    ASSERT(strstr(buf, "Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n") != NULL);

    /* 请求 no_context_takeover (client 自我承诺 + server 请求) */
    ws_deflate_params p = {0};
    p.client_no_context_takeover = true;
    p.server_no_context_takeover = true;
    n = ws_build_request(buf, sizeof(buf), "h", 1, "/", key, NULL, true, &p);
    ASSERT_GT(n, 0);
    ASSERT(strstr(buf, "permessage-deflate; client_max_window_bits; "
                       "client_no_context_takeover; server_no_context_takeover\r\n") != NULL);

    /* 带值 client_max_window_bits (降窗功能预留) */
    p.client_max_window_bits = 9;
    n = ws_build_request(buf, sizeof(buf), "h", 1, "/", key, NULL, true, &p);
    ASSERT_GT(n, 0);
    ASSERT(strstr(buf, "client_max_window_bits=9; client_no_context_takeover; "
                       "server_no_context_takeover\r\n") != NULL);
#endif
}

/* ---- 响应解析 ---- */

/* 辅助: 构建一个模拟的 HTTP 101 响应 */
static const char *sample_101_response = "HTTP/1.1 101 Switching Protocols\r\n"
                                         "Upgrade: websocket\r\n"
                                         "Connection: Upgrade\r\n"
                                         "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
                                         "Sec-WebSocket-Protocol: chat\r\n"
                                         "\r\n";

/* 辅助: 构建不含协议头的 101 响应 */
static const char *sample_101_no_proto = "HTTP/1.1 101 Switching Protocols\r\n"
                                         "Upgrade: websocket\r\n"
                                         "Connection: Upgrade\r\n"
                                         "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
                                         "\r\n";

TEST(handshake_parse_101_basic) {
    ws_handshake_response resp;
    int n = ws_parse_response((const uint8_t *)sample_101_response, strlen(sample_101_response), &resp);
    ASSERT_GT(n, 0);
    ASSERT_EQ(101, resp.status_code);
    ASSERT_EQ(0, strcmp(resp.accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));
    ASSERT_EQ(0, strcmp(resp.protocol, "chat"));
}

TEST(handshake_parse_101_no_protocol) {
    ws_handshake_response resp;
    int n = ws_parse_response((const uint8_t *)sample_101_no_proto, strlen(sample_101_no_proto), &resp);
    ASSERT_GT(n, 0);
    ASSERT_EQ(101, resp.status_code);
    ASSERT_EQ(0, strcmp(resp.accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));
    ASSERT_EQ(0, resp.protocol[0]); /* 未协商 */
}

TEST(handshake_parse_non_101) {
    const char           *resp_404 = "HTTP/1.1 404 Not Found\r\n"
                                     "Content-Length: 0\r\n"
                                     "\r\n";
    ws_handshake_response resp;
    int                   n = ws_parse_response((const uint8_t *)resp_404, strlen(resp_404), &resp);
    ASSERT_EQ(404, resp.status_code);
    ASSERT_GT(n, 0); /* 现在非 101 也返回 header 长度, 让调用方提取 body */
}

TEST(handshake_parse_incomplete) {
    const char           *partial = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: ";
    ws_handshake_response resp;
    int                   n = ws_parse_response((const uint8_t *)partial, strlen(partial), &resp);
    ASSERT_EQ(0, n); /* 等待更多数据 */
}

TEST(handshake_parse_incremental) {
    /* 分两次接收, 模拟 TCP 分块 */
    const char *part1 = "HTTP/1.1 101 Switching Protocols\r\n";
    const char *part2 = "Upgrade: websocket\r\n"
                        "Connection: Upgrade\r\n"
                        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
                        "\r\n";

    char combined[512];
    int  len1 = (int)strlen(part1);
    memcpy(combined, part1, (size_t)len1);
    memcpy(combined + len1, part2, strlen(part2) + 1);

    ws_handshake_response resp;
    int                   n = ws_parse_response((const uint8_t *)combined, strlen(combined), &resp);
    ASSERT_GT(n, 0);
    ASSERT_EQ(101, resp.status_code);
    ASSERT_EQ(0, strcmp(resp.accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));
}

TEST(handshake_parse_case_insensitive) {
    const char           *resp = "HTTP/1.1 101 Switching Protocols\r\n"
                                 "upgrade: websocket\r\n"
                                 "CONNECTION: Upgrade\r\n"
                                 "SEC-WEBSOCKET-ACCEPT: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
                                 "\r\n";
    ws_handshake_response resp_hdr;
    int                   n = ws_parse_response((const uint8_t *)resp, strlen(resp), &resp_hdr);
    ASSERT_GT(n, 0);
    ASSERT_EQ(101, resp_hdr.status_code);
    ASSERT_EQ(0, strcmp(resp_hdr.accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));
}

TEST(handshake_parse_missing_accept) {
    const char           *resp = "HTTP/1.1 101 Switching Protocols\r\n"
                                 "Upgrade: websocket\r\n"
                                 "\r\n";
    ws_handshake_response resp_hdr;
    int                   n = ws_parse_response((const uint8_t *)resp, strlen(resp), &resp_hdr);
    ASSERT_EQ(-1, n); /* 缺少 Accept 头 */
}

/* ---- Accept 验证 ---- */

TEST(handshake_verify_accept) {
    const char *key    = "dGhlIHNhbXBsZSBub25jZQ==";
    const char *accept = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";
    ASSERT_EQ(0, ws_verify_accept(key, accept));
}

TEST(handshake_verify_accept_wrong) {
    const char *key    = "dGhlIHNhbXBsZSBub25jZQ==";
    const char *accept = "AAAAAAAAAAAAAAAAAAAAAAAAAAA="; /* 错误值 */
    ASSERT_EQ(-1, ws_verify_accept(key, accept));
}

/* ---- 完整流程: 构建请求 → 模拟服务器 → Accept 验证 ---- */

TEST(handshake_full_roundtrip) {
    /* 1. 客户端生成 key */
    char key[WS_KEY_BASE64_LEN];
    ws_gen_key(key);

    /* 2. 模拟服务器计算 accept */
    char accept[WS_ACCEPT_BASE64_LEN];
    char concat[256];
    snprintf(concat, sizeof(concat), "%s%s", key, WS_GUID);
    uint8_t digest[WS_SHA1_DIGEST_SIZE];
    ws_sha1(concat, strlen(concat), digest);
    ws_base64_encode(digest, WS_SHA1_DIGEST_SIZE, accept, sizeof(accept));

    /* 3. 验证 accept (客户端侧) */
    ASSERT_EQ(0, ws_verify_accept(key, accept));
}

/* ====================================================================
 *  连接测试 — 使用 TCP loopback 驱动完整状态机
 *
 *  架构:
 *    同一事件循环中运行客户端(sevent_ws_connect)和模拟服务器.
 *    listen_fd → accept → server-side IO → send 101 → send frames → close
 *
 *  测试按序进行: 接收到 on_open / on_message / on_close 后递减计数器,
 *  loop 在计数器归零后 stop.
 * ==================================================================== */

#include "../src/websockets/ws_conn.h"

/* 全局测试状态 */
/* removed */ /* 未完成的预期回调数 */
/* removed */
/* removed */
/* removed */

/* removed */

/* removed */

/* removed */

/* removed */

#define TEST_LIST                                                                                                      \
    T(sha1_empty)                                                                                                      \
    T(sha1_abc)                                                                                                        \
    T(sha1_len_448)                                                                                                    \
    T(sha1_streaming)                                                                                                  \
    T(sha1_million_a)                                                                                                  \
    T(sha1_ws_key)                                                                                                     \
    T(base64_empty)                                                                                                    \
    T(base64_single)                                                                                                   \
    T(base64_double)                                                                                                   \
    T(base64_triple)                                                                                                   \
    T(base64_4bytes)                                                                                                   \
    T(base64_5bytes)                                                                                                   \
    T(base64_6bytes)                                                                                                   \
    T(base64_binary)                                                                                                   \
    T(base64_insufficient_buffer)                                                                                      \
    T(base64_just_fit)                                                                                                 \
    T(base64_encode_size)                                                                                              \
    T(frame_parse_small_unmasked)                                                                                      \
    T(frame_parse_small_masked)                                                                                        \
    T(frame_parse_medium_length)                                                                                       \
    T(frame_parse_large_length)                                                                                        \
    T(frame_parse_incomplete)                                                                                          \
    T(frame_parse_incomplete_ext16)                                                                                    \
    T(frame_parse_incomplete_ext64)                                                                                    \
    T(frame_parse_incomplete_mask)                                                                                     \
    T(frame_parse_rsv)                                                                                                 \
    T(frame_parse_msb_length_error)                                                                                    \
    T(frame_parse_continuation)                                                                                        \
    T(frame_build_small_unmasked)                                                                                      \
    T(frame_build_small_masked)                                                                                        \
    T(frame_build_medium)                                                                                              \
    T(frame_build_large)                                                                                               \
    T(frame_build_invalid_opcode)                                                                                      \
    T(frame_roundtrip_small)                                                                                           \
    T(frame_apply_mask)                                                                                                \
    T(handshake_gen_key)                                                                                               \
    T(handshake_build_request_basic)                                                                                   \
    T(handshake_build_request_with_protocol)                                                                           \
    T(handshake_build_request_buffer_too_small)                                                                        \
    T(handshake_build_request_pmd_offer)                                                                               \
    T(handshake_parse_101_basic)                                                                                       \
    T(handshake_parse_101_no_protocol)                                                                                 \
    T(handshake_parse_non_101)                                                                                         \
    T(handshake_parse_incomplete)                                                                                      \
    T(handshake_parse_incremental)                                                                                     \
    T(handshake_parse_case_insensitive)                                                                                \
    T(handshake_parse_missing_accept)                                                                                  \
    T(handshake_verify_accept)                                                                                         \
    T(handshake_verify_accept_wrong)                                                                                   \
    T(handshake_full_roundtrip)


/* ====================================================================                \
 *  主函数                                                                          \
 * ====================================================================                \
 */
int main(void) {
    struct test_entry *test_list = NULL;
#define T(name)                                                                                                        \
    do {                                                                                                               \
        struct test_entry *e = malloc(sizeof(*e));                                                                     \
        e->label             = #name;                                                                                  \
        e->fn                = test_##name;                                                                            \
        e->next              = test_list;                                                                              \
        test_list            = e;                                                                                      \
    } while(0);
    TEST_LIST
#undef T

    printf("\n  WebSocket Round 1 — SHA-1 / Base64\n");
    printf("  ==================================\n");

    int n = 0, passed = 0;
    for(struct test_entry *e = test_list; e; e = e->next) {
        n++;
        fail_count = 0;
        e->fn();
        if(fail_count == 0) {
            printf("  \xE2\x9C\x93  %s\n", e->label);
            passed++;
        } else {
            printf("  \xC3\x97  %s  (%d assertions failed)\n", e->label, fail_count);
        }
    }

    while(test_list) {
        struct test_entry *n = test_list->next;
        free(test_list);
        test_list = n;
    }

    printf("\n  result: %d / %d passed\n", passed, n);
    return n == passed ? 0 : 1;
}
