/* test_http_parse.c — HTTP 语法层单测 (分帧 + 惰性解析 + 构建骨架)
 *
 * 覆盖: 请求/响应行解析、半包语义 (0)、协议错误 (<0)、分帧 (CL 收齐/不足/
 *       无 body/超限/非法/溢出)、预解析字段 (upgrade/keep_alive/CL)、
 *       find_header 大小写不敏感、chunked 拒绝、构建骨架.
 */
#include "sevent_http_parse.h"
#include <stdio.h>
#include <string.h>

static int g_ok = 0, g_fail = 0;

#define CHECK(cond, ...)                                                                                               \
    do {                                                                                                               \
        if(cond) {                                                                                                     \
            g_ok++;                                                                                                    \
        } else {                                                                                                       \
            g_fail++;                                                                                                  \
            printf("  FAIL %s:%d: ", __FILE__, __LINE__);                                                              \
            printf(__VA_ARGS__);                                                                                       \
            printf("\n");                                                                                              \
        }                                                                                                              \
    } while(0)

/* ---- 请求解析 ---- */

static void t_request_basic(void) {
    const char     *req = "GET /chat HTTP/1.1\r\n"
                          "Host: example.com\r\n"
                          "Upgrade: websocket\r\n"
                          "Connection: keep-alive, Upgrade\r\n"
                          "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                          "Sec-WebSocket-Version: 13\r\n\r\n";
    sevent_http_msg m;
    int             r = sevent_http_parse(req, strlen(req), &m);
    CHECK(r > 0, "完整请求应 >0, got %d", r);
    CHECK(!m.is_response, "请求");
    CHECK(m.method == HTTP_METHOD_GET, "method 枚举=GET (got %d)", m.method);
    CHECK(sevent_http_str_eq(m.method_ref, m.method_len, "GET"), "method_ref 引用 (len=%zu)", m.method_len);
    CHECK(sevent_http_str_eq(m.target, m.target_len, "/chat"), "target=/chat (len=%zu)", m.target_len);
    CHECK(m.keep_alive, "HTTP/1.1 默认保持");
    CHECK(m.upgrade, "Upgrade+Connection: Upgrade → upgrade=true");
    CHECK(m.content_length == 0, "无 body → CL=0");
    CHECK(m.body_len == 0, "body_len=0");
    CHECK(!m.chunked, "非 chunked");
    /* find_header 大小写不敏感 */
    size_t      vl;
    const char *v = sevent_http_find_header(&m, "sec-websocket-key", &vl);
    CHECK(v && vl == 24 && memcmp(v, "dGhlIHNhbXBsZSBub25jZQ==", 24) == 0, "key 提取");
    v = sevent_http_find_header(&m, "Sec-WebSocket-Version", &vl);
    CHECK(v && vl == 2 && memcmp(v, "13", 2) == 0, "version 提取 (大写键)");
    CHECK(sevent_http_find_header(&m, "X-Not-Exist", &vl) == NULL, "未找到 → NULL");
}

static void t_request_body(void) {
    const char     *req = "POST /submit HTTP/1.1\r\n"
                          "Host: x.com\r\n"
                          "Content-Length: 5\r\n\r\n"
                          "hello";
    sevent_http_msg m;
    CHECK(sevent_http_parse(req, strlen(req), &m) > 0, "带 body 完整请求");
    CHECK(m.content_length == 5 && m.body_len == 5, "CL=5 body_len=5");
    CHECK(m.body && memcmp(m.body, "hello", 5) == 0, "body 内容 hello");
    CHECK(m.method == HTTP_METHOD_POST, "method 枚举=POST (got %d)", m.method);
    CHECK(sevent_http_str_eq(m.target, m.target_len, "/submit"), "target=/submit (len=%zu)", m.target_len);
}

static void t_request_methods(void) {
    /* 9 个标准方法识别 + 未知方法 (UNKNOWN + 引用保留) */
    struct {
        const char        *name;
        sevent_http_method want;
    } cases[] = {
            {"GET", HTTP_METHOD_GET},
            {"HEAD", HTTP_METHOD_HEAD},
            {"POST", HTTP_METHOD_POST},
            {"PUT", HTTP_METHOD_PUT},
            {"DELETE", HTTP_METHOD_DELETE},
            {"OPTIONS", HTTP_METHOD_OPTIONS},
            {"PATCH", HTTP_METHOD_PATCH},
            {"CONNECT", HTTP_METHOD_CONNECT},
            {"TRACE", HTTP_METHOD_TRACE},
            {"PROPFIND", HTTP_METHOD_UNKNOWN},
            {"M-SEARCH", HTTP_METHOD_UNKNOWN},
    };
    for(size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char            req[128];
        sevent_http_msg m;
        int             n = snprintf(req, sizeof(req), "%s /x HTTP/1.1\r\nHost: h\r\n\r\n", cases[i].name);
        CHECK(sevent_http_parse(req, (size_t)n, &m) > 0, "%s 可解析", cases[i].name);
        CHECK(m.method == cases[i].want, "%s → 枚举 %d (got %d)", cases[i].name, cases[i].want, m.method);
        if(m.method == HTTP_METHOD_UNKNOWN)
            CHECK(sevent_http_str_eq(m.method_ref, m.method_len, cases[i].name), "%s 未知方法引用保留", cases[i].name);
    }
}

static void t_target_split(void) {
    /* path/query 拆分: 带 query / 无 query / 空 query */
    const char *t1 = "/api?a=1&b=2";
    const char *path;
    const char *query;
    size_t      pl, ql;
    sevent_http_target_split(t1, strlen(t1), &path, &pl, &query, &ql);
    CHECK(pl == 4 && memcmp(path, "/api", 4) == 0, "path=/api (len=%zu)", pl);
    CHECK(ql == 7 && memcmp(query, "a=1&b=2", 7) == 0, "query=a=1&b=2 (len=%zu)", ql);

    const char *t2 = "/plain";
    sevent_http_target_split(t2, strlen(t2), &path, &pl, &query, &ql);
    CHECK(pl == 6 && memcmp(path, "/plain", 6) == 0, "path=/plain (len=%zu)", pl);
    CHECK(query == NULL && ql == 0, "无 query → NULL/0");

    const char *t3 = "/?";
    sevent_http_target_split(t3, strlen(t3), &path, &pl, &query, &ql);
    CHECK(pl == 1 && path[0] == '/', "path=/ (len=%zu)", pl);
    CHECK(query != NULL && ql == 0, "空 query → 指针有效 len=0");

    /* 空 target */
    sevent_http_target_split(NULL, 0, &path, &pl, &query, &ql);
    CHECK(path == NULL && pl == 0, "NULL target 安全");
}

static void t_query_get(void) {
    const char *q = "a=1&b=2&flag&c=&utm_source=x";
    size_t      vl = 0; /* query_get 未找到时不写 val_len, 初始化防 -Wmaybe-uninitialized */
    const char *v;
    /* 正常查找 */
    v = sevent_http_query_get(q, strlen(q), "b", &vl);
    CHECK(v && vl == 1 && *v == '2', "查 b → 2 (len=%zu)", vl);
    v = sevent_http_query_get(q, strlen(q), "a", &vl);
    CHECK(v && vl == 1 && *v == '1', "查 a → 1");
    v = sevent_http_query_get(q, strlen(q), "utm_source", &vl);
    CHECK(v && vl == 1 && *v == 'x', "最后一段 (无 & 结尾) → x");
    /* 未找到 */
    v = sevent_http_query_get(q, strlen(q), "nope", &vl);
    CHECK(v == NULL, "未找到 → NULL");
    /* 空值参数 */
    v = sevent_http_query_get(q, strlen(q), "c", &vl);
    CHECK(v != NULL && vl == 0, "空值参数 → 指针有效 len=0");
    /* 无 '=' 的段跳过 (flag) */
    v = sevent_http_query_get(q, strlen(q), "flag", &vl);
    CHECK(v == NULL, "无 '=' 段 → NULL (无值可返回)");
    /* 大小写敏感 */
    v = sevent_http_query_get(q, strlen(q), "B", &vl);
    CHECK(v == NULL, "大小写敏感: B ≠ b");
    /* 同名重复 → 第一个 */
    const char *dup = "x=first&x=second";
    v               = sevent_http_query_get(dup, strlen(dup), "x", &vl);
    CHECK(v && vl == 5 && memcmp(v, "first", 5) == 0, "同名重复取第一个");
    /* NULL 安全 */
    CHECK(sevent_http_query_get(NULL, 0, "a", &vl) == NULL, "NULL query 安全");
    CHECK(sevent_http_query_get(q, strlen(q), NULL, &vl) == NULL, "NULL name 安全");
}

static void t_request_partial(void) {
    /* 半包: 无 \r\n\r\n → 0 */
    const char     *p1 = "GET / HTTP/1.1\r\nHost: x.com\r\n";
    sevent_http_msg m;
    CHECK(sevent_http_parse(p1, strlen(p1), &m) == 0, "头区未到 → 0");
    /* 半包: 头区到但 body 不足 → 0 */
    const char *p2 = "POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\nabc";
    CHECK(sevent_http_parse(p2, strlen(p2), &m) == 0, "body 不足 → 0");
    /* 补足 → 完整 */
    const char *p3 = "POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\nabcdefghij";
    CHECK(sevent_http_parse(p3, strlen(p3), &m) > 0, "body 收齐 → >0");
    CHECK(m.body_len == 10, "body_len=10");
}

static void t_dup_content_length(void) {
    /* 重复 CL: 值冲突必拒 (RFC 7230 §3.3.2, 走私面), 值一致容忍 */
    sevent_http_msg m;
    const char     *conflict = "POST / HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello";
    CHECK(sevent_http_parse(conflict, strlen(conflict), &m) < 0, "冲突 CL → <0");
    const char *same = "POST / HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello";
    CHECK(sevent_http_parse(same, strlen(same), &m) > 0, "一致 CL 容忍");
}

static void t_request_invalid(void) {
    sevent_http_msg m;
    CHECK(sevent_http_parse("GARBAGE\r\n\r\n", 12, &m) < 0, "非法首行 → <0");
    CHECK(sevent_http_parse("GET\r\n\r\n", 8, &m) < 0, "缺路径 → <0");
    const char *bad_cl = "POST / HTTP/1.1\r\nContent-Length: abc\r\n\r\n";
    CHECK(sevent_http_parse(bad_cl, strlen(bad_cl), &m) < 0, "非法 CL → <0");
    const char *big_cl = "POST / HTTP/1.1\r\nContent-Length: 99999999999999999999999\r\n\r\n";
    CHECK(sevent_http_parse(big_cl, strlen(big_cl), &m) < 0, "CL 溢出 → <0");
    const char *chunked = "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n";
    CHECK(sevent_http_parse(chunked, strlen(chunked), &m) < 0, "chunked 初版拒绝 → <0");
    CHECK(m.chunked, "chunked 标记已置");
}

static void t_request_keepalive(void) {
    sevent_http_msg m;
    const char     *close1 = "GET / HTTP/1.1\r\nConnection: close\r\n\r\n";
    CHECK(sevent_http_parse(close1, strlen(close1), &m) > 0 && !m.keep_alive, "Connection: close → keep_alive=false");
    const char *h10 = "GET / HTTP/1.0\r\n\r\n";
    CHECK(sevent_http_parse(h10, strlen(h10), &m) > 0 && !m.keep_alive, "HTTP/1.0 → keep_alive=false");
    const char *h10ka = "GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n";
    CHECK(sevent_http_parse(h10ka, strlen(h10ka), &m) > 0 && !m.keep_alive,
          "HTTP/1.0 + keep-alive 头 → 仍 false (1.0 无 keep-alive 概念)");
    const char *h11 = "GET / HTTP/1.1\r\n\r\n";
    CHECK(sevent_http_parse(h11, strlen(h11), &m) > 0 && m.keep_alive, "HTTP/1.1 默认保持");
}

static void t_request_upgrade_neg(void) {
    sevent_http_msg m;
    const char     *no_up = "GET / HTTP/1.1\r\nConnection: Upgrade\r\n\r\n";
    CHECK(sevent_http_parse(no_up, strlen(no_up), &m) > 0 && !m.upgrade,
          "Connection: Upgrade 但无 Upgrade 头 → upgrade=false");
    const char *no_conn = "GET / HTTP/1.1\r\nUpgrade: websocket\r\n\r\n";
    CHECK(sevent_http_parse(no_conn, strlen(no_conn), &m) > 0 && !m.upgrade,
          "Upgrade 头但 Connection 无 upgrade → upgrade=false");
}

/* ---- 响应解析 ---- */

static void t_response(void) {
    const char     *resp = "HTTP/1.1 101 Switching Protocols\r\n"
                           "Upgrade: websocket\r\n"
                           "Connection: Upgrade\r\n"
                           "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
    sevent_http_msg m;
    CHECK(sevent_http_parse(resp, strlen(resp), &m) > 0, "完整响应");
    CHECK(m.is_response, "响应");
    CHECK(m.status_code == 101, "status=101, got %d", m.status_code);
    size_t      vl;
    const char *v = sevent_http_find_header(&m, "Sec-WebSocket-Accept", &vl);
    CHECK(v && vl == 28, "accept 提取 (28 字节)");
    /* 无 body → CL=0 body_len=0 */
    CHECK(m.content_length == 0 && m.body_len == 0, "101 无 body");

    const char *h404 = "HTTP/1.0 404 Not Found\r\n\r\n";
    CHECK(sevent_http_parse(h404, strlen(h404), &m) > 0 && m.status_code == 404, "404 + HTTP/1.0");
    CHECK(!m.keep_alive, "HTTP/1.0 响应 keep_alive=false");
}

static void t_response_partial(void) {
    sevent_http_msg m;
    const char     *p = "HTTP/1.1 101 Swi";
    CHECK(sevent_http_parse(p, strlen(p), &m) == 0, "响应半包 → 0");
}

/* ---- 构建 ---- */

static void t_build_request(void) {
    char buf[512];
    int  n = sevent_http_build_request(
            buf, sizeof(buf), "GET", "/ws", "127.0.0.1", 8080, "Upgrade: websocket\r\nConnection: Upgrade\r\n");
    CHECK(n > 0, "构建请求");
    CHECK(strstr(buf, "GET /ws HTTP/1.1\r\n") != NULL, "请求行");
    CHECK(strstr(buf, "Host: 127.0.0.1:8080\r\n") != NULL, "Host 行");
    CHECK(strstr(buf, "Upgrade: websocket\r\n") != NULL, "extra 注入");
    CHECK(strstr(buf, "\r\n\r\n") != NULL, "结尾空行");
    /* 容量不足 */
    CHECK(sevent_http_build_request(buf, 8, "GET", "/ws", "h", 1, NULL) < 0, "容量不足 → <0");
}

static void t_build_response(void) {
    char buf[512];
    int  n = sevent_http_build_response(buf,
                                       sizeof(buf),
                                       101,
                                       "Switching Protocols",
                                       "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                                        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n");
    CHECK(n > 0, "构建响应");
    CHECK(strstr(buf, "HTTP/1.1 101 Switching Protocols\r\n") != NULL, "状态行");
    CHECK(strstr(buf, "Sec-WebSocket-Accept:") != NULL, "extra 注入");
    CHECK(sevent_http_build_response(buf, 4, 200, "OK", NULL) < 0, "容量不足 → <0");
}

/* ---- 注册 ---- */

typedef struct {
    const char *n;
    void (*f)(void);
} test_entry;

static const test_entry tests[] = {
        {"request_basic", t_request_basic},
        {"request_body", t_request_body},
        {"request_methods", t_request_methods},
        {"target_split", t_target_split},
        {"query_get", t_query_get},
        {"request_partial", t_request_partial},
        {"dup_content_length", t_dup_content_length},
        {"request_invalid", t_request_invalid},
        {"request_keepalive", t_request_keepalive},
        {"request_upgrade_neg", t_request_upgrade_neg},
        {"response", t_response},
        {"response_partial", t_response_partial},
        {"build_request", t_build_request},
        {"build_response", t_build_response},
        {NULL, NULL},
};

int main(void) {
    setbuf(stdout, NULL);
    printf("http_parse tests (sevent_http_parse 语法层)\n");
    printf("===========================================\n");
    for(int i = 0; tests[i].n; i++) {
        printf("  %-24s ", tests[i].n);
        g_ok = g_fail = 0;
        tests[i].f();
        printf("%s (%d ok)\n", g_fail ? "×" : "✓", g_ok);
        if(g_fail) {
            printf("  FAILED: %d checks failed in %s\n", g_fail, tests[i].n);
            return 1;
        }
    }
    printf("all passed\n");
    return 0;
}
