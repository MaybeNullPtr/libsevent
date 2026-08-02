/* =========================================================================
 *  http_parse.c — HTTP 语法层 (分帧 + 惰性解析, 纯函数)
 *
 *  设计定案 (doc/http-layer-design.md §3):
 *    - 分帧: 头区边界 (\r\n\r\n) + Content-Length 收 body — 请求边界确定,
 *      keep-alive 的前提; 分帧本身只需 CL 一个头
 *    - 预解析面: upgrade (升级分派) / keep_alive (连接决策) / method+target
 *      (路由) / status_code — http server 运行所需, 其余 header 零开销
 *    - 其余 header 不预解析: sevent_http_find_header 按需扫描头区
 *    - chunked 初版不支持: 遇到 → 返回 <0 (明确拒绝, 上层回 400)
 *  零拷贝: 所有指针指向输入缓冲, 调用方保证生命周期.
 *  ========================================================================= */

#include "sevent_http_parse.h"

#include <string.h>
#include <stdio.h>

/* 状态行前缀与 HTTP/1.1 版本串 (定长判定, 常数化避免魔法数字) */
#define HTTP_PREFIX "HTTP/"
#define HTTP_PREFIX_LEN 5u
#define HTTP_VERSION_11 "HTTP/1.1"
#define HTTP_VERSION_11_LEN 8u /* "HTTP/1.1" 为 8 字符 (请求行精确匹配用) */

/* 大小写不敏感比较 (ASCII): a_len 字节的 a 与 C 串 b */
static int ci_eq(const char *a, size_t a_len, const char *b) {
    size_t b_len = strlen(b);
    if(a_len != b_len)
        return 0;
    for(size_t i = 0; i < a_len; i++) {
        char ca = a[i], cb = b[i];
        if(ca >= 'A' && ca <= 'Z')
            ca += 32;
        if(cb >= 'A' && cb <= 'Z')
            cb += 32;
        if(ca != cb)
            return 0;
    }
    return 1;
}

/* 头值是否含 token (逗号分隔, 大小写不敏感, 容忍空白) */
static bool hdr_has_token(const char *val, size_t len, const char *token) {
    size_t      tlen = strlen(token);
    const char *p    = val;
    const char *end  = val + len;
    while(p < end) {
        const char *q = p;
        while(q < end && *q != ',')
            q++;
        /* 去两侧空白 */
        while(p < q && (*p == ' ' || *p == '\t'))
            p++;
        while(q > p && (q[-1] == ' ' || q[-1] == '\t'))
            q--;
        if((size_t)(q - p) == tlen && ci_eq(p, (size_t)(q - p), token))
            return true;
        p = q < end ? q + 1 : q;
    }
    return false;
}

/* 头区中按名找第 nth 个匹配头 (大小写不敏感; nth=0 即 find_header_in):
 * 返回值指针+长度, 未找到 NULL */
static const char *find_header_nth(const char *hstart, size_t hlen, const char *name, int nth, size_t *vlen_out) {
    const char *p   = hstart;
    const char *end = hstart + hlen;
    while(p < end) {
        const char *eol = (const char *)memchr(p, '\n', (size_t)(end - p));
        if(!eol)
            break;
        size_t line_len = (size_t)(eol - p);
        if(line_len > 0 && p[line_len - 1] == '\r')
            line_len--;
        const char *colon = (const char *)memchr(p, ':', line_len);
        if(colon) {
            size_t      name_len = (size_t)(colon - p);
            const char *vstart   = colon + 1;
            size_t      vlen     = line_len - name_len - 1;
            while(vlen > 0 && (*vstart == ' ' || *vstart == '\t')) {
                vstart++;
                vlen--;
            }
            while(vlen > 0 && (vstart[vlen - 1] == ' ' || vstart[vlen - 1] == '\t'))
                vlen--;
            if(ci_eq(p, name_len, name)) {
                if(nth == 0) {
                    *vlen_out = vlen;
                    return vstart;
                }
                nth--;
            }
        }
        p = eol + 1;
    }
    return NULL;
}

/* 头区中按名找头: 同 find_header_nth(..., 0, ...) */
static const char *find_header_in(const char *hstart, size_t hlen, const char *name, size_t *vlen_out) {
    return find_header_nth(hstart, hlen, name, 0, vlen_out);
}

/* ===== 解析 ===== */

/* 请求方法识别 (RFC 9110 §9.1 标准方法, 大小写敏感); 未知 → UNKNOWN
 * (method_ref 引用保留, 调用方按字符串处理) */
static sevent_http_method parse_method(const char *p, size_t len) {
#define M(s) (len == sizeof(s) - 1 && memcmp(p, s, sizeof(s) - 1) == 0)
    if(M("GET"))
        return HTTP_METHOD_GET;
    if(M("HEAD"))
        return HTTP_METHOD_HEAD;
    if(M("POST"))
        return HTTP_METHOD_POST;
    if(M("PUT"))
        return HTTP_METHOD_PUT;
    if(M("DELETE"))
        return HTTP_METHOD_DELETE;
    if(M("OPTIONS"))
        return HTTP_METHOD_OPTIONS;
    if(M("PATCH"))
        return HTTP_METHOD_PATCH;
    if(M("CONNECT"))
        return HTTP_METHOD_CONNECT;
    if(M("TRACE"))
        return HTTP_METHOD_TRACE;
    return HTTP_METHOD_UNKNOWN;
#undef M
}

int sevent_http_parse(const char *buf, size_t len, sevent_http_msg *out) {
    if(!buf || !out)
        return -1; /* 语法层无 SEVENT_ERR 依赖, 约定 <0 即协议错误 */
    memset(out, 0, sizeof(*out));

    /* 头区结束 \r\n\r\n (未到 → 数据不足) */
    const char *hdr_end = NULL;
    for(size_t i = 0; i + 3 < len; i++) {
        if(buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n') {
            hdr_end = buf + i;
            break;
        }
    }
    if(!hdr_end)
        return 0;

    /* 首行: 全局第一个 \n 必是首行结尾 — 无头行请求时该 \n 是 \r\n\r\n 的
     * 第一组 (首行自己的结尾), 在 hdr_end+1, 不在 hdr_end 之前. */
    const char *line_end = (const char *)memchr(buf, '\n', len);
    if(!line_end)
        return 0; /* 首行未完整 — 数据不足 */
    size_t line_len = (size_t)(line_end - buf);
    if(line_len > 0 && buf[line_len - 1] == '\r')
        line_len--;

    /* 区分请求/响应: 状态行以 "HTTP/" 开始 */
    if(line_len >= HTTP_PREFIX_LEN && memcmp(buf, HTTP_PREFIX, HTTP_PREFIX_LEN) == 0) {
        /* "HTTP/1.1 200 OK" */
        out->is_response = 1;
        const char *sp1  = (const char *)memchr(buf, ' ', line_len);
        if(!sp1)
            return -1;
        const char *sp2    = (const char *)memchr(sp1 + 1, ' ', (size_t)(buf + line_len - sp1 - 1));
        const char *st     = sp1 + 1;
        size_t      st_len = sp2 ? (size_t)(sp2 - st) : (size_t)(buf + line_len - st);
        if(st_len == 0 || st_len > 3)
            return -1;
        int code = 0;
        for(size_t i = 0; i < st_len; i++) {
            if(st[i] < '0' || st[i] > '9')
                return -1;
            code = code * 10 + (st[i] - '0');
        }
        out->status_code    = code;
        /* 版本: buf+5 .. sp1 → "1.1" 等; 1.1+ 默认保持, 1.0 及更早 → 关 */
        const char *ver     = buf + HTTP_PREFIX_LEN;
        size_t      ver_len = (size_t)(sp1 - ver);
        out->keep_alive     = (ver_len == 3 && ver[0] == '1' && ver[1] == '.' && ver[2] >= '1');
    } else {
        /* "GET /path HTTP/1.1" — method/target 零拷贝引用 (无长度上限,
         * 由输入缓冲长度兜底; 无 NUL 结尾, 用 *_len 取长) */
        out->is_response = 0;
        const char *sp1  = (const char *)memchr(buf, ' ', line_len);
        if(!sp1)
            return -1;
        const char *sp2 = (const char *)memchr(sp1 + 1, ' ', (size_t)(buf + line_len - sp1 - 1));
        if(!sp2)
            return -1;
        size_t mlen = (size_t)(sp1 - buf);
        if(mlen == 0)
            return -1;
        out->method     = parse_method(buf, mlen);
        out->method_ref = buf;
        out->method_len = mlen;
        size_t tlen     = (size_t)(sp2 - sp1 - 1);
        if(tlen == 0)
            return -1;
        out->target         = sp1 + 1;
        out->target_len     = tlen;
        /* 版本: 1.1 精确匹配 → 默认保持; 其他 (1.0) → 关 */
        const char *ver     = sp2 + 1;
        size_t      ver_len = (size_t)(buf + line_len - ver);
        out->keep_alive = (ver_len == HTTP_VERSION_11_LEN && memcmp(ver, HTTP_VERSION_11, HTTP_VERSION_11_LEN) == 0);
    }

    /* 头区: \r\n\r\n 的第一组 \r\n 属于最后一个头行的结尾 — 头区须含之
     * (find_header_in 按行解析, 行以 \n 结束), 截止到空行起点 (hdr_end+2). */
    out->headers_start = line_end + 1;
    out->headers_len   = (size_t)((hdr_end + 2) - out->headers_start);

    /* 预解析头 (单次遍历匹配需要的键) */
    size_t      vlen;
    const char *v;
    bool        conn_upgrade = false;
    if((v = find_header_in(out->headers_start, out->headers_len, "connection", &vlen))) {
        if(hdr_has_token(v, vlen, "upgrade"))
            conn_upgrade = true;
        if(hdr_has_token(v, vlen, "close"))
            out->keep_alive = false;
    }
    if(conn_upgrade && find_header_in(out->headers_start, out->headers_len, "upgrade", &vlen))
        out->upgrade = true; /* Upgrade 头存在 + Connection 含 upgrade (RFC 7230 §6.7) */

    if((v = find_header_in(out->headers_start, out->headers_len, "content-length", &vlen))) {
        size_t cl = 0;
        for(size_t i = 0; i < vlen; i++) {
            unsigned digit = (unsigned)(v[i] - '0');
            if(digit > 9)
                return -1; /* 非法 CL */
            /* 防 cl*10+digit 回绕 (含 cl == SIZE_MAX/10 且 digit≥6 的边界) */
            if(cl > ((size_t)-1 - digit) / 10)
                return -1; /* 溢出 */
            cl = cl * 10 + digit;
        }
        out->content_length = cl;
        /* 重复 CL 头: RFC 7230 §3.3.2 — 值一致可容忍 (代理/框架常见), 冲突必拒
         * (走私面) */
        size_t      v2len;
        const char *v2 = find_header_nth(out->headers_start, out->headers_len, "content-length", 1, &v2len);
        if(v2) {
            size_t cl2 = 0;
            for(size_t i = 0; i < v2len; i++) {
                unsigned digit = (unsigned)(v2[i] - '0');
                if(digit > 9)
                    return -1;
                if(cl2 > ((size_t)-1 - digit) / 10)
                    return -1;
                cl2 = cl2 * 10 + digit;
            }
            if(cl2 != cl)
                return -1; /* 冲突 CL → 协议错误 */
        }
    }

    if((v = find_header_in(out->headers_start, out->headers_len, "transfer-encoding", &vlen))) {
        if(hdr_has_token(v, vlen, "chunked")) {
            out->chunked = true;
            return -1; /* 初版不支持 chunked — 明确拒绝 (上层回 400) */
        }
    }

    /* 分帧: body 从头区结束起, 按 CL 收齐 */
    const char *bstart = hdr_end + 4;
    size_t      avail  = (size_t)(buf + len - bstart);
    if(avail < out->content_length)
        return 0; /* body 未收齐 */
    out->body     = bstart;
    out->body_len = out->content_length;
    return 1; /* 完整 */
}

const char *sevent_http_find_header(const sevent_http_msg *m, const char *name, size_t *val_len) {
    if(!m || !name)
        return NULL;
    return find_header_in(m->headers_start, m->headers_len, name, val_len);
}

/* ===== 构建骨架 ===== */

static int append_str(char *buf, size_t cap, size_t *n, const char *s) {
    size_t slen = strlen(s);
    if(*n + slen >= cap)
        return -1;
    memcpy(buf + *n, s, slen);
    *n += slen;
    return 0;
}

int sevent_http_build_request(char       *buf,
                              size_t      cap,
                              const char *method,
                              const char *target,
                              const char *host,
                              uint16_t    port,
                              const char *extra_headers) {
    size_t n = 0;
    if(append_str(buf, cap, &n, method) < 0 || append_str(buf, cap, &n, " ") < 0 ||
       append_str(buf, cap, &n, target) < 0 || append_str(buf, cap, &n, " HTTP/1.1\r\nHost: ") < 0 ||
       append_str(buf, cap, &n, host) < 0)
        return -1;
    char port_buf[16];
    int  plen = snprintf(port_buf, sizeof(port_buf), ":%u\r\n", (unsigned)port);
    if(plen < 0 || (size_t)plen >= sizeof(port_buf) || append_str(buf, cap, &n, port_buf) < 0)
        return -1;
    if(extra_headers && append_str(buf, cap, &n, extra_headers) < 0)
        return -1;
    if(append_str(buf, cap, &n, "\r\n") < 0)
        return -1;
    if(n < cap)
        buf[n] = '\0'; /* NUL 结尾 (调用方可能用字符串函数) */
    return (int)n;
}

int sevent_http_build_response(char *buf, size_t cap, int status, const char *text, const char *extra_headers) {
    size_t n = 0;
    char   head[64];
    int    hlen = snprintf(head, sizeof(head), "HTTP/1.1 %d %s\r\n", status, text);
    if(hlen < 0 || (size_t)hlen >= sizeof(head) || append_str(buf, cap, &n, head) < 0)
        return -1;
    if(extra_headers && append_str(buf, cap, &n, extra_headers) < 0)
        return -1;
    if(append_str(buf, cap, &n, "\r\n") < 0)
        return -1;
    if(n < cap)
        buf[n] = '\0'; /* NUL 结尾 */
    return (int)n;
}
