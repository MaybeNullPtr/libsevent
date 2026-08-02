/* =========================================================================
 *  sevent_http_parse.h — HTTP 语法层 (分帧 + 惰性解析, 纯函数无连接状态)
 *
 *  职责 (设计定案):
 *    - 分帧: 请求行/状态行 + 头区边界 (\r\n\r\n) + Content-Length 收 body
 *    - 预解析服务器运行必需的少量字段: method/target/status_code/upgrade/
 *      keep_alive/content_length — 其余 header 不解析, 用户按需调
 *      sevent_http_find_header 惰性扫描
 *    - 构建骨架: 请求 (行 + Host + 注入点) / 响应 (状态行 + 注入点)
 *
 *  零拷贝: 所有指针指向输入缓冲 — 调用方保证缓冲在解析结果使用期间有效.
 *  纯函数: 无连接对象, 无内部状态, 可并发调用.
 *
 *  用途: http server 请求解析 + ws 客户端握手响应解析 + ws 服务端握手请求
 *        解析 — ws 与 http 共用同一语法底座.
 *  ========================================================================= */

#ifndef SEVENT_HTTP_PARSE_H
#define SEVENT_HTTP_PARSE_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h> /* sevent_http_str_eq 的 memcmp/strlen */

#ifdef __cplusplus
extern "C" {
#endif

/* ===== 方法枚举 (RFC 9110 §9.1 标准方法; 未知方法落 UNKNOWN, 引用仍可用) ===== */
typedef enum {
    HTTP_METHOD_UNKNOWN = 0, /* 非标准方法 (WebDAV/扩展): 用 method_ref/method_len 字符串处理 */
    HTTP_METHOD_GET,
    HTTP_METHOD_HEAD,
    HTTP_METHOD_POST,
    HTTP_METHOD_PUT,
    HTTP_METHOD_DELETE,
    HTTP_METHOD_OPTIONS,
    HTTP_METHOD_PATCH,
    HTTP_METHOD_CONNECT,
    HTTP_METHOD_TRACE,
} sevent_http_method;

/* ===== 解析结果 (分帧 + 预解析) =====
 * 全部字段零拷贝: 指针指向输入缓冲 (无 NUL 结尾, 用 *_len 取长) —
 * msg 仅在输入缓冲存活期间有效 (http server 场景 = 回调内). */
typedef struct sevent_http_msg {
    bool               is_response; /* true=响应(状态行) / false=请求(请求行) */
    sevent_http_method method;      /* 预解析: 标准方法枚举 (UNKNOWN=非标准, 用下方引用) */
    const char        *method_ref;  /* 请求行 method 原始引用 (零拷贝, UNKNOWN 时用) */
    size_t             method_len;
    const char        *target; /* 请求行预解析: /path (is_response 时为 NULL) */
    size_t             target_len;
    int                status_code; /* 响应: 任意状态码, 不枚举 */

    /* ---- 分帧 + 服务器运行必需 (预解析) ---- */
    bool        upgrade;        /* Upgrade 头存在 + Connection 含 upgrade (RFC 7230 §6.7) */
    bool        keep_alive;     /* 连接是否保持: HTTP/1.1 默认 true, Connection: close 或 HTTP/1.0 → false */
    size_t      content_length; /* Content-Length (分帧必需) */
    const char *body;           /* body 指针 (零拷贝, 指向输入缓冲; 分帧收齐后可用) */
    size_t      body_len;       /* 分帧收齐后 = content_length */
    bool        chunked;        /* Transfer-Encoding: chunked (初版不支持: 解析返回 <0) */

    /* ---- 原始头区 (按需解析用) ---- */
    const char *headers_start;
    size_t      headers_len;
} sevent_http_msg;

/* 零拷贝比较辅助: p 为 msg 内引用字段 (无 NUL 结尾), s 为 C 串.
 * 纯函数, 无共享状态, 可并发调用. */
static inline int sevent_http_str_eq(const char *p, size_t len, const char *s) {
    size_t sl = strlen(s);
    return (len == sl && memcmp(p, s, sl) == 0);
}

/* 拆分 target 为 path 与 query (零拷贝引用, 指向 target 内):
 *   "/api?a=1&b=2" → path="/api" query="a=1&b=2"; 无 '?' → query=NULL/0.
 * target/target_len 传 msg 的 target 字段 (或任意引用). 纯函数, 可并发. */
static inline void sevent_http_target_split(const char  *target,
                                            size_t       target_len,
                                            const char **path,
                                            size_t      *path_len,
                                            const char **query,
                                            size_t      *query_len) {
    const char *q = target ? (const char *)memchr(target, '?', target_len) : NULL;
    if(path)
        *path = target;
    if(path_len)
        *path_len = q ? (size_t)(q - target) : target_len;
    if(query)
        *query = q ? q + 1 : NULL;
    if(query_len)
        *query_len = q ? target_len - (size_t)(q - target) - 1 : 0;
}

/* 按名查 query 参数 (零拷贝引用, 指向 query 内; 与 find_header 同构的惰性按需):
 *   query="a=1&b=2" 查 "b" → val="2"; 未找到 → NULL.
 * query/query_len 传 target_split 的 query 输出. 参数名大小写敏感,
 * 同名重复取第一个; 空值参数 ("a=") → 指针有效 val_len=0; 无 '=' 的段跳过.
 * 纯函数, 可并发. */
static inline const char *
sevent_http_query_get(const char *query, size_t query_len, const char *name, size_t *val_len) {
    if(!query || !name)
        return NULL;
    size_t      nlen = strlen(name);
    const char *p    = query;
    const char *end  = query + query_len;
    while(p < end) {
        const char *q = (const char *)memchr(p, '&', (size_t)(end - p));
        if(!q)
            q = end;
        const char *eq = (const char *)memchr(p, '=', (size_t)(q - p));
        if(eq && (size_t)(eq - p) == nlen && memcmp(p, name, nlen) == 0) {
            *val_len = (size_t)(q - eq - 1);
            return eq + 1;
        }
        p = q < end ? q + 1 : q;
    }
    return NULL;
}

/*
 * 分帧解析 HTTP 请求/响应.
 * 预解析: method/target/status_code/upgrade/keep_alive/content_length (+ body 分帧).
 * 返回: >0 = 完整请求/响应 (含 body 收齐); 0 = 数据不足, 等更多; <0 = 协议错误.
 *       头区边界未到或 body 未收齐 → 0; 行/头格式非法、CL 非法/溢出/冲突、
 *       chunked 请求 (初版不支持) → <0.
 * 约束: buf/out 必须非 NULL (NULL → <0). 输入缓冲须在 msg 使用期间存活
 *       (全部字段零拷贝引用); msg 可经 memset 清零后重复使用.
 */
int sevent_http_parse(const char *buf, size_t len, sevent_http_msg *out);

/*
 * 按需查 header: 惰性扫描头区, 大小写不敏感匹配.
 * 返回: 值指针 + 长度 (指向输入缓冲, 零拷贝), 未找到返回 NULL.
 * 非预解析字段 (cookie/auth 等) 用此函数. msg 须为解析成功 (>0) 的结果.
 */
const char *sevent_http_find_header(const sevent_http_msg *m, const char *name, size_t *val_len);

/*
 * 构建请求骨架: "METHOD target HTTP/1.1\r\nHost: host:port\r\n" + extra + "\r\n".
 * extra: 调用方拼的完整头行, 每行必须以 "\r\n" 结尾 (如
 *   "Upgrade: websocket\r\nConnection: Upgrade\r\n"), NULL=无额外头.
 * 返回: 写入字节数 (含结尾 \r\n); <0 = 容量不足 (buf 未写).
 */
int sevent_http_build_request(char       *buf,
                              size_t      cap,
                              const char *method,
                              const char *target,
                              const char *host,
                              uint16_t    port,
                              const char *extra_headers);

/*
 * 构建响应骨架: "HTTP/1.1 status text\r\n" + extra + "\r\n".
 * 101/400/... 通用; extra 为完整头行 (每行 "\r\n" 结尾, 同上), 如
 *   "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: xxx\r\n".
 * 返回: 写入字节数 (含结尾 \r\n); <0 = 容量不足 (buf 未写).
 */
int sevent_http_build_response(char *buf, size_t cap, int status, const char *text, const char *extra_headers);

#ifdef __cplusplus
}
#endif

#endif /* SEVENT_HTTP_PARSE_H */
