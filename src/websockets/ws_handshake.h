/* =========================================================================
 *  ws_handshake.h — WebSocket HTTP Upgrade 握手 (RFC 6455 §4)
 *
 *  职责:
 *    - 生成随机 Sec-WebSocket-Key
 *    - 构建客户端 Upgrade 请求
 *    - 解析服务端 101 响应并验证 Accept
 *  ========================================================================= */

#ifndef SEVENT_WS_HANDSHAKE_H
#define SEVENT_WS_HANDSHAKE_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* GUID 常量 (RFC 6455 §4.2.2) */
#define WS_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

/* 握手相关常量 */
#define WS_KEY_BASE64_LEN 25    /* 16 字节随机数 → base64 (24 字符 + NUL) */
#define WS_ACCEPT_BASE64_LEN 29 /* 20 字节 SHA1 → base64 (含 NUL) */

/* HTTP 状态码 (握手/重定向判断用) */
#define WS_HTTP_STATUS_SWITCHING 101 /* 101 Switching Protocols */
#define WS_HTTP_STATUS_REDIRECT_MIN 300
#define WS_HTTP_STATUS_REDIRECT_MAX 399

/* ws:// 无端口时的默认端口 */
#define WS_DEFAULT_PORT 80

/* permessage-deflate 协商参数名 (RFC 7692 §7.1, offer/解析共用) */
#define WS_EXT_PMD "permessage-deflate"
#define WS_EXT_SERVER_NO_CTX "server_no_context_takeover"
#define WS_EXT_CLIENT_NO_CTX "client_no_context_takeover"
#define WS_EXT_CLIENT_MAX_WB "client_max_window_bits"

/* HTTP 响应头名 (小写, 解析用 ci_eq 比较) */
#define WS_HDR_EXTENSIONS "sec-websocket-extensions"
#define WS_HDR_PROTOCOL "sec-websocket-protocol"
#define WS_HDR_ACCEPT "sec-websocket-accept"
#define WS_HDR_LOCATION "location"

/* ===== 握手响应解析结果 ===== */
typedef struct {
    int  status_code;                  /* 应 = 101 */
    char accept[WS_ACCEPT_BASE64_LEN]; /* Sec-WebSocket-Accept 原始值 */
    char protocol[64];                 /* Sec-WebSocket-Protocol 协商结果 */
    char location[256];   /* Location 头 (重定向用) */
    char extensions[256]; /* Sec-WebSocket-Extensions 头 (扩展协商) */
} ws_handshake_response;

/* ===== 生成随机 Sec-WebSocket-Key =====
 *
 * 写入 28 字节 base64 字符串 (含 NUL).
 * 使用 /dev/urandom; fallback 到 time+PID 种子 PRNG.
 */
void ws_gen_key(char key[WS_KEY_BASE64_LEN]);

/* ===== 构建 HTTP Upgrade 请求 =====
 *
 * 构建完整 GET 请求到 buf. 返回写入字节数 (含 \r\n 结尾).
 * sub_protocol 为 NULL 表示不请求子协议.
 * <0 表示 buf 容量不足.
 */
int ws_build_request(char       *buf,
                     size_t      cap,
                     const char *host,
                     uint16_t    port,
                     const char *path,
                     const char *key,
                     const char *sub_protocol,
                     bool        enable_deflate);

/* ===== 解析 HTTP 升级响应 =====
 *
 * 从 buf 中解析服务端握手响应.
 * 返回:   >0 = 解析完成 (resp.status_code 区分 101 与否, 101 需 ws_verify_accept)
 *         0  = 数据不足, 继续等待
 *         <0 = 协议错误 (非法 HTTP 响应)
 */
int ws_parse_response(const uint8_t *buf, size_t len, ws_handshake_response *resp);

/* ===== 验证 Sec-WebSocket-Accept =====
 *
 * 计算 SHA1(key + GUID) → base64, 与 accept 比较.
 * 返回: 0 = 匹配, <0 = 不匹配.
 */
int ws_verify_accept(const char *key, const char *accept);

#ifdef __cplusplus
}
#endif

#endif /* SEVENT_WS_HANDSHAKE_H */
