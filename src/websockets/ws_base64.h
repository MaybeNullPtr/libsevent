/* =========================================================================
 *  ws_base64.h — Base64 编码 (RFC 4648 §4)
 *
 *  仅实现编码方向 — WebSocket 握手只需要 base64(SHA1(...)).
 *  ========================================================================= */

#ifndef SEVENT_WS_BASE64_H
#define SEVENT_WS_BASE64_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 编码后的缓冲区大小 (含 NUL). */
size_t ws_base64_encode_size(size_t raw_len);

/*
 * Base64 编码.
 * raw:     输入数据
 * raw_len: 输入长度
 * dst:     输出缓冲区
 * dst_cap: 输出容量 (应 >= ws_base64_encode_size(raw_len))
 * 返回:    写入 dst 的字节数 (不含 NUL), <0 表示 dst 容量不足.
 */
int ws_base64_encode(const void *raw, size_t raw_len, char *dst, size_t dst_cap);

#ifdef __cplusplus
}
#endif

#endif /* SEVENT_WS_BASE64_H */
