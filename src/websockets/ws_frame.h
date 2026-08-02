/* =========================================================================
 *  ws_frame.h — WebSocket 帧编解码 (RFC 6455 §5-6)
 *
 *  职责:
 *    - 帧头解析 (ws_frame_parse_header)
 *    - 帧头构建 (ws_frame_build_header)
 *    - 掩码应用 (ws_frame_apply_mask)
 *
 *  仅处理帧格式, 不维护分片状态, 不包含业务逻辑.
 *  ========================================================================= */

#ifndef SEVENT_WS_FRAME_H
#define SEVENT_WS_FRAME_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ===== Opcodes (RFC 6455 §11.8) ===== */
#define WS_OPCODE_CONT 0x0
#define WS_OPCODE_TEXT 0x1
#define WS_OPCODE_BINARY 0x2
#define WS_OPCODE_CLOSE 0x8
#define WS_OPCODE_PING 0x9
#define WS_OPCODE_PONG 0xA

/* ===== 帧头 (解析后的结构化表示) ===== */
typedef struct {
    uint8_t  fin;
    uint8_t  rsv1;
    uint8_t  rsv2;
    uint8_t  rsv3;        /* 1=最后帧, 0=还有续帧 */
    uint8_t  opcode;      /* 操作码 */
    uint8_t  mask;        /* 1=有掩码 (client→server 必为 1) */
    uint64_t payload_len; /* payload 长度 */
    uint8_t  mask_key[4]; /* 掩码密钥 (仅在 mask==1 时有效) */
} ws_frame_header;

/* ===== 帧头解析 =====
 *
 * 从 buf 中解析帧头, 写入 hdr.
 * 返回:    >0 = 帧头占用的字节数 (整个帧头已完整解析)
 *          0  = 数据不足, 需要更多字节
 *          <0 = 协议错误 (RSV 位非零, 非法 opcode, 超长 payload 等)
 */
int ws_frame_parse_header(const uint8_t *buf, size_t len, ws_frame_header *hdr);

/* ===== 掩码应用 =====
 *
 * 对 payload 做 XOR 掩码/去掩码操作 (原地).
 * mask_key 必须为 4 字节 (从帧头取得).
 */
void ws_frame_apply_mask(uint8_t *payload, uint64_t len, const uint8_t mask_key[4]);

/* 带偏移掩码应用: 流式大帧边收边消费时, chunk 是 payload 的片段 —
 * XOR 周期按 payload 内全局偏移推进 (key[(offset+i) & 3]), 非从头重算.
 * offset = 本 chunk 在 payload 内的起始偏移 (帧总长 - 未消费剩余). */
void ws_frame_apply_mask_offset(uint8_t *payload, uint64_t len, const uint8_t mask_key[4], uint64_t offset);

/* ===== 帧头构建 =====
 *
 * 构建帧头到 buf. mask_key 为 NULL 表示不掩码 (server→client),
 * 非 NULL 表示掩码 (client→server).
 * 返回: 写入 buf 的字节数, <0 表示参数错误.
 */
int ws_frame_build_header(
        uint8_t *buf, uint8_t fin, uint8_t rsv1, uint8_t opcode, const uint8_t mask_key[4], uint64_t payload_len);

#ifdef __cplusplus
}
#endif

#endif /* SEVENT_WS_FRAME_H */
