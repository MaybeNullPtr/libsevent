/* =========================================================================
 *  ws_frame.c — WebSocket 帧编解码 (RFC 6455 §5-6)
 *
 *  纯帧层: 无状态, 无分配, 无业务逻辑.
 *  ========================================================================= */

#include "ws_frame.h"

/* ---- Byte 0 中各字段的掩码/位移 ---- */
#define FIN_BIT 0x80
#define RSV1_BIT 0x40
#define RSV2_BIT 0x20
#define RSV3_BIT 0x10
#define RSV_MASK 0x70 /* RSV1|RSV2|RSV3 */
#define OPCODE_MASK 0x0F

/* ---- Byte 1 中各字段的掩码 ---- */
#define MASK_BIT 0x80
#define LEN7_MASK 0x7F

/* ---- 扩展长度标记 ---- */
#define LEN16_CODE 126
#define LEN64_CODE 127

int ws_frame_parse_header(const uint8_t *buf, size_t len, ws_frame_header *hdr) {
    /* 最少需要 2 字节 */
    if(len < 2)
        return 0;

    /* ---- 解析 Byte 0 ---- */
    uint8_t b0  = buf[0];
    /* RSV 位由上层协议 (如 permessage-deflate) 协商后检查, 此处仅记录 */
    hdr->fin    = (b0 & FIN_BIT) ? 1 : 0;
    hdr->rsv1   = (b0 & RSV1_BIT) ? 1 : 0;
    hdr->rsv2   = (b0 & RSV2_BIT) ? 1 : 0;
    hdr->rsv3   = (b0 & RSV3_BIT) ? 1 : 0;
    hdr->opcode = b0 & OPCODE_MASK;

    /* ---- 解析 Byte 1 ---- */
    uint8_t b1   = buf[1];
    hdr->mask    = (b1 & MASK_BIT) ? 1 : 0;
    uint8_t len7 = b1 & LEN7_MASK;

    /* ---- 解析扩展长度 ---- */
    size_t offset = 2;
    if(len7 < LEN16_CODE) {
        hdr->payload_len = len7;
    } else if(len7 == LEN16_CODE) {
        if(len < 4)
            return 0; /* 需要 2+2=4 字节 */
        hdr->payload_len = ((uint64_t)buf[2] << 8) | (uint64_t)buf[3];
        offset           += 2;
    } else { /* len7 == 127 */
        if(len < 10)
            return 0; /* 需要 2+8=10 字节 */
        hdr->payload_len = 0;
        for(int i = 0; i < 8; i++) {
            hdr->payload_len = (hdr->payload_len << 8) | (uint64_t)buf[2 + i];
        }
        /* RFC 6455 §5.2: MSB of 64-bit length MUST be 0 */
        if(buf[2] & 0x80)
            return -1;
        offset += 8;
    }

    /* ---- 解析掩码 ---- */
    if(hdr->mask) {
        if(len < offset + 4)
            return 0;
        hdr->mask_key[0] = buf[offset];
        hdr->mask_key[1] = buf[offset + 1];
        hdr->mask_key[2] = buf[offset + 2];
        hdr->mask_key[3] = buf[offset + 3];
        offset           += 4;
    }

    return (int)offset;
}

void ws_frame_apply_mask(uint8_t *payload, uint64_t len, const uint8_t mask_key[4]) {
    for(uint64_t i = 0; i < len; i++) {
        payload[i] ^= mask_key[i & 3];
    }
}

int ws_frame_build_header(
        uint8_t *buf, uint8_t fin, uint8_t rsv1, uint8_t opcode, const uint8_t mask_key[4], uint64_t payload_len) {
    /* 参数校验 */
    if(rsv1 & ~1)
        return -1;
    if(opcode > 0x0F)
        return -1;

    size_t offset = 0;

    /* Byte 0: FIN + RSV(0) + opcode */
    buf[offset++] = (uint8_t)((fin ? FIN_BIT : 0) | (rsv1 ? 0x40 : 0) | (opcode & OPCODE_MASK));

    /* Byte 1: MASK + payload length (7-bit 或扩展) */
    if(payload_len < LEN16_CODE) {
        buf[offset++] = (uint8_t)((mask_key ? MASK_BIT : 0) | (payload_len & LEN7_MASK));
    } else if(payload_len <= 0xFFFF) {
        buf[offset++] = (uint8_t)((mask_key ? MASK_BIT : 0) | LEN16_CODE);
        buf[offset++] = (uint8_t)(payload_len >> 8);
        buf[offset++] = (uint8_t)(payload_len);
    } else {
        buf[offset++] = (uint8_t)((mask_key ? MASK_BIT : 0) | LEN64_CODE);
        /* 64-bit big-endian */
        for(int i = 7; i >= 0; i--) {
            buf[offset++] = (uint8_t)(payload_len >> (i * 8));
        }
    }

    /* Mask key */
    if(mask_key) {
        buf[offset++] = mask_key[0];
        buf[offset++] = mask_key[1];
        buf[offset++] = mask_key[2];
        buf[offset++] = mask_key[3];
    }

    return (int)offset;
}
