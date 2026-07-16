#!/usr/bin/env python3
"""WebSocket echo server — 配合 ws_client.c demo 测试.

usage: python3 ws_echo_server.py [port]
  默认端口 9000
"""

import asyncio
import sys

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 9000


async def echo_handler(reader, writer):
    """处理一个 WebSocket 连接."""
    # ----- HTTP Upgrade 握手 -----
    data = await reader.readuntil(b"\r\n\r\n")
    req = data.decode("utf-8", errors="replace")
    # 提取 Sec-WebSocket-Key
    key = None
    for line in req.split("\r\n"):
        if line.lower().startswith("sec-websocket-key:"):
            key = line.split(":", 1)[1].strip()
            break
    if not key:
        writer.close()
        return

    # 计算 Sec-WebSocket-Accept
    import hashlib, base64
    GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    accept = base64.b64encode(
        hashlib.sha1((key + GUID).encode()).digest()
    ).decode()

    resp = (
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Accept: {accept}\r\n"
        "\r\n"
    )
    writer.write(resp.encode())
    await writer.drain()

    peer = writer.get_extra_info("peername")
    print(f"[connect] {peer}")

    # ----- WebSocket 数据帧循环 -----
    buf = bytearray()
    try:
        while True:
            chunk = await reader.read(4096)
            if not chunk:
                break
            buf.extend(chunk)

            while True:
                if len(buf) < 2:
                    break
                fin = (buf[0] >> 7) & 1
                opcode = buf[0] & 0x0F
                masked = (buf[1] >> 7) & 1
                length = buf[1] & 0x7F
                offset = 2

                if length == 126:
                    if len(buf) < 4:
                        break
                    length = (buf[2] << 8) | buf[3]
                    offset = 4
                elif length == 127:
                    if len(buf) < 10:
                        break
                    length = 0
                    for i in range(8):
                        length = (length << 8) | buf[2 + i]
                    offset = 10

                mask_key = None
                if masked:
                    if len(buf) < offset + 4:
                        break
                    mask_key = buf[offset:offset + 4]
                    offset += 4

                if len(buf) < offset + length:
                    break

                payload = bytearray(buf[offset:offset + length])
                if mask_key:
                    for i in range(len(payload)):
                        payload[i] ^= mask_key[i & 3]

                # 处理帧
                if opcode == 0x8:  # Close
                    code = 1000
                    reason = b""
                    if len(payload) >= 2:
                        code = (payload[0] << 8) | payload[1]
                        reason = bytes(payload[2:])
                    print(f"[close] code={code} reason={reason.decode(errors='replace')}")
                    # 回 Close
                    close_payload = bytearray([code >> 8, code & 0xFF])
                    frame = bytearray([0x88, 0x02, close_payload[0], close_payload[1]])
                    writer.write(frame)
                    await writer.drain()
                    writer.close()
                    return

                elif opcode == 0x9:  # Ping
                    # 自动回 Pong
                    frame = bytearray([0x8A, len(payload)] + list(payload))
                    writer.write(frame)
                    await writer.drain()

                elif opcode in (0x1, 0x2):  # Text / Binary
                    text = bytes(payload).decode("utf-8", errors="replace") if opcode == 0x1 else str(payload)
                    print(f"[recv] {text[:120]}")

                    # Echo back (server → client, 无掩码)
                    if opcode == 0x1:
                        encoded = payload
                        frame = bytearray([0x81, len(encoded)]) + encoded
                    else:
                        frame = bytearray([0x82, len(payload)]) + payload
                    writer.write(frame)
                    await writer.drain()
                    print(f"[echo] {text[:120]}")

                # 移除已处理的数据
                del buf[:offset + length]

    except (ConnectionError, asyncio.IncompleteReadError):
        pass
    finally:
        print(f"[disconnect] {peer}")
        writer.close()


async def main():
    server = await asyncio.start_server(echo_handler, "127.0.0.1", PORT)
    addr = server.sockets[0].getsockname()
    print(f"WS echo server listening on ws://{addr[0]}:{addr[1]}/echo")
    print(f"Run client: ./example-ws-client ws://{addr[0]}:{addr[1]}/echo")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
