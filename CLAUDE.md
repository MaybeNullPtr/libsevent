# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

> **开发前先看 [doc/testing.md](doc/testing.md)** — 模块 ↔ 测试套件映射 + 变更检查表
> （改哪个模块跑哪些测试、构建矩阵、提交纪律）。

## Build

```bash
cd build && cmake .. -DCMAKE_BUILD_TYPE=Debug && make -j$(nproc)
```

Key CMake options:
- `-DSEVENT_WS_DEFLATE=ON` — WebSocket permessage-deflate compression (requires zlib)
- `-DSEVENT_WS_THREAD_SAFE=ON` — thread-safe WebSocket API
- `-DSEVENT_ASAN=ON` — AddressSanitizer (memory/leak detection)
- `-DSEVENT_TSAN=ON` — ThreadSanitizer (data race detection)

## Tests

```bash
cd build && cmake .. -DCMAKE_BUILD_TYPE=Debug && make -j$(nproc) && ctest --output-on-fire -j$(nproc)
```

Individual test targets:
- `test-ws` — WebSocket frame unit tests
- `test-ws-conn` — WebSocket connection integration tests
- `test-frag-stream` — fragment/stream tests
- `test-redirect` — redirect tests
- `test-deflate` — permessage-deflate compression tests
- `test_sevent` — core event loop unit tests

Run a single test directly:
```bash
cd build && ./test-ws
```

## Code Format

```bash
cd build && make format    # apply clang-format
make check-format          # dry-run check
```

## Code Architecture

### Libraries

**libsevent** (`src/sevent.c`, `src/sevent_platform.c`) — select-based event loop (~600 lines core). Three event types:

| Phase | Event | Description |
|-------|-------|-------------|
| ① | run_free_death | Reap deferred-delete IO/timer handles from previous iteration |
| ② | select | Build fd_set, poll for IO/timer |
| ③ | IO callbacks | Read/write callbacks on ready fds |
| ④ | run_posts | FIFO async tasks (sevent_post) |
| ⑤ | run_timers | Expired interval timers |

Thread safety: post/io_register/timer_register use internal locks; callbacks always run on the loop thread.

**libsevent_ws** (`src/websockets/`) — RFC 6455 WebSocket client library, built on libsevent.

### WebSocket Module Structure (`src/websockets/`)

| File | Role |
|------|------|
| `ws_conn.c/h` | Connection state machine — the main module. Handles handshake, frame processing, send queue, state transitions |
| `ws_frame.c/h` | Frame encode/decode — parse/build WS frames, apply mask |
| `ws_handshake.c/h` | HTTP Upgrade: build request, parse response (101 upgrade, 3xx redirect) |
| `ws_sha1.c/h` | SHA-1 for Sec-WebSocket-Accept |
| `ws_base64.c` | Base64 for Sec-WebSocket-Accept |
| `ws_deflate.c/h` | permessage-deflate (RFC 7692) — compress/decompress message payload |

### Connection State Machine (`ws_conn.c`)

States: `CONNECTING → HANDSHAKE → OPEN → CLOSING → CLOSED`

Key fields:
- `state` — enum ws_state (protocol state)
- `destroyed` — re-entry guard; set by `sevent_ws_close()`/`sevent_ws_destroy()` before free
- `recv_buf/recv_len/recv_pos` — receive buffer with cursor
- `frag_pending/frag_compressed` — fragmentation state
- `stream_active/stream_compressed` — large-frame streaming state
- `deflate` — permessage-deflate compression state

Callback safety: `sevent_ws_destroy()` defers `free(c)` via `sevent_post()` to `run_posts` phase, so the connection object stays alive during callback stack unwinding. All callbacks can safely read `c->destroyed` after returning from user code.

### Memory Allocation

Replaceable allocator via `sevent_set_allocator(my_malloc, my_free)`, defaults to libc. All internal allocations go through `sevent_i_malloc`/`sevent_i_free` (in `src/sevent_i.h`).

### Autobahn Tests

```bash
# Run the compressed 12.2.6 test specifically:
cd build && cmake .. -DSEVENT_WS_DEFLATE=ON && make autobahn_client
# Then run with a running fuzzingserver on port 9001:
./autobahn_client 127.0.0.1 9001
```
