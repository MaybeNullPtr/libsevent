# 测试矩阵（模块 ↔ 测试套件映射）

开发变更前对照本表：改了哪个模块，跑对应测试。**原则：改库必重编，验证一关再过一关。**

## 1. 测试资产总览

### 1.1 ctest 注册测试（主 build：`cd build && ctest -j$(nproc)`）

| ctest 名称 | 可执行文件 | 被测模块 | 覆盖内容 | 依赖选项 |
|---|---|---|---|---|
| unit_tests | test_sevent | 核心事件循环 | post/timer/io 注册/锁/唤醒语义 | — |
| ssl_tests | test-ssl | TLS 后端抽象 | ssl.c openssl/mbedtls 双后端回环 | SEVENT_WS_TLS |
| stream_conn_tests | test-stream-conn | stream 抽象层 | open/accept/回调/读写契约（TLS 用例含） | (TLS 用例需 SEVENT_WS_TLS) |
| tcp_conn_tests | test-tcp-conn | tcp_conn 公开 API | create/open/accept/write/close 独立链路 | — |
| tls_conn_tests | test-tls-conn | tls_conn 公开 API | 握手/证书链失败/hostname 不匹配/mTLS | SEVENT_WS_TLS |
| ws_unit_tests | test-ws | ws 语法件 | ws_sha1 / ws_base64 / ws_frame | — |
| ws_conn_tests | test-ws-conn | ws_conn | 状态机/写队列/粘包/close 握手 | — |
| frag_stream_tests | test-frag-stream | ws_conn | 分片/流式（Autobahn 9.3.2/9.4.8 精简复现） | — |
| redirect_tests | test-redirect | ws_conn+ws_handshake | 301 自动重定向 | — |
| deflate_tests | test-deflate | ws_deflate | 压缩/解压正确性 | SEVENT_WS_DEFLATE |
| wss_tests | test-wss | ws+stream TLS 链路 | wss 端到端/证书验证失败/hostname 映射 | SEVENT_WS_TLS |
| ws_server_tests | test-ws-server | ws 服务端入口 | accept/upgrade 端到端/掩码双向/非法握手/CLOSE 粘包忽略/OOM 注入（fd 归还 + alloc 平衡） | — |
| http_parse_tests | test-http-parse | http_parse 语法层 | 分帧/预解析/构建骨架 | — |
| http_server_tests | test-http-server | http_server 服务器层 | 8 态状态机/keep-alive/空闲超时/升级出口 | — |
| http_parse_fuzz_smoke | fuzz-http-parse | http_parse 语法层 | 变异输入回归（10 万次，~0.1s） | SEVENT_FUZZ |

### 1.2 手动测试

| 套件 | 入口 | 覆盖 | 何时跑 |
|---|---|---|---|
| Autobahn 全合规（双向） | `MODE=fuzzingserver ./tests/run_autobahn_docker.sh`（测 client）+ `MODE=fuzzingclient ./tests/run_autobahn_docker.sh`（测 server，需 deflate=ON） | 双向各 517 用例（帧/分片/流式/压缩/关闭握手） | ws 层任何改动后、发布前 |
| fuzz 大跑 | `./fuzz-http-parse [iterations] [seed]` | http_parse 深度模糊（ASAN 下亿级迭代） | http_parse 改动后 |
| ASAN 全量 | `bash tools/test-asan.sh` | 全测试 + 内存/泄漏检测 | 提交前（CI 级验证） |

## 2. 模块 → 测试映射（改这里跑这些）

### 核心库（src/sevent.c / sevent_platform.c / sevent_i.h）

| 模块 | 相关测试 | 说明 |
|---|---|---|
| 事件循环（run_once/select/timer/post） | unit_tests | 直接单测 |
| 事件循环（任何改动） | **全部 ctest**（默认 10 个，全选项 14 个） | 所有层都构建在其上，语义变更必须全量回归 |
| 内存分配（sevent_set_allocator） | unit_tests + ASAN 全量 | 泄漏检测依赖替换分配器正确性 |

### TLS 后端抽象（src/ssl/ssl.c）

| 模块 | 相关测试 | 说明 |
|---|---|---|
| ssl.c 任一后端（openssl/mbedtls） | ssl_tests → tls_conn_tests → wss_tests | 自底向上：抽象回环 → 公开 API → 端到端 |

### stream 传输层（src/stream_conn.c / tcp_conn.c / tls_conn.c）

| 模块 | 相关测试 | 说明 |
|---|---|---|
| stream_conn 接口契约 | stream_conn_tests + tcp_conn_tests + tls_conn_tests | 抽象层改动波及两实现 |
| tcp_conn.c | tcp_conn_tests + stream_conn_tests + ws_conn_tests | ws 默认传输 |
| tls_conn.c | tls_conn_tests + stream_conn_tests + wss_tests | TLS 模式 |
| stream 半关（shutdown） | tcp_conn_tests + http_server_tests | http 响应后关依赖它 |

### ws 层（src/websockets/）

| 模块 | 相关测试 | 说明 |
|---|---|---|
| ws_conn.c 状态机 | ws_conn_tests + frag_stream_tests + wss_tests | 连接管理核心 |
| ws_conn.c 粘包/缓冲数学 | ws_conn_tests + frag_stream_tests | 分帧边界 |
| ws_conn.c 重定向 | redirect_tests | 301 → 自动重连 |
| ws_frame.c / ws_sha1.c / ws_base64.c | ws_unit_tests + ws_conn_tests | 帧编解码/握手原语 |
| ws_deflate.c | deflate_tests + ws_conn_tests（deflate=ON） | 压缩正确性 + 全链路 |
| ws_handshake.c（client） | ws_conn_tests + redirect_tests | 请求构建/响应解析 |
| ws 层任何改动 | **Autobahn 517 用例** | 合规基准，发布前必跑 |

### http 层（src/http_parse.c / http_server.c / include/sevent_http_*.h）

| 模块 | 相关测试 | 说明 |
|---|---|---|
| http_parse.c 语法层 | http_parse_tests + fuzz smoke/大跑 | 纯函数解析器，fuzz 优先；**改动也影响 ws 握手（共用底座）** |
| http_parse.c 任何改动 | **+ ws_conn_tests + redirect_tests** | ws 客户端握手已重构到 http_parse 底座上 |
| http_server.c 服务器层 | http_server_tests | 25 用例：状态机/keep-alive/超时/升级分派/矩阵非法调用/溢出契约/头注入规则（204/304/用户头） |
| http_server_i.h（内部接口） | ws_server_tests（upgrade_oom / accept_oom_fd） | OOM 注入: ws_upgrade 失败收尾 alloc 平衡 + ws_accept fd 归还 |
| sevent_http_*.h 公开头 | 对应层测试 + examples 编译 | 接口变更看 example 是否能编过 |

### 示例（examples/）

| 示例 | 验证点 | 手动验证 |
|---|---|---|
| example-http-server | http 服务器层 API | `curl` 各路径（keep-alive/async/404/405） |
| example-ws-client / example-chat-server | ws 客户端 API | 连 wstest/echo 服务端 |
| 其余示例（echo/timer/signal/…） | 核心库 API | 编译即验证 |

## 3. 构建矩阵

| build 目录 | 配置 | 用途 |
|---|---|---|
| build/ | `cmake .. -DCMAKE_BUILD_TYPE=Debug` | 默认全量（gcc） |
| build-openssl/ | `-DSEVENT_WS_TLS=ON`（openssl 后端） | TLS 相关测试（ssl/tls_conn/wss） |
| build-asan/ | `-DSEVENT_ASAN=ON`（+ 需要时 `SEVENT_WS_DEFLATE=ON`） | 内存/泄漏/越界检测 |
| build-fuzz/ | `-DSEVENT_FUZZ=ON -DSEVENT_ASAN=ON` | fuzz 目标 + smoke |
| build-ts/ | `-DSEVENT_THREAD_SAFE=ON` | **锁路径实际执行**（全量 ctest；锁代码在 OFF 构建是空宏，必须在此套验证） |

改 ws_conn.c / tcp_conn.c / stream_conn.c 的锁逻辑 → **+ build-ts 全量**（锁是编译期宏，OFF 构建测不到）。

mbedtls 后端：`-DSEVENT_WS_TLS=ON -DSEVENT_WS_TLS_BACKEND=MBEDTLS`。

## 4. 变更检查表（速查）

```
改 sevent.c / sevent_platform.c   → unit_tests + 全量 ctest + ASAN
改 ssl.c                          → ssl_tests → tls_conn_tests → wss_tests
改 stream_conn 接口                → stream_conn + tcp_conn + tls_conn + ws_conn + wss
改 tcp_conn.c                     → tcp_conn + stream_conn + ws_conn + http_server
改 tls_conn.c                     → tls_conn + stream_conn + wss
改 ws_conn.c                      → ws_conn + frag_stream + redirect + wss + Autobahn
改 ws_frame/sha1/base64           → ws_unit + ws_conn + Autobahn
改 ws_deflate                     → deflate + ws_conn(deflate=ON) + Autobahn(deflate=ON)
改 ws_handshake                   → ws_conn + redirect + http_parse(共用底座)
改 http_parse.c                   → http_parse + fuzz + http_server + ws_conn + redirect + Autobahn
改 http_server.c                  → http_server + example-http-server 手动 curl
改 http_server_i.h                → http_server +（阶段③ 后）ws 侧升级测试
改公开头文件                       → 对应层测试 + 全量编译（examples 是编译冒烟）
```

## 5. 纪律提醒（历史教训）

- **改库必重编**：修改 src/ 后必须重新 make，不能只重跑旧二进制（build.sh 全量 clean 重建防残留）
- **验证一关再过一关**：单测绿 → 集成绿 → Autobahn 绿 → 发布
- **有怀疑先打日志**：不要凭记忆猜行为，加日志复现后再断言
- **ASAN 是提交门槛**：`tools/test-asan.sh` 跑全量，泄漏/越界零容忍
