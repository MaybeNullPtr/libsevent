# WebSocket 服务端设计（ws/wss server，双入口）

## 1. 目标与范围

为 libsevent_ws 增加服务端能力：接受客户端连接，完成 HTTP 升级（ws/wss），进入 OPEN 后与客户端完全对等的消息收发。支持**共用端口**（http 服务 + ws 服务器同一端口）。

- **范围内**：RFC 6455 服务端（握手接收、掩码方向、帧/分片/流式/压缩复用客户端引擎）、wss（TLS 证书、可选 mTLS）、共用端口（http_server 升级出口）、Autobahn fuzzingclient 合规验证
- **范围外（初版不做）**：子协议协商（不响应 offer）、路径策略、Origin 校验、压缩选参精调（A 方案：简化接受，见 §5.4）、多 host/SNI 证书选择

## 2. 接入模型（已定：双入口）

```
语法层:  sevent_http_parse (公开, 共用底座 — 见 http-layer-design.md)

共用端口:  sevent_http_server 监听 (端口宿主)
             ├─ 普通请求 → on_request → 应用层 http 处理 (keep-alive 多请求)
             └─ Upgrade 请求 → on_upgrade (返回 TAKEN/DECLINED 告知接管与否)
                    ├─ 拒绝: respond(4xx) → DECLINED → 连接留 http server
                    └─ 升级: sevent_ws_upgrade(conn, ws_cfg) → TAKEN
                           (调用即接管: 无论句柄是否 NULL, 连接已脱离 http 管理)

独立端口:  tcp_acceptor → sevent_ws_accept(fd, ws_cfg) → ws_conn
             (内部 sevent_http_parse, 非升级请求 → 400)
```

决策依据：
1. **共用端口分派必须在 ws 之上**：ws 独占连接解析会抢走非升级请求（http 服务收不到）——已否决"ws 内部解析"单入口
2. **协议引擎复用度 ~95%**：OPEN 后的帧/分片/压缩/流式/缓冲数学/close 握手两端逐字相同；数据面唯一差异是掩码方向
3. **与 stream_conn 哲学一致**：open/accept 双入口 → ws 层 connect/accept 双入口；升级（upgrade）是第三个入口，只差"请求已解析"这个起点
4. **TLS 角色已在 stream 层消化**：SSL_accept + 证书装载 ws 层零 TLS 新代码

## 3. 接口设计

### 3.1 独立端口入口

```c
/* fd 来自 tcp_acceptor 的 on_accept; 所有权契约: 成功 → 移交本层 (调用方不得
 * 再使用); 失败 → 归还调用方, 调用方负责 close (谁拥有谁关闭 — 库不关闭).
 * 流程: stream 建连 (enable_tls 时含 TLS 服务端握手) → ws 升级 (收请求回 101).
 * 返回: 句柄 (on_open 通知升级完成, on_error 通知失败), NULL=参数错误/内存不足. */
sevent_ws_conn *sevent_ws_accept(sevent_context *ev, int fd, const sevent_ws_config *cfg);
```

**fd 契约（全 accept 系统一）**：`sevent_tcp_conn_accept` / `sevent_stream_accept` / `sevent_ws_accept` 同规则——**成功才接管，失败归还**（失败时 fd 仍打开、归调用方）。http_server 内部同理：`srv_on_accept` 是 fd 最终拥有者（acceptor 回调内部，用户不可见），stream accept 失败由 http 层自关。

### 3.2 共用端口入口（升级转移）

```c
/* 在 http_server 的 on_upgrade 回调内调用 — 调用即升级决定 (决定权在用户,
 * 见 http-layer-design §4.4; 内部完成释放摘除, 无两段式 API):
 *   内部: i_release (摘除管理) → i_detach_stream + i_take_recv (资源移交,
 *         缓冲含完整升级请求 + 粘包残留) → ws 层自行解析请求 (与 accept
 *         同一条 ws_handshake_data_server 路径, http 零 ws 感知) → 同步握手.
 * 升级成功: conn 句柄作废 (http_conn 壳由库延迟释放), 回调返回后 http server
 *      检测 TAKEN → 跳过收尾; ws_cfg 中 TLS 字段一律忽略 (stream 已在
 *      http_server 侧完成 TLS 握手); ws_conn 已 OPEN, on_open 在 ws_upgrade
 *      调用栈内同步触发.
 * 失败 (NULL): 非法状态 → 连接留 http server; 资源已移交后失败 (OOM) →
 *      ws 层负责收尾 (stream 销毁 + 移交缓冲释放 + conn 壳 i_destroy),
 *      用户无需善后. on_upgrade 返回契约: 调用了本函数一律 TAKEN
 *      (无论句柄是否 NULL — 连接已脱离 http 管理). */
sevent_ws_conn *sevent_ws_upgrade(sevent_http_conn *conn, const sevent_ws_config *ws_cfg);
```

**升级转移的内部接口**（http_server_i.h / 本次，见 §3.6）——**纯资源移交，http 层零 ws 感知**（升级语义全部由 ws 层从移交缓冲解析）：

| 内部接口 | 职责 | 状态 |
|---|---|---|
| `sevent_http_conn_i_release` | 升级决定: 置 RELEASED + 摘列表 + 停空闲超时 (仅 on_upgrade 内, REQUEST 态) | 已实现 |
| `sevent_http_conn_i_detach_stream` | 取走 stream 所有权 (RELEASED 态) | 已实现 |
| `sevent_http_conn_i_take_recv` | 取走解析缓冲 (含**完整升级请求** + 粘包残留, len/cap 输出) | 已实现 |
| `sevent_http_conn_i_destroy` | 消费完成后延迟释放 http_conn 壳 (post) | 已实现 |
| `sevent_http_conn_i_ev` | 事件循环上下文 (ws_upgrade 建 ws_conn 用) | 已实现 |
| `sevent_stream_conn_i_set_callbacks` | 换 stream 回调组 (http 回调 → ws 回调) | 已实现 |

**升级失败路径收尾（OOM 全链，测试验证）**：`ws_conn_new` 失败 / ws 缓冲分配失败 → `sevent_stream_destroy(stream)`（fd 由 stream 层关）+ **`sevent_i_free(rbuf)`**（已取走的 http 缓冲必须归还 — 泄漏回归）+ `sevent_http_conn_i_destroy(conn)`（壳 + 未取的 http 缓冲回收）。三条缺一即泄漏（allocator 计数平衡断言覆盖）。

### 3.3 `sevent_ws_config` 字段按入口的语义

| 字段 | connect（客户端） | accept / upgrade（服务端） |
|---|---|---|
| host / port / path / tls_hostname | 生效 | **忽略**（连接已建立） |
| sub_protocol | 请求协商 | **忽略**（不响应 offer，初版不协商） |
| connect_timeout_ms | 生效 | 忽略（stream accept 不启动超时 timer，见 §4） |
| ping_interval_ms | 生效 | **生效**（服务端同样可发心跳） |
| enable_tls | wss 客户端 | **忽略**（upgrade：http_server 已握手；accept：由 stream accept 内 TLS 服务端握手决定，与 ws_cfg 无关）※ accept 场景 TLS 配置来源见 §3.4 |
| ca / cert / key | mTLS 可选 | upgrade：**忽略**；accept：见 §3.4 |
| enable_peer_verify | 校验服务器 | **mTLS 开关**（upgrade：忽略，随 http_server 配置） |
| enable_hostname_verify | 校验服务器名 | 忽略（对端无主机名概念） |
| recv_buf_size / enable_deflate / deflate 系列 | 生效 | **生效**（与 client 同语义；recv_buf_size 见 §3.7 缓冲数学） |
| 回调组 / user_data | 生效 | 生效（on_http_response 服务端无意义，忽略） |

### 3.4 accept 入口的 TLS 配置来源（已定 A）

**复用 `sevent_ws_config` 字段**：`sevent_ws_accept` 用 `cert_path`/`cert_pem`/`key_path`/`key_pem` + `enable_peer_verify`/`ca`——语义切换：connect=客户端 mTLS 可选 / **accept=服务端必填**（enable_tls=true 时缺 cert/key → accept 失败）/ upgrade=全部忽略。零新增结构，§3.3 表即三入口语义。

### 3.5 连接生命周期

- 所有权归用户：on_open 后持有，send/close/destroy 全部复用现有 API
- **upgrade 入口**：http_conn 壳已销毁，ws_conn 独立（http server 不再管理它）；**on_open 在 ws_upgrade 调用栈内同步触发**（请求已解析完，无等待期——101 构建入队即 OPEN）；accept 入口 on_open 在 stream 建连完成回调栈内（与 client 一致）
- destroy 纪律不变：回调内可 destroy（destroyed 标记 + post 延迟 free）
- get_state：accept 入口升级期（HANDSHAKE）显示 `SEVENT_WS_STATE_CONNECTING`（与 client 一致）；upgrade 入口无升级期（创建即 OPEN）

### 3.6 升级转移的内部接口细节（本阶段新增）

**a. `sevent_http_conn_i_destroy(conn)` — http_conn 壳延迟释放**
- RELEASED 连接已摘出 server 列表（release 时 conn_unlink），http server 不再管理——**内存必须由 ws_upgrade 消费完毕后释放**
- post 延迟释放：ws_upgrade 在 on_upgrade 回调栈内；回调返回后 http 层**零访问 c**（D4 枚举返回值 TAKEN/DECLINED 是唯一信息源，conn_dispatch 不再读 `c->released`）→ post 延迟是为了回调栈内安全展开，OOM 直调同样安全（无后续读）
- 约束：仅 RELEASED 态可调（未 release → 空操作）

**b. `sevent_stream_conn_i_set_callbacks(s, init)` — 换 stream 回调组**
- **缺口**：stream 层回调在 open/accept 时一次性传入（http server 建连时绑定的是 http 回调组 + user_data=conn）；升级后数据推送会进 `conn_on_data`（RELEASED 守卫直接丢弃）——**必须换成 ws 回调组**
- 实现：ops 表新增 `set_callbacks` 槽（stream_conn.c 转发 + tcp_conn.c/tls_conn.c 实现：覆盖 user_data/on_open/on_data/on_close/on_error 字段；connect_timeout_ms/recv_buf_size 忽略——连接已建立，无意义）
- 线程：ws_upgrade 在 [loop 线程]（on_upgrade 回调内）调用，与 stream 无并发；TLS 模式 tls_conn 转发到内部回调存储（实施时按 tls_conn 结构落地）

**c. 升级请求的解析（架构定案：ws 层自己做）**
- **关键事实**：`ws_upgrade` 在 on_upgrade 回调栈内同步调用——此时请求**还在 http 解析缓冲**（`request_after_callback` 在 on_upgrade 返回后才消费请求）
- 因此：`i_take_recv` 移交的缓冲含**完整升级请求**（+ 粘包残留），ws_upgrade 直接复用 accept 入口的 `ws_handshake_data_server`（ws_parse_request 解析 → 400/426/establish）——**upgrade 与 accept 握手同一条代码路径**
- http 层**零 ws 感知**：不保存 key、不解析 extensions（曾错误地由 http 层保存 Sec-WebSocket-Key + deflate offer 标志——已移除，回归纯资源移交）

### 3.7 升级缓冲移交（修正设计）

**设计文档原论证有误，本阶段修正**：
- 原：`i_take_recv` 指针移交 → "残留 ≤ 缓冲容量，缓冲数学恒成立，无需拷贝"
- 实际：http server 的 stream 推送上限 = `recv_cap`（[http_server.c:313](src/http_server.c#L313) `init.recv_buf_size = c->recv_cap`，默认 4096），而 ws 缓冲数学要求**推送 ≤ recv_cap/2**（[ws_stream_init](src/websockets/ws_conn.c#L1050) 推送 = cap/2 是有意为之：帧 ≤ cap/2 路由阈值 + 推送 ≤ cap/2 → 残留 + 推送 ≤ cap 恒成立）。升级移交后：
  - 残留（粘包帧）理论上限 = 原缓冲容量 C（HTTP 请求可小到 ~20 字节，剩余几乎全是残留）
  - 后续 stream 推送 ≤ C（已定死，stream 层不可改）
  - **残留 + 推送 ≤ 2C > C → 溢出**（ws 侧数学被破坏）
- **修正方案：ws_upgrade 内重分配 2C 缓冲并拷贝残留**（一次性 memcpy ≤ 4096 字节，仅升级连接发生一次）：
  ```
  newcap = 2 * rcap          /* 推送 ≤ rcap = newcap/2, 残留 ≤ rcap = newcap/2 */
  → 残留 + 推送 ≤ newcap 恒成立 — 与 client 路径数学完全一致, 零新分支
  frag_buf 同步分配 = newcap
  ```
- 缓冲数学注释（ws_stream_on_data 的"数学上不可达"防御）升级路径同样成立，无需改动

### 3.8 新建入口的公共初始化骨架

`sevent_ws_connect` 的初始化（分配 c / 锁 / 缓冲 / stream_cfg 拷贝 / 回调拷贝）抽出为内部 `ws_conn_new(ev, cfg, is_client)`，三入口复用：

| 入口 | ws_conn_new 后 |
|---|---|
| connect | stream_create + stream_open(host, port)（现状路径，is_client=true） |
| accept | stream_create + stream_accept(fd)（TLS 服务端握手在 stream 内部；is_client=false） |
| upgrade | 外部注入：i_detach_stream + i_set_callbacks + i_take_recv(2×重分配) + 同步握手（is_client=false） |

## 4. 状态机适配

```
ws_accept:   CONNECTING(瞬过) → HANDSHAKE(收请求回 101) → OPEN
ws_upgrade:  请求已由 http_server 解析完 → 校验/算 accept → 写 101 → OPEN (同步完成)
```

- **落地（审查已补）**：`ws_stream_on_open`（[ws_conn.c:1331](src/websockets/ws_conn.c#L1331)）现为纯 client 逻辑——按 `c->is_client` 分支：server 分支不写请求（无 key 可生成），置 HANDSHAKE 等数据（accept 入口）；upgrade 入口无 on_stream_open（stream 已在 http_server 侧就绪，ws_upgrade 直接建 ws_conn 并同步握手）
- **ws_upgrade 的 101 响应**：构建 → stream_write（异步入队）→ 立即置 OPEN + 触发 on_open（on_open 在回调栈内；客户端等 101 完整再发数据，写队列保证发送）
- **升级期超时（审查更新）**：**upgrade 入口已被覆盖**——http server 的 idle_timeout 计入"连接建立后到首个完整请求"的等待，客户端连上不发升级请求会被超时关；**accept 入口仍无**（stream accept 不启动 timer），与 client 握手期现状一致，用户自管
- HANDSHAKE/OPEN/CLOSING/CLOSED 其余逻辑零改动

## 5. 协议差异处理

### 5.1 掩码方向（唯一数据面差异 + 现状合规修正）

| 方向 | 规则 | 现状 | 改动 |
|---|---|---|---|
| client → server | **必须** mask | 收到 mask 就去 mask，未校验 | **server 模式补校验**：未 mask 客户端帧 → 1002 |
| server → client | **不得** mask | 发送无条件 mask | 加 `c->is_client`：server 发送不 mask |
| client 收帧 | **不得** mask（RFC 6455 §5.1：客户端收到 mask 帧必须关） | **未校验（合规缺口）** | **client 模式补校验**：mask 帧 → 1002 |

- 统一校验公式：`if(hdr.mask == c->is_client) return SEVENT_WS_ERR_PROTOCOL;`（server 要求 mask=true，client 要求 mask=false，两行合一）
- 发送：`ws_frame_build_header(hdr, c->is_client, ...)`（mask 标志 = is_client）+ `if(c->is_client) ws_frame_apply_mask(...)`
- client 模式补校验是合规改进（Autobahn 517 回归验证无行为变化——fuzzingserver 不发 mask 帧给 client）

### 5.2 握手反向（ws_handshake server 侧）

- `ws_parse_request`（基于 sevent_http_parse + find_header）：校验 Upgrade 值==websocket / Connection 含 upgrade / Key 存在 / Version==13 / 请求行 method==GET；提取 key + deflate offer
- `ws_build_response`：计算 accept（ws_sha1+GUID+base64，算法已在 test_ws_wss.c 验证）+ sevent_http_build_response 构建 101（+PMD 确认行，见 §5.4）
- **分发点**：`ws_handshake_data` 按 `c->is_client` 分支——server 分支解析请求/回 101；粘包残留帧处理与 client 101 模式对称（recv_pos 跳过 HTTP 请求 + process_frames）
- **非法请求 → 400 / 版本错 → 426**（RFC 6455 §4.4：不支持的版本必须回 426 + `Sec-WebSocket-Version: 13`）：
  - 响应构建 → stream_write 入队 → shutdown(WR) 半关（队列 flush 后 FIN）→ on_error(SEVENT_WS_ERR_HANDSHAKE) → CLOSING 等对端 EOF 收尾
  - 发送时序：shutdown(WR) 保证 400/426 发完（P1 修复后 flush 完成才执行）——不用立即 close（会丢未 flush 队列）
- upgrade 入口的非法请求由 http_server 处理（on_upgrade 前解析失败 → http_server 回 400），ws 层不再见

### 5.3 ws_handshake 瘦身（依赖 sevent_http_parse）

| 现有（client） | 重构后 |
|---|---|
| [ws_build_request](src/websockets/ws_handshake.c#L54) 硬编码 ws 头 | sevent_http_build_request 骨架 + ws 层拼 Upgrade/Connection/Key/Version 头行 ✓ 已完成（工作区） |
| [ws_parse_response](src/websockets/ws_handshake.c#L128)（语法+提取） | sevent_http_parse + find_header 提取 + ws_verify_accept；非 101 响应带 CL body 按"仅头区"语义 ✓ 已完成（工作区） |
| — | **新增 server**：ws_parse_request / ws_build_response（本阶段） |

**新增 server 侧接口**（ws_handshake.h）：

```c
typedef struct ws_handshake_request {
    int  status;        /* 0=合法 / -1=语法错 / 400=普通非法 / 426=版本不支持 */
    char key[WS_KEY_BASE64_LEN];  /* Sec-WebSocket-Key (合法升级请求必有) */
    bool deflate_offered;         /* 请求 offer 含 permessage-deflate */
    bool client_no_context_takeover; /* offer 声明 (server 解压方向参数, §5.4) */
} ws_handshake_request;

/* 服务端解析升级请求 (语法交给 sevent_http_parse).
 * 返回: >0 = 完整请求 (req->status 判定可升级性); 0 = 数据不足; <0 = 语法错误. */
int ws_parse_request(const uint8_t *buf, size_t len, ws_handshake_request *req);

/* 构建 101 响应: 状态行 + Upgrade/Connection/Sec-WebSocket-Accept (+ PMD 确认).
 * accept = base64(sha1(key + GUID)); enable_deflate=true 时带 PMD 行 (A 方案, 无参数).
 * 返回: 写入字节数; <0 = 容量不足. */
int ws_build_response(char *buf, size_t cap, const char *key, bool enable_deflate);
```

### 5.4 压缩协商（A 方案已定 + 参数映射补全）

- offer 识别：sevent_http_find_header 查 Sec-WebSocket-Extensions 含 `permessage-deflate`（与 client [ws_extensions_ok](src/websockets/ws_conn.c#L170) 同风格，无参数解析器）
- 响应：`Sec-WebSocket-Extensions: permessage-deflate`（不带参数——RFC 7692 §4.2 省略=默认值 15/有 takeover，offer 参数未确认不得假设生效）
- **server 侧 deflate 创建参数（补全）**：
  - `client_no_context_takeover` = **从 offer 提取**（RFC 7692 §7.1.1.1：offer 带该参数 = 客户端单方面承诺无 takeover，不依赖响应确认）——server 解压方向必须与客户端实际发送一致，否则解压错乱；响应省略该参数合规
  - `server_no_context_takeover` = false（响应没带，默认有 takeover——server 发送方向）
  - `client_max_window_bits` 不需处理：客户端发送窗口 ≤15 位默认，server 解压窗口 15 位 ≥ 压缩窗口，安全
  - `compression_level` = cfg->deflate_level
- **方向语义核对（client 侧 1297 行已验证）**：ws_deflate 的 client_* 参数 = client 角色方向（client 上 = 本端发送；server 上 = 对端发送）——server 创建时从 offer 提取 ✓ 与 client 自我承诺行为自洽
- 预期：Autobahn fuzzingserver 12.x 参数类用例可能 NON-STRICT/FAIL——阶段④实测定档

## 6. 错误码

| 场景 | 回调/错误码 |
|---|---|
| TCP 建连失败 | on_error(SEVENT_WS_ERR_CONNECT)（仅 client 模式可能） |
| TLS 握手/证书失败（accept） | on_error(SEVENT_WS_ERR_HANDSHAKE)（HANDSHAKE 优先——server 模式 stream 失败只有 TLS 场景） |
| 升级请求非法（accept 入口） | 回 400/426 + on_error(SEVENT_WS_ERR_HANDSHAKE)（§5.2 发送时序） |
| upgrade 入口的请求非法 | http_server 回 400（ws 层不见） |
| upgrade 前置失败（未 RELEASED / 无 key） | 返回 NULL，无回调（连接仍归 http server 管理；文档注明"仅 release 后调用"） |
| upgrade 中途失败（分配失败等） | 库内部 stream close + 延迟释放，返回 NULL（无回调——连接从未交付） |
| upgrade 入口的 TLS 握手失败 | http_server 的 on_error 回调（连接未建立，无 ws 层错误） |
| 数据期帧违例（未 mask / mask 帧 / RSV 等） | 1002 close（现有 PROTOCOL 路径 + §5.1 新增校验） |
| 客户端 close / TCP 断开 | on_close（含 EOF → 1006） |

## 7. 生命周期与线程模型

- 全部 [loop 线程]；SEVENT_WS_THREAD_SAFE 时跨线程 send/close/destroy 由既有锁保护
- http_server destroy 不触碰已升级的 ws 连接（所有权已转移）
- **升级转移的释放链**：ws_upgrade 消费（i_detach/i_take_recv/key）→ i_destroy（post 释放 http 壳）→ 101 入队 + OPEN → 后续 ws 生命周期与 client 完全一致（ws_cleanup_conn 统一释放）

## 8. 测试计划

| # | 项 | 说明 |
|---|---|---|
| 1 | 握手单测 | ws_parse_request/ws_build_response（合法/缺头/半包/粘包/非升级/Version 错/非 GET） |
| 2 | 独立端口端到端 | tcp_acceptor + ws_accept ↔ 现有 test-ws-conn client 反向连：消息/分片/大帧/close |
| 3 | 共用端口端到端 | http_server 同端口 http 请求 + ws 升级并存；on_upgrade 转移含粘包帧 |
| 4 | wss | accept/upgrade 两入口带证书；mTLS（verify_peer：有证书过/无证书拒） |
| 5 | 掩码校验 | 未 mask 客户端帧 → 1002；mask 帧给 client → 1002（裸帧直写 stream） |
| 6 | 非法握手 | 缺 key / Version≠13（426）/ 非 GET → 客户端收到 400/426 |
| 7 | Autobahn fuzzingserver | docker 镜像起 wstest fuzzingclient 连本地 ws server（ws_accept 入口载体），用例基线对比（新增脚本；现有脚本为 fuzzingclient 模式测 client，保留） |
| 8 | 三套 build + ASAN | mbedtls / openssl / ASAN 全量 |

## 9. 实施阶段（本阶段 = 阶段③）

| 步骤 | 内容 | 验证 |
|---|---|---|
| ① | ws_handshake.h/c：ws_parse_request + ws_build_response + ws_handshake_request | 握手单测（测试 #1） |
| ② | stream 层：ops 槽 set_callbacks + tcp/tls 实现 + 转发 | 既有 stream 测试全绿（零行为变化） |
| ③ | http_server_i.h：sevent_http_conn_i_destroy（post 释放壳） | http server 测试全绿 |
| ④ | ws_conn：is_client 字段 + 掩码双向校验 + ws_conn_new 骨架抽取 + 握手 server 分支 | client 回归（Autobahn 517 零回归） |
| ⑤ | sevent_ws_accept / sevent_ws_upgrade + sevent_ws.h 声明 | 端到端测试 #2/#3 |
| ⑥ | deflate server 协商（offer 提取 + A 方案响应） | Autobahn fuzzingserver 12.x 定档 |
| ⑦ | 测试全量（#1-#8）+ 示例（**先共用端口** examples/ws_http_shared.c：http_server + on_upgrade + ws_upgrade 同端口共存；后独立端口 examples/ws_server.c：tcp_acceptor + ws_accept echo）+ CMake 目标 | 三套 build + ASAN 全绿 |
| ⑧ | 全量验证 + 提交（版本升级等指示） | — |

## 10. 风险

1. Autobahn fuzzingserver 12.x 参数类/握手严格用例定档（A 方案预期部分 NON-STRICT/FAIL，与 client 基线同档管理）
2. **升级转移的缓冲数学（已修正）**：stream 推送上限 = http recv_cap ≠ ws 的 cap/2 → ws_upgrade 重分配 2× 缓冲 + 拷贝残留（§3.7）；实施时校验 i_take_recv 的 cap 输出与 2× 分配一致性
3. **stream 回调替换（新内部 API）**：tls_conn 的回调存储位置实施时确认（tls 层 vs 组合的 tcp 层），set_callbacks 必须两端都覆盖
4. **400/426 发送时序**：shutdown(WR) 半关（flush+FIN）而非立即 close——实施时验证客户端确实收到响应（测试 #6）
5. **client 模式 mask 校验新增**：合规修正，Autobahn 517 回归确认无行为变化
6. 头提取行为一致性：ws_parse_request 与 client 侧重构同模式（find_header 指针），回归覆盖
7. keep-alive 残留处理三路径——http server 核心正确性，单测覆盖（升级转移的粘包帧用例）
