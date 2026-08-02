# HTTP 层设计（sevent_http_parse 语法层 + sevent_http_server 服务器层）

## 1. 背景与动机

1. **ws server 需求**：服务端握手需要反向 HTTP 处理（解析客户端升级请求 → 构建 101/400）。
2. **共用端口需求**（关键）：http 服务 + ws 服务器共用端口——连接分派（升级 vs 普通请求）必须发生在 ws 之上。
3. **纯 HTTP 是并行目标**（已确认）：不是"ws 附庸"——http server 要能正经服务：多请求复用（keep-alive）、body 分帧、连接管理。**on_request 不是一次性的**。

## 2. 定位：两层

| 层 | 内容 | 公开性 |
|---|---|---|
| **语法层** `sevent_http_parse` | 纯函数：行 + 头 + **body 分帧**（Content-Length）解析、查键、构建骨架。无连接对象 | 公开（include/sevent_http_parse.h） |
| **服务器层** `sevent_http_server` | 监听器类（内部组合 `sevent_tcp_acceptor` 做监听 + stream_conn 建连接）+ **连接管理**（连接列表/状态机/keep-alive/空闲超时）+ 请求回调 + 升级出口 | 公开（include/sevent_http_server.h） |

原则：语法层做库（纯函数），服务器层做宿主（连接级管理）；**升级协议语义（websocket 判定/accept 计算/协商）不在 HTTP 层**。

## 3. 语法层 sevent_http_parse（公开）

**解析策略（已定：惰性/按需）**：分帧 + 预解析**服务器运行必需**的少量字段；其余 header **不预解析**，用户调用 `sevent_http_find_header` 按需扫描。

```c
typedef struct sevent_http_msg {
    bool        is_response; /* true=响应(状态行) / false=请求(请求行) */
    sevent_http_method method; /* 预解析: 标准方法枚举 (UNKNOWN=非标准, 用 method_ref) */
    const char *method_ref;  /* 请求行 method 原始引用 (零拷贝, UNKNOWN 时用) */
    size_t      method_len;
    const char *target; /* 请求行预解析: /path (零拷贝引用, is_response 时 NULL) */
    size_t      target_len;
    int  status_code;   /* 响应: 任意状态码, 不枚举 */
    /* ---- 分帧 + 服务器运行必需 (预解析) ---- */
    bool        upgrade;      /* Upgrade 头存在 + Connection 含 upgrade (分派用) */
    bool        keep_alive;   /* 连接是否保持: HTTP/1.1 默认 true, Connection: close 或 HTTP/1.0 → false */
    size_t      content_length; /* Content-Length (分帧必需) */
    const char *body;         /* body 指针 (零拷贝, 指向解析缓冲) */
    size_t      body_len;     /* 分帧收齐后 = content_length */
    bool        chunked;      /* Transfer-Encoding: chunked (初版不支持, 见边界) */
    /* ---- 原始头区 (按需解析用) ---- */
    const char *headers_start;
    size_t      headers_len;
} sevent_http_msg;

/* 分帧解析: 请求行 + 头区边界 (\r\n\r\n) + Content-Length 收 body.
 * 预解析: method/target/status/upgrade/keep_alive/content_length.
 * 返回: >0 = 完整请求/响应 (含 body); 0 = 数据不足, 等更多; <0 = 协议错误 */
int  sevent_http_parse(const char *buf, size_t len, sevent_http_msg *out);

/* 按需查 header: 惰性扫描头区, 零拷贝返回值指针+长度; 未找到返回 NULL.
 * 用户需要 cookie/auth 等非预解析字段时调用. */
const char *sevent_http_find_header(const sevent_http_msg *m, const char *name, size_t *val_len);

int sevent_http_build_request(char *buf, size_t cap, const char *method, const char *target,
                       const char *host, uint16_t port, const char *extra_headers);
int sevent_http_build_response(char *buf, size_t cap, int status, const char *text,
                        const char *extra_headers);
```

- 返回语义与 [ws_parse_response](src/websockets/ws_handshake.c#L155) 一致（>0/0/<0）
- **分帧**：头区（`\r\n\r\n`）后按 `Content-Length` 收 body——请求边界确定，是 keep-alive 的前提；分帧本身只需 CL 一个头
- **预解析面**：升级判定（upgrade）、keep-alive 判定（keep_alive）、路由（method/target）——http server 运行所需，其余零开销
- 无 Content-Length 且非 chunked：body_len=0（GET 等无 body 请求）
- 零拷贝：**全部字段**（method_ref/target/body/头区）指针指向输入缓冲，无 NUL 结尾（用 `*_len`），比较用 `sevent_http_str_eq` 辅助；msg 仅在输入缓冲存活期间有效（回调内使用）
- method/target 无长度上限（由输入缓冲长度兜底）——长 URL/扩展方法不截断

## 4. 服务器层 http_server

### 4.1 形态（服务器类 + 连接管理）

```c
typedef struct sevent_http_server sevent_http_server;
typedef struct sevent_http_conn   sevent_http_conn;  /* 连接对象: 用户可持有 */

typedef struct sevent_http_server_config {
    /* 传输 (stream 同构): wss 时 enable_tls + cert/key 必填 */
    bool        enable_tls;
    const char *cert_path, *cert_pem, *key_path, *key_pem;
    bool        verify_peer;
    const char *ca_path, *ca_pem;
    size_t      recv_buf_size;     /* 解析缓冲 = 单请求上限 (头+body), 0=默认 4096 */
    int         idle_timeout_ms;   /* keep-alive 空闲超时: 0=默认 60s, <0=禁用 */
} sevent_http_server_config;

sevent_http_server *sevent_http_server_create(sevent_context *ev, const sevent_http_server_config *cfg);

int  sevent_http_server_listen(sevent_http_server *s,
                               const char *host, uint16_t port, int backlog,
                               sevent_http_on_accept_fn on_accept,        /* 可选: 连接就绪 (stream/TLS 完成, 解析前) */
                               sevent_http_on_request_fn on_request,      /* 必填其一 */
                               sevent_http_on_upgrade_fn on_upgrade,      /* 必填其一 */
                               sevent_http_on_conn_close_fn on_conn_close, /* 可选: 连接将销毁, 用户清理引用 */
                               sevent_http_on_error_fn on_error,          /* 可选: 传输层错误 (TLS 握手失败等), 无连接上下文 */
                               void *ud);
uint16_t sevent_http_server_port(sevent_http_server *s);
void     sevent_http_server_destroy(sevent_http_server *s);

typedef void (*sevent_http_on_accept_fn)(void *ud, sevent_http_conn *conn); /* 连接已就绪: 可 close 拒绝 (黑名单/连接数超限), 可持有引用 */
typedef void (*sevent_http_on_request_fn)(void *ud, const sevent_http_msg *req, sevent_http_conn *conn);
typedef void (*sevent_http_on_upgrade_fn)(void *ud, const sevent_http_msg *req, sevent_http_conn *conn);
typedef void (*sevent_http_on_conn_close_fn)(void *ud, sevent_http_conn *conn);
typedef void (*sevent_http_on_error_fn)(void *ud, int err);
    /* 传输层错误 (stream accept/TLS 握手失败): 连接从未建立 — 无 conn 参数,
     * 无 on_conn_close. err 为 stream 层错误码 (SEVENT_ERR_CONNECT/HANDSHAKE 等).
     * NULL=静默 (默认). 用于监控/日志. */

/* ===== 响应构造 (声明式: 用户填结构体 + 辅助函数, http 层自己构造 + 发送) ===== */
typedef struct sevent_http_header {          /* 头链表节点: 库管理 (堆分配, 无槽位上限) */
    const char *name;
    const char *value;
    struct sevent_http_header *next;
} sevent_http_header;

typedef struct sevent_http_response {
    int   status;                            /* 状态码 */
    const char *text;                        /* NULL=库查表 (常见码), 未知码必填 */
    bool  close;                             /* true=响应后关: 注入 Connection: close + 半关 (shutdown WR); false=保持 */
    const void *body;                        /* NULL=无 body */
    size_t body_len;
    sevent_http_header *headers;             /* 库管理链表, 用户经辅助函数操作 */
} sevent_http_response;

void sevent_http_response_init(sevent_http_response *resp);                 /* 清零 */
int  sevent_http_response_header_set(sevent_http_response *resp, const char *name, const char *value);
    /* 查重: 同名覆盖 (后一个生效); 返回 0=OK, <0=非法/内存不足 */
int  sevent_http_response_header_add(sevent_http_response *resp, const char *name, const char *value);
    /* 追加: 允许重复 (Set-Cookie 多值等); 返回 0=OK, <0=非法/内存不足 */
int  sevent_http_response_header_del(sevent_http_response *resp, const char *name);
    /* 删除: 按名删全部同名; 返回删除条数 */
void sevent_http_response_clear(sevent_http_response *resp);                /* 释放节点, 可复用 */

/* 连接对象 API (回调外可调用 — 支持异步响应; 线程: 全部 [loop 线程],
 * 跨线程调用无保护) */
int  sevent_http_conn_respond(sevent_http_conn *conn, sevent_http_response *resp);
    /* 库内: 状态行 + 遍历头 + 自动 Content-Length + close 时注入 Connection: close
     *     → 入写队列 (同步拷贝) → close 标记 → 半关 (shutdown WR: 发完 + FIN).
     * 返回: 0=已接受; <0=错误 (INVAL/状态非法/已响应/本请求已 write/NOMEM/头区溢出).
     *     无论成败 resp 头节点都已释放 (调用后 resp 即弃 — 重试场景用户重新 set).
     *     一请求一响应: 重复 respond 报错. */
int  sevent_http_conn_write(sevent_http_conn *conn, const uint8_t *buf, size_t len);
    /* 原始写 (write 路径): 用户全手写响应 (含所有头) + 多次 write 流式 + write_end/close 结束.
     * 不含任何头注入 (Content-Length/Connection: close 等用户自管).
     * 与 respond 互斥: 本请求 write 过数据后 respond 报错 (反之 respond 后回 PARSING,
     * write 也报错). 回调内 write 后返回 → 连接转 RESPONDING (流式中, 空闲超时豁免),
     * 回调外可继续 write + write_end 收尾. */
int  sevent_http_conn_write_end(sevent_http_conn *conn);
    /* write 路径专用: 声明"响应已完整写完" → 转换 PARSING (keep-alive) 或 CLOSING (关)
     * (先前调过 close). 调用后 write 报错 (响应已结束).
     * 未写过数据 (AWAIT_RESP) / respond 路径 → 报错. */
void sevent_http_conn_close(sevent_http_conn *conn);       /* 关闭: 半关 (shutdown WR: 发完已入队数据 + FIN,
                                                              之后只能读, 等对端 EOF); 关闭中 write/respond 报错 */
int  sevent_http_conn_state(const sevent_http_conn *conn); /* 返回 http_conn_state 枚举值 */
```

### 4.2 连接状态机（最终实现版）

```c
typedef enum {
    HTTP_CONN_NEW,        /* stream+TLS 建连 (on_accept 前) */
    HTTP_CONN_PARSING,    /* 累积+分帧, 等完整请求 (响应完成后转换回此态 — keep-alive) */
    HTTP_CONN_REQUEST,    /* 回调中 (on_request/on_upgrade) */
    HTTP_CONN_AWAIT_RESP, /* 回调返回未响应 (异步窗口, 空闲超时适用) */
    HTTP_CONN_RESPONDING, /* write 路径流式中 (已 write 未 write_end) */
    HTTP_CONN_RELEASED,   /* release 后, 等 ws_upgrade 消费 */
    HTTP_CONN_CLOSING,    /* 关闭收尾 (半关: shutdown(WR) 发完已入队数据 + FIN, 等对端 EOF) */
    HTTP_CONN_CLOSED,     /* 已销毁 (on_conn_close 已回调) */
} http_conn_state;

/* 状态 × API 允许矩阵 (✓=允许, ✗=报错):
 * 响应完成 = 状态转换 (respond/write_end/close 调用时): close_pending → CLOSING,
 * 否则 → PARSING. 故 PARSING 里 respond/write 全 ✗ (响应已完成, 等下一请求). */
/* API \ 状态  | NEW | PARSING | REQUEST | AWAIT_RESP | RESPONDING | RELEASED | CLOSING */
/* respond     |  ✗  |   ✗     |   ✓     |     ✓      |     ✗      |    ✗     |   ✗    */
/* write       |  ✗  |   ✗     |   ✓     |     ✓      |  ✓(流式续写)|    ✗    |   ✗    */
/* write_end   |  ✗  |   ✗     |   ✓     |     ✗      |   ✓        |    ✗    |   ✗    */
/* close       |  ✓(on_accept 拒绝) | ✓ |   ✓     |     ✓      |  ✓(提前终止)|    ✗    |   ✗    */
/* release     |  ✗  |   ✗     |   ✓(on_upgrade) |  ✗ |     ✗      |    ✗    |   ✗    */
```

**状态转换**（响应完成 = 转换，无独立标记）：

```
NEW(stream+TLS) → on_accept(连接就绪; 可 close 拒绝) → PARSING(累积+分帧)
    → 完整请求 → REQUEST (回调 on_request / on_upgrade)
        ├─ on_upgrade:
        │    拒绝分支 → respond(4xx, close=true) → CLOSING (半关)
        │    升级分支 → release(→ RELEASED) → ws_upgrade 消费 (见 §4.4)
        └─ on_request 返回 (request_after_callback):
            ├─ 回调内已 respond/write_end → PARSING (转换已完成) → 处理残留
            ├─ 回调内已 write (未 write_end) → RESPONDING (流式续写, 保持)
            └─ 未响应 → AWAIT_RESP (异步窗口)

响应完成 (respond / write_end / close 调用时):
    close_pending (close 字段 / keep_alive=false / 用户 close) → CLOSING
        半关: shutdown(WR) — 已入队数据发完 + FIN (内核保证), 之后只能读, 等对端 EOF
    否则 → PARSING (keep-alive, 等下一请求)

残留处理 (粘包下一请求; 请求消费发生在回调返回后):
    回调内完成 (REQUEST)     → request_after_callback (state==PARSING 分支)
    异步 respond (AWAIT_RESP, 请求已消费) → respond 内 (was_await)
    异步 write_end (RESPONDING, 已消费)  → write_end 内 (was_responding)
    其余数据到达              → conn_on_data (state==PARSING 时 http_process)

独立触发 (非转换路径):
    - 用户 close: 任意状态 → CLOSING (半关)
    - 空闲超时: PARSING / AWAIT_RESP / CLOSING → 终结 (防挂起; on_conn_close)
    - 分帧错误: PARSING → 库内部 400/413 + CLOSING
    - 传输错误 (stream accept/TLS 握手失败): 连接未建立 → on_error 回调 (无 conn)
    - 客户端断开: 任意状态 → CLOSED (on_conn_close)
```

- **keep-alive 是默认**（HTTP/1.1 标准语义）：响应不带 `Connection: close` 时连接保持，继续服务下一请求——on_request **可多次触发**（同一连接）；**响应发送不阻塞下一请求处理**（响应在写队列异步发出，读方向独立）
- 关闭条件①②时：库在响应自动带 `Connection: close`（RFC 7230 §6.6 合规），101 升级响应例外
- **矩阵规则**：
  - **respond 单次**：respond 后回 PARSING——PARSING 里再 respond 报错（一请求一响应）
  - **路径互斥**：respond 后回 PARSING——PARSING 里 write 报错（响应已完成、CL 冲突）；write 路径（未 respond）可多次 write 流式续传
  - **响应完成声明**：respond 隐含结束（转换 PARSING）；write 路径必须显式 `write_end`（保持连接）或 `close`（响应后关）——否则连接永远停 RESPONDING（keep-alive 不可用）
  - **close=true 半双工**：CLOSING 后 write/respond 全禁——业务上仅"发完响应"一条路（shutdown(WR) 后只能读），不可再写
  - **release 出口唯一**：RELEASED 只能 ws_upgrade 消费（或库关）——close/write/respond 全禁
- **待响应态（异步窗口）**：回调返回后用户未 respond——连接不读（请求已消费）、空闲超时**继续适用**（超时内未 respond → 关 + on_conn_close 通知用户）；write/close 可用
- **空闲超时覆盖面**：PARSING（等请求）+ AWAIT_RESP（等响应）+ CLOSING（半关后防挂起）适用；**RESPONDING（write 流式中）不超时**——由用户 close 或对端断开收尾
- **`req` 仅回调内有效**：解析缓冲循环复用——下一请求会覆盖上一请求的指针；回调内必须用完（拷贝 body/头），返回后不得访问
- **空闲超时覆盖首请求等待**：连接建立后到第一个完整请求的等待也计入 idle_timeout——共用端口场景下"客户端连上不发升级请求"被超时关（**升级期无超时缺口在 upgrade 入口被覆盖**，accept 入口仍无，见 ws-server-design §4）

### 4.3 连接对象生命周期（用户可持有）

- 创建：http server 内部（连接列表持有）
- 获得：on_request/on_upgrade 回调拿到 `sevent_http_conn*`
- **回调外有效**：异步响应（查库后 write）→ 写响应不受"回调返回"限制；状态可查（`state`）；关闭后 write 返回错误
- 关闭：连接将销毁时回调 `on_conn_close`（用户清理引用）→ 之后句柄作废
- **升级成功 conn 立即作废且无 on_conn_close**（闭环补）：升级（release）路径不走关闭回调——on_upgrade 里若存了 conn 引用，升级成功分支必须自行置空（on_conn_close 只覆盖未升级连接）
- destroy server：关闭全部连接（已升级转交的 ws 连接不在管理内）；**回调内 destroy server 需延迟**（与 ws destroy 纪律一致：post 延迟，回调栈安全展开）

### 4.4 升级出口（两段式：释放 + 消费，决定权在用户）

```c
/* 段 1 (http 层): 显式释放 — 用户决定"这条连接不再走 http 路径"的声明.
 * 从 http server 摘除 (停止管理/标记已释放/壳延迟销毁计划).
 * release 后: respond/write 返回错误; 只能 ws_upgrade 消费 (或放弃).
 * 返回: 0=成功, <0=错误 (已关闭/已释放). */
int sevent_http_conn_release(sevent_http_conn *conn);

/* 段 2 (ws 层, 见 ws-server-design §3): 消费已释放的 conn — 前置校验 RELEASED. */
sevent_ws_conn *sevent_ws_upgrade(sevent_http_conn *conn, const sevent_ws_config *cfg);
```

- **决定权在用户**：拒绝（respond 404/403）→ 不调 release，连接留在 http server 正常收尾；升级 → release + upgrade 两段显式
- release 是承诺：释放后不能反悔（respond/write 已禁），出口只有两个——ws 成功 / 关闭
- **upgrade 失败善后**：返回 NULL 时库内部关闭底层连接（已摘除+已消费，无人管理）——用户无需善后，conn 作废即可，无悬空
- 回调返回后 http server 检测 RELEASED → 跳过收尾（等同原 TRANSFERRED）

## 5. 与 ws 的关系（双入口）

```
共用端口:  http_server 监听 → on_upgrade
               └─ release(conn) → sevent_ws_upgrade(conn, ws_cfg) → ws_conn (见 §4.4)
独立端口:  tcp_acceptor → sevent_ws_accept(fd, ws_cfg) → ws_conn (内部 sevent_http_parse, 非升级→400)
```

- 升级请求无 body（分帧后 body_len=0），与 keep-alive 模型兼容
- 升级后连接脱离 http server（RELEASED），http 侧不再管理——keep-alive 循环不适用于 ws 连接
- 升级时 stream 已 (TLS) 握手完成 → ws_upgrade 的 ws_cfg 中 TLS 字段一律忽略

## 6. 使用示例（伪代码）

```c
/* 普通请求: 填结构体 + 辅助函数 → http 层构造+发送. close=false → 连接保持 */
static void on_request(void *ud, const sevent_http_msg *req, sevent_http_conn *conn) {
    sevent_http_response resp = {0};
    resp.status = 200;
    resp.body   = "hello";
    resp.body_len = 5;
    sevent_http_response_header_set(&resp, "Content-Type", "text/plain");
    sevent_http_response_header_set(&resp, "Cache-Control", "no-cache");
    sevent_http_conn_respond(conn, &resp);
    /* 想响应后关: resp.close = true 再 respond (自动注入 Connection: close) */
}

/* 升级请求: 两个显式分支 — 拒绝(留 http) 或 release+升级(转 ws) */
static void on_upgrade(void *ud, const sevent_http_msg *req, sevent_http_conn *conn) {
    size_t vl;
    const char *proto = sevent_http_find_header(req, "upgrade", &vl);
    if(!proto || vl != 9 || memcmp(proto, "websocket", 9) != 0) {
        sevent_http_response resp = {0};
        resp.status = 404;
        resp.close  = true;                        /* 拒绝: conn 留 http server */
        sevent_http_conn_respond(conn, &resp);
        return;
    }
    if(sevent_http_conn_release(conn) != 0)   /* 显式释放 (连接已死则放弃) */
        return;
    sevent_ws_config cfg = {0};
    cfg.on_message = on_ws_msg;
    cfg.on_close   = on_ws_close;
    sevent_ws_conn *ws = sevent_ws_upgrade(conn, &cfg);   /* 消费已释放 conn; NULL=失败已由库关闭 */
}

/* 连接就绪 (可选): 可 close 拒绝 / 持有引用 */
static void on_accept(void *ud, sevent_http_conn *conn) {
    /* if(黑名单) sevent_http_conn_close(conn); */
}

/* 连接关闭 (可选): 清理引用 */
static void on_conn_close(void *ud, sevent_http_conn *conn) {
    if(g_pending_conn == conn) g_pending_conn = NULL;   /* 异步响应场景的引用清理 */
}

/* 传输层错误 (可选): TLS 握手失败等 — 监控/日志 */
static void on_error(void *ud, int err) {
    /* fprintf(stderr, "http conn error: %d\n", err); */
}

int main(void) {
    sevent_context *ev = sevent_create();
    sevent_http_server_config scfg = {0};   /* 明文; wss 填 cert/key; idle_timeout_ms 默认 60s */
    sevent_http_server *srv = sevent_http_server_create(ev, &scfg);
    sevent_http_server_listen(srv, "0.0.0.0", 8080, 8,
                              on_accept, on_request, on_upgrade, on_conn_close, on_error, NULL);
    sevent_run(ev);
}
```

## 7. 边界（当前不做，将来可扩）

| 项 | 现状 | 将来扩展点 |
|---|---|---|
| chunked 传输编码 | 不支持（chunked 请求 → 返回 <0 → 400） | 分块解析（hex 长度行 + 0 终止） |
| 单请求体上限 | recv_buf_size（默认 4096），超出 → 413 | 流式 body / 动态扩容 |
| 连接数上限 | 无 | server 配置加 max_conns + 拒绝策略 |
| cookie / 路由 / 状态码枚举 | 不做 | 独立模块再议 |
| 异步响应 | 支持（conn 跨回调有效） | —（已是能力） |

## 8. 【未决】点（待用户定）

**已定**：
1. ~~公开命名~~ → 带 `sevent_` 前缀（公开头 include/sevent_http_parse.h，实现 src/http_parse.c）
2. ~~传输配置位置~~ → create 带（cfg 含 TLS + recv_buf_size + idle_timeout_ms）
3. ~~on_upgrade 触发面~~ → 机制触发（HTTP 层不懂协议名）
4. ~~http server 定位~~ → **并行目标，连接管理（keep-alive 模型），on_request 非一次性**
5. ~~解析策略~~ → **惰性/按需**：分帧 + 预解析必要字段（method/target/upgrade/keep_alive/CL），其余 header 用户调 `sevent_http_find_header` 按需查；无头槽数组
6. ~~空闲超时~~ → **0=默认 60s，<0=禁用**
7. ~~chunked 初版~~ → **不做**（请求带 chunked → 400；`chunked` 字段预留，将来分帧加分支即可）
8. ~~连接关闭通知~~ → **listen 直接回调 on_conn_close**（可选）+ **新增 on_accept**（可选：连接就绪通知，可 close 拒绝/持有引用）+ **on_error**（可选：传输层错误——TLS 握手失败等，无连接上下文）——生命周期对称：on_accept → on_request/on_upgrade → on_conn_close；on_error 兜底传输错误
9. ~~Connection: close 管理~~ → **响应结构体方案**（`sevent_http_response.close` 字段）：用户填字段表达"响应后关"，http 层构造时注入 `Connection: close` + 半关（shutdown WR）——意图与响应同一次表达，无分离事实

**补充定案（响应构造）**：
- `sevent_http_conn_respond(conn, &resp)`：声明式响应——用户填结构体（status/text/close/body）+ 辅助函数组装头（set 查重覆盖/add 追加/del 删除），http 层构造状态行 + 遍历头 + 自动 `Content-Length` + 按 close 注入 `Connection: close` → 入写队列
- 头链表**库管理节点**（无槽位上限）：**无论成败** respond 调用后头节点都已释放（调用后 resp 即弃——重试场景重新 set）；response 对象 {0} 初始化可复用
- `text=NULL` → 库查表（200 OK/201/204/301/302/304/400/401/403/404/405/409/413/429/500/501/502/503 等常见码），未知码必须填
- 头区构造缓冲上限（默认 4096）溢出 → respond 返回 <0
- HTTP/1.0 请求（keep_alive=false 预解析字段）：响应后**自动关**（1.0 无 keep-alive 概念，close 字段忽略）
- `write` 保留（write 路径）：用户全手写响应 + 多次 write 流式（大文件下载，CL 已知）+ 结束用 `write_end`（保持连接）或 `close`（响应后关）；与 respond 路径互斥
- `sevent_http_build_request` / `sevent_http_build_response` 保留：ws 层握手请求/101 构建 + 高级手拼场景（语法层纯函数）
- HEAD 请求语义初版不特殊处理；SSE 依赖 chunked → 初版不支持（write 路径可用 CL 已知的大文件流）

**补充定案（升级出口两段式）**：
- `sevent_http_conn_release(conn)`（http 层，显式）：从 http server 摘除——用户决定"不再走 http 路径"；release 后 respond/write 返回错误，出口只有 ws 成功/关闭
- `sevent_ws_upgrade(conn, cfg)`（ws 层，消费）：前置校验 RELEASED（未释放 → NULL）→ stream + 缓冲残留移交 → 101/OPEN；失败（NULL）库内部关底层——无悬空
- 拒绝分支（respond 4xx）不调 release——连接留在 http server 正常收尾

**补充定案（连接状态机）**：
- 8 态（NEW/PARSING/REQUEST/AWAIT_RESP/RESPONDING/RELEASED/CLOSING/CLOSED）+ 状态 × API 矩阵
- **响应完成 = 状态转换**（respond/write_end/close → PARSING 或 CLOSING），无独立标记（曾用 responded 标记，重构为纯状态表达）
- 关闭 = 半关（stream shutdown(WR)：发完已入队数据 + FIN，内核保证）；空闲超时覆盖 PARSING/AWAIT_RESP/CLOSING
- 空闲超时覆盖面：PARSING + AWAIT_RESP + **CLOSING**（半关后防挂起）；RESPONDING 不超时

## 9. 测试计划

| # | 项 | 内容 |
|---|---|---|
| 1 | sevent_http_parse 单测 | 行/头/半包/非法/大小写 + **分帧**（CL 收齐/不足/无 body/超限）+ 构建骨架 |
| 2 | http_server 单测 | 回调分发/keep-alive 多请求复用/关闭条件①②③/400/413/空闲超时覆盖面（PARSING+AWAIT_RESP 适用、RESPONDING 不超时）/待响应异步窗口/on_conn_close/**release+upgrade 两段流程（含拒绝分支）**/升级转移含粘包/TLS + **respond 构造**（状态行/头遍历/CL/close 注入/body/查表/未知码必填/头区溢出/HTTP1.0 自动关）+ **辅助函数**（set 查重覆盖/add 重复/del/clear/节点释放语义）+ **状态机矩阵**（非法状态调用报错：重复 respond/respond 后 write/close=true 后写/RELEASED 后操作）+ **write_end**（write 路径结束后恢复读下一请求/close 后关/调用后 write 报错/respond 后调用报错）+ **on_error**（TLS 握手失败触发/无 conn 上下文） |
| 3 | ws client 回归 | test-ws-conn 56 + test-redirect + test-deflate（ws_handshake 重构后） |
| 4 | 共用端口端到端 | 同端口 http 多请求 + ws 升级并存 |
| 5 | Autobahn | fuzzingclient 连 ws 端口 517 用例零回归 |

## 10. 实施阶段

| 阶段 | 内容 | 验证 |
|---|---|---|
| ① 语法层 | sevent_http_parse（公开，含分帧）+ ws_handshake 重构瘦身 | sevent_http_parse 单测 + client 回归 |
| ② 服务器层 | http_server（连接状态机/keep-alive/空闲超时/五回调/respond 响应构造/release 升级出口/TLS）+ 单测 | http_server 单测全过 |
| ③ ws 接入 | ws_accept(fd) + ws_upgrade(http_conn) + is_client/掩码 + 握手 server 侧 | 端到端 + client 回归 |
| ④ 全量 | 共用端口 + wss/mTLS + Autobahn fuzzingclient + 三套 build + 示例 | 零回归 |
