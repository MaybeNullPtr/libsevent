# SSL 抽象层设计（sevent_ssl：openssl / mbedtls 双后端）

> **状态**：设计定稿（2026-08-02）— 实施中，进度见 §8
> 本文件是 SSL 层设计的唯一决策载体。已确认项见 §1；未决已清零（§2）。
> 变更走 git 修订本文件。

## 1. 决策记录（全部 ✅ 已确认）

| 编号 | 决策点 | 结论 |
|------|--------|------|
| D1 | 后端选择时机 | 编译期：CMake `SEVENT_WS_TLS_BACKEND=OPENSSL\|MBEDTLS`，只编译选中后端，工厂 `#ifdef` 选 ops。**默认 = MBEDTLS** |
| D2 | hostname 校验：开关 + 名字 | **开关与名字同处 config（对象级）**：`enable_hostname_verify`（bool，两端通用，默认 true；openssl 可关仍发 SNI / mbedtls 恒开）+ `tls_hostname`（本端期望的对端证书名，create 时定）。客户端=校验服务器证书 SAN；服务端（mTLS）=校验客户端证书 SAN。**TCP 目标（open 的 host，应用 resolve 后为 IP）与校验名（域名）分离**——传输层不解析域名（DNS 是应用层工作） |
| D3 | 证书输入方式 | 文件路径 + 内存 PEM 双通道（每对字段互斥报错；平铺 6 字段；stream_conn_config 同步加 PEM 字段）；仅 PEM 格式、NUL 结尾 |
| D4 | mbedtls 版本基线 | 按 2.x API 写（目标 2.25，自编译安装 `~/documents/thirdparty/install`，本机私有）；openssl 按系统版（3.x/1.1.1） |
| D5 | ssl 层公开性 | `src/ssl/` 内部（不进 include/）：openssl/mbedtls 类型不泄露公开头；tls_conn 只暴露 stream 接口 |
| D6 | enable_peer_verify 语义 / mTLS | 客户端 true=验证服务器证书链（默认）；服务端 true=**mTLS**（要求客户端证书并验证）。mTLS 本期做，测试含客户端证书 |
| D7 | 数据通道模型（F 方案） | ssl 层**不碰 fd**：密文经 `feed`（对端→SSL）/`drain`（SSL→对端）交换；tls_conn **组合 tcp_conn** 作底层字节流（建连/事件/写队列/destroy 全复用），自身只做握手状态机 + 密文搬运。网络写由 tcp_conn（MSG_NOSIGNAL）负责 |

## 2. 未决事项

**✅ 全部确认完毕（2026-08-02）— 未决清零。** 服务端 `enable_hostname_verify` 默认 **true**（独立开关，不随 enable_peer_verify 决定；enable_peer_verify=false 时无效果，自然无害）。

## 3. 背景与动机

TLS 做两件事：握手（协商密钥 + 证书验证）与加密传输。握手完成后对上层就是普通字节流。
两个 TLS 库 API 完全不同，需一层适配：

| | OpenSSL | mbedtls |
|---|---|---|
| 出身 | 事实标准，Linux 系统自带 | ARM 出品，嵌入式首选 |
| 优点 | 自动加载系统 CA 信任库 | 代码小、可裁剪、依赖少 |
| API 模型 | `SSL_CTX`（配置）→ `SSL`（连接） | `mbedtls_ssl_config` → `mbedtls_ssl_context` |

## 4. 架构

```
ws_conn ──▶ stream_conn (统一接口, ops+impl 壳)
              ├── tcp_conn.c (impl=tcp_conn, fd 直连)
              └── tls_conn.c (公开 API: sevent_tls_conn_*; impl=tls_conn, 组合 tcp_conn)
                    │  用户 ⇄ TLS 明文 ⇄ ssl 层(加解密) ⇄ TLS 密文 ⇄ tcp_conn ⇄ fd
                    └──▶ sevent_ssl (src/ssl/: 统一接口, 不碰 fd)
                          ├── ssl_openssl.c  (BIO pair 密文通道)
                          └── ssl_mbedtls.c  (缓冲回调密文通道)
```

- 壳 `struct sevent_ssl { ops; impl; err[160]; }` — 与 stream_conn 同构
- 对象两段式：`ctx`（配置+证书材料，每连接一份）→ `ssl`（单连接：角色 + hostname）
- **数据通道（D7）**：`ssl_new` 不绑定 fd；对端密文经 `feed` 喂入，本端密文经 `drain` 取走；对端 TCP 关闭经 `peer_close` 标记（已喂密文耗尽后 read 返回 0=EOF）
- **tls_conn（组合 tcp_conn）**：TCP 建连/事件/写队列/destroy 全复用；tls 内部回调把 tcp 密文喂给 SSL、把 SSL 产出的密文写回 tcp；用户只感知 stream 接口，TLS 完全透明（on_data 推的就是明文）
- 调用时序：
  - 客户端：`ssl_ctx_new(cfg)` → TCP 建连后 `ssl_new(ctx, is_server=false, hostname)` → `handshake()`（WANT_READ/WANT_WRITE 反复驱动）→ 完成 → `read/write`
  - 服务端：`ssl_new(ctx, is_server=true, hostname=期望的客户端证书名)` → `handshake()` → 读写
- 主动关闭**不发** close_notify（WebSocket 场景 Close 帧已由 ws 层处理，TLS 直接 TCP close）；对端 close_notify → read 返回 0（EOF）

## 5. 接口定稿

### 5.1 ssl 层（src/ssl/ssl.h，内部）

```c
typedef struct sevent_ssl_config {
    /* 证书三件套: 文件路径 + 内存 PEM 双通道 (D3)
     *   每对字段互斥 — 同时提供 → ctx_new 失败
     *   均为 NULL: CA → openssl=系统默认信任库 / mbedtls=配置错误; cert/key → 配置错误
     *   格式: 仅 PEM 文本 (NUL 结尾), 私钥不支持加密 */
    const char *ca_path;   const char *ca_pem;
    const char *cert_path; const char *cert_pem;
    const char *key_path;  const char *key_pem;
    bool enable_peer_verify;              /* D6: 客户端=验证服务器证书链; 服务端=true=mTLS */
    bool enable_hostname_verify;   /* D2: 开关, 两端通用, 默认 true; mbedtls 恒开 */
} sevent_ssl_config;

enum { SEVENT_SSL_OK = 0, SEVENT_SSL_WANT_READ = 1, SEVENT_SSL_WANT_WRITE = 2 };

sevent_ssl *sevent_ssl_ctx_new(const sevent_ssl_config *cfg); /* NULL=失败; 每连接一个, 不跨连接共享 */
void        sevent_ssl_ctx_free(sevent_ssl *ctx);
sevent_ssl *sevent_ssl_new(sevent_ssl *ctx, bool is_server, const char *hostname);
    /* NULL=失败 (错误文本经 ctx->err 取). hostname 两端通用 (D2):
     *   客户端: SNI + 校验名 (enable_hostname_verify 时; NULL=不设 SNI 不校名)
     *   服务端: 期望的客户端证书主机名 (mTLS 时; NULL=不校验名)
     *   服务端 cert 必填检查在此做: is_server && cert/key 全 NULL → 失败 */
void        sevent_ssl_free(sevent_ssl *ssl);
/* 数据通道 (D7) */
int         sevent_ssl_feed(sevent_ssl *ssl, const uint8_t *data, size_t len);  /* 喂入对端密文, 0=接受 */
ssize_t     sevent_ssl_drain(sevent_ssl *ssl, void *buf, size_t cap);           /* 取本端密文, >0 字节, 0=无 */
void        sevent_ssl_peer_close(sevent_ssl *ssl);  /* 对端底层连接已关闭 (tcp on_close 时) */
/* 操作 */
int         sevent_ssl_handshake(sevent_ssl *ssl);      /* 0 / WANT_READ / WANT_WRITE / <0 */
ssize_t     sevent_ssl_read(sevent_ssl *ssl, void *buf, size_t len);   /* >0 / 0=EOF / <0 */
ssize_t     sevent_ssl_write(sevent_ssl *ssl, const void *buf, size_t len); /* >0 / 0=未写重试 / <0 */
int         sevent_ssl_want(sevent_ssl *ssl);           /* read/write 未完成操作的原因 */
int         sevent_ssl_pending(sevent_ssl *ssl);        /* 已解密待读字节数 (fd 无事件但 SSL 内部有数据) */
void        sevent_ssl_error(sevent_ssl *ssl, char *buf, size_t cap); /* 错误文本; ctx/ssl 壳均可调 */
const char *sevent_ssl_backend_name(void);               /* 后端名+版本, 如 "mbedtls 2.25.0" */
```

### 5.2 stream 层

```c
typedef struct sevent_stream_conn_config {
    /* ... 既有字段 (enable_tls/ca_path/cert_path/key_path/enable_peer_verify) ... */
    bool        enable_hostname_verify; /* D2: 校验对端证书名开关, 两端通用, 默认 true */
    const char *tls_hostname; /* D2: 本端期望的对端证书名 (对象级 — 与开关同处)
                               *   客户端: SNI+校验名 (NULL=用 open 的 host, 校验连接目标)
                               *   服务端: 校验客户端证书名 (mTLS 时, NULL=不校验名)
                               *   应用负责 DNS — TCP 目标 (open 的 host) 传 IP, 域名校验名经此字段 */
} sevent_stream_conn_config;

typedef struct sevent_stream_conn_init {
    /* ... 既有字段 (回调组/connect_timeout_ms/recv_buf_size) — 无 TLS 字段 ... */
} sevent_stream_conn_init;
```

**hostname 来源（tls_conn）**：对象级（create 时存 `t->hostname`）；客户端 open 时 `t->hostname ?: open 的 host`（sevent_i_malloc 拷贝）；服务端用 `t->hostname`（NULL=不校验名）。ssl_new 的 hostname 参数**两端通用**（非 NULL 且 enable_hostname_verify 时校验；SNI 仅客户端，RFC 6066）。

### 5.3 tls_conn 公开 API（与 tcp_conn 对称，见 include/sevent_tls_conn.h）

```c
sevent_tls_conn *sevent_tls_conn_create(sevent_context *ev, const sevent_stream_conn_config *cfg);
int  sevent_tls_conn_open(sevent_tls_conn *c, const char *host, uint16_t port, const sevent_stream_conn_init *init);
int  sevent_tls_conn_accept(sevent_tls_conn *c, int fd, const sevent_stream_conn_init *init);
int  sevent_tls_conn_write(sevent_tls_conn *c, const void *data, size_t len);
void sevent_tls_conn_close(sevent_tls_conn *c);
void sevent_tls_conn_destroy(sevent_tls_conn *c);
void *sevent_tls_conn_get_ssl(sevent_tls_conn *c); /* 底层 SSL 对象 (特殊需求) */
```

用户可直接用本 API（不经过 stream_conn 抽象），用法与 tcp_conn 完全一致（仅 create 多 TLS 配置）；
ws 模块经 stream_conn 使用（tls_stream_create 包壳，ops 转发到本 API —— 与 tcp 层同构）。

证书三件套（ca/cert/key）**路径 + PEM 内存双通道**（D3）：`ca_path/ca_pem`、
`cert_path/cert_pem`、`key_path/key_pem`——每对字段互斥（同时给 → create 失败），
cert/key 必须成对；格式仅 PEM 文本（NUL 结尾），私钥不支持加密。全透传到 ssl 层
（sevent_ssl_config），互斥/成对校验在 ssl 层 ctx_new 统一做。

**字段归属规则（生命周期维度）**：
- **对象级（config，create 时）**：跨连接不变——证书/CA/私钥、验证开关、**校验名 tls_hostname**（目标身份）
- **连接级（init，open/accept 时）**：每轮可变——回调组、超时、缓冲
- **函数参数（ssl_new）**：只有执行到那步才知道——is_server、hostname（TCP 建连后确定）

**分离原因**：传输层不解析域名（DNS 是应用层工作）→ wss://example.com 用法为"应用 resolve → IP 连 TCP，SNI/校验名用域名"；host 二合一无法表达（实测：mbedtls 2.25 把 IP 当 DNS 名匹配证书 SAN 失败）。

### 归一化语义（各后端内部翻译）

| 操作 | 返回值 |
|------|--------|
| handshake | 0=完成 / WANT_READ / WANT_WRITE / <0=失败（含证书验证失败、hostname 不匹配） |
| read | >0 数据 / 0=EOF(close_notify/对端关闭) / <0=错误（WANT 经 want() 查询） |
| write | >0 实际写 / 0=未写重试（want() 查原因）/ <0=致命 |
| pending | ≥0 字节数 |
| feed | 0=全接受 / -1=缓冲不足（内部复制） |
| drain | >0 字节 / 0=无（调用方循环取空） |
| error | 文本写入调用方缓冲（尽力而为） |

## 6. 后端实现映射（数据通道版）

| 接口 | OpenSSL | mbedtls (2.25, 2.x API) |
|------|---------|----------------|
| ctx_new | `SSL_CTX_new(TLS_method)`（角色无关）+ `load_verify_locations`/`set_default_verify_paths` + `use_certificate_chain_file`/`use_PrivateKey_file` + `check_private_key`；PEM 走 `BIO_new_mem_buf` + `PEM_read_bio_*`；`SSL_CTX_set_min_proto_version(TLS1_2_VERSION)` | 仅解析**材料**：`x509_crt_parse`/`parse_file`(CA/cert) + `pk_parse_key`/`parse_keyfile` + entropy+ctr_drbg（**不建 config**——见注②） |
| ssl_new | `SSL_new` + **BIO pair 密文通道**（`BIO_new_bio_pair`×2，内部端交 SSL，外部端 peer_rbio/peer_wbio 供 feed/drain）+ verify 模式 + 主机名：`SSL_set_tlsext_host_name`(SNI, 客户端) + `SSL_set1_host`(两端, enable_hostname_verify 时) | `mbedtls_ssl_init` + **此时建 config**（`config_defaults(endpoint=is_server)` + conf_rng + conf_authmode + conf_ca_chain/own_cert + conf_min_version(TLS1.2)）+ `mbedtls_ssl_setup` + `set_bio`(缓冲回调) + `set_hostname`(两端, SNI+校验合一) |
| feed | `BIO_write(peer_rbio, ...)`（64KB pair 缓冲） | 追加 `recv_buf`（64KB），recv 回调消费；peer_closed 后耗尽返回 CONN_EOF |
| drain | `BIO_read(peer_wbio, ...)`（空 → 0） | 取 `send_buf`（send 回调追加，满 → WANT_WRITE） |
| peer_close | `BIO_shutdown_wr(peer_rbio)` → 读耗尽后 EOF | 置 peer_closed → recv 回调返回 CONN_EOF |
| handshake | `SSL_connect`/`SSL_accept` → `SSL_get_error` 翻译 | `mbedtls_ssl_handshake` → 错误码翻译（含 CERT_VERIFY_FAILED） |
| read | `SSL_read` → 0=ZERO_RETURN / WANT_* | `mbedtls_ssl_read` → 0=close_notify/EOF / WANT_* |
| write | `SSL_write` | `mbedtls_ssl_write` |
| want | `SSL_get_error` 缓存 | WANT 错误码缓存 |
| pending | `SSL_pending` | `mbedtls_ssl_get_bytes_avail` |
| error | `ERR_get_error` 队列 + `ERR_error_string_n` | `mbedtls_strerror` + 自存 last_error（err 字段两结构体同偏移（最前），统一读） |

> **注①（2.x vs 3.x API）**：`mbedtls_pk_parse_keyfile` 2.x 签名 `(pk, path, password)` **无 f_rng**（3.x 才加）；最低版本用 `mbedtls_ssl_conf_min_version(conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3)`（3.x 改名 `conf_min_tls_version`）；错误码只判 `<0` 与特殊值 `WANT_READ/WANT_WRITE`（两版本相同），不依赖具体错误码。
>
> **注②（C1）**：mbedtls 的 endpoint 在 `config_defaults` 定死而角色在 ssl_new 才知（同一对象可重开两种角色）→ **mbedtls config 推迟到 ssl_new 创建**，ctx 只存材料 + entropy/drbg。openssl 用角色无关 `TLS_method()` 无此问题。

## 7. 后端行为差异（文档化，非缺陷）

| 差异 | OpenSSL | mbedtls (2.25) |
|------|---------|---------|
| 系统信任库 | ca 全 NULL → 默认系统 CA 链 | **无此概念** — ca 必填，否则验证必失败 |
| 主机名校验开关 | `enable_hostname_verify=false` 可关（仍发 SNI） | 无法只关 — `set_hostname` 同时做 SNI+校验，恒开 |
| IP 名校验 | 支持（`SSL_set1_host("1.2.3.4")` 匹配证书 IP SAN） | **不支持**（IP 当 DNS 名匹配 → 失败；实测 "127.0.0.1" 对 SAN=`DNS:localhost,IP:127.0.0.1` 验证失败）— IP 直连请用域名做校验名或 enable_peer_verify=false |
| 密文通道 | BIO pair | 缓冲回调（set_bio 自定义 recv/send） |
| 随机数 | 内部管理 | ctx 持有 entropy+ctr_drbg（/dev/urandom） |
| TLS 版本能力 | 支持 TLS1.3 | 2.25 无 TLS1.3，上限 TLS1.2（正常兼容） |
| 最低版本默认 | 3.x 默认 TLS1.2 | 2.x 默认 TLS1.0 — **实现强制 TLS1.2**（安全基线，两后端统一） |
| 对端关闭 EOF 信号（无 close_notify） | 3.x：`SSL_read` 返回 -1 + `SSL_ERROR_SSL` + reason=`SSL_R_UNEXPECTED_EOF_WHILE_READING`；2.x：`SSL_ERROR_SYSCALL` + errno=0 — **实现均归一化为 read 返回 0（EOF）**（3.x 的 err=2 勿误判为协议错误） | `peer_close` 后密文耗尽 read 直接返回 0 |
| EOF 时产出 close_notify | **会**（`SSL_read` 检测到对端关闭后尝试发出）— 底层 tcp 已收尾时该密文无处可送，tls_conn 视为**非错误丢弃**（`tls_send_cipher` 返回 1 走完 EOF 流程，不误报 WRITE） | 不产出（静默） |

## 8. 实施进度（2026-08-02）

| 步骤 | 内容 | 状态 |
|------|------|------|
| 0 | mbedtls 2.25 自编译安装 `~/documents/thirdparty/`（脚本 build_mbedtls.sh 幂等，含 GCC11 stringop-overflow 修复） | ✅ |
| 1 | ssl 层：ssl.h/ssl_i.h/ssl.c（壳+工厂+互斥校验）+ 后端名 | ✅ |
| 2 | ssl_openssl.c（BIO pair 数据通道） | ✅ |
| 3 | ssl_mbedtls.c（缓冲回调数据通道，2.x API） | ✅ |
| 4 | CMake：SEVENT_WS_TLS + SEVENT_WS_TLS_BACKEND（默认 MBEDTLS）+ 库缺失指引 + test-ssl target | ✅ |
| 5 | 测试：gen_certs.sh + test_ssl 8 用例，双后端 × ASAN 全过 | ✅ |
| 6 | tls_conn.c 组合 tcp_conn + tls_hostname（config 对象级）+ 命名定稿 + **公开 API（sevent_tls_conn_create/open/accept/write/close/destroy/get_ssl，与 tcp_conn 对称）** —— 双后端 × ASAN：test-ssl 8/8 + ctest 8/8 + 端到端 PASS 零泄漏 | ✅ |
| 6.1 | **tls_conn 行为补全（公开 API 独立测试暴露）**：① 终结语义 — EOF/error **及 open/accept 同步失败**后自动回 IDLE 可重开（`tls_reset_after_term`，与 tcp_conn 契约一致；on_error/on_close 回调内可直接 open）；② 回调安全 — 用户回调内 close/destroy 后 ssl 判空（各循环复查）；③ close 复用终结复位（同一套释放不重复）；④ openssl EOF 归一化（见 §7 新增两行）；⑤ 对象级 tls_hostname 归 `tls_cleanup` 释放（close 不清 — 重开校验名保持，分离场景不退化）；⑥ open 前置检查含 host NULL（与 tcp 一致） | ✅ |
| 6.2 | **公开 API 独立测试**：test-tcp-conn 7 用例 + test-tls-conn 7 用例（握手 echo/验证失败/hostname 不匹配/mTLS 拒绝/EOF+重开/1MB 大包/握手期对端关闭）—— 双后端 × ASAN：ctest 10/10 全绿，零泄漏零警告 | ✅ |
| 6.3 | **公开 API 独立测试补全**：tls 加 inval（NULL host/同步失败重试）与 close 后重开（对象级 hostname 保持）—— 暴露并修复 open 缺 host 检查、同步失败 established 残留、close 清 hostname 三缺陷 | ✅ |
| 7 | stream_conn_config 加 PEM 字段（D3：ca_pem/cert_pem/key_pem，path 互斥透传 ssl 层）—— test-tls-conn 加 t_pem_config（客户端 ca_pem + 服务端 PEM + 互斥/成对校验），双后端 × ASAN：ctest 10/10 全绿 | ✅ |
| 8 | ws 层接线 + 版本升 minor | ⬜ |

## 9. 约束（不重复决策）

- stream_conn 错误码复用 sevent 核心：TLS 握手失败 → `SEVENT_ERR_HANDSHAKE`，ssl 层不建独立错误码体系
- 线程：ssl 层不带锁（被 tls_conn 调用，后者在 loop 线程 + SEVENT_THREAD_SAFE 时由锁保护）
- ALPN 本期不支持（ws 场景不需要，ops 表将来可扩）
- 私钥不支持加密（明文 PEM only）
- **SIGPIPE**：ssl 层不碰网络（密文经通道交换，网络写由 tcp_conn 带 MSG_NOSIGNAL）→ ssl 层无 SIGPIPE 问题；应用层仍按库契约调 `sevent_ignore_sigpipe`
- 读/写 0 值语义不同：`read 0`=EOF，`write 0`=未写重试（want() 查原因）——头文件注释写死
- 服务端 cert 必填检查：**ssl_new（is_server=true 时）**；ctx_new 只查 cert/key 成对（角色未知）
- **hostname 校验场景矩阵**：仅"验证对端证书身份"时发生——客户端验证服务器证书（SAN==连接名）；服务端 mTLS 验证客户端证书（SAN==期望名）；服务端无 mTLS 时无校验。CA 链验证≠hostname 校验（链=证书真伪，名=证书归属）
- **内存分配纪律**：所有分配/释放走替换分配器接口（`sevent_i_malloc`/`sevent_i_calloc`/`sevent_i_free`）；禁止 strdup/裸 malloc/free；realloc 语义手动 malloc+memcpy+free。已全库扫描清零
- **tls_conn 写路径**：明文同步 SSL_write（drain 密文→tcp.write 循环），无队列；极端 WANT_READ（TLS1.3 密钥更新）时剩余明文暂存 pending_buf，tcp on_data 续写
- 测试证书：根 CA → 服务器证书（SAN 含 `localhost` 与 `IP:127.0.0.1`）+ 客户端证书（mTLS）；hostname 正例连 `localhost`、反例连 `127.0.0.1`（反例在 openssl 后端做，见 §7 IP 名校验行）
