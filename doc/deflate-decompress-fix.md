# 解压截断修复方案 — zlib 放协议层 + 分批输出

## 问题

Autobahn 12.2.6 压缩消息流式解压后数据被截断（7404 vs 8192，缺 788 字节）。
根因：`decompress_stream_end` 用固定 64 字节缓冲接收 zlib 内部积压，缓冲不足时
zlib 静默截断（`ws_deflate_decompress_end` 不报错）。

更根本的问题：**zlib 无法预判解压输出大小**（只有压缩侧有 deflateBound），
输出缓冲不足必须处理。

## 方案 v2（当前采用）：分批输出，固定缓冲

- 把 zlib 直接放到协议层（`ws_conn.c`），删除 `ws_deflate` 的解压封装
  （`ws_deflate_decompress` / `_stream` / `_end` / `_reset` 及 stub 版），
  压缩侧封装保留（deflateBound 可预判输出，封装自包含）。
- `struct ws_deflate` 公开到 `ws_deflate.h`，协议层直接操作 `df->inflate`（z_stream）。
- 解压循环用**固定大小输出缓冲**（`SEVENT_WS_DECOMP_BATCH` 4096，栈上分配）：
  输入一段，多次调 `inflate()`，每次解满一批就 `on_message` 一批（fin=false，
  on_message 本就是流式回调，可多次调用）。**无 malloc、无扩容、无连续大内存**。
- 终止条件：
  - chunk（Z_NO_FLUSH）：`avail_in == 0 && avail_out > 0` → 输入消费完且输出未满，
    本批完成。当前 block 的 pending 数据留在 zlib 内部，由下个 chunk 或 end 吐出。
  - end（Z_SYNC_FLUSH）：`avail_out > 0` → 到达 sync 点，积压清空。
- 换输出缓冲是 zlib 标准用法：进度在 z_stream 内部，每次调用从 `next_out` 开始写，
  上次解到一半的位置下次无缝继续。
- **total 语义**：压缩消息的解压函数不提供 total——解压前无法预知原始长度，
  压缩路径的 `on_message` 一律传 0（未知）；非压缩路径保持原语义不变。
- 协议层 zlib 代码用 `#ifdef SEVENT_WS_DEFLATE` 隔离。

### 内存压力设备说明

- 固定 4KB 栈缓冲，无 malloc 失败路径；输出无论多大都只占 4KB。
- 真正的内存瓶颈是 zlib 内部窗口缓冲（默认 32KB+，`inflateInit2(windowBits=15)`），
  内存紧张设备应在握手协商 `server_max_window_bits`（RFC 7692，最小 8，
  窗口降到 256B 级）——协商层解决，不是输出缓冲能解决的。

## 伪代码（文字版，v2）

### decompress_stream_chunk(c, data, len, is_bin)

处理一个压缩分块：

1. 输入：`z->next_in = data; z->avail_in = len`（每次调用都是新 chunk——循环保证
   输入消费完（或出错/回调销毁）才返回，跨调用无残留，重置输入安全）。
2. 循环：
   - 设置固定 batch 输出缓冲（4096 栈上），`inflate(Z_NO_FLUSH)`。
   - 出错（非 Z_OK/Z_BUF_ERROR）→ inflateReset + 返回协议错误。
   - `used > 0` → `on_message(batch, used, fin=false, total=0)`；
     若回调内 destroy，返回中止。
   - **终止：`avail_in == 0 && avail_out > 0`**（输入消费完且输出未满）。
   - 输出满（avail_out == 0）→ 换下一批继续循环。
3. 返回 0。

### decompress_stream_end(c, is_bin)

消息收尾，吐 zlib 内部积压：

1. 输入：喂一次静态 tail `0x0000FFFF`（RFC 7692 §6），`avail_in = 4`。
2. 循环：同 chunk，但用 `Z_SYNC_FLUSH`；接受 `Z_STREAM_END`；
   **终止：`avail_out > 0`**（到达 sync 点，积压清空）。
3. `on_message(batch, 0, fin=true, total=0)` 发 fin。
4. `server_no_context_takeover` 时 `inflateReset(z)`。

### decompress_oneshot(c, in, in_len, is_bin)

非流式整条消息解压（替换 `ws_deflate_decompress`）：

1. 拼 tail：malloc(in_len+4)，拷贝输入 + 追加 `0x0000FFFF`（唯一一次输入侧分配）。
2. 循环同 end（Z_SYNC_FLUSH + 固定 batch）。
3. 发 fin 的 on_message，释放输入缓冲。

## 完整代码（参考实现，v2）

### ws_deflate.h — 公开结构

```c
#ifdef SEVENT_WS_DEFLATE
#include <zlib.h>
#endif

/* SEVENT_WS_DEFLATE 下公开, OFF 下保持 opaque stub */
struct ws_deflate {
#ifdef SEVENT_WS_DEFLATE
    z_stream deflate;
    z_stream inflate;
#endif
    bool     server_no_context_takeover;
    bool     client_no_context_takeover;
    uint8_t  server_window_bits;
    uint8_t  client_window_bits;
};
```

### ws_conn.c — 解压（协议层直接调 zlib，分批输出）

```c
#ifdef SEVENT_WS_DEFLATE
#include <zlib.h>
#endif

/* 单批解压输出缓冲: 固定, 栈上分配, 无 malloc */
#define SEVENT_WS_DECOMP_BATCH 4096

static int decompress_stream_chunk(struct sevent_ws_conn *c, const uint8_t *data,
                                   size_t len, bool is_bin) {
#ifdef SEVENT_WS_DEFLATE
    if(!c->on_message)
        return 0;
    z_stream *z = &c->deflate->inflate;
    z->next_in  = (uint8_t *)data;
    z->avail_in = (uInt)len;

    uint8_t batch[SEVENT_WS_DECOMP_BATCH];

    for(;;) {
        z->next_out  = batch;
        z->avail_out = (uInt)sizeof(batch);
        int rc = inflate(z, Z_NO_FLUSH);
        if(rc == Z_BUF_ERROR && z->avail_in > 0) {
            /* 有输入却无进展: 异常 */
            inflateReset(z);
            return -1;
        }
        if(rc != Z_OK && rc != Z_BUF_ERROR) {
            inflateReset(z);
            return -1;
        }
        size_t used = sizeof(batch) - z->avail_out;
        if(used > 0) {
            c->on_message(c->user_data, batch, used, is_bin, false, 0);
            if(c->destroyed)
                return 0; /* 回调内销毁, 中止 */
        }
        if(z->avail_in == 0 && z->avail_out > 0)
            break; /* 输入消费完且输出未满 */
        /* 输出满 → 换下一批 */
    }
    return 0;
#else
    return -1;
#endif
}

static int decompress_stream_end(struct sevent_ws_conn *c, bool is_bin) {
#ifdef SEVENT_WS_DEFLATE
    if(!c->on_message)
        return 0;
    z_stream *z = &c->deflate->inflate;
    static const uint8_t tail[4] = {0x00, 0x00, 0xFF, 0xFF};
    z->next_in  = (uint8_t *)tail; /* 只喂一次 */
    z->avail_in = 4;

    uint8_t batch[SEVENT_WS_DECOMP_BATCH];

    for(;;) {
        z->next_out  = batch;
        z->avail_out = (uInt)sizeof(batch);
        int rc = inflate(z, Z_SYNC_FLUSH);
        if(rc == Z_BUF_ERROR && z->avail_in > 0) {
            inflateReset(z);
            return -1;
        }
        if(rc != Z_OK && rc != Z_STREAM_END && rc != Z_BUF_ERROR) {
            inflateReset(z);
            return -1;
        }
        size_t used = sizeof(batch) - z->avail_out;
        if(used > 0) {
            c->on_message(c->user_data, batch, used, is_bin, false, 0);
            if(c->destroyed)
                return 0;
        }
        if(z->avail_out > 0)
            break; /* 到达 sync 点 */
    }
    c->on_message(c->user_data, batch, 0, is_bin, true, 0);
    if(c->deflate->server_no_context_takeover)
        inflateReset(z);
    return 0;
#else
    return -1;
#endif
}

static int decompress_oneshot(struct sevent_ws_conn *c, const uint8_t *in, size_t in_len,
                              bool is_bin) {
#ifdef SEVENT_WS_DEFLATE
    if(!c->on_message)
        return 0;
    uint8_t *buf = (uint8_t *)sevent_i_malloc(in_len + 4); /* tail 拼接输入 */
    if(!buf)
        return -1;
    memcpy(buf, in, in_len);
    buf[in_len]     = 0x00;
    buf[in_len + 1] = 0x00;
    buf[in_len + 2] = 0xFF;
    buf[in_len + 3] = 0xFF;

    z_stream *z = &c->deflate->inflate;
    z->next_in  = buf;
    z->avail_in = (uInt)(in_len + 4);

    uint8_t batch[SEVENT_WS_DECOMP_BATCH];
    int     ret = -1;

    for(;;) {
        z->next_out  = batch;
        z->avail_out = (uInt)sizeof(batch);
        int rc = inflate(z, Z_SYNC_FLUSH);
        if(rc == Z_BUF_ERROR && z->avail_in > 0) {
            inflateReset(z);
            goto out;
        }
        if(rc != Z_OK && rc != Z_STREAM_END && rc != Z_BUF_ERROR) {
            inflateReset(z);
            goto out;
        }
        size_t used = sizeof(batch) - z->avail_out;
        if(used > 0) {
            c->on_message(c->user_data, batch, used, is_bin, false, 0);
            if(c->destroyed)
                goto out;
        }
        if(z->avail_out > 0)
            break;
    }
    c->on_message(c->user_data, batch, 0, is_bin, true, 0);
    ret = 0;
out:
    sevent_i_free(buf);
    return ret;
#else
    return -1;
#endif
}
```

### ws_deflate.c — 删除与保留

删除：`ws_deflate_decompress`、`ws_deflate_decompress_stream`、
`ws_deflate_decompress_end`、`ws_deflate_decompress_reset`（含 stub 版）。
保留：`ws_deflate_create` / `_destroy` / `_compress_maxlen` / `_compress` /
压缩流式三件套（reset / stream / end）。

注意：`ws_deflate_create` 里 `inflateInit2` 保留（z_stream 初始化仍在这里）；
结构定义从 .c 移到 .h 后，.c 里不再有私有结构。

### 调用点（ws_conn.c）

- `process_frames` 里的 one-shot 路径：`ws_deflate_decompress(...)` →
  `decompress_oneshot(c, payload, payload_len, is_bin)`。
- `stream_consume` / `frag_flush`：`decompress_stream_chunk(c, data, len, is_bin)` /
  `decompress_stream_end(c, is_bin)`——签名去掉 last/total 参数（fin 统一由 end 发，
  total 压缩路径传 0），调用处同步。

### 决策记录

- **解压封装删除**：解压循环与协议层语义（on_message/fin/缓冲所有权）深度耦合，
  封装层无法独立成层；状态跨层是静默截断 bug 的根源；保留会产生两个行为不一致的入口。
- **压缩封装保留**：deflateBound 可预判输出，封装自包含（Z_SYNC_FLUSH + 去 tail +
  reset 内部完成）；协议层不需要了解 zlib 样板；流式发送（compress_stream/end）现成。
- **v2 选分批而非扩容**：on_message 是流式回调（fin=false 可多次调用），不存在
  "一次 chunk 必须一次 on_message" 的约束；固定缓冲无 malloc 失败路径，内存压力
  设备友好；v1 扩容方案见附录。
- **total 语义**：压缩路径一律传 0（解压前无法预知原始长度）；非压缩路径保持原语义。

## 附录：旧方案 v1（扩容循环，已废弃，保留对照）

v1 思路：每次调用局部 malloc 一个估算缓冲，输出满 → 翻倍扩容（malloc+memcpy+free
搬移，allocator 无 realloc）→ 重试，直到输出未满。问题：需要连续大缓冲、有
malloc 失败路径、消息膨胀多大就分多大内存。

### v1 伪代码

```
decompress_stream_chunk(c, data, len, is_bin):
    z->next_in = data; z->avail_in = len
    dec = malloc(len*4+64); used = 0
    循环:
        z->next_out = dec+used; z->avail_out = cap-used
        inflate(Z_NO_FLUSH)
        出错 → inflateReset + free + 返回协议错
        used = cap - z->avail_out
        avail_out > 0 → break            /* 输出未满 ⇒ 输入必已消费完 */
        cap *= 2; dec = malloc+memcpy(used)+free 搬移
    used > 0 → on_message(dec, used, fin=false)
    free(dec)

decompress_stream_end(c, is_bin):
    z->next_in = tail(0x0000FFFF); z->avail_in = 4   /* 喂一次 */
    dec = malloc(4096); used = 0
    循环: 同 chunk 但 Z_SYNC_FLUSH, avail_out > 0 → break
    used > 0 → on_message(dec, used, fin=false)
    on_message(dec, 0, fin=true)
    free(dec)
    no_context_takeover → inflateReset(z)

decompress_oneshot(c, in, in_len, is_bin):
    buf = malloc(in_len+4); 拼接 tail
    同一循环 (Z_SYNC_FLUSH + 扩容), 发 on_message
    free(buf)
```

### v1 完整代码

```c
static int decompress_stream_chunk(struct sevent_ws_conn *c, const uint8_t *data,
                                   size_t len, bool is_bin) {
    z_stream *z = &c->deflate->inflate;
    z->next_in  = (uint8_t *)data;
    z->avail_in = (uInt)len;

    size_t   cap = len * 4 + 64;
    size_t   used = 0;
    uint8_t *dec = (uint8_t *)sevent_i_malloc(cap);
    if(!dec)
        return -1;

    for(;;) {
        z->next_out  = dec + used;
        z->avail_out = (uInt)(cap - used);
        int rc = inflate(z, Z_NO_FLUSH);
        if(rc != Z_OK && rc != Z_BUF_ERROR) {
            inflateReset(z);
            sevent_i_free(dec);
            return -1;
        }
        used = cap - z->avail_out;
        if(z->avail_out > 0)
            break;
        if(cap > UINT_MAX / 2) {
            inflateReset(z);
            sevent_i_free(dec);
            return -1;
        }
        cap *= 2;
        uint8_t *nb = (uint8_t *)sevent_i_malloc(cap);
        if(!nb) {
            inflateReset(z);
            sevent_i_free(dec);
            return -1;
        }
        memcpy(nb, dec, used);
        sevent_i_free(dec);
        dec = nb;
    }
    if(used > 0)
        c->on_message(c->user_data, dec, used, is_bin, false, 0);
    sevent_i_free(dec);
    return 0;
}

static int decompress_stream_end(struct sevent_ws_conn *c, bool is_bin) {
    z_stream *z = &c->deflate->inflate;
    static const uint8_t tail[4] = {0x00, 0x00, 0xFF, 0xFF};
    z->next_in  = (uint8_t *)tail;
    z->avail_in = 4;

    size_t   cap = 4096;
    size_t   used = 0;
    uint8_t *dec = (uint8_t *)sevent_i_malloc(cap);
    if(!dec)
        return -1;

    for(;;) {
        z->next_out  = dec + used;
        z->avail_out = (uInt)(cap - used);
        int rc = inflate(z, Z_SYNC_FLUSH);
        if(rc != Z_OK && rc != Z_STREAM_END && rc != Z_BUF_ERROR) {
            inflateReset(z);
            sevent_i_free(dec);
            return -1;
        }
        used = cap - z->avail_out;
        if(z->avail_out > 0)
            break;
        if(cap > UINT_MAX / 2) {
            inflateReset(z);
            sevent_i_free(dec);
            return -1;
        }
        cap *= 2;
        uint8_t *nb = (uint8_t *)sevent_i_malloc(cap);
        if(!nb) {
            inflateReset(z);
            sevent_i_free(dec);
            return -1;
        }
        memcpy(nb, dec, used);
        sevent_i_free(dec);
        dec = nb;
    }
    if(used > 0)
        c->on_message(c->user_data, dec, used, is_bin, false, 0);
    c->on_message(c->user_data, dec, 0, is_bin, true, 0);
    sevent_i_free(dec);
    if(c->deflate->server_no_context_takeover)
        inflateReset(z);
    return 0;
}

static int decompress_oneshot(struct sevent_ws_conn *c, const uint8_t *in, size_t in_len,
                              bool is_bin) {
    uint8_t *buf = (uint8_t *)sevent_i_malloc(in_len + 4);
    if(!buf)
        return -1;
    memcpy(buf, in, in_len);
    buf[in_len]     = 0x00;
    buf[in_len + 1] = 0x00;
    buf[in_len + 2] = 0xFF;
    buf[in_len + 3] = 0xFF;

    z_stream *z = &c->deflate->inflate;
    z->next_in  = buf;
    z->avail_in = (uInt)(in_len + 4);

    size_t   cap = in_len * 4 + 64;
    size_t   used = 0;
    uint8_t *dec = (uint8_t *)sevent_i_malloc(cap);
    if(!dec) {
        sevent_i_free(buf);
        return -1;
    }

    for(;;) {
        z->next_out  = dec + used;
        z->avail_out = (uInt)(cap - used);
        int rc = inflate(z, Z_SYNC_FLUSH);
        if(rc != Z_OK && rc != Z_STREAM_END && rc != Z_BUF_ERROR) {
            inflateReset(z);
            sevent_i_free(dec);
            sevent_i_free(buf);
            return -1;
        }
        used = cap - z->avail_out;
        if(z->avail_out > 0)
            break;
        if(cap > UINT_MAX / 2) {
            inflateReset(z);
            sevent_i_free(dec);
            sevent_i_free(buf);
            return -1;
        }
        cap *= 2;
        uint8_t *nb = (uint8_t *)sevent_i_malloc(cap);
        if(!nb) {
            inflateReset(z);
            sevent_i_free(dec);
            sevent_i_free(buf);
            return -1;
        }
        memcpy(nb, dec, used);
        sevent_i_free(dec);
        dec = nb;
    }
    if(used > 0)
        c->on_message(c->user_data, dec, used, is_bin, false, 0);
    c->on_message(c->user_data, dec, 0, is_bin, true, 0);
    sevent_i_free(dec);
    sevent_i_free(buf);
    if(c->deflate->server_no_context_takeover)
        inflateReset(z);
    return 0;
}
```
