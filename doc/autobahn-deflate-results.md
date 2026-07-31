# Autobahn 压缩用例（12.\*/13.\*）全量测试结果

> 跑测日期：2026-08-01 · fuzzingserver 模式（测 C client）

## 环境

| 项 | 值 |
|----|----|
| wstest | crossbario/autobahn-testsuite:25.10.1（autobahntestsuite 源码映射本地） |
| client | tests/autobahn_client.cpp，`enable_deflate=on`，回显 `deflate_level=NONE`（明文回显） |
| 看门狗 | 10s（周期定时器 + 计数比较，10s 无新消息判定卡死） |
| 构建 | build.sh 全量重建，SEVENT_WS_DEFLATE=ON |
| 脚本超时上限 | 15 min |

## 结果总览

| 范围 | 总 case | OK | FAILED |
|------|--------:|----:|-------:|
| 12.\*（5 数据集 × 18 尺寸） | 90 | 90 | 0 |
| 13.\*（7 组压缩参数 × 18 尺寸） | 126 | 126 | 0 |
| **合计** | **216** | **216 (100%)** | **0** |

耗时：总计 **214s**，平均 0.99s/case，最慢 6.6s。

## Case 结构

### 12.x — 默认压缩参数，按测试数据集分系列

每系列 18 个 case：前 10 个为整帧消息（16B ~ 128KB × 1000 条），后 8 个为自动分片
（8KB~128KB 消息，fragment 256/1K/4K/32K）。

| 系列 | 数据集 | 类型 | 说明 |
|------|--------|------|------|
| 12.1 | data1.json | utf8 | 大 JSON 数据 |
| 12.2 | lena512.bmp | binary | 512x512 位图 |
| 12.3 | pg2229.txt | binary | 歌德《浮士德》德语文本 |
| 12.4 | data1.html | utf8 | 大 HTML 文件 |
| 12.5 | 10.1.1.105.5439.pdf | binary | 较大 PDF |

### 13.x — 压缩参数协商，数据固定为 data1.json

每系列 18 个 case（尺寸同 12.x）。

| 系列 | 协商参数（client offer） |
|------|--------------------------|
| 13.1 | 默认 offer（无附加参数） |
| 13.2 | requestNoContextTakeover |
| 13.3 | requestMaxWindowBits=9 |
| 13.4 | requestMaxWindowBits=15 |
| 13.5 | noContextTakeover + maxWindowBits=9 |
| 13.6 | noContextTakeover + maxWindowBits=15 |
| 13.7 | 多 offer 降级链（5→2→1） |

## 最慢 case（前 10）

| case | 耗时 | 说明 |
|------|-----:|------|
| 12.3.15 | 6.6s | gutenberg_faust 131072B, frag=4096 |
| 12.3.10 | 6.5s | gutenberg_faust 131072B, 整帧 |
| 12.3.17 | 6.5s | gutenberg_faust 131072B, frag=32768 |
| 12.3.18 | 6.4s | gutenberg_faust 131072B, frag=32768 |
| 12.3.16 | 6.4s | gutenberg_faust 131072B, frag=1024 |
| 12.2.15 | 4.7s | lena512 131072B, frag=4096 |
| 12.2.16 | 4.5s | lena512 131072B, frag=1024 |
| 12.2.18 | 4.4s | lena512 131072B, frag=32768 |
| 12.2.17 | 4.4s | lena512 131072B, frag=32768 |
| 12.2.10 | 4.3s | lena512 131072B, 整帧 |

慢的全部是 12.3（德语文本，压缩比最高的数据集，解压数据量最大）。

## 与修复前对比

| 时间点 | 结果 |
|--------|------|
| 2026-07-31 修复前（初次全量） | 60 OK / 30 失败（frag 溢出、stream_compressed、is_bin 三类根因） |
| 2026-08-01 12.x/13.x 单跑 | 216/216 OK |
| **2026-08-01 全量 1~12 回归** | **377 OK + 4 NON-STRICT + 3 INFORMATIONAL，FAILED=0** |

## 全量 1~12 回归（2026-08-01）

状态机重构 + msg_end 统一收尾修复后的完整回归：`CASES='["1.*","2.*","4.*","5.*","6.*","7.*","8.*","9.*","10.*","12.*"]'`（384 case，fuzzingserver 模式，TIMEOUT=900）。

| 分类 | 数量 | case | 说明 |
|------|-----:|------|------|
| OK | 377 | — | 全部通过 |
| NON-STRICT | 4 | 67, 68, 69, 70 | 无效 UTF-8 消息（6.4.x 变体）。预期表本身为 NON-STRICT/OK 双路径；实际匹配 NON-STRICT 分支（服务端以 1007 关闭、客户端未回数据、timeout 条件命中），宽容判定非失败 |
| INFORMATIONAL | 3 | 208, 238, 239 | 信息性 case：208 大消息+close+ping 实际 clean close 1000 ✓；238/239 自定义 close code 5000/65535，均在预期表 [1000, X, 1002] 内 ✓ |
| **FAILED** | **0** | — | **无失败，无回归** |

本轮关键修复（相对 12.x/13.x 单跑）：

- **msg_end 统一收尾**：压缩路径无条件补 00 00 FF FF tail（修复消息压缩后恰为 4096 整数倍时 fin 帧 0 字节、tail 缺失导致下一条消息解压错位的 12.3.13 失败）；非压缩路径补空 fin 回调（修复 6.1.2 空分片消息无回调）
- **fin 回调恰好一次**：`fin_sent` 标志保证 on_message(fin) 不重复、不漏发
- **状态机重构**：8 个消息级 flag → `struct ws_msg_state {mode, opcode, compressed, total, fin_sent}`（WS_MSG_NONE/FRAG/STREAM 三路径统一收尾）

本轮相对上一轮的代码变更：

- `frag_append`：压缩分片溢出时整块喂流式解压（不再 return -1 丢弃）
- `frag_flush`：压缩路径 `frag_len == recv_cap` 也 flush
- `stream_compressed`：消息级属性，`hdr.rsv1 || c->frag_compressed`（CONT 帧沿用）
- `stream_opcode`：消息级属性，CONT 帧（opcode=0）不覆盖（修复 is_bin 误判）
- `stream_consume`：消息结束补清 `frag_pending/frag_compressed`

## 遗留事项

- 调试日志已全部清理（client 的 case 进度日志保留，lib 的插桩日志已删）
- 修复未提交（待确认后提交，带 unsafe 提示）
