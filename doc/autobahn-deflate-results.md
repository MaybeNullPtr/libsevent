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
| **2026-08-01（本轮）** | **216/216 OK** |

本轮相对上一轮的代码变更：

- `frag_append`：压缩分片溢出时整块喂流式解压（不再 return -1 丢弃）
- `frag_flush`：压缩路径 `frag_len == recv_cap` 也 flush
- `stream_compressed`：消息级属性，`hdr.rsv1 || c->frag_compressed`（CONT 帧沿用）
- `stream_opcode`：消息级属性，CONT 帧（opcode=0）不覆盖（修复 is_bin 误判）
- `stream_consume`：消息结束补清 `frag_pending/frag_compressed`

## 遗留事项

- client / case12 调试日志（ECHO-DBG/SB-DBG/DBG12 等）未清理，待调通确认后删除
- 修复未提交（待确认后提交，带 unsafe 提示）
