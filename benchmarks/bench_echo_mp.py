#!/usr/bin/env python3
"""
echo_server 性能测试 — 多进程版

用 multiprocessing 替代 threading，绕开 GIL 瓶颈，
更准确测量服务器上限。

用法: ./bench_echo_mp.py --clients 100 --size 4096 --count 1000
"""

import socket
import time
import subprocess
import argparse
import multiprocessing as mp
import os
import signal

# ── 解析参数 ──────────────────────────────────────────────

parser = argparse.ArgumentParser()
parser.add_argument('--clients', type=int, default=10, help='并发连接数')
parser.add_argument('--size', type=int, default=512, help='消息大小 (bytes)')
parser.add_argument('--count', type=int, default=100, help='每个连接发送次数')
parser.add_argument('--port', type=int, default=7777, help='服务端口')
parser.add_argument('--server', type=str, default='./build/example-echo-server', help='服务器路径')
args = parser.parse_args()

# ── 启动 echo server ─────────────────────────────────────

server_proc = None

def start_server():
    global server_proc
    log = open('/dev/null', 'w')
    server_proc = subprocess.Popen([args.server], stdout=log, stderr=log)
    time.sleep(0.2)
    try:
        s = socket.create_connection(('127.0.0.1', args.port), timeout=1)
        s.close()
    except:
        print("❌ 服务器启动失败")
        sys.exit(1)
    print(f"✅ 服务器已启动 (pid={server_proc.pid})")

def stop_server():
    global server_proc
    if server_proc:
        server_proc.terminate()
        server_proc.wait()

# ── 工作进程：每个进程跑一个连接 ─────────────────────────

def worker(count, size, port, result_queue):
    """一个进程只维护一个连接，发 count 次"""
    sent = 0
    recv = 0
    err  = 0
    data = b'x' * size
    try:
        s = socket.create_connection(('127.0.0.1', port), timeout=10)
        for _ in range(count):
            s.sendall(data)
            sent += size
            # 收完 size 字节
            remain = size
            while remain > 0:
                chunk = s.recv(remain)
                if not chunk:
                    raise ConnectionError("closed")
                recv += len(chunk)
                remain -= len(chunk)
        s.close()
    except Exception as e:
        err = 1
        print(f"  ⚠️  worker error: {e}")
    result_queue.put((sent, recv, err))

# ── 启动测试 ─────────────────────────────────────────────

if __name__ == '__main__':
    # 注意：subprocess 需要知道 server 路径
    # 在 Windows 上需要 if __name__ guard
    pass

start_server()

total_clients = args.clients
per_count = args.count
msg_size = args.size

print(f"\n📊 多进程测试: {total_clients} 进程 × {per_count} 次 × {msg_size}B")
print(f"  总数据量: {total_clients * per_count * msg_size / 1024 / 1024:.1f} MB")
print()

result_queue = mp.Queue()
start_ts = time.time()

procs = []
for i in range(total_clients):
    p = mp.Process(target=worker, args=(per_count, msg_size, args.port, result_queue))
    p.start()
    procs.append(p)

# 进度打印（单独的进程）
total_done = 0
total_sent = 0
total_recv = 0
total_err = 0
done_expected = total_clients

while total_done < done_expected:
    try:
        sent, recv, err = result_queue.get(timeout=0.5)
        total_done += 1
        total_sent += sent
        total_recv += recv
        total_err += err
        elapsed = time.time() - start_ts
        mb = total_sent / 1024 / 1024
        print(f"  完成: {total_done}/{done_expected}, {mb:.1f}MB, "
              f"{total_sent/1024/elapsed:.0f}KB/s"
              f"{'  ⚠️' if err else ''}")
    except:
        # timeout, 继续等
        elapsed = time.time() - start_ts
        if elapsed > 0:
            mb = total_sent / 1024 / 1024
            print(f"  进行中: {total_done}/{done_expected}, {mb:.1f}MB, "
                  f"{total_sent/1024/elapsed:.0f}KB/s", end='\r')

for p in procs:
    p.join()

elapsed = time.time() - start_ts

# ── 结果 ─────────────────────────────────────────────────

print("\n" + "─" * 50)
print("📈 测试结果 (multiprocessing)")
print(f"  耗时:         {elapsed:.2f}s")
print(f"  进程数:        {total_clients}")
print(f"  总发送:       {total_sent / 1024:.1f} KB")
print(f"  总接收:       {total_recv / 1024:.1f} KB")
print(f"  错误:         {total_err}")
print(f"  吞吐量:       {total_sent / 1024 / elapsed:.1f} KB/s")
print(f"  吞吐量:       {total_sent / 1024 / 1024 / elapsed:.3f} MB/s")

if total_err > 0:
    print(f"  ⚠️  发生了 {total_err} 个错误")
    passed = False
else:
    passed = total_sent == total_recv and total_sent > 0

if passed:
    print(f"\n✅ 测试通过 (数据完整)")
else:
    print(f"\n❌ 测试失败")

stop_server()
