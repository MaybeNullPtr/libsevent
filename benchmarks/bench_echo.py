#!/usr/bin/env python3
"""
echo_server 性能测试

启动 echo server，多连接并发发送数据，统计吞吐量。

用法:
  ./bench_echo.py                              # 默认参数
  ./bench_echo.py --clients 100 --size 1024    # 100 连接, 1KB 消息
  ./bench_echo.py --duration 5                 # 持续 5 秒吞吐
"""

import socket
import time
import sys
import os
import signal
import subprocess
import argparse
from threading import Thread, Lock

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
    time.sleep(0.2)  # 等它起来
    # 验证服务器是否在监听
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
        print(f"  服务器已停止")

# ── 单连接测试 ───────────────────────────────────────────

stats = {
    'total_sent': 0,
    'total_recv': 0,
    'errors': 0,
}
stats_lock = Lock()
start_time = time.time()

def client_worker(conn_id):
    global start_time
    data = b'x' * args.size
    try:
        s = socket.create_connection(('127.0.0.1', args.port), timeout=5)
        for i in range(args.count):
            # 发送
            s.sendall(data)
            with stats_lock:
                stats['total_sent'] += args.size
            # 接收 (echo 返回同样大小的数据)
            recvd = 0
            while recvd < args.size:
                chunk = s.recv(args.size - recvd)
                if not chunk:
                    raise ConnectionError("连接关闭")
                recvd += len(chunk)
                with stats_lock:
                    stats['total_recv'] += len(chunk)
            # 进度
            if conn_id == 0 and (i + 1) % 10 == 0:
                elapsed = time.time() - start_time
                mb = stats['total_sent'] / 1024 / 1024
                print(f"  进度: {i+1}/{args.count}, {mb:.1f}MB, "
                      f"{stats['total_sent']/1024/elapsed:.0f}KB/s", end='\r')
        s.close()
    except Exception as e:
        with stats_lock:
            stats['errors'] += 1
        if conn_id == 0:
            print(f"\n  ⚠️  连接 {conn_id}: {e}")

# ── 启动测试 ─────────────────────────────────────────────

start_server()
print(f"\n📊 测试参数: {args.clients} 连接 × {args.count} 次 × {args.size}B")
print(f"  总数据量: {args.clients * args.count * args.size / 1024 / 1024:.1f} MB")
print()

start_time = time.time()

threads = []
for i in range(args.clients):
    t = Thread(target=client_worker, args=(i,))
    t.start()
    threads.append(t)

for t in threads:
    t.join()

elapsed = time.time() - start_time

# ── 结果 ─────────────────────────────────────────────────

print("\n" + "─" * 50)
print("📈 测试结果")
print(f"  耗时:         {elapsed:.2f}s")
print(f"  连接数:        {args.clients}")
print(f"  总发送:       {stats['total_sent'] / 1024:.1f} KB")
print(f"  总接收:       {stats['total_recv'] / 1024:.1f} KB")
print(f"  错误:         {stats['errors']}")
print(f"  吞吐量:       {stats['total_sent'] / 1024 / elapsed:.1f} KB/s")
print(f"  吞吐量:       {stats['total_sent'] / 1024 / 1024 / elapsed:.3f} MB/s")

if stats['errors'] > 0:
    print(f"  ⚠️  发生了 {stats['errors']} 个错误")
    passed = False
else:
    passed = stats['total_sent'] == stats['total_recv'] and stats['total_sent'] > 0

if passed:
    print(f"\n✅ 测试通过 (数据完整)")
else:
    print(f"\n❌ 测试失败")
    sys.exit(1)

stop_server()
