#!/usr/bin/env python3
"""
http_server 性能压测 — asyncio 客户端, keep-alive 连发

测 sevent_http_server 的: 解析吞吐 / keep-alive 多请求复用 / 并发连接扩展.
对应 TCP 版先例: bench_echo_mp.py (echo 67K QPS / 900+ 连接).

用法:
    ./bench_http.py --clients 100 --requests 1000 --port 8080
    ./bench_http.py --clients 500 --requests 500 --url http://127.0.0.1:8080/hello

指标: QPS / 延迟 p50 p95 p99 / 错误数 (按连接聚合, 不跨连接共享统计 — 无锁)
"""

import argparse
import asyncio
import statistics
import time


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--clients", type=int, default=100, help="并发连接数")
    p.add_argument("--requests", type=int, default=1000, help="每连接请求数 (keep-alive 连发)")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--path", default="/hello")
    return p.parse_args()


async def worker(host, port, path, requests, results, errors):
    """单连接 keep-alive 连发, 返回 (延迟列表, 错误数) — 每 worker 独立结果, 无共享写."""
    lat = []
    err = 0
    try:
        reader, writer = await asyncio.open_connection(host, port)
    except OSError as e:
        return lat, err + 1

    req = f"GET {path} HTTP/1.1\r\nHost: x\r\n\r\n".encode()
    try:
        for _ in range(requests):
            t0 = time.perf_counter()
            writer.write(req)
            await writer.drain()
            # 读响应: 头到空行 + body 5 字节 ("hello")
            head = await reader.readuntil(b"\r\n\r\n")
            await reader.readexactly(5)
            if b" 200 " not in head.split(b"\r\n")[0]:
                err += 1
                break
            lat.append(time.perf_counter() - t0)
    except (asyncio.IncompleteReadError, ConnectionError, OSError):
        err += 1
    finally:
        writer.close()
        await writer.wait_closed()
    return lat, err


async def main():
    args = parse_args()
    print(f"压测: {args.clients} 连接 x {args.requests} 请求/连接 (keep-alive) -> {args.host}:{args.port}{args.path}")
    print(f"预计总请求: {args.clients * args.requests}")

    t0 = time.perf_counter()
    results = await asyncio.gather(*[
        worker(args.host, args.port, args.path, args.requests, [], [])
        for _ in range(args.clients)
    ])
    elapsed = time.perf_counter() - t0

    all_lat = [l for lat, _ in results for l in lat]
    errors = sum(e for _, e in results)
    total = len(all_lat)

    print(f"\n完成: {total}/{args.clients * args.requests} 请求, {elapsed:.2f}s, 错误 {errors}")
    if total:
        qps = total / elapsed
        all_lat.sort()
        p = lambda q: all_lat[min(len(all_lat) - 1, int(len(all_lat) * q))] * 1000
        print(f"QPS:   {qps:,.0f}")
        print(f"延迟:  p50 {p(0.50):.2f}ms  p95 {p(0.95):.2f}ms  p99 {p(0.99):.2f}ms  max {p(1.0):.2f}ms")
    return 0 if errors == 0 and total > 0 else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
