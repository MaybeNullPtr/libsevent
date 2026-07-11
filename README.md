# libsevent — 轻量 select 事件循环

[![CI](https://github.com/wanglb/libsevent/actions/workflows/ci.yml/badge.svg)](https://github.com/wanglb/libsevent/actions/workflows/ci.yml)

```c
// 核心 API 就 16 个函数, 不搞虚的
sevent_context *sevent_create(void);
void            sevent_destroy(sevent_context *);
int             sevent_run(sevent_context *);
int             sevent_run_once(sevent_context *);
void            sevent_stop(sevent_context *);
int             sevent_wakeup(sevent_context *);

sevent_post_t   sevent_post(sevent_context *, sevent_handler_fn, void *);
void            sevent_post_cancel(sevent_context *, sevent_post_t);
int             sevent_dispatch(sevent_context *, sevent_handler_fn, void *);

sevent_io_t     sevent_io_register(sevent_context *, struct sevent_io_handler *);
void            sevent_io_unregister(sevent_context *, sevent_io_t);

sevent_timer_t  sevent_timer_register(sevent_context *, unsigned int ms,
                                      sevent_timer_fn, void *);
void            sevent_timer_unregister(sevent_context *, sevent_timer_t);

void            sevent_ignore_sigpipe(void);
int             sevent_set_allocator(sevent_malloc_fn, sevent_free_fn);
void            sevent_get_counts(sevent_context *, int *io, int *timer, int *post);
```

## 概要

libsevent 是一个极小 C99 事件循环库, 基于 `select()` 多路复用.
主打 **简单、低内存、够用**——核心 ~600 行, 零外部依赖 (仅 POSIX 标准头文件).

### 特性

- **三种事件类型**: I/O / 定时器 / 异步任务 (post)
- **select 多路复用**, 毫秒级定时器精度
- **跨线程安全**: post/register/unregister 内部加锁
- **平台抽象层**: `SEVENT_RTOS` 宏一键切换 POSIX/RTOS 代码路径
- **可移植 wakeup**: Linux eventfd → POSIX pipe → UDP loopback 自动降级
- **回调安全**: IO/定时器回调内可安全 unregister 自己或操作其他对象
- **延迟释放**: 回调中注销的资源由 loop 在下轮统一回收
- **可替换分配器**: `sevent_set_allocator` 定制内存管理
- **单元测试**, GitHub Actions CI

### 非目标

- ❌ epoll/kqueue/IOCP (用 select 就够了)
- ❌ 文件异步 I/O / DNS / 进程管理
- ❌ 高性能 10k+ 连接 (用 libuv/libevent)
- ❌ 全平台适配 (RTOS 提供骨架, 用户按需填充)

## 构建

```bash
cd libsevent
mkdir build && cd build
cmake ..
make                # 编译库 + 测试 + 8 个例子
make check          # 跑单元测试
```

RTOS 构建:
```bash
cmake .. -DSEVENT_RTOS=ON    # RTOS 代码路径
make                          # mutex/thread 为骨架 TODO
```

```
libsevent/
├── .github/workflows/ci.yml  ← GitHub Actions CI
├── CMakeLists.txt
├── README.md
├── include/
│   ├── sevent.h              ← 公开 API
│   └── sevent_platform.h     ← 平台抽象声明 (内部)
├── src/
│   ├── sevent.c              ← 事件循环实现
│   └── sevent_platform.c     ← 平台抽象实现 (mutex/wakeup)
├── tests/
│   └── test_sevent.c         ← 单元测试
└── examples/
    ├── stdin_echo.c           ← 最简入门: stdin → stdout
    ├── timer_demo.c           ← 多定时器精度观测
    ├── echo_server.c          ← TCP echo 服务
    ├── echo_client.c          ← TCP echo 压测客户端
    ├── http_server.c          ← HTTP/1.0 服务器
    ├── chat_server.c          ← 多客户端聊天中继
    ├── signal_demo.c          ← 信号驱动优雅退出
    └── thread_worker.c        ← 跨线程异步任务
```

## 快速开始

读 stdin, 写 stdout, 输入 "quit" 退出:

```c
#include "sevent.h"
#include <stdio.h>
#include <unistd.h>
#include <string.h>

static void on_stdin(void *data)
{
    char buf[256];
    ssize_t n = read(0, buf, sizeof(buf) - 1);
    if (n <= 0) { sevent_stop((sevent_context *)data); return; }
    buf[n] = '\0';
    printf("echo: %s", buf);
    if (strcmp(buf, "quit\n") == 0) sevent_stop((sevent_context *)data);
}

int main(void)
{
    sevent_context *ctx = sevent_create();
    sevent_io_register(ctx, &(struct sevent_io_handler){
        .fd = 0, .io_read = on_stdin, .data = ctx
    });
    sevent_run(ctx);
    sevent_destroy(ctx);
    return 0;
}
```

编译:

```bash
gcc -std=c99 -Ilibsevent/include -o demo demo.c \
    libsevent/src/sevent.c libsevent/src/sevent_platform.c
```

## API 参考

### 版本

```c
#define SEVENT_VERSION_MAJOR 1
#define SEVENT_VERSION_MINOR 0
#define SEVENT_VERSION_PATCH 0
#define SEVENT_VERSION       "1.0.0"
```

编译期检查版本: `#if SEVENT_VERSION_MAJOR >= 1`

### 事件循环

| 函数 | 前置条件 | 说明 | 线程 |
|------|---------|------|------|
| `sevent_create()` | — | 创建 ctx, 返回 NULL 失败 | 串行 |
| `sevent_destroy(ctx)` | loop 已停止, 无其他线程操作 ctx | 释放所有内部资源, ctx 不可再用 | 串行 |
| `sevent_run(ctx)` | ctx 已创建, 无并发 run | 阻塞直到 stop | 串行(单 loop 线程) |
| `sevent_run_once(ctx)` | loop 线程专用 | 跑一轮: 1=有事件, 0=空闲, <0=错误 | 串行 |
| `sevent_stop(ctx)` | ctx 非空 | 通知 loop 退出; 回调内可安全调用 | 跨线程(无锁) |
| `sevent_wakeup(ctx)` | ctx 非空 | 唤醒 select; 用于跨线程通知 | 跨线程(无锁) |

### 异步任务

| 函数 | 说明 | 线程 |
|------|------|------|
| `sevent_post(ctx, cb, data)` | 投递 FIFO 任务, 返回句柄或 NULL | 跨线程(post_lock) |
| `sevent_post_cancel(ctx, h)` | 取消未执行任务; 已执行或句柄失效则无效果. 幂等, h 可为 NULL | 跨线程(post_lock) |
| `sevent_dispatch(ctx, cb, data)` | loop 线程内立即执行, 否则入队 post | 跨线程 |

### 句柄生命周期

| 句柄类型 | 何时失效 | 多次操作安全? |
|----------|---------|-------------|
| `sevent_io_t` / `sevent_timer_t` | 用户调 unregister 后, 下轮 loop 回收 | 是 (幂等) |
| `sevent_post_t` | 任务执行后自动释放 | 是 (cancel 只查 pending) |

### 内存分配器

```c
typedef void *(*sevent_malloc_fn)(size_t size);
typedef void  (*sevent_free_fn)(void *ptr);

int sevent_set_allocator(sevent_malloc_fn malloc_fn, sevent_free_fn free_fn);
```

- 前置条件: `sevent_create()` 之前调用
- 两个参数必须同时非 NULL 或同时 NULL
- `sevent_set_allocator(NULL, NULL)` 恢复默认
- 线程: 串行

### I/O

监听 fd 的可读/可写事件. 注册时指定回调, fd 就绪时触发.
回调中可安全 unregister 自己 (延迟释放, 下轮 loop 回收).

```c
struct sevent_io_handler {
    int               fd;
    sevent_io_read_fn  io_read;   /* 可读回调, NULL=忽略 */
    sevent_io_write_fn io_write;  /* 可写回调, NULL=忽略 */
    void              *data;
};

// fd 不能重复注册, fd < FD_SETSIZE, h 内容调用后不再使用
sevent_io_t sevent_io_register  (sevent_context *ctx, struct sevent_io_handler *h);
// 未注册/已注销句柄安全 (幂等). 回调内安全. h 必须有效
void        sevent_io_unregister(sevent_context *ctx, sevent_io_t h);
```

### 定时器

注册间隔定时器, 到期后自动循环触发. 回调内可安全 register/unregister
任意定时器 (包括自己), 无需担心死锁或重入问题.

```c
// interval_ms > 0, 返回句柄或 NULL
sevent_timer_t sevent_timer_register  (sevent_context *ctx, unsigned int interval_ms,
                                       sevent_timer_fn cb, void *data);
// 未注册/已注销句柄安全 (幂等). 回调内安全. h 必须有效
void           sevent_timer_unregister(sevent_context *ctx, sevent_timer_t h);
```

### Loop 一轮顺序

```
① 回收资源         ← 释放上一轮注销的 IO/定时器/post
② 构建监听集       ← 收集所有活跃 fd, 计算最短定时器超时
③ 多路复用         ← select() 等待 fd 就绪或定时器到期
④ 处理 IO          ← 就绪的 fd 触发对应回调
⑤ 处理异步任务     ← 按 FIFO 顺序执行 post 队列
⑥ 处理定时器       ← 到期的定时器触发回调
```

### 可观测性

```c
void sevent_get_counts(sevent_context *ctx,
                       int *io_count, int *timer_count, int *post_count);
```

返回当前活跃对象数量瞬间快照。
- 任一指针为 NULL 表示不关心该项
- io_count: 活跃 IO 注册数
- timer_count: 活跃定时器数
- post_count: 待处理异步任务数 (pending 队列)
- 线程: 跨线程 (内部锁)

### 平台抽象层

`sevent_platform.h` / `sevent_platform.c` 隔离平台差异, RTOS 用户按需填充:

| 模块 | POSIX (默认) | RTOS (`-DSEVENT_RTOS`) |
|------|-------------|----------------------|
| 互斥锁 | `pthread_mutex_t` | 需用户实现 |
| 线程ID | `pthread_self/equal` | 需用户实现 |
| Wakeup | eventfd/pipe/UDP 自动降级 | 需用户实现 |

编译: `cmake .. -DSEVENT_RTOS=ON` 后补充 `sevent_mutex_*` 和 `sevent_thread_*`.

## 例子

| 例子 | 说明 | 运行 |
|------|------|------|
| `example-stdin-echo` | stdin → stdout, 最简入门 | `./build/example-stdin-echo` |
| `example-timer-demo` | 3 个定时器, 精度对比 | `./build/example-timer-demo` |
| `example-echo-server` | TCP echo (7777) | `./build/example-echo-server` |
| `example-echo-client` | TCP echo 压测客户端 | `./build/example-echo-client` |
| `example-http-server` | HTTP/1.0 服务器 (8080) | `./build/example-http-server` |
| `example-chat-server` | 多客户端聊天中继 (7778) | `./build/example-chat-server` |
| `example-signal-demo` | 信号驱动优雅退出 | `./build/example-signal-demo` |
| `example-thread-worker` | 跨线程异步任务 | `./build/example-thread-worker` |

## 设计原则

1. **够用即可** — 不追求 libuv 的全覆盖, 只做基础事件分发
2. **零拷贝** — 数据 buffer 由用户管理, 库不碰你的数据
3. **直来直去** — 没有 handle 继承体系, 没有 close 回调
4. **低内存** — 侵入式链表, 无线程池, 无动态扩容
5. **错误可见** — 返回值错误码, 不吞异常

## License

MIT
