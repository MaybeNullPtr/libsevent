# libsevent — 轻量 select 事件循环

```c
// 核心 API 就 11 个函数, 不搞虚的
sevent_context *sevent_create(void);
void            sevent_destroy(sevent_context *);
int             sevent_run(sevent_context *);
int             sevent_run_once(sevent_context *);
void            sevent_stop(sevent_context *);
int             sevent_wakeup(sevent_context *);
int             sevent_post(sevent_context *, sevent_handler_fn, void *);

sevent_io_t       sevent_io_register(sevent_context *, struct sevent_io_handler *);
void            sevent_io_unregister(sevent_io_t);

sevent_timer_t    sevent_timer_register(sevent_context *, unsigned int ms, sevent_timer_fn, void *);
void            sevent_timer_unregister(sevent_timer_t);
```

## 概要

libsevent 是一个极小 C 语言事件循环库, 基于 `select()` 多路复用.
主打 **简单、低内存、够用**——代码量 ~400 行, 零外部依赖.

### 特性

- **三种事件类型**: I/O / 定时器 / 异步任务 (post)
- **select 多路复用**, 30ms 定时器精度
- **self-pipe 跨线程唤醒**
- **intrusive linked list**, O(1) 注册/注销
- **错误码返回值**, 清晰的错误处理

### 非目标

- ❌ 跨平台 (Linux only)
- ❌ 文件异步 I/O
- ❌ DNS / 进程 / 文件系统
- ❌ 高性能 (1k+ 连接的场景请用 epoll)

## 构建

```bash
cd libsevent
mkdir build && cd build
cmake ..
make                # 编译库 + 测试 + 例子
make check          # 跑单元测试
```

```
libsevent/
├── CMakeLists.txt
├── README.md
├── .gitignore
├── include/
│   └── sevent.h          ← 公开 API
├── src/
│   └── sevent.c          ← 完整实现
├── tests/
│   └── test_sevent.c     ← 32 个单元测试
└── examples/
    ├── stdin_echo.c       ← 最简单: stdin → stdout
    ├── timer_demo.c       ← 多定时器, 各自状态
    └── echo_server.c      ← TCP echo server
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
    sevent_io_register(ctx, &(struct sevent_io_handler){.fd=0, .io_read=on_stdin, .data=ctx});
    sevent_run(ctx);
    sevent_destroy(ctx);
    return 0;
}
```

编译:

```bash
gcc -std=c99 -Ilibsevent/include -o demo demo.c libsevent/src/sevent.c
```

## API 参考

### 事件循环

| 函数 | 说明 |
|------|------|
| `sevent_create()` | 创建 loop, 返回 NULL 失败 |
| `sevent_destroy(ctx)` | 销毁 (自动释放所有资源) |
| `sevent_run(ctx)` | 阻塞运行, 直到 stop |
| `sevent_run_once(ctx)` | 跑一轮就返回: 1=有事件, 0=空闲 |
| `sevent_stop(ctx)` | 停止 loop (回调内可安全调用) |
| `sevent_wakeup(ctx)` | 唤醒 select (跨线程安全) |
| `sevent_post(ctx, cb, data)` | 投递异步任务 |

### 内存分配器

默认使用 libc `malloc`/`free`。可用 `sevent_set_allocator` 替换：

```c
typedef void *(*sevent_malloc_fn)(size_t size);
typedef void  (*sevent_free_fn)(void *ptr);

int sevent_set_allocator(sevent_malloc_fn malloc_fn, sevent_free_fn free_fn);
```

- 两个参数必须同时非 NULL 或同时 NULL
- 一个 NULL 一个非 NULL → `SEVENT_ERR_INVAL`
- `sevent_set_allocator(NULL, NULL)` 恢复默认
- 必须在 `sevent_create()` **之前**调用

```c
/* 示例: 跟踪分配的统计分配器 */
static int n_alloc, n_free;
static void *my_malloc(size_t sz) { n_alloc++; return malloc(sz); }
static void my_free(void *p)      { n_free++;  free(p); }

sevent_set_allocator(my_malloc, my_free);
sevent_context *ctx = sevent_create();
// ... ctx 的所有内部内存分配都会经过 my_malloc/my_free
```

### I/O

每轮 loop 执行 `select()` 后遍历 fd_set, 就绪的 fd 触发回调.
回调中可安全 unregister 自己.

```c
struct sevent_io_handler {
    int          fd;                /* 要监听的 fd          */
    sevent_io_read_fn   io_read;    /* 可读时回调, NULL=忽略 */
    sevent_io_write_fn  io_write;   /* 可写时回调, NULL=忽略 */
    void        *data;       /* 回调参数              */
};

sevent_io_t sevent_io_register(sevent_context *ctx, struct sevent_io_handler *h);
void      sevent_io_unregister(sevent_io_t h);
```

### 定时器

每轮 loop 用 `clock_gettime` 计算经过时间, 递减 `remaining_ms`.
≤ 0 时触发回调并重置.

```c
sevent_timer_t sevent_timer_register(sevent_context *ctx, unsigned int interval_ms,
                            sevent_timer_fn cb, void *data);
void         sevent_timer_unregister(sevent_timer_t h);
```

### Loop 一轮顺序

```
① select()  ← 超时 = min(timer 剩余, 30ms)
     ↓
② I/O 回调   ← 就绪的 fd (安全遍历)
     ↓
③ Post 任务  ← 快照队列, 防止递归
     ↓
④ 定时器     ← 递减 → 触发 → 重置
```

## 例子

| 例子 | 说明 | 运行 |
|------|------|------|
| `example-stdin-echo` | stdin → stdout | `./build/example-stdin-echo` |
| `example-timer-demo` | 3 个定时器, 对比周期 | `./build/example-timer-demo` |
| `example-echo-server` | TCP echo, 端口 7777 | `./build/example-echo-server` |

## 设计原则

1. **够用即可** — 不追求 libuv 的全覆盖, 只做基础事件分发
2. **零拷贝** — 数据 buffer 由用户管理, 库不碰你的数据
3. **直来直去** — 没有 handle 继承体系, 没有 close 回调
4. **低内存** — ~400 行, 侵入式链表, 没有线程池
5. **错误可见** — 返回值错误码, 不吞异常

## License

MIT
