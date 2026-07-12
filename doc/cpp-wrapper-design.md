# libsevent C++ Header-Only 封装设计

> 三层架构：按事件生命周期选择最合适的抽象层级。
> 目标：不改变 libsevent 的 C 内核，在其上叠加 C++ 类型安全与 RAII 资源管理。

---

## 设计原则

1. **按生命周期分层** — 持久事件用 OOP（零额外开销），瞬态事件用 lambda（便利优先），不搞一刀切
2. **零开销不妥协** — 持久路径（IO/Timer）不允许额外堆分配，`watcher*` 直接穿过 `void*` 孔
3. **单头文件** — 三个层级合并为一个 `.hpp`，`#include "sevent.hpp"` 即用
4. **不改变 C API** — 不改 `sevent.h`，不改 ABI，C 用户零影响
5. **C 层契约必须是安全的** — unregister 后回调不再触发（见测试要求章节）

---

## 架构总览

```
┌──────────────────────────────────────────────────┐
│                   用户代码                         │
│  MyConnection : IoWatcher    post([&]{...})       │
└──────────────────┬───────────────────────────────┘
                   │ 继承/调用
┌──────────────────┴───────────────────────────────┐
│  Layer 2: OOP 常驻事件层 (IoWatcher/TimerWatcher) │
│  Layer 3: Lambda 一次性任务层 (post/dispatch)     │
├──────────────────────────────────────────────────┤
│  Layer 1: RAII 基础设施层 (EventLoop/IoGuard/    │
│            TimerGuard + move 语义)               │
├──────────────────────────────────────────────────┤
│  C 内核: sevent.h / sevent.c                     │
│  (select 事件循环, void* 回调, 链表管理)          │
└──────────────────────────────────────────────────┘
```

| 层 | 事件类型 | 回调形式 | 额外开销 | 核心理由 |
|----|---------|---------|---------|---------|
| 1 | 全部（RAII 基座） | — | 零 | 每个句柄必须自动释放 |
| 2 | IO / Timer（**持久**） | 虚函数 override | vtable（~2 次指针间接） | `watcher*` 直接当 `void*` 传，零堆分配 |
| 3 | Post（**瞬态**） | `std::function` | 一次堆分配 + 间接调用 | lambda 便利 >> 一次 malloc 成本 |

---

## Layer 1 — RAII 基础设施

### 职责

管理 `sevent_context` 和所有句柄的生命周期，确保资源自动释放。
这是所有上层封装的地基，Layer 2 和 Layer 3 都依赖它。

### 暴露的类

```cpp
namespace sevent {

class EventLoop {
public:
    EventLoop();                          // sevent_create()
    ~EventLoop();                         // sevent_destroy()
    EventLoop(const EventLoop&) = delete;
    EventLoop& operator=(const EventLoop&) = delete;
    EventLoop(EventLoop&&) noexcept;
    EventLoop& operator=(EventLoop&&) noexcept;

    // 循环控制
    int  run();
    int  runOnce();
    void stop();
    int  wakeup();
    explicit operator bool() const;       // ctx != nullptr

    // 句柄注册（Layer 2 和 3 通过这些注册）
    // ↓ 具体签名在后续层给出

private:
    struct sevent_context *ctx_ = nullptr;
    friend class IoGuard;
    friend class TimerGuard;
};

class IoGuard {
public:
    IoGuard() = default;
    ~IoGuard() { cleanup(); }                     // 析构 → unregister
    IoGuard(const IoGuard&) = delete;
    IoGuard& operator=(const IoGuard&) = delete;
    IoGuard(IoGuard&& o) noexcept
        : ctx_(o.ctx_), h_(o.h_) { o.h_ = nullptr; }
    IoGuard& operator=(IoGuard&& o) noexcept {
        if (this != &o) { cleanup(); ctx_ = o.ctx_; h_ = o.h_; o.h_ = nullptr; }
        return *this;
    }

    void reset() { cleanup(); }                   // 主动 unregister（回调中自注销用）
    explicit operator bool() const { return h_ != nullptr; }

private:
    friend class EventLoop;
    struct sevent_context *ctx_ = nullptr;
    struct sevent_io      *h_   = nullptr;
    void cleanup() {
        if (h_) { sevent_io_unregister(ctx_, h_); h_ = nullptr; }
    }
};

class TimerGuard {
public:
    TimerGuard() = default;
    ~TimerGuard() { cleanup(); }                  // 析构 → unregister
    TimerGuard(const TimerGuard&) = delete;
    TimerGuard& operator=(const TimerGuard&) = delete;
    TimerGuard(TimerGuard&& o) noexcept
        : ctx_(o.ctx_), h_(o.h_) { o.h_ = nullptr; }
    TimerGuard& operator=(TimerGuard&& o) noexcept {
        if (this != &o) { cleanup(); ctx_ = o.ctx_; h_ = o.h_; o.h_ = nullptr; }
        return *this;
    }

    void reset() { cleanup(); }
    explicit operator bool() const { return h_ != nullptr; }

private:
    friend class EventLoop;
    struct sevent_context *ctx_ = nullptr;
    struct sevent_timer   *h_   = nullptr;
    void cleanup() {
        if (h_) { sevent_timer_unregister(ctx_, h_); h_ = nullptr; }
    }
};

// 自由函数
void ignoreSigpipe();
int  setAllocator(sevent_malloc_fn, sevent_free_fn);

} // namespace sevent
```

### 核心语义

- **move-only**：`IoGuard`/`TimerGuard` 禁止拷贝，只能移动。移动后原对象变为空，析构安全
- **析构自动释放**：`IoGuard` 析构调 `sevent_io_unregister`，`TimerGuard` 析构调 `sevent_timer_unregister`
- **`.reset()`**：回调中主动自注销用，等同于析构但不销毁 guard 对象本身，之后可重新赋值

---

## Layer 2 — OOP 常驻事件层（IO / Timer）

### 设计哲学

IO 和 Timer 是持久性的——往往伴随一个连接或会话的整个生命周期。它们天然对应 C++ 中的业务对象（`TcpConnection`、`Heartbeat`）。

用 `IoWatcher*` 直接作为 C 层的 `void* data`：
- **零额外堆分配**，一个指针穿过 C 层
- **自然 OOP**：`onRead()`/`onWrite()`/`onTimer()` 是成员函数，状态在派生类成员变量里
- **统一读写**：同一个对象同时处理读和写回调，共享 fd/buffer/状态

### 接口定义

```cpp
namespace sevent {

// ---- 纯虚基类 ----

class IoWatcher {
public:
    virtual void onRead(EventLoop &loop) = 0;
    virtual void onWrite(EventLoop &loop) {}   // 可选重写
    virtual ~IoWatcher() = default;
};

class TimerWatcher {
public:
    virtual void onTimer(EventLoop &loop) = 0;
    virtual ~TimerWatcher() = default;
};

// ---- EventLoop 注册方法 ----

class EventLoop {
    // ...（Layer 1 的成员）...

public:
    // 注册常驻 IO。watcher* 直接作为 void* data 传给 C 层。
    // read/write 控制监听 FD_ISSET 的哪一组。
    // 返回 IoGuard：析构时 unregister，回调中 guard.reset() 自注销。
    IoGuard watch(int fd, IoWatcher *watcher,
                  bool read = true, bool write = false);

    // 注册常驻定时器。interval_ms > 0，循环触发。
    TimerGuard timer(unsigned int interval_ms, TimerWatcher *watcher);
};

} // namespace sevent
```

### 使用示例：Echo Server

```cpp
#include "sevent.hpp"
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

// ---- 每个客户端连接一个对象 ----

class TcpConnection : public sevent::IoWatcher {
public:
    TcpConnection(sevent::EventLoop &loop, int fd)
        : loop_(loop), fd_(fd) {
        guard_ = loop.watch(fd_, this);   // move-assign IoGuard
    }

private:
    void onRead(sevent::EventLoop &loop) override {
        char buf[4096];
        auto n = read(fd_, buf, sizeof(buf));
        if (n <= 0) {
            guard_.reset();               // unregister 自己
            close(fd_);
            delete this;                  // self-owned, 安全释放
            return;
        }
        write(fd_, buf, n);   // echo
    }

    sevent::EventLoop &loop_;
    int fd_;
    sevent::IoGuard guard_;    // HAS-A：持有注册句柄，析构自动 unregister
};

// ---- 监听者也是 IoWatcher ----

class Listener : public sevent::IoWatcher {
public:
    Listener(sevent::EventLoop &loop, int port)
        : loop_(loop) {
        listen_fd_ = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        // ... bind, listen ...
        loop.watch(listen_fd_, this);  // 监听 accept
    }

    ~Listener() { close(listen_fd_); }

private:
    void onRead(sevent::EventLoop &loop) override {
        int cfd = accept(listen_fd_, nullptr, nullptr);
        if (cfd >= 0)
            new TcpConnection(loop_, cfd);  // self-owned
    }

    sevent::EventLoop &loop_;
    int listen_fd_ = -1;
};

int main() {
    sevent::EventLoop loop;
    Listener listener(loop, 7777);
    loop.run();
}
```

### 自注销模式

这是必须文档化的关键模式。回调中需要断连/停止定时器时：

```cpp
class Heartbeat : public sevent::TimerWatcher {
public:
    Heartbeat(sevent::EventLoop &loop, int n)
        : loop_(loop), limit_(n) {
        guard_ = loop_.timer(200, this);
    }

private:
    void onTimer(sevent::EventLoop &loop) override {
        printf("beat %d/%d\n", ++count_, limit_);
        if (count_ >= limit_)
            guard_.reset();       // ← 自注销（unregister 自己）
    }

    sevent::EventLoop &loop_;
    sevent::TimerGuard guard_;   // HAS-A：持有注册句柄
    int count_ = 0;
    int limit_;
};
```

`guard_.reset()` 等价于 `sevent_timer_unregister(ctx, h)`。在 C 内核中：
- `deleted = 1`，timer 移到 `death_timer` 链表
- 当前回调继续执行（数据还在 `death_timer` 中存活）
- 后续 `run_free_death` 回收内存，不会再触发

### ⚠️ 生命周期铁律（IoWatcher / TimerWatcher）

1. **`IoGuard`/`TimerGuard` 必须在 `EventLoop` 析构之前 unregister。** 否则 `~IoGuard()` 访问 `ctx_` 时 `EventLoop` 已销毁，野指针崩溃。
2. 两种安全模式：
   - **栈/成员变量**：确保 `EventLoop` 声明在 watcher **之前**，C++ 反向析构时 watcher 先析构 → guard 先 unregister → 然后 EventLoop 才析构。
   - **heap + delete this**：回调内 `guard_.reset()` 先 unregister，然后 `delete this`。此时 EventLoop 仍存活，安全。
3. **self-owned 时** `guard_.reset()` 必须在 `delete this` 之前调用
4. `watch()`/`timer()` 返回的 guard 为空时（注册失败），后续操作安全无效果

---

## Layer 3 — Lambda 一次性任务层（Post）

### 设计哲学

Post 任务是瞬时性的，执行完即销毁。用 `std::function` 包装 lambda 极其便利，且因为生命周期极短（`run_posts` 调用栈内），不存在悬空引用的风险。

### 接口定义

```cpp
namespace sevent {

class EventLoop {
    // ...（Layer 1 + Layer 2 的成员）...

public:
    // 异步投递一次性任务，返回 false 表示分配失败
    bool post(std::function<void()> task);

    // 同步分派：如果在 loop 线程则立即执行，否则入队
    bool dispatch(std::function<void()> task);
};

} // namespace sevent
```

### 实现要点

```cpp
bool EventLoop::post(std::function<void()> task) {
    // 在堆上分配一个包装器，让 C 层的 void* 指向它
    auto *p = new std::function(std::move(task));
    int ret = sevent_post(ctx_,
        [](void *d) {              // trampoline
            auto *f = static_cast<std::function<void()>*>(d);
            (*f)();
            delete f;
        },
        p);
    if (ret != 0) { delete p; return false; }
    return true;
}
```

**为什么这对 Post 可以但 IO/Timer 不行？**
- Post 任务执行完包装器就 `delete` 了——堆分配代价只付一次
- IO/Timer 回调是持久性的——如果每个 IO 回调都包一层 `std::function`，代价会持续累积
- 这里不碰 `void*` 孔——trampoline 函数指针 + 堆上 `std::function` 是标准做法

### 使用示例

```cpp
// 跨线程投递结果
loop.post([this] {
    sendResponse(data_);
});

// loop 线程内立即执行
loop.dispatch([&] {
    state_ = State::Stopped;
});

// 配合 shared_ptr 避免悬空
auto sp = shared_from_this();
loop.post([sp] {
    sp->onAsyncResult();
});
```

### 自定义分配器兼容

`std::function` 内部的堆分配使用 `operator new`，不走 `sevent_set_allocator`。对嵌入场景，C 层的 `sevent_post` 本就接受函数指针 + `void*`，不存在此问题。

```cpp
// C 层 sevent_post 始终使用 sevent_set_allocator 设定的分配器
// C++ 层 post(lambda) 使用 operator new，如需受控分配器，直接用 C API
```

---

## 完整 API 总览

```cpp
namespace sevent {

// ---- Layer 1: RAII 基座 ----

class EventLoop {
public:
    EventLoop();
    ~EventLoop();
    EventLoop(const EventLoop&) = delete;
    EventLoop& operator=(const EventLoop&) = delete;
    EventLoop(EventLoop&&) noexcept;
    EventLoop& operator=(EventLoop&&) noexcept;

    int  run();
    int  runOnce();
    void stop();
    int  wakeup();
    explicit operator bool() const;

    // ---- Layer 2: OOP 常驻事件 ----
    IoGuard watch(int fd, IoWatcher *w, bool read = true, bool write = false);
    TimerGuard timer(unsigned ms, TimerWatcher *w);

    // ---- Layer 3: Lambda 一次性任务 ----
    bool post(std::function<void()> task);
    bool dispatch(std::function<void()> task);

    // 观测
    void getCounts(int *io = nullptr, int *timer = nullptr, int *post = nullptr);

private:
    struct sevent_context *ctx_ = nullptr;
};

class IoGuard { /* move-only, reset(), ~IoGuard → unregister */ };
class TimerGuard { /* move-only, reset(), ~TimerGuard → unregister */ };

class IoWatcher {
public:
    virtual void onRead(EventLoop&) = 0;
    virtual void onWrite(EventLoop&) {}
    virtual ~IoWatcher() = default;
};

class TimerWatcher {
public:
    virtual void onTimer(EventLoop&) = 0;
    virtual ~TimerWatcher() = default;
};

void ignoreSigpipe();
int  setAllocator(sevent_malloc_fn, sevent_free_fn);

} // namespace sevent
```

---

## C 层安全前提（必须满足的契约）

在实现 C++ 封装之前，C 层必须满足：**unregister 后回调不再被触发**。

### 现有测试覆盖

| 事件类型 | 是否有测试验证 | 状态 |
|---------|--------------|------|
| **Timer** | ✅ `timer_unregister_before_fire` / `timer_self_unregister_in_callback` / `timer_cross_unregister_in_callback` / `timer_multi_fire_self_unregister` | 已覆盖 |
| **Post** | ✅ FIFO 执行, 无取消路径 | C 层不再支持取消, 无需此测试 |
| **IO** | ❌ `io_unregister_self_in_callback` 标注 TODO 未实现 | **缺失** |

### C 层实现分析（为什么现在是安全的）

IO 回调派发路径 ([sevent.c:run_io_callbacks](src/sevent.c#L312))：

```c
for (int i = 0; i < n_io; i++) {
    struct sevent_io *io = iosnap[i];
    if (io->deleted) continue;        // ① 已注销直接跳过
    if (io->read_cb && FD_ISSET(...)) {
        io->read_cb(io->data);        // ② 回调中可能 unregister 自己
    }
}
```

安全机制：
1. `iosnap` 在持锁时快照——快照后无论 `io_list` 如何变，指针有效
2. `deleted` 标志位——unregister 设置 `deleted=1`，回调派发前检查跳过
3. `death_io` 延迟释放——unregister 将节点移到 `death_io`，下轮 `run_free_death` 才释放内存。即使回调在 check→call 之间被另一个线程 unregister，`io->data` 仍然有效

**同一线程场景**（正常 loop 使用）：回调内 `unregister` 自己或他人，`deleted` 设置后 `iosnap` 后续迭代会跳过，**安全**。

**跨线程场景**：check→call 之间存在微小窗口，但 `death_io` 保证数据存活，不会访问已释放内存。

### 必须新增的测试（C++ 封装之前）

在已有 IO 测试基础上补充以下用例，锁定安全契约：

```
[io_unregister_self_in_callback]  // 补完现有 TODO
  注册 IO → 回调中 unregister 自己 → 跑多轮 → 只触发 1 次

[io_unregister_before_select]
  注册 IO → 有数据可读 → unregister → 跑 loop → 回调不被触发

[io_unregister_other_in_callback]
  两个 IO 同时就绪 → 回调 A unregister B → B 不被触发
    
[timer_unregister_other_before_fire]
  注册两个定时器 → unregister 第二个 → 只触发第一个
```

---

## 与"三选一"方案的关系

旧方案的"三种风格选一种" → 新方案的"按层级各取所长"：

| 旧方案 | 在新方案中的位置 |
|-------|----------------|
| 方案 A（RAII 薄封装） | Layer 1 — RAII 基座，所有上层的基础 |
| 方案 B（Lambda 全栈） | **废弃**，仅保留 post/dispatch 部分作为 Layer 3 |
| 方案 C（OOP 全栈） | **优化**，IO/Timer 保留虚接口，但不用于 post |

关键区别：旧方案让用户选**风格**，新方案让用户按**事件生命周期**自然选择。新方案不是"又一个选择"，而是对旧方案的综合和替代。

---

## 文件结构

```
include/
  sevent.hpp           ← C++ header-only 封装（三层合一）
  sevent.h             ← C API（不变）

examples/
  echo_server_oop.cpp  ← Layer 2 示例：OOP Echo Server
  timer_oop.cpp        ← Layer 2 示例：定时器 + 自注销
  post_lambda.cpp      ← Layer 3 示例：Lambda post/dispatch
```

所有 C++ 示例与原有 C 示例共存，各自独立 main()。

---

## 实施顺序

```
  Step 1: 补 IO 测试（io_unregister_self_in_callback 等）
  Step 2: 实现 sevent.hpp 的 Layer 1（EventLoop/IoGuard/TimerGuard）
  Step 3: 实现 Layer 2（IoWatcher/TimerWatcher + watch/timer）
  Step 4: 实现 Layer 3（post/dispatch lambda 版本）
  Step 5: 写示例 + 验证编译
```

每个步骤独立可编译、可测试。

---

## 决策记录

| 议题 | 结论 | 理由 |
|------|------|------|
| IO/Timer 用什么回调形式 | 虚函数 | `watcher*` 直接穿过 `void*`，零堆分配 |
| Post 用什么回调形式 | `std::function` | 一次性任务，便利覆盖微小开销 |
| 回调签名加 `EventLoop&` 参数 | 加 | watcher 不用自己存 loop 引用，但需要时可直接拿 |
| `watch()` 读写参数 | `bool read, bool write` | 同一个业务对象处理读写，比两个函数签名更自然 |
| 自注销方式 | `guard_.reset()` | 与 RAII 析构一致语义，`reset()` 后 guard 为空，可重新赋值 |
| Post 是否支持取消 | **不支持** | 业务上不需要（事件即投即执行），C 层已删除 cancel 路径 |
| IO/Timer 回调的 `EventLoop&` 参数 | 传入调用方 loop | watcher 无需成员持有 loop 引用，避免循环依赖 |
| 三个层级放几个头文件 | **一个** `sevent.hpp` | 反正都要包含，拆开增加管理负担 |
