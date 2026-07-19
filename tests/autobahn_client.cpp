/**
 *  autobahn_client.cpp — Autobahn fuzzingserver echo client
 *
 *  协议: /getCaseCount → /runCase?case=<N>&agent=<name> 逐个回显
 *  全部跑完后连 /updateReports?agent=<name> 触发报告生成。
 *
 *  编译: g++ -std=c++17 -I include -I src -I src/websockets \
 *          tests/autobahn_client.cpp -L build -lsevent_ws -lsevent \
 *          -o build/autobahn_client
 *
 *  用法: ./autobahn_client [host] [port] [agent]
 */

#include "sevent.h"
#include "sevent_ws.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

/* ---- 全局状态 ---- */
static sevent_context *g_ctx = nullptr;
static sevent_ws_conn *g_ws = nullptr;

static std::string g_host = "127.0.0.1";
static int         g_port = 9001;
static std::string g_agent = "libsevent";

static int g_total = 0;     /* getCaseCount 返回的总用例数 */
static int g_cur   = 0;     /* 当前用例编号 (1-based) */
static int g_fail  = 0;     /* 失败计数 */
static bool g_run  = false; /* true=正在跑用例 */
static bool g_done = false; /* true=updateReports 阶段 */

/* 流式大帧累积: fin=0 时追加, fin=1 时回显 */
static std::vector<uint8_t> g_acc;
static bool g_is_bin = false;

/* ---- 前向声明 ---- */
static void connect_path(const std::string &path);
static void do_count();
static void do_case();
static void do_report();

/* ================================================================
 *  回调
 * ================================================================ */

static void on_open(void *) {
    /* 连接建立成功 */
}

static void on_close(void *, uint16_t code, const char *, size_t) {
    (void)code;
    if (g_ws) { sevent_ws_destroy(g_ws); g_ws = nullptr; }

    if (g_done) {
        /* /updateReports 完成 → 退出 */
        sevent_stop(g_ctx);
        return;
    }

    if (g_run) {
        /* 当前用例完成 → 下一个 */
        g_cur++;
        if (g_cur <= g_total)
            sevent_post(g_ctx, (sevent_handler_fn)do_case, nullptr);
        else {
            std::printf("[done] %d cases, generating report...\n", g_total);
            g_run  = false;
            g_done = true;
            sevent_post(g_ctx, (sevent_handler_fn)do_report, nullptr);
        }
    } else {
        /* /getCaseCount 完成 → 开始跑用例 */
        if (g_total > 0) {
            g_run = true;
            g_cur = 1;
            do_case();
        } else {
            std::fprintf(stderr, "[error] no cases from server\n");
            sevent_stop(g_ctx);
        }
    }
}

static void on_error(void *, int err) {
    std::fprintf(stderr, "[error] 0x%x\n", err);
    if (g_ws) { sevent_ws_destroy(g_ws); g_ws = nullptr; }

    if (g_done) { sevent_stop(g_ctx); return; }

    if (g_run) {
        g_fail++;
        g_cur++;
        if (g_cur <= g_total)
            sevent_post(g_ctx, (sevent_handler_fn)do_case, nullptr);
        else {
            g_run  = false;
            g_done = true;
            sevent_post(g_ctx, (sevent_handler_fn)do_report, nullptr);
        }
    } else {
        sevent_stop(g_ctx);
    }
}

static void on_message(void *, const void *m, size_t l, bool bin, bool fin, uint64_t) {
    if (g_done) return; /* /updateReports 阶段忽略数据 */

    if (g_total == 0 && !g_run) {
        /* /getCaseCount 响应: 解析数字 */
        char buf[32] = {0};
        std::memcpy(buf, m, l < 31 ? l : 31);
        g_total = std::atoi(buf);
        std::printf("[info] total cases: %d\n", g_total);
        return;
    }

    if (g_run) {
        g_is_bin = bin;
        if (!fin) {
            g_acc.insert(g_acc.end(),
                         static_cast<const uint8_t *>(m),
                         static_cast<const uint8_t *>(m) + l);
        } else {
            /* 最后一块 → 拼完整条回显 */
            g_acc.insert(g_acc.end(),
                         static_cast<const uint8_t *>(m),
                         static_cast<const uint8_t *>(m) + l);

            if (g_is_bin)
                sevent_ws_send_binary(g_ws, g_acc.data(), g_acc.size());
            else
                sevent_ws_send_text(g_ws, g_acc.data(), g_acc.size());

            g_acc.clear();
        }
    }
}

/* ================================================================
 *  连接辅助
 * ================================================================ */

static void connect_path(const std::string &path) {
    sevent_ws_config cfg;
    std::memset(&cfg, 0, sizeof(cfg));
    cfg.host       = g_host.c_str();
    cfg.port       = static_cast<uint16_t>(g_port);
    cfg.path       = path.c_str();
    cfg.on_open    = on_open;
    cfg.on_message = on_message;
    cfg.on_close   = on_close;
    cfg.on_error   = on_error;
    g_ws = sevent_ws_connect(g_ctx, &cfg);
}

static void do_count() {
    connect_path("/getCaseCount");
    if (!g_ws)
        sevent_timer_register(g_ctx, 1000, (sevent_timer_fn)do_count, nullptr);
}

static void do_case() {
    char path[256];
    std::snprintf(path, sizeof(path), "/runCase?case=%d&agent=%s",
                  g_cur, g_agent.c_str());
    connect_path(path);
    if (!g_ws)
        sevent_timer_register(g_ctx, 500, (sevent_timer_fn)do_case, nullptr);
}

static void do_report() {
    char path[256];
    std::snprintf(path, sizeof(path), "/updateReports?agent=%s",
                  g_agent.c_str());
    connect_path(path);
    if (!g_ws)
        sevent_timer_register(g_ctx, 1000, (sevent_timer_fn)do_report, nullptr);
}

/* ================================================================
 *  main
 * ================================================================ */

int main(int argc, char **argv) {
    if (argc > 1) g_host = argv[1];
    if (argc > 2) g_port = std::atoi(argv[2]);
    if (argc > 3) g_agent = argv[3];

    g_ctx = sevent_create();
    if (!g_ctx) { std::fprintf(stderr, "create fail\n"); return 1; }
    sevent_ignore_sigpipe();

    do_count();
    sevent_run(g_ctx);

    if (g_ws) sevent_ws_destroy(g_ws);
    sevent_destroy(g_ctx);

    std::printf("[exit] %s\n", g_fail ? "FAIL" : "PASS");
    return g_fail ? 1 : 0;
}
