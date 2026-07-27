/**
 *  autobahn_client.cpp — Autobahn fuzzingserver echo client
 *
 *  协议: /getCaseCount → /runCase?case=<N>&agent=<name> 逐个回显
 *  全部跑完后连 /updateReports?agent=<name> 触发报告生成。
 */

#include "sevent.h"
#include "sevent_ws.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <chrono>
#include <ctime>

static const char *now_str() {
    static char buf[16];
    auto        tt = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::strftime(buf, sizeof(buf), "%H:%M:%S", std::localtime(&tt));
    return buf;
}

static sevent_context                       *g_ctx   = nullptr;
static sevent_ws_conn                       *g_ws    = nullptr;
static std::string                           g_host  = "127.0.0.1";
static int                                   g_port  = 9001;
static std::string                           g_agent = "libsevent";
static int                                   g_total = 0, g_cur = 0;
static bool                                  g_run = false, g_done = false;
static std::chrono::steady_clock::time_point g_case_start;
static std::vector<uint8_t>                  g_acc;

static void connect_path(const std::string &path);
static void do_count(void *data);
static void do_case(void *data);
static void do_report(void *data);

static void on_open(void *) {
    g_case_start = std::chrono::steady_clock::now();
    g_acc.clear();
}

static void on_close(void *, uint16_t, const char *, size_t) {
    if(g_ws) {
        sevent_ws_destroy(g_ws);
        g_ws = nullptr;
    }
    if(g_done) {
        sevent_stop(g_ctx);
        return;
    }
    if(g_run) {
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - g_case_start)
                          .count();
        std::printf("%s case %d/%d done (%ldms)\n", now_str(), g_cur, g_total, ms);
        g_cur++;
        if(g_cur <= g_total)
            sevent_post(g_ctx, do_case, nullptr);
        else {
            std::printf("%s all %d cases done, generating report...\n", now_str(), g_total);
            g_run  = false;
            g_done = true;
            sevent_post(g_ctx, do_report, nullptr);
        }
    } else {
        if(g_total > 0) {
            g_run = true;
            g_cur = 1;
            do_case();
        } else {
            std::fprintf(stderr, "[error] no cases\n");
            sevent_stop(g_ctx);
        }
    }
}

static void on_error(void *, int err) {
    std::fprintf(stderr, "[error] 0x%x\n", err);
    if(g_ws) {
        sevent_ws_destroy(g_ws);
        g_ws = nullptr;
    }
    if(g_done) {
        sevent_stop(g_ctx);
        return;
    }
    if(g_run) {
        g_cur++;
        if(g_cur <= g_total)
            sevent_post(g_ctx, do_case, nullptr);
        else {
            g_run  = false;
            g_done = true;
            sevent_post(g_ctx, do_report, nullptr);
        }
    } else {
        sevent_stop(g_ctx);
    }
}

static void on_message(void *, const void *m, size_t l, bool bin, bool fin, uint64_t) {
    if(g_done)
        return;
    if(g_total == 0 && !g_run) {
        char buf[32] = {0};
        std::memcpy(buf, m, l < 31 ? l : 31);
        g_total = std::atoi(buf);
        std::printf("%s total cases: %d\n", now_str(), g_total);
        return;
    }
    if(g_run) {
        if(!fin) {
            g_acc.insert(g_acc.end(), static_cast<const uint8_t *>(m), static_cast<const uint8_t *>(m) + l);
        } else {
            g_acc.insert(g_acc.end(), static_cast<const uint8_t *>(m), static_cast<const uint8_t *>(m) + l);
            auto t1 = std::chrono::steady_clock::now();
            int  r;
            if(bin)
                r = sevent_ws_send_binary(g_ws, g_acc.data(), g_acc.size());
            else
                r = sevent_ws_send_text(g_ws, g_acc.data(), g_acc.size());
            auto t2  = std::chrono::steady_clock::now();
            auto snd = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count();
            std::printf("%s echo %zu bytes r=%d send=%ldms\n", now_str(), g_acc.size(), r, snd);
            g_acc.clear();
        }
    }
}

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
    g_ws           = sevent_ws_connect(g_ctx, &cfg);
}

static void do_count(void *data) {
    (void)data;
    connect_path("/getCaseCount");
    if(!g_ws)
        sevent_timer_register(g_ctx, 1000, do_count, nullptr);
}

static void do_case(void *data) {
    (void)data;
    char path[256];
    std::snprintf(path, sizeof(path), "/runCase?case=%d&agent=%s", g_cur, g_agent.c_str());
    connect_path(path);
    if(!g_ws)
        sevent_timer_register(g_ctx, 500, do_case, nullptr);
}

static void do_report(void *data) {
    (void)data;
    char path[256];
    std::snprintf(path, sizeof(path), "/updateReports?agent=%s", g_agent.c_str());
    connect_path(path);
    if(!g_ws)
        sevent_timer_register(g_ctx, 1000, do_report, nullptr);
}

int main(int argc, char **argv) {
    if(argc > 1)
        g_host = argv[1];
    if(argc > 2)
        g_port = std::atoi(argv[2]);
    if(argc > 3)
        g_agent = argv[3];
    g_ctx = sevent_create();
    if(!g_ctx)
        return 1;
    sevent_ignore_sigpipe();
    do_count();
    sevent_run(g_ctx);
    if(g_ws)
        sevent_ws_destroy(g_ws);
    sevent_destroy(g_ctx);
    return 0;
}
