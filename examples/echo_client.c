/**
 *  echo_client.c — TCP Echo 压测客户端 (tcp_conn)
 *
 *  设计:
 *    纯回调模型 — on_open 发第一条, on_data 收齐续发, 写队列由 tcp_conn
 *    内部管理 (write 返回"已接受", 异步自动 flush; 原 post/io_write
 *    手写队列机制简化).
 */

#include "sevent.h"
#include "sevent_tcp_conn.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

static const char *g_host = "127.0.0.1";
static int         g_port = 7777, g_ncli = 10, g_size = 1024, g_nmsg = 100;

static void parse_args(int argc, char **argv) {
    for(int i = 1; i < argc; i++) {
        if(strcmp(argv[i], "--host") == 0 && i + 1 < argc)
            g_host = argv[++i];
        else if(strcmp(argv[i], "--port") == 0 && i + 1 < argc)
            g_port = atoi(argv[++i]);
        else if(strcmp(argv[i], "--clients") == 0 && i + 1 < argc)
            g_ncli = atoi(argv[++i]);
        else if(strcmp(argv[i], "--size") == 0 && i + 1 < argc)
            g_size = atoi(argv[++i]);
        else if(strcmp(argv[i], "--count") == 0 && i + 1 < argc)
            g_nmsg = atoi(argv[++i]);
        else {
            fprintf(stderr, "usage: %s [--host H] [--port P] [--clients N] [--size N] [--count N]\n", argv[0]);
            exit(1);
        }
    }
}

/* ==================== 连接状态 ==================== */

typedef struct {
    sevent_tcp_conn *c;
    int              rem;         /* 剩余消息数 */
    int              len;         /* 单条消息字节 */
    int              recv_in_msg; /* 当前消息已收字节 (on_data 可能跨条推送) */
    long             bytes_read, bytes_written;
    int              err, done;
    char            *buf; /* 发送内容 */
} cli_t;

static sevent_context *g_ctx;
static cli_t          *g_c;
static int             g_fin, g_err;
static long long       g_sent, g_recv;

/* ---- 收尾 (幂等): 统计 + destroy 连接 + 全部完成时停 loop ---- */

static void finish_cli(cli_t *cl) {
    if(cl->done)
        return;
    cl->done = 1;
    g_fin++;
    if(cl->err)
        g_err++;
    if(cl->c) {
        sevent_tcp_conn_destroy(cl->c);
        cl->c = NULL;
    }
    if(g_fin >= g_ncli)
        sevent_stop(g_ctx);
}

/* ---- 回调 ---- */

static void on_open(void *d) {
    cli_t *cl = (cli_t *)d;
    memset(cl->buf, 'x', (size_t)cl->len);
    int rc = sevent_tcp_conn_write(cl->c, cl->buf, (size_t)cl->len);
    if(rc != 0) {
        cl->err = 1;
        finish_cli(cl);
        return;
    }
    cl->bytes_written += cl->len;
    g_sent            += cl->len;
}

static void on_data(void *d, const uint8_t *data, size_t len) {
    cli_t *cl  = (cli_t *)d;
    size_t pos = 0;
    while(pos < len && !cl->done) {
        /* 按单条消息对齐 (推送可能跨条/多条) */
        size_t take = (size_t)cl->len - (size_t)cl->recv_in_msg;
        if(take > len - pos)
            take = len - pos;
        cl->recv_in_msg += (int)take;
        pos             += take;
        if(cl->recv_in_msg == cl->len) {
            /* 收齐一条: 统计 + 续发下一条 */
            cl->recv_in_msg = 0;
            cl->bytes_read  += cl->len;
            g_recv          += cl->len;
            if(--cl->rem <= 0) {
                finish_cli(cl);
                return;
            }
            int rc = sevent_tcp_conn_write(cl->c, cl->buf, (size_t)cl->len);
            if(rc != 0) {
                cl->err = 1;
                finish_cli(cl);
                return;
            }
            cl->bytes_written += cl->len;
            g_sent            += cl->len;
        }
    }
}

static void on_close(void *d) {
    cli_t *cl = (cli_t *)d;
    cl->err   = 1; /* 对端提前关闭 */
    finish_cli(cl);
}

static void on_error(void *d, int err) {
    cli_t *cl = (cli_t *)d;
    (void)err;
    cl->err = 1;
    finish_cli(cl);
}

/* ---- main ---- */

int main(int argc, char **argv) {
    parse_args(argc, argv);

    printf("echo_client: %d × %d msg × %d bytes → %s:%d\n", g_ncli, g_nmsg, g_size, g_host, g_port);

    g_c = calloc((size_t)g_ncli, sizeof(cli_t));
    if(!g_c) {
        perror("calloc");
        return 1;
    }
    g_ctx = sevent_create();
    if(!g_ctx) {
        fprintf(stderr, "create fail\n");
        return 1;
    }
    sevent_ignore_sigpipe();

    int ok = 0;
    for(int i = 0; i < g_ncli; i++) {
        cli_t *cl = &g_c[i];
        cl->buf   = malloc((size_t)g_size);
        if(!cl->buf) {
            perror("malloc");
            return 1;
        }
        cl->rem = g_nmsg;
        cl->len = g_size;
        cl->c   = sevent_tcp_conn_create(g_ctx);
        if(!cl->c)
            continue;
        sevent_stream_conn_init init = {
                .user_data = cl, .on_open = on_open, .on_data = on_data, .on_close = on_close, .on_error = on_error};
        if(sevent_tcp_conn_open(cl->c, g_host, (uint16_t)g_port, &init) < 0)
            continue;
        ok++;
    }
    printf("  conn ok: %d / %d\n", ok, g_ncli);
    if(!ok)
        return 1;

    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    sevent_run(g_ctx);
    struct timespec t1;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double el = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;

    printf("\n── result ──────────────────────\n");
    printf("  duration: %.6fs\n", el);
    printf("  clients:  %d\n", g_ncli);
    printf("  sent:     %.0f KB (%.1f MB)\n", g_sent / 1024.0, g_sent / 1024.0 / 1024.0);
    printf("  recv:     %.0f KB\n", g_recv / 1024.0);
    printf("  errors:   %d\n", g_err);
    printf("\n  per-connection read/write:\n");
    for(int i = 0; i < g_ncli; i++)
        printf("    conn[%d]  read=%ld  wrote=%ld\n", i, g_c[i].bytes_read, g_c[i].bytes_written);
    printf("  xput:     %.0f KB/s (%.1f MB/s)\n", g_sent / 1024.0 / el, g_sent / 1024.0 / 1024.0 / el);
    printf("  qps:      %.0f\n", (double)(g_sent / g_size) / el);

    for(int i = 0; i < g_ncli; i++)
        free(g_c[i].buf);
    free(g_c);
    sevent_destroy(g_ctx);
    return g_err ? 1 : 0;
}
