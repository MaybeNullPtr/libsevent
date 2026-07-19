/**
 *  echo_client.c — TCP Echo 压测客户端 (libsevent + post 方案)
 *
 *  设计:
 *    注册 io_read, 收到数据后 post 写任务。
 *    写回调在 post 阶段同步执行, 避免 io_mode 切换。
 *    EAGAIN 极小概率下才启用 io_write 回调。
 */

#include "sevent.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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
            fprintf(stderr, "usage...\n");
            exit(1);
        }
    }
}

/* ==================== 连接状态 ==================== */

typedef struct {
    int             fd, rem, len, off, err, eagain;
    long            bytes_read, bytes_written;
    char           *buf;
    sevent_io      *hio;
    sevent_context *ctx;
} cli_t;

static cli_t    *g_c;
static int       g_fin, g_err;
static long long g_sent, g_recv;

/* ---- 前向声明 ---- */

static void on_read(void *data);
static void on_write(void *data);
static void do_write(void *data);

/* ---- 辅助: 只注册读回调 ---- */

static void cli_reg_read(cli_t *c) {
    if(c->hio)
        sevent_io_unregister(c->ctx, c->hio);
    sevent_io_handler h = {.fd = c->fd, .io_read = on_read, .data = c};
    c->hio              = sevent_io_register(c->ctx, &h);
    if(!c->hio) {
        fprintf(stderr, "reg_read fail\n");
        exit(1);
    }
    c->eagain = 0;
}

/* ---- 辅助: 注册写回调 (EAGAIN 兜底) ---- */

static void cli_reg_write(cli_t *c) {
    if(c->hio)
        sevent_io_unregister(c->ctx, c->hio);
    sevent_io_handler h = {.fd = c->fd, .io_write = on_write, .data = c};
    c->hio              = sevent_io_register(c->ctx, &h);
    if(!c->hio) {
        fprintf(stderr, "reg_write fail\n");
        exit(1);
    }
}

/* ---- 连接完成回调 ---- */

static void on_connect(void *data) {
    cli_t    *c  = (cli_t *)data;
    int       e  = 0;
    socklen_t el = sizeof(e);
    getsockopt(c->fd, SOL_SOCKET, SO_ERROR, &e, &el);
    if(e) {
        c->err = 1;
        goto done;
    }

    /* 连接建立, 准备发送数据, 切到读监听 (等待 do_write 发完再读) */
    memset(c->buf, 'x', (size_t)c->len);
    c->off = 0;
    cli_reg_read(c);
    /* post 写任务, 第一次发送 */
    sevent_post(c->ctx, do_write, c);
    return;

done:
    g_fin++;
    g_err++;
    close(c->fd);
    c->fd  = -1;
    c->hio = NULL;
    if(g_fin >= g_ncli)
        sevent_stop(g_c[0].ctx);
}

/* ---- 写回调 (只在 EAGAIN 后启用) ---- */

static void on_write(void *data) {
    cli_t *c = (cli_t *)data;
    while(c->off < c->len) {
        ssize_t w = write(c->fd, c->buf + c->off, (size_t)(c->len - c->off));
        if(w > 0) {
            c->off           += (int)w;
            c->bytes_written += w;
        } else if(errno == EAGAIN || errno == EINTR)
            return;
        else {
            c->err = 1;
            goto done;
        }
    }
    /* 写完了, 切回读 */
    cli_reg_read(c);
    return;

done:
    g_fin++;
    g_err++;
    close(c->fd);
    c->fd = -1;
    if(c->hio) {
        sevent_io_unregister(c->ctx, c->hio);
        c->hio = NULL;
    }
    if(g_fin >= g_ncli)
        sevent_stop(g_c[0].ctx);
}

/* ---- post 阶段写任务 ---- */

static void do_write(void *data) {
    cli_t *c = (cli_t *)data;
    if(c->fd < 0)
        return; /* 已关闭 */

    while(c->off < c->len) {
        ssize_t w = write(c->fd, c->buf + c->off, (size_t)(c->len - c->off));
        if(w > 0) {
            c->off           += (int)w;
            c->bytes_written += w;
        } else if(errno == EAGAIN) {
            /* 写缓存满, 退化到 io_write 回调继续 */
            cli_reg_write(c);
            return;
        } else if(errno == EINTR) {
            continue;
        } else {
            c->err = 1;
            goto done;
        }
    }
    /* 写完了, 等读 */
    return;

done:
    g_fin++;
    g_err++;
    close(c->fd);
    c->fd = -1;
    if(c->hio) {
        sevent_io_unregister(c->ctx, c->hio);
        c->hio = NULL;
    }
    if(g_fin >= g_ncli)
        sevent_stop(g_c[0].ctx);
}

/* ---- 读回调 ---- */

static void on_read(void *data) {
    cli_t *c = (cli_t *)data;

    /* 读取 echo 数据 (do_write 后 c->off == c->len, 需重置) */
    c->off = 0;
    while(c->off < c->len) {
        ssize_t n = read(c->fd, c->buf + c->off, (size_t)(c->len - c->off));
        if(n > 0) {
            c->off        += (int)n;
            c->bytes_read += n;
        } else if(n == 0) {
            c->err = 1;
            goto done;
        } else if(errno == EAGAIN || errno == EINTR)
            return;
        else {
            c->err = 1;
            goto done;
        }
    }

    /* 收完一条 */
    g_sent += c->len;
    g_recv += c->len;
    c->rem--;
    if(c->rem <= 0)
        goto done;

    /* 继续发下一条 (通过 post) */
    c->off = 0;
    memset(c->buf, 'x', (size_t)c->len);
    sevent_post(c->ctx, do_write, c);
    return;

done:
    g_fin++;
    if(c->err)
        g_err++;
    if(c->fd >= 0) {
        /* 排空接收缓冲，防止 close() 发 RST */
        char    tmp[4096];
        ssize_t dn;
        do {
            dn = read(c->fd, tmp, sizeof(tmp));
        } while(dn > 0 || (dn < 0 && errno == EINTR));
        close(c->fd);
    }
    c->fd = -1;
    if(c->hio) {
        sevent_io_unregister(c->ctx, c->hio);
        c->hio = NULL;
    }
    if(g_fin >= g_ncli)
        sevent_stop(g_c[0].ctx);
}

/* ---- TCP 非阻塞连接 ---- */

static int tcp_connect(const char *host, int port) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if(fd < 0)
        return -1;
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port   = htons(port);
    if(inet_pton(AF_INET, host, &a.sin_addr) <= 0) {
        close(fd);
        return -1;
    }
    int r = connect(fd, (struct sockaddr *)&a, sizeof(a));
    if(r < 0 && errno != EINPROGRESS) {
        close(fd);
        return -1;
    }
    return fd;
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

    sevent_context *ctx = sevent_create();
    if(!ctx) {
        fprintf(stderr, "create fail\n");
        return 1;
    }

    int ok = 0;
    for(int i = 0; i < g_ncli; i++) {
        g_c[i].buf = malloc((size_t)g_size);
        if(!g_c[i].buf) {
            perror("malloc");
            return 1;
        }

        int fd = tcp_connect(g_host, g_port);
        if(fd < 0) {
            fprintf(stderr, "  conn[%d] fail\n", i);
            g_fin++;
            continue;
        }
        ok++;

        g_c[i].fd  = fd;
        g_c[i].rem = g_nmsg;
        g_c[i].len = g_size;
        g_c[i].ctx = ctx;

        /* 初始注册写回调, 等待连接完成 */
        sevent_io_handler h = {
                .fd       = fd,
                .io_write = on_connect,
                .data     = &g_c[i],
        };
        g_c[i].hio = sevent_io_register(ctx, &h);
        if(!g_c[i].hio) {
            fprintf(stderr, "  reg[%d] fail\n", i);
            close(fd);
            g_fin++;
            ok--;
        }
    }
    printf("  conn ok: %d / %d\n", ok, g_ncli);
    if(!ok)
        return 1;

    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    sevent_run(ctx);
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
    sevent_destroy(ctx);
    return g_err ? 1 : 0;
}
