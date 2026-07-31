/**
 *  frag_stream_test.c — 分片消息合规测试 (Autobahn 9.3.2 / 9.4.8 精简复现)
 *
 *  三个 scenario:
 *     0. 精确填满 recv_cap + 0 字节终止帧 (原 frag_terminator_test)
 *     1. 流式读取 + 0 字节终止帧         (原 stream_test scen 0)
 *     2. 流式读取 + 最后分片 fin=1        (原 stream_test scen 1)
 *
 *  每个 scenario 跑独立事件循环, 自建 TCP 服务端 + WS 客户端.
 *  ================================================================ */

#include "sevent.h"
#include "sevent_ws.h"
#include "../src/websockets/ws_frame.h"
#include "../src/websockets/ws_sha1.h"
#include "../src/websockets/ws_base64.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* ====================================================================
 *  常量
 * ==================================================================== */

#define BASE_PORT 19410 /* 每个 scenario 用 BASE_PORT + index */
#define TIMEOUT_MS 5000
#define CLIENT_DELAY_MS 10
#define FILL_SEED 'a'
#define SERVER_BUF_SIZE 65536
#define CLI_BUF_SIZE 65536
#define HTTP_RESP_BUF 512    /* HTTP 101 响应缓冲区 */
#define WS_KEY_MAX 128       /* Sec-WebSocket-Key 值最大长度 */
#define WS_ACCEPT_LEN 32     /* Sec-WebSocket-Accept 缓冲区 */
#define WS_KEY_VALUE_MAX 127 /* key 值截断阈值 */
#define SHA1_CONCAT_BUF 256  /* SHA1 拼接缓冲区 */
#define LISTEN_BACKLOG 5     /* listen backlog */

/* ====================================================================
 *  Scenario 表
 * ==================================================================== */

enum { SCEN_EXACT_FILL, SCEN_STREAM_TERM, SCEN_STREAM_FIN };
#define SCEN_COUNT 3

static const struct {
    const char *name;
    size_t      recv_buf;   /* recv_buf_size (影响 recv_cap) */
    int         n_data;     /* 数据分片数 (不含可能的终止帧) */
    size_t      frag_sz;    /* 每个数据分片的 payload 大小 */
    int         terminator; /* 1=单独 0 字节 CONT(fin=1), 0=最后分片带 fin=1 */
    int         bin;        /* 1=BINARY, 0=TEXT */
} g_scenarios[SCEN_COUNT] = {
        {"exact-fill + 0-byte terminator", 256, 2, 128, 1, 0}, /* 原 frag_terminator */
        {"stream + 0-byte terminator", 256, 2, 512, 1, 1},     /* 原 stream scen 0 */
        {"stream + last frag fin=1", 256, 3, 512, 0, 1},       /* 原 stream scen 1 */
};

/* ====================================================================
 *  全局 (per-scenario, 每次 run_one 前重置)
 * ==================================================================== */

static sevent_context *g_ctx;
static int             g_pass;
static int             g_scenario_idx; /* 当前正在跑的 scenario 索引 */

/* 服务端 */
enum { S_LISTEN, S_HANDSHAKE, S_WAIT_ECHO, S_DONE };

static struct {
    int        state;
    int        listen_fd;
    int        client_fd;
    sevent_io *io;
    uint8_t    buf[SERVER_BUF_SIZE];
    size_t     len;
} g_srv;

/* 客户端 */
static sevent_ws_conn *g_ws;
static uint8_t         g_cli_buf[CLI_BUF_SIZE];
static size_t          g_cli_len;

/* ====================================================================
 *  SHA1 + Base64
 * ==================================================================== */

static void compute_accept(const char *key, char *out, size_t cap) {
    char    concat[SHA1_CONCAT_BUF];
    int     n = snprintf(concat, sizeof(concat), "%s%s", key, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    uint8_t digest[20];
    ws_sha1((const uint8_t *)concat, (size_t)n, digest);
    ws_base64_encode(digest, 20, out, cap);
}

/* ====================================================================
 *  构造 HTTP 101
 * ==================================================================== */

static int build_101(const uint8_t *req, size_t req_len, char *resp, size_t resp_cap) {
    const char *key_hdr = "sec-websocket-key:";
    const char *p       = (const char *)req;
    const char *end     = p + req_len;
    while(p && p < end) {
        const char *nl = (const char *)memchr(p, '\n', (size_t)(end - p));
        if(!nl)
            break;
        size_t llen = (size_t)(nl - p);
        if(llen > 0 && p[llen - 1] == '\r')
            llen--;
        if(llen > strlen(key_hdr)) {
            int match = 1;
            for(size_t i = 0; key_hdr[i]; i++) {
                char a = p[i], b = key_hdr[i];
                if(a >= 'A' && a <= 'Z')
                    a += 0x20;
                if(a != b) {
                    match = 0;
                    break;
                }
            }
            if(match) {
                const char *vs = p + strlen(key_hdr);
                while(vs < nl && (*vs == ' ' || *vs == '\t'))
                    vs++;
                size_t vlen = (size_t)(nl - vs);
                if(vlen > 0 && vs[vlen - 1] == '\r')
                    vlen--;
                if(vlen > WS_KEY_VALUE_MAX)
                    vlen = WS_KEY_VALUE_MAX;
                char key[WS_KEY_MAX] = {0};
                memcpy(key, vs, vlen);
                char accept[WS_ACCEPT_LEN];
                compute_accept(key, accept, sizeof(accept));
                return snprintf(resp,
                                resp_cap,
                                "HTTP/1.1 101 Switching Protocols\r\n"
                                "Upgrade: websocket\r\n"
                                "Connection: Upgrade\r\n"
                                "Sec-WebSocket-Accept: %s\r\n"
                                "\r\n",
                                accept);
            }
        }
        p = nl + 1;
    }
    return -1;
}

/* ====================================================================
 *  发送 WS 帧
 * ==================================================================== */

static int srv_frame(int fd, int fin, int opcode, const uint8_t *pld, uint64_t len) {
    uint8_t hdr[16];
    int     hlen = ws_frame_build_header(hdr, (uint8_t)fin, 0, (uint8_t)opcode, NULL, len);
    if(hlen <= 0)
        return -1;
    uint8_t *buf = (uint8_t *)malloc((size_t)hlen + (size_t)len);
    if(!buf)
        return -1;
    memcpy(buf, hdr, (size_t)hlen);
    if(len > 0 && pld)
        memcpy(buf + hlen, pld, (size_t)len);
    ssize_t w = write(fd, buf, (size_t)(hlen + len));
    int     r = (w == (ssize_t)(hlen + len)) ? 0 : -1;
    free(buf);
    return r;
}

/* ====================================================================
 *  服务端关闭
 * ==================================================================== */

static void srv_close(void) {
    if(g_srv.state == S_DONE)
        return;
    g_srv.state = S_DONE;
    if(g_srv.io) {
        sevent_io_unregister(g_ctx, g_srv.io);
        g_srv.io = NULL;
    }
    if(g_srv.client_fd > 0) {
        close(g_srv.client_fd);
        g_srv.client_fd = 0;
    }
}

/* ====================================================================
 *  服务端读回调
 * ==================================================================== */

static void on_srv_read(void *data) {
    (void)data;
    if(g_srv.state == S_DONE)
        return;
    if(g_srv.len >= sizeof(g_srv.buf))
        return;
    size_t  space = sizeof(g_srv.buf) - g_srv.len;
    ssize_t n     = read(g_srv.client_fd, g_srv.buf + g_srv.len, space);
    if(n <= 0) {
        if(g_pass == 0)
            g_pass = -1;
        srv_close();
        return;
    }
    g_srv.len += (size_t)n;

    if(g_srv.state == S_HANDSHAKE) {
        char resp[HTTP_RESP_BUF];
        int  rlen = build_101(g_srv.buf, g_srv.len, resp, sizeof(resp));
        if(rlen < 0)
            return;
        if(write(g_srv.client_fd, resp, (size_t)rlen) != (ssize_t)rlen)
            goto fail;

        /* 按 scenario 参数发分片 */
        int idx = g_scenario_idx;
        if(idx < 0 || idx >= SCEN_COUNT)
            idx = 0;

        size_t frag_sz  = g_scenarios[idx].frag_sz;
        int    n_data   = g_scenarios[idx].n_data;
        int    op_start = g_scenarios[idx].bin ? WS_OPCODE_BINARY : WS_OPCODE_TEXT;

        uint8_t *fill = (uint8_t *)malloc(frag_sz);
        for(size_t i = 0; i < frag_sz; i++)
            fill[i] = (uint8_t)(FILL_SEED + (i % 26));

        /* 起始帧 */
        if(srv_frame(g_srv.client_fd, 0, op_start, fill, frag_sz) < 0) {
            free(fill);
            goto fail;
        }

        /* 中间数据分片 */
        for(int i = 1; i < n_data; i++) {
            int f = (i == n_data - 1 && !g_scenarios[idx].terminator) ? 1 : 0;
            if(srv_frame(g_srv.client_fd, f, WS_OPCODE_CONT, fill, frag_sz) < 0) {
                free(fill);
                goto fail;
            }
        }

        /* 终止帧 */
        if(g_scenarios[idx].terminator) {
            if(srv_frame(g_srv.client_fd, 1, WS_OPCODE_CONT, NULL, 0) < 0) {
                free(fill);
                goto fail;
            }
        }
        free(fill);

        g_srv.len   = 0;
        g_srv.state = S_WAIT_ECHO;
        return;

    fail:
        fprintf(stderr, "  FAIL: send\n");
        g_pass = -1;
        srv_close();
        return;
    }

    if(g_srv.state == S_WAIT_ECHO) {
        size_t pos = 0;
        while(pos < g_srv.len) {
            ws_frame_header hdr;
            int             hlen = ws_frame_parse_header(g_srv.buf + pos, g_srv.len - pos, &hdr);
            if(hlen == 0)
                break;
            if(hlen < 0) {
                g_pass = -1;
                srv_close();
                return;
            }
            size_t fsize = (size_t)hlen + (size_t)hdr.payload_len;
            if(g_srv.len - pos < fsize)
                break;
            uint8_t *pld = g_srv.buf + pos + hlen;
            if(hdr.mask)
                ws_frame_apply_mask(pld, hdr.payload_len, hdr.mask_key);
            if((hdr.opcode == WS_OPCODE_TEXT || hdr.opcode == WS_OPCODE_BINARY) && hdr.fin) {
                int    idx  = g_scenario_idx;
                size_t want = (size_t)g_scenarios[idx].n_data * g_scenarios[idx].frag_sz;
                if((size_t)hdr.payload_len == want && pld[0] == FILL_SEED) {
                    printf("  PASS: echo %llu bytes\n", (unsigned long long)hdr.payload_len);
                    g_pass = 1;
                    srv_frame(g_srv.client_fd, 1, WS_OPCODE_CLOSE, NULL, 0);
                } else {
                    fprintf(stderr, "  FAIL: len=%llu want=%zu\n", (unsigned long long)hdr.payload_len, want);
                    g_pass = -1;
                    srv_close();
                    return;
                }
            } else if(hdr.opcode == WS_OPCODE_CLOSE) {
                srv_close();
                return;
            }
            pos += fsize;
        }
        if(pos > 0) {
            if(pos < g_srv.len)
                memmove(g_srv.buf, g_srv.buf + pos, g_srv.len - pos);
            g_srv.len -= pos;
        }
    }
}

/* ====================================================================
 *  accept
 * ==================================================================== */

static void on_accept(void *data) {
    (void)data;
    int cfd = accept(g_srv.listen_fd, NULL, NULL);
    if(cfd < 0)
        return;
    fcntl(cfd, F_SETFL, fcntl(cfd, F_GETFL) | O_NONBLOCK);
    if(g_srv.io) {
        sevent_io_unregister(g_ctx, g_srv.io);
        g_srv.io = NULL;
    }
    g_srv.client_fd = cfd;
    g_srv.state     = S_HANDSHAKE;
    sevent_io_handler h;
    h.fd       = cfd;
    h.io_read  = on_srv_read;
    h.io_write = NULL;
    h.data     = NULL;
    g_srv.io   = sevent_io_register(g_ctx, &h);
}

/* ====================================================================
 *  客户端回调
 * ==================================================================== */

static void on_ws_open(void *d) { (void)d; }

static void on_ws_msg(void *d, const void *m, size_t l, bool bin, bool fin, uint64_t total) {
    (void)d;
    (void)bin;
    (void)total;
    memcpy(g_cli_buf + g_cli_len, m, l);
    g_cli_len += l;
    if(fin) {
        int r = bin ? sevent_ws_send_binary(g_ws, g_cli_buf, g_cli_len)
                    : sevent_ws_send_text(g_ws, g_cli_buf, g_cli_len);
        if(r) {
            fprintf(stderr, "  FAIL: echo 0x%x\n", r);
            g_pass = -1;
        }
    }
}

static void on_ws_close(void *d, uint16_t c, const char *r, size_t l) {
    (void)d;
    (void)c;
    (void)r;
    (void)l;
    sevent_stop(g_ctx);
}

static void on_ws_err(void *d, int e) {
    (void)d;
    fprintf(stderr, "  FAIL: err 0x%x\n", e);
    g_pass = -1;
    sevent_stop(g_ctx);
}

static void on_start(void *d) {
    (void)d;
    if(g_ws) {
        sevent_ws_destroy(g_ws);
        g_ws = NULL;
    }
    g_cli_len = 0;

    int idx = g_scenario_idx;
    if(idx < 0 || idx >= SCEN_COUNT)
        idx = 0;

    sevent_ws_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host          = "127.0.0.1";
    cfg.port          = (uint16_t)(BASE_PORT + idx);
    cfg.path          = "/";
    cfg.recv_buf_size = g_scenarios[idx].recv_buf;
    cfg.on_open       = on_ws_open;
    cfg.on_message    = on_ws_msg;
    cfg.on_close      = on_ws_close;
    cfg.on_error      = on_ws_err;
    g_ws              = sevent_ws_connect(g_ctx, &cfg);
    if(!g_ws) {
        fprintf(stderr, "  FAIL: connect\n");
        g_pass = -1;
        sevent_stop(g_ctx);
    }
}

static void on_timeout(void *d) {
    (void)d;
    fprintf(stderr, "  FAIL: timeout\n");
    if(g_pass == 0) {
        g_pass = -1;
    }
    sevent_stop(g_ctx);
}

/* ====================================================================
 *  跑一个 scenario
 * ==================================================================== */

static int run_one(int idx) {
    printf("frag_stream[%d] %s ...\n", idx, g_scenarios[idx].name);

    g_ctx = sevent_create();
    if(!g_ctx)
        return 1;
    sevent_ignore_sigpipe();

    g_pass         = -1;
    g_scenario_idx = idx;
    memset(&g_srv, 0, sizeof(g_srv));

    /* listen */
    int port        = BASE_PORT + idx;
    g_srv.listen_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if(g_srv.listen_fd < 0) {
        perror("  socket");
        return 1;
    }
    int opt = 1;
    setsockopt(g_srv.listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if(bind(g_srv.listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("  bind");
        return 1;
    }
    if(listen(g_srv.listen_fd, LISTEN_BACKLOG) < 0) {
        perror("  listen");
        return 1;
    }
    g_srv.state = S_LISTEN;
    sevent_io_handler h;
    h.fd       = g_srv.listen_fd;
    h.io_read  = on_accept;
    h.io_write = NULL;
    h.data     = NULL;
    if(!sevent_io_register(g_ctx, &h)) {
        fprintf(stderr, "  FAIL: io\n");
        return 1;
    }

    g_pass = 0;
    sevent_timer_register(g_ctx, CLIENT_DELAY_MS, on_start, NULL);
    sevent_timer_register(g_ctx, TIMEOUT_MS, on_timeout, NULL);
    sevent_run(g_ctx);

    int pass = g_pass;
    if(g_ws) {
        sevent_ws_destroy(g_ws);
        g_ws = NULL;
    }
    srv_close();
    if(g_srv.listen_fd > 0)
        close(g_srv.listen_fd);
    if(g_srv.client_fd > 0)
        close(g_srv.client_fd);
    sevent_destroy(g_ctx);
    g_ctx = NULL;

    if(pass == 1) {
        printf("  PASS\n");
        return 0;
    }
    printf("  FAIL\n");
    return 1;
}

/* ====================================================================
 *  main
 * ==================================================================== */

int main(void) {
    int failed = 0;
    for(int i = 0; i < SCEN_COUNT; i++)
        if(run_one(i) != 0)
            failed++;
    printf("%s: %d/%d scenarios passed\n", failed == 0 ? "PASS" : "FAIL", SCEN_COUNT - failed, SCEN_COUNT);
    return failed;
}
