/**
 *  frag_terminator_test.c — 分片精确填满 recv_cap + 0 字节终止帧
 *
 *  测试场景 (Autobahn 9.3.2 的精简复现):
 *     服务端发送分片消息, payload 总和 = recv_buf_size (精确填满),
 *     随后发一个 0 字节 CONT 终止帧 (fin=1).
 *     客户端收到后 on_message 最后一块应带 fin=1, 回显成功.
 *
 *  架构: 同一事件循环中,
 *     1. 服务端 (raw TCP) — 握手 → 发分片 → 收验证回显 → CLOSE
 *     2. 客户端 (sevent_ws) — 收消息 → 回显
 *
 *  用定时器延迟客户端连接, 确保服务端 listen 已就绪.
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
 *  测试参数
 * ==================================================================== */

#define TEST_PORT     19302
#define RECV_BUF_SIZE 256
#define TEXT_DATA     "frag-test"
#define TEXT_LEN      ((int)sizeof(TEXT_DATA) - 1)   /* 8 */
#define CONT_LEN      (RECV_BUF_SIZE - TEXT_LEN)     /* 248 */

/* ====================================================================
 *  全局
 * ==================================================================== */

static sevent_context *g_ctx;
static int             g_test_pass;  /* 0=未决, 1=通过, -1=失败 */

/* ====================================================================
 *  服务端状态
 * ==================================================================== */

enum { S_LISTEN, S_HANDSHAKE, S_WAIT_ECHO, S_DONE };

static struct {
    int        state;
    int        listen_fd;
    int        client_fd;
    sevent_io *io;           /* 当前活跃的 server I/O (listen 或 client) */
    uint8_t    buf[65536];
    size_t     len;
} g_srv;

/* ====================================================================
 *  客户端
 * ==================================================================== */

static sevent_ws_conn *g_ws;
static uint8_t         g_cli_buf[65536];
static size_t          g_cli_len;

/* ====================================================================
 *  SHA1 + Base64: 计算 Sec-WebSocket-Accept
 * ==================================================================== */

static void compute_accept(const char *key, char *out, size_t cap) {
    char    concat[256];
    int     n = snprintf(concat, sizeof(concat), "%s%s", key,
                         "258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    uint8_t digest[20];
    ws_sha1((const uint8_t *)concat, (size_t)n, digest);
    ws_base64_encode(digest, 20, out, cap);
}

/* ====================================================================
 *  构造 HTTP 101 升级响应
 * ==================================================================== */

static int build_101(const uint8_t *req, size_t req_len,
                     char *resp, size_t resp_cap) {
    const char *key_hdr = "sec-websocket-key:";
    const char *p   = (const char *)req;
    const char *end = p + req_len;

    while(p && p < end) {
        const char *nl = (const char *)memchr(p, '\n', (size_t)(end - p));
        if(!nl) break;
        size_t llen = (size_t)(nl - p);
        if(llen > 0 && p[llen - 1] == '\r') llen--;

        if(llen > strlen(key_hdr)) {
            int match = 1;
            for(size_t i = 0; key_hdr[i]; i++) {
                char a = p[i], b = key_hdr[i];
                if(a >= 'A' && a <= 'Z') a += 0x20;
                if(a != b) { match = 0; break; }
            }
            if(match) {
                const char *vs = p + strlen(key_hdr);
                while(vs < nl && (*vs == ' ' || *vs == '\t')) vs++;
                size_t vlen = (size_t)(nl - vs);
                if(vlen > 0 && vs[vlen - 1] == '\r') vlen--;
                if(vlen > 127) vlen = 127;
                char key[128] = {0};
                memcpy(key, vs, vlen);
                char accept[32];
                compute_accept(key, accept, sizeof(accept));
                return snprintf(resp, resp_cap,
                    "HTTP/1.1 101 Switching Protocols\r\n"
                    "Upgrade: websocket\r\n"
                    "Connection: Upgrade\r\n"
                    "Sec-WebSocket-Accept: %s\r\n"
                    "\r\n", accept);
            }
        }
        p = nl + 1;
    }
    return -1;
}

/* ====================================================================
 *  发送 WS 帧 (server→client, 无掩码)
 * ==================================================================== */

static int srv_send_frame(int fd, int fin, int opcode,
                          const uint8_t *payload, uint64_t len) {
    uint8_t hdr[16];
    int     hlen = ws_frame_build_header(hdr, (uint8_t)fin, (uint8_t)opcode,
                                        NULL, len);
    if(hlen <= 0) return -1;
    uint8_t *buf = (uint8_t *)malloc((size_t)hlen + (size_t)len);
    if(!buf) return -1;
    memcpy(buf, hdr, (size_t)hlen);
    if(len > 0 && payload)
        memcpy(buf + hlen, payload, (size_t)len);
    ssize_t w = write(fd, buf, (size_t)(hlen + len));
    int     r = (w == (ssize_t)(hlen + len)) ? 0 : -1;
    free(buf);
    return r;
}

/* ====================================================================
 *  服务端 → 客户端连接关闭清理
 * ==================================================================== */

static void srv_close(void) {
    if(g_srv.state == S_DONE) return;
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

    if(g_srv.state == S_DONE) return;

    ssize_t n = read(g_srv.client_fd,
                     g_srv.buf + g_srv.len,
                     sizeof(g_srv.buf) - g_srv.len);
    if(n <= 0) {
        if(g_test_pass == 0) {
            fprintf(stderr, "  FAIL: server connection lost\n");
            g_test_pass = -1;
        }
        srv_close();
        return;
    }
    g_srv.len += (size_t)n;

    if(g_srv.state == S_HANDSHAKE) {
        /* ---- 握手 ---- */
        char resp[512];
        int  rlen = build_101(g_srv.buf, g_srv.len, resp, sizeof(resp));
        if(rlen < 0) return; /* 等待更多数据 */

        if(write(g_srv.client_fd, resp, (size_t)rlen) != (ssize_t)rlen)
            goto fail;

        /* 帧 1: TEXT start (fin=0, len=8) */
        if(srv_send_frame(g_srv.client_fd, 0, WS_OPCODE_TEXT,
                          (const uint8_t *)TEXT_DATA, TEXT_LEN) < 0)
            goto fail;

        /* 帧 2: CONT (fin=0, len=248) — 总和 = 256 = recv_cap */
        {
            uint8_t fill[CONT_LEN];
            memset(fill, 'x', CONT_LEN);
            if(srv_send_frame(g_srv.client_fd, 0, WS_OPCODE_CONT,
                              fill, CONT_LEN) < 0)
                goto fail;
        }

        /* 帧 3: CONT 终止帧 (fin=1, len=0) ← 复现 Bug 的关键 */
        if(srv_send_frame(g_srv.client_fd, 1, WS_OPCODE_CONT, NULL, 0) < 0)
            goto fail;

        g_srv.len   = 0;
        g_srv.state = S_WAIT_ECHO;
        return;

    fail:
        fprintf(stderr, "  FAIL: send fragments\n");
        g_test_pass = -1;
        srv_close();
        return;
    }

    if(g_srv.state == S_WAIT_ECHO) {
        /* ---- 读取客户端回显 ---- */
        size_t pos = 0;
        while(pos < g_srv.len) {
            ws_frame_header hdr;
            int hlen = ws_frame_parse_header(g_srv.buf + pos,
                                             g_srv.len - pos, &hdr);
            if(hlen == 0) break;
            if(hlen < 0) goto echo_fail;

            size_t fsize = (size_t)hlen + (size_t)hdr.payload_len;
            if(g_srv.len - pos < fsize) break;

            uint8_t *payload = g_srv.buf + pos + hlen;
            if(hdr.mask)
                ws_frame_apply_mask(payload, hdr.payload_len, hdr.mask_key);

            if((hdr.opcode == WS_OPCODE_TEXT ||
                hdr.opcode == WS_OPCODE_BINARY) && hdr.fin) {
                /* 验证回显 */
                if((size_t)hdr.payload_len != RECV_BUF_SIZE ||
                   memcmp(payload, TEXT_DATA, TEXT_LEN) != 0)
                    goto echo_fail;

                printf("  PASS: echo %llu bytes match\n",
                       (unsigned long long)hdr.payload_len);
                g_test_pass = 1;

                /* 发 CLOSE 通知客户端结束 */
                srv_send_frame(g_srv.client_fd, 1, WS_OPCODE_CLOSE, NULL, 0);

            } else if(hdr.opcode == WS_OPCODE_CLOSE) {
                /* 客户端 CLOSE 响应 → 结束 */
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
        return;

    echo_fail:
        fprintf(stderr, "  FAIL: echo verification\n");
        g_test_pass = -1;
        srv_close();
    }
}

/* ====================================================================
 *  服务端 accept 回调
 * ==================================================================== */

static void on_accept(void *data) {
    (void)data;
    int cfd = accept(g_srv.listen_fd, NULL, NULL);
    if(cfd < 0) return;
    fcntl(cfd, F_SETFL, fcntl(cfd, F_GETFL) | O_NONBLOCK);

    /* 取消 listen 事件 (只需一个客户端) */
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

static void on_ws_open(void *data) {
    (void)data;
    /* 服务端将在握手完成后自动发分片 */
}

static void on_ws_message(void *data, const void *m, size_t l,
                          bool bin, bool fin, uint64_t total) {
    (void)data;
    (void)bin;
    (void)total;

    memcpy(g_cli_buf + g_cli_len, m, l);
    g_cli_len += l;

    if(fin) {
        int r = bin ? sevent_ws_send_binary(g_ws, g_cli_buf, g_cli_len)
                    : sevent_ws_send_text(g_ws, g_cli_buf, g_cli_len);
        if(r != 0) {
            fprintf(stderr, "  FAIL: echo send error 0x%x\n", r);
            g_test_pass = -1;
        }
    }
}

static void on_ws_close(void *data, uint16_t code, const char *reason,
                        size_t rl) {
    (void)data;
    (void)code;
    (void)reason;
    (void)rl;
    sevent_stop(g_ctx);
}

static void on_ws_error(void *data, int err) {
    (void)data;
    fprintf(stderr, "  FAIL: client error 0x%x\n", err);
    g_test_pass = -1;
    sevent_stop(g_ctx);
}

/* ====================================================================
 *  启动客户端 (定时器回调, 确保事件循环已运行)
 * ==================================================================== */

static void on_start_client(void *data) {
    (void)data;

    sevent_ws_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host          = "127.0.0.1";
    cfg.port          = TEST_PORT;
    cfg.path          = "/";
    cfg.recv_buf_size = RECV_BUF_SIZE;
    cfg.on_open       = on_ws_open;
    cfg.on_message    = on_ws_message;
    cfg.on_close      = on_ws_close;
    cfg.on_error      = on_ws_error;

    g_ws = sevent_ws_connect(g_ctx, &cfg);
    if(!g_ws) {
        fprintf(stderr, "FAIL: ws_connect\n");
        g_test_pass = -1;
        sevent_stop(g_ctx);
    }
}

/* ====================================================================
 *  监控定时器: 超时保护
 * ==================================================================== */

static void on_timeout(void *data) {
    (void)data;
    fprintf(stderr, "  FAIL: test timeout\n");
    if(g_test_pass == 0) g_test_pass = -1;
    sevent_stop(g_ctx);
}

/* ====================================================================
 *  main
 * ==================================================================== */

int main(void) {
    g_ctx = sevent_create();
    if(!g_ctx) { fprintf(stderr, "FAIL: create ctx\n"); return 1; }
    sevent_ignore_sigpipe();

    /* ---- 建立 TCP listen ---- */
    g_srv.listen_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if(g_srv.listen_fd < 0) { perror("FAIL: socket"); return 1; }

    int opt = 1;
    setsockopt(g_srv.listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(TEST_PORT);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if(bind(g_srv.listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("FAIL: bind"); close(g_srv.listen_fd); return 1;
    }
    if(listen(g_srv.listen_fd, 5) < 0) {
        perror("FAIL: listen"); close(g_srv.listen_fd); return 1;
    }
    g_srv.state = S_LISTEN;

    /* 注册 listen */
    {
        sevent_io_handler h;
        h.fd       = g_srv.listen_fd;
        h.io_read  = on_accept;
        h.io_write = NULL;
        h.data     = NULL;
        g_srv.io   = sevent_io_register(g_ctx, &h);
    }

    /* 延迟启动客户端 (等事件循环开始后再连) */
    sevent_timer_register(g_ctx, 10, on_start_client, NULL);

    /* 10 秒超时保护 */
    sevent_timer_register(g_ctx, 10000, on_timeout, NULL);

    printf("frag_terminator_test: running\n");
    sevent_run(g_ctx);

    /* ---- 结果 ---- */
    int pass = g_test_pass;
    if(g_ws) { sevent_ws_destroy(g_ws); g_ws = NULL; }
    if(g_srv.state != S_DONE) srv_close();
    if(g_srv.listen_fd > 0) close(g_srv.listen_fd);

    sevent_destroy(g_ctx);

    printf("%s: %s\n", pass == 1 ? "PASS" : "FAIL",
           pass == 1 ? "frag + 0-byte terminator echo OK" :
           pass == 0 ? "incomplete" : "see errors above");
    return pass == 1 ? 0 : 1;
}
