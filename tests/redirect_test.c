/**
 *  redirect_test.c — 自动重定向测试 (HTTP 301 → ws://)
 *
 *  自建 TCP 重定向服务端 + WS 回声服务端 + WS 客户端。
 *  客户端先连重定向服务端，收到 301 + Location 后自动重连到回声服务端。
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

#define PORT_REDIR 19450
#define PORT_ECHO 19451
#define TEST_MSG "Hello via redirect!"

static sevent_context *g_ctx;
static int             g_pass;

/* 包装: sevent_timer_fn 参数为 void*，中转 sevent_stop */
static void stop_timer(void *d) { sevent_stop((sevent_context *)d); }

/* ---- 小辅助: 创建 nonblock + REUSEADDR 监听 socket ----------------- */
static int tcp_listen(uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if(fd < 0) {
        perror("socket");
        return -1;
    }
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#ifdef SO_REUSEPORT
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
#endif
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port        = htons(port);
    if(bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(fd);
        return -1;
    }
    if(listen(fd, 5) < 0) {
        perror("listen");
        close(fd);
        return -1;
    }
    return fd;
}

/* ====================================================================
 *  重定向服务端
 *
 *  accept → 读 HTTP 请求 → 回复 301 + Location: ws://echo-server
 *  ==================================================================== */
static int        g_redir_fd;
static sevent_io *g_redir_io;

static void on_redir_conn(void *data) {
    int     fd = (int)(uintptr_t)data;
    uint8_t buf[4096];
    ssize_t n = read(fd, buf, sizeof(buf));
    if(n <= 0)
        goto close;
    char resp[512];
    int  rl = snprintf(resp,
                      sizeof(resp),
                      "HTTP/1.1 301 Moved Permanently\r\n"
                       "Location: ws://127.0.0.1:%d/new-path\r\n"
                       "Content-Length: 0\r\n"
                       "\r\n",
                      PORT_ECHO);
    write(fd, resp, (size_t)rl);
close:
    if(g_redir_io) {
        sevent_io_unregister(g_ctx, g_redir_io);
        g_redir_io = NULL;
    }
    close(fd);
}

static void on_redir_accept(void *data) {
    (void)data;
    int fd = accept(g_redir_fd, NULL, NULL);
    if(fd < 0)
        return;
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
    if(g_redir_io) {
        sevent_io_unregister(g_ctx, g_redir_io);
        g_redir_io = NULL;
    }
    sevent_io_handler h = {.fd = fd, .io_read = on_redir_conn, .data = (void *)(uintptr_t)fd};
    g_redir_io          = sevent_io_register(g_ctx, &h);
}

/* ====================================================================
 *  回声服务端
 *
 *  accept → WS 握手 → 收到 TEXT/BINARY 就原样回显
 *  ==================================================================== */
static int        g_echo_listen; /* 监听 fd */
static int        g_echo_fd;     /* 当前连接 fd */
static sevent_io *g_echo_io;
static int        g_echo_hs; /* 握手完成标志 */
static uint8_t    g_echo_buf[65536];
static size_t     g_echo_len;

/* 小写比较 */
static int ci_eq_n(const char *s, size_t n, const char *t) {
    for(size_t i = 0; i < n; i++) {
        if(!t[i])
            return 0;
        char a = s[i], b = t[i];
        if(a >= 'A' && a <= 'Z')
            a += 0x20;
        if(b >= 'A' && b <= 'Z')
            b += 0x20;
        if(a != b)
            return 0;
    }
    return t[n] == '\0';
}

static void on_echo_read(void *data) {
    (void)data;
    if(g_echo_fd <= 0)
        return;
    ssize_t n = read(g_echo_fd, g_echo_buf + g_echo_len, sizeof(g_echo_buf) - g_echo_len);
    if(n < 0 && (errno == EAGAIN || errno == EINTR))
        return;
    if(n <= 0) {
        if(g_echo_io) {
            sevent_io_unregister(g_ctx, g_echo_io);
            g_echo_io = NULL;
        }
        close(g_echo_fd);
        g_echo_fd = 0;
        return;
    }
    g_echo_len += (size_t)n;

    /* --- WS 握手阶段 --- */
    if(!g_echo_hs) {
        const char *end = (const char *)g_echo_buf + g_echo_len, *p = (const char *)g_echo_buf;
        while(p < end) {
            const char *nl = (const char *)memchr(p, '\n', (size_t)(end - p));
            if(!nl)
                break;
            size_t llen = (size_t)(nl - p);
            if(llen > 0 && p[llen - 1] == '\r')
                llen--;

            if(llen > 18 && ci_eq_n(p, 18, "sec-websocket-key:")) {
                const char *vs = p + 18;
                while(vs < nl && (*vs == ' ' || *vs == '\t'))
                    vs++;
                size_t vlen = (size_t)(nl - vs);
                if(vlen > 0 && vs[vlen - 1] == '\r')
                    vlen--;
                if(vlen > 127)
                    vlen = 127;
                char key[128] = {0};
                memcpy(key, vs, vlen);

                char concat[256];
                snprintf(concat, sizeof(concat), "%s%s", key, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
                uint8_t digest[20];
                ws_sha1((const uint8_t *)concat, strlen(concat), digest);
                char b64[32];
                ws_base64_encode(digest, 20, b64, sizeof(b64));
                char resp[512];
                int  rl = snprintf(resp,
                                  sizeof(resp),
                                  "HTTP/1.1 101 Switching Protocols\r\n"
                                   "Upgrade: websocket\r\n"
                                   "Connection: Upgrade\r\n"
                                   "Sec-WebSocket-Accept: %s\r\n"
                                   "\r\n",
                                  b64);
                write(g_echo_fd, resp, (size_t)rl);
                g_echo_hs  = 1;
                g_echo_len = 0;
                return;
            }
            p = nl + 1;
        }
        return;
    }

    /* --- WS 帧回显阶段 --- */
    size_t pos = 0;
    while(pos < g_echo_len) {
        ws_frame_header hdr;
        int             hlen = ws_frame_parse_header(g_echo_buf + pos, g_echo_len - pos, &hdr);
        if(hlen == 0)
            break;
        if(hlen < 0) {
            g_echo_len = 0;
            return;
        }
        size_t fsize = (size_t)hlen + (size_t)hdr.payload_len;
        if(g_echo_len - pos < fsize)
            break;

        uint8_t *pld = g_echo_buf + pos + hlen;
        if(hdr.mask)
            ws_frame_apply_mask(pld, hdr.payload_len, hdr.mask_key);
        if(hdr.opcode == WS_OPCODE_TEXT || hdr.opcode == WS_OPCODE_BINARY) {
            uint8_t  rh[16];
            int      hh  = ws_frame_build_header(rh, 1, hdr.opcode, NULL, hdr.payload_len);
            uint8_t *out = (uint8_t *)malloc((size_t)hh + (size_t)hdr.payload_len);
            memcpy(out, rh, (size_t)hh);
            memcpy(out + hh, pld, (size_t)hdr.payload_len);
            write(g_echo_fd, out, (size_t)(hh + hdr.payload_len));
            free(out);
        }
        pos += fsize;
    }
    if(pos > 0) {
        if(pos < g_echo_len)
            memmove(g_echo_buf, g_echo_buf + pos, g_echo_len - pos);
        g_echo_len -= pos;
    }
}

static void on_echo_accept(void *data) {
    (void)data;
    if(g_echo_fd > 0)
        return;
    struct sockaddr_in unused;
    socklen_t          ulen = sizeof(unused);
    g_echo_fd               = accept(g_echo_listen, (struct sockaddr *)&unused, &ulen);
    if(g_echo_fd < 0)
        return;
    fcntl(g_echo_fd, F_SETFL, fcntl(g_echo_fd, F_GETFL) | O_NONBLOCK);
    if(g_echo_io) {
        sevent_io_unregister(g_ctx, g_echo_io);
        g_echo_io = NULL;
    }
    g_echo_hs           = 0;
    g_echo_len          = 0;
    sevent_io_handler h = {.fd = g_echo_fd, .io_read = on_echo_read};
    g_echo_io           = sevent_io_register(g_ctx, &h);
    if(!g_echo_io) {
        close(g_echo_fd);
        g_echo_fd = 0;
    }
}

/* ====================================================================
 *  WS 客户端
 * ==================================================================== */
static sevent_ws_conn *g_ws;
static uint8_t         g_rxbuf[1024];
static size_t          g_rxlen;

static void on_ws_open(void *d) {
    (void)d;
    printf("  on_open\n");
    fflush(stdout);
    sevent_ws_send_text(g_ws, TEST_MSG, strlen(TEST_MSG));
}

static void on_ws_msg(void *d, const void *m, size_t l, bool b, bool f, uint64_t t) {
    (void)d;
    (void)b;
    (void)t;
    memcpy(g_rxbuf + g_rxlen, m, l);
    g_rxlen += l;
    if(f && g_rxlen == strlen(TEST_MSG) && memcmp(g_rxbuf, TEST_MSG, g_rxlen) == 0) {
        printf("  PASS: echo match (%zu bytes)\n", g_rxlen);
        g_pass = 1;
        sevent_ws_shutdown(g_ws, SEVENT_WS_CLOSE_NORMAL, "ok");
        sevent_stop(g_ctx);
    }
}

static void on_ws_close(void *d, uint16_t c, const char *r, size_t l) {
    (void)d;
    (void)c;
    (void)r;
    (void)l;
    if(g_pass != 1)
        g_pass = (g_rxlen == strlen(TEST_MSG) && memcmp(g_rxbuf, TEST_MSG, g_rxlen) == 0) ? 1 : -1;
    if(g_ws) {
        sevent_ws_destroy(g_ws);
        g_ws = NULL;
    }
    sevent_stop(g_ctx);
}

static void on_ws_err(void *d, int e) {
    (void)d;
    printf("  FAIL: err 0x%x\n", e);
    g_pass = -1;
    sevent_stop(g_ctx);
}

/* ====================================================================
 *  main
 * ==================================================================== */
int main(void) {
    setbuf(stdout, NULL);
    g_ctx = sevent_create();
    if(!g_ctx) {
        printf("FAIL: ctx\n");
        return 1;
    }
    sevent_ignore_sigpipe();
    printf("redirect_test ...\n");

    /* 重定向服务端 */
    g_redir_fd = tcp_listen(PORT_REDIR);
    if(g_redir_fd < 0)
        return 1;
    if(!sevent_io_register(g_ctx, &(sevent_io_handler){.fd = g_redir_fd, .io_read = on_redir_accept})) {
        printf("FAIL: io redir\n");
        return 1;
    }

    /* 回声服务端 */
    g_echo_listen = tcp_listen(PORT_ECHO);
    if(g_echo_listen < 0)
        return 1;
    if(!sevent_io_register(g_ctx, &(sevent_io_handler){.fd = g_echo_listen, .io_read = on_echo_accept})) {
        printf("FAIL: io echo\n");
        return 1;
    }

    /* WS 客户端 — 连的是重定向服务端 */
    g_ws = sevent_ws_connect(g_ctx,
                             &(sevent_ws_config){.host       = "127.0.0.1",
                                                 .port       = PORT_REDIR,
                                                 .path       = "/old-path",
                                                 .on_open    = on_ws_open,
                                                 .on_message = on_ws_msg,
                                                 .on_close   = on_ws_close,
                                                 .on_error   = on_ws_err});
    if(!g_ws) {
        printf("  FAIL: connect\n");
        return 1;
    }

    /* 安全网 (5s fallback) */
    sevent_timer_register(g_ctx, 5000, stop_timer, g_ctx);

    /* 跑事件循环 — on_msg 正常路径会提前 stop */
    sevent_run(g_ctx);

    /* 清理 */
    if(g_ws) {
        sevent_ws_destroy(g_ws);
        g_ws = NULL;
    }
    if(g_echo_io) {
        sevent_io_unregister(g_ctx, g_echo_io);
        g_echo_io = NULL;
    }
    if(g_echo_fd)
        close(g_echo_fd);
    if(g_redir_io) {
        sevent_io_unregister(g_ctx, g_redir_io);
        g_redir_io = NULL;
    }
    close(g_echo_listen);
    close(g_redir_fd);
    sevent_destroy(g_ctx);

    int ok = (g_pass == 1);
    printf("%s: redirect_test\n", ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}
