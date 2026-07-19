/* ws_conn 集成测试 */
#include "sevent.h"
#include "../src/websockets/ws_sha1.h"
#include "../src/websockets/ws_base64.h"
#include "../src/websockets/ws_frame.h"
#include "../src/websockets/ws_handshake.h"
#include "../src/websockets/ws_conn.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#ifdef SEVENT_WS_THREAD_SAFE
#include <pthread.h>
#endif

/* 抑制 CI 上 -Werror=unused-result */
#define WS_WRITE(fd, buf, len)                                                                                         \
    do {                                                                                                               \
        ssize_t _wr = write(fd, buf, len);                                                                             \
        (void)_wr;                                                                                                     \
    } while(0)

static int      g_ev;
static char     g_msg[256];
static int      g_frag_count;
static int      g_frag_last_fin;
static size_t   g_frag_len;   /* g_msg 累计长度(受 256 限制) */
static size_t   g_frag_total; /* 实际累计字节数(无限制) */
static uint64_t g_last_total; /* 最近一次 on_message 的 total 参数 */

static void ev_open(void *d) {
    (void)d;
    g_ev = 1;
}
static void ev_msg(void *d, const void *m, size_t l, int b, int fin, uint64_t total) {
    (void)d;
    (void)b;
    (void)fin;
    g_last_total = total;
    g_ev         = 2;
    size_t c     = l < 255 ? l : 255;
    memcpy(g_msg, m, c);
    g_msg[c] = 0;
}

/* 分片测试专用回调: 累计调用次数 + 总长度 */
static void ev_msg_frag(void *d, const void *m, size_t l, int b, int fin, uint64_t total) {
    (void)d;
    (void)b;
    g_last_total = total;
    g_ev         = 2;
    g_frag_count++;
    g_frag_last_fin = fin;
    g_frag_total    += l;
    size_t c        = l + g_frag_len < sizeof(g_msg) ? l : sizeof(g_msg) - g_frag_len - 1;
    memcpy(g_msg + g_frag_len, m, c);
    g_frag_len        += c;
    g_msg[g_frag_len] = 0;
}

static void ev_close(void *d, uint16_t co, const char *r, size_t rl) {
    (void)d;
    (void)co;
    (void)r;
    (void)rl;
    g_ev = 3;
}
static void ev_error(void *d, int err) {
    (void)d;
    (void)err;
    g_ev = 3;
}
static void ev_tick(void *d) { (void)d; }

/* PONG 回调记录 */
static int      g_pong_fired;
static char     g_pong_payload[256];
static size_t   g_pong_len;
static void ev_pong(void *d, const void *p, size_t l) {
    (void)d;
    g_pong_fired = 1;
    g_pong_len    = l < sizeof(g_pong_payload) ? l : sizeof(g_pong_payload) - 1;
    if(l > 0 && p)
        memcpy(g_pong_payload, p, g_pong_len);
    g_pong_payload[g_pong_len] = '\0';
}

/* HTTP 响应回调记录 */
static int      g_http_status;
static char     g_http_body[256];
static size_t   g_http_body_len;
static void ev_http_resp(void *d, int code, const char *h, size_t hl, const char *b, size_t bl) {
    (void)d;
    (void)h;
    (void)hl;
    g_ev          = 4;
    g_http_status = code;
    g_http_body_len = bl < sizeof(g_http_body) ? bl : sizeof(g_http_body) - 1;
    if(bl > 0 && b)
        memcpy(g_http_body, b, g_http_body_len);
    g_http_body[g_http_body_len] = '\0';
}

/* 粘包/分包测试专用: 计数 + 累积内容 */
static int  g_call_count;
static void ev_msg_count(void *d, const void *m, size_t l, int b, int fin, uint64_t total) {
    (void)d;
    (void)b;
    (void)fin;
    g_last_total = total;
    g_ev         = 2;
    g_call_count++;
    g_frag_total += l;
    size_t c     = l + g_frag_len < sizeof(g_msg) ? l : sizeof(g_msg) - g_frag_len - 1;
    memcpy(g_msg + g_frag_len, m, c);
    g_frag_len        += c;
    g_msg[g_frag_len] = 0;
}
/* 带重试的 write: 处理非阻塞 socket 部分写入 */
static void write_all(int fd, const void *b, size_t l) {
    const uint8_t *p = (const uint8_t *)b;
    while(l > 0) {
        ssize_t n = write(fd, p, l);
        if(n > 0) {
            p += n;
            l -= (size_t)n;
        } else if(errno != EINTR)
            break;
    }
}

/* pair: 创建 TCP 连接, 返回 sfd */
static int pair(sevent_context *ctx, sevent_ws_config *cfg, sevent_ws_conn **ws) {
    int lfd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    int o   = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &o, sizeof(o));
    struct sockaddr_in ba;
    memset(&ba, 0, sizeof(ba));
    ba.sin_family      = AF_INET;
    ba.sin_port        = htons(0);
    ba.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if(bind(lfd, (struct sockaddr *)&ba, sizeof(ba)) < 0 || listen(lfd, 1) < 0) {
        close(lfd);
        return -1;
    }
    struct sockaddr_in ga;
    socklen_t          gl = sizeof(ga);
    getsockname(lfd, (struct sockaddr *)&ga, &gl);
    cfg->port = ntohs(ga.sin_port);
    *ws       = sevent_ws_connect(ctx, cfg);
    if(!*ws) {
        close(lfd);
        return -1;
    }
    struct sockaddr_in pa;
    socklen_t          pl = sizeof(pa);
    int                sfd;
    for(int i = 0; i < 100; i++) {
        sfd = accept(lfd, (struct sockaddr *)&pa, &pl);
        if(sfd >= 0)
            break;
        sevent_run_once(ctx);
    }
    if(sfd < 0) {
        close(lfd);
        return -1;
    }
    fcntl(sfd, F_SETFL, fcntl(sfd, F_GETFL) | O_NONBLOCK);
    close(lfd);
    return sfd;
}

/* shake: 服务端读 HTTP 请求 → 回复 101 */
static int shake(int sfd) {
    char    b[4096];
    ssize_t n = read(sfd, b, sizeof(b) - 1);
    if(n <= 0)
        return -1;
    b[n]    = 0;
    char *k = strstr(b, "Sec-WebSocket-Key:");
    if(!k)
        return -1;
    k += 19;
    while(*k == ' ')
        k++;
    char  ke[256];
    char *e = strstr(k, "\r\n");
    if(!e)
        return -1;
    size_t kl = (size_t)(e - k);
    if(kl > 255)
        kl = 255;
    memcpy(ke, k, kl);
    ke[kl] = 0;
    char cat[384];
    snprintf(cat, sizeof(cat), "%s%s", ke, WS_GUID);
    uint8_t dg[20];
    ws_sha1(cat, strlen(cat), dg);
    char ac[64];
    ws_base64_encode(dg, 20, ac, sizeof(ac));
    char resp[512];
    int  rn = snprintf(resp,
                      sizeof(resp),
                      "HTTP/1.1 101 Switching Protocols\r\n"
                       "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                       "Sec-WebSocket-Accept: %s\r\n\r\n",
                      ac);
    WS_WRITE(sfd, resp, (size_t)rn);
    return 0;
}

/* wsend: 服务端发 WS 帧 (无掩码) */
static void wsend(int fd, uint8_t op, const void *p, uint64_t l) {
    uint8_t b[4096];
    int     h = ws_frame_build_header(b, 1, op, NULL, l);
    if(p && l)
        memcpy(b + h, p, (size_t)l);
    WS_WRITE(fd, b, (size_t)(h + (int)l));
}

/* wread: 服务端读 WS 帧, 返回 payload 长度 */
static int wread(int fd, ws_frame_header *hdr, uint8_t *pay, size_t cap) {
    uint8_t b[4096];
    ssize_t n = read(fd, b, sizeof(b));
    if(n <= 0)
        return -1;
    int r = ws_frame_parse_header(b, (size_t)n, hdr);
    if(r <= 0)
        return -1;
    size_t pl = (size_t)hdr->payload_len;
    if(pl > cap)
        pl = cap;
    if(hdr->mask)
        ws_frame_apply_mask(b + r, hdr->payload_len, hdr->mask_key);
    memcpy(pay, b + r, pl);
    return (int)pl;
}

/* ===== 测试用例 ===== */
static int t_lifecycle(void) {
    sevent_context *ctx = sevent_create();
    if(!ctx)
        return 1;
    sevent_ws_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host       = "127.0.0.1";
    cfg.path       = "/";
    cfg.on_open    = ev_open;
    cfg.on_message = ev_msg;
    cfg.on_close   = ev_close;
    g_ev           = 0;
    sevent_ws_conn *ws;
    int             sfd = pair(ctx, &cfg, &ws);
    if(sfd < 0)
        return 1;
    sevent_run_once(ctx);
    if(shake(sfd) < 0)
        return 1;
    for(int i = 0; i < 200; i++) {
        sevent_run_once(ctx);
        if(g_ev == 1)
            break;
    }
    if(g_ev != 1)
        return 1;
    wsend(sfd, WS_OPCODE_TEXT, "Hello", 5);
    g_ev = 1;
    for(int i = 0; i < 50; i++) {
        sevent_run_once(ctx);
        if(g_ev == 2)
            break;
    }
    if(g_ev != 2 || strcmp(g_msg, "Hello") || g_last_total != 5)
        return 1;
    uint8_t cp[6];
    int     hl = ws_frame_build_header(cp, 1, WS_OPCODE_CLOSE, NULL, 2);
    cp[hl]     = 0x03;
    cp[hl + 1] = (uint8_t)0xE8;
    WS_WRITE(sfd, cp, (size_t)(hl + 2));
    g_ev = 2;
    for(int i = 0; i < 100; i++) {
        sevent_run_once(ctx);
        if(g_ev == 3)
            break;
    }
    if(g_ev != 3)
        return 1;
    close(sfd);
    sevent_ws_destroy(ws);
    sevent_destroy(ctx);
    return 0;
}

static int t_client_send_text(void) {
    sevent_context *ctx = sevent_create();
    if(!ctx)
        return 1;
    sevent_ws_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host    = "127.0.0.1";
    cfg.path    = "/";
    cfg.on_open = ev_open;
    g_ev        = 0;
    sevent_ws_conn *ws;
    int             sfd = pair(ctx, &cfg, &ws);
    if(sfd < 0)
        return 1;
    sevent_run_once(ctx);
    if(shake(sfd) < 0)
        return 1;
    for(int i = 0; i < 200; i++) {
        sevent_run_once(ctx);
        if(g_ev == 1)
            break;
    }
    if(g_ev != 1)
        return 1;
    if(sevent_ws_send_text(ws, "Hi", 2) != 0)
        return 1;
    ws_frame_header h;
    uint8_t         pay[128];
    if(wread(sfd, &h, pay, sizeof(pay)) < 1 || h.opcode != WS_OPCODE_TEXT || memcmp("Hi", pay, 2))
        return 1;
    close(sfd);
    sevent_ws_destroy(ws);
    sevent_destroy(ctx);
    return 0;
}

static int t_client_send_binary(void) {
    sevent_context *ctx = sevent_create();
    if(!ctx)
        return 1;
    sevent_ws_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host    = "127.0.0.1";
    cfg.path    = "/";
    cfg.on_open = ev_open;
    g_ev        = 0;
    sevent_ws_conn *ws;
    int             sfd = pair(ctx, &cfg, &ws);
    if(sfd < 0)
        return 1;
    sevent_run_once(ctx);
    if(shake(sfd) < 0)
        return 1;
    for(int i = 0; i < 200; i++) {
        sevent_run_once(ctx);
        if(g_ev == 1)
            break;
    }
    if(g_ev != 1)
        return 1;
    if(sevent_ws_send_binary(ws, "\x00\xFF\xAB", 3) != 0)
        return 1;
    ws_frame_header h;
    uint8_t         pay[128];
    if(wread(sfd, &h, pay, sizeof(pay)) < 1 || h.opcode != WS_OPCODE_BINARY)
        return 1;
    if(pay[0] != 0 || pay[1] != 0xFF || pay[2] != 0xAB)
        return 1;
    close(sfd);
    sevent_ws_destroy(ws);
    sevent_destroy(ctx);
    return 0;
}

static int t_auto_pong(void) {
    sevent_context *ctx = sevent_create();
    if(!ctx)
        return 1;
    sevent_ws_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host    = "127.0.0.1";
    cfg.path    = "/";
    cfg.on_open = ev_open;
    g_ev        = 0;
    sevent_ws_conn *ws;
    int             sfd = pair(ctx, &cfg, &ws);
    if(sfd < 0)
        return 1;
    sevent_run_once(ctx);
    if(shake(sfd) < 0)
        return 1;
    for(int i = 0; i < 200; i++) {
        sevent_run_once(ctx);
        if(g_ev == 1)
            break;
    }
    if(g_ev != 1)
        return 1;
    wsend(sfd, WS_OPCODE_PING, NULL, 0);
    ws_frame_header h;
    uint8_t         pay[128];
    int             pl = -1;
    for(int i = 0; i < 50; i++) {
        pl = wread(sfd, &h, pay, sizeof(pay));
        if(pl >= 0 && h.opcode == WS_OPCODE_PONG)
            break;
        sevent_run_once(ctx);
    }
    if(pl < 0 || h.opcode != WS_OPCODE_PONG)
        return 1;
    close(sfd);
    sevent_ws_destroy(ws);
    sevent_destroy(ctx);
    return 0;
}

static int t_on_pong(void) {
    /* 收到 PONG → on_pong 回调被触发 */
    sevent_context *ctx = sevent_create();
    if(!ctx) return 1;
    sevent_ws_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host    = "127.0.0.1";
    cfg.path    = "/";
    cfg.on_open = ev_open;
    cfg.on_pong = ev_pong;
    g_ev         = 0;
    g_pong_fired = 0;
    g_pong_len   = 0;
    sevent_ws_conn *ws;
    int             sfd = pair(ctx, &cfg, &ws);
    if(sfd < 0) return 1;
    sevent_run_once(ctx);
    if(shake(sfd) < 0) return 1;
    for(int i = 0; i < 200; i++) {
        sevent_run_once(ctx);
        if(g_ev == 1) break;
    }
    if(g_ev != 1) return 1;

    /* 服务端发 PONG (payload = "pongdata") */
    wsend(sfd, WS_OPCODE_PONG, "pongdata", 8);
    g_pong_fired = 0;
    for(int i = 0; i < 50; i++) {
        sevent_run_once(ctx);
        if(g_pong_fired) break;
    }
    if(!g_pong_fired) return 1;
    if(g_pong_len != 8 || strcmp(g_pong_payload, "pongdata") != 0) return 1;
    close(sfd);
    sevent_ws_destroy(ws);
    sevent_destroy(ctx);
    return 0;
}

static int t_large_msg(void) {
    sevent_context *ctx = sevent_create();
    if(!ctx)
        return 1;
    sevent_ws_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host       = "127.0.0.1";
    cfg.path       = "/";
    cfg.on_open    = ev_open;
    cfg.on_message = ev_msg;
    g_ev           = 0;
    sevent_ws_conn *ws;
    int             sfd = pair(ctx, &cfg, &ws);
    if(sfd < 0)
        return 1;
    sevent_run_once(ctx);
    if(shake(sfd) < 0)
        return 1;
    for(int i = 0; i < 200; i++) {
        sevent_run_once(ctx);
        if(g_ev == 1)
            break;
    }
    if(g_ev != 1)
        return 1;
    char big[200];
    memset(big, 'X', 200);
    wsend(sfd, WS_OPCODE_TEXT, big, 200);
    g_ev = 1;
    for(int i = 0; i < 50; i++) {
        sevent_run_once(ctx);
        if(g_ev == 2)
            break;
    }
    if(g_ev != 2 || strlen(g_msg) != 200 || g_last_total != 200)
        return 1;
    close(sfd);
    sevent_ws_destroy(ws);
    sevent_destroy(ctx);
    return 0;
}

static int t_client_ping(void) {
    sevent_context *ctx = sevent_create();
    if(!ctx)
        return 1;
    sevent_ws_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host    = "127.0.0.1";
    cfg.path    = "/";
    cfg.on_open = ev_open;
    g_ev        = 0;
    sevent_ws_conn *ws;
    int             sfd = pair(ctx, &cfg, &ws);
    if(sfd < 0)
        return 1;
    sevent_run_once(ctx);
    if(shake(sfd) < 0)
        return 1;
    for(int i = 0; i < 200; i++) {
        sevent_run_once(ctx);
        if(g_ev == 1)
            break;
    }
    if(g_ev != 1)
        return 1;
    if(sevent_ws_ping(ws, "ping", 4) != 0)
        return 1;
    ws_frame_header h;
    uint8_t         pay[128];
    if(wread(sfd, &h, pay, sizeof(pay)) < 0 || h.opcode != WS_OPCODE_PING)
        return 1;
    close(sfd);
    sevent_ws_destroy(ws);
    sevent_destroy(ctx);
    return 0;
}

static int t_client_close(void) {
    sevent_context *ctx = sevent_create();
    if(!ctx)
        return 1;
    sevent_ws_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host     = "127.0.0.1";
    cfg.path     = "/";
    cfg.on_open  = ev_open;
    cfg.on_close = ev_close;
    g_ev         = 0;
    sevent_ws_conn *ws;
    int             sfd = pair(ctx, &cfg, &ws);
    if(sfd < 0)
        return 1;
    sevent_run_once(ctx);
    if(shake(sfd) < 0)
        return 1;
    for(int i = 0; i < 200; i++) {
        sevent_run_once(ctx);
        if(g_ev == 1)
            break;
    }
    if(g_ev != 1)
        return 1;
    if(sevent_ws_close(ws, 1000, "bye") != 0)
        return 1;
    ws_frame_header h;
    uint8_t         pay[128];
    int             plen = wread(sfd, &h, pay, sizeof(pay));
    if(plen < 1 || h.opcode != WS_OPCODE_CLOSE)
        return 1;
    uint16_t code = (uint16_t)((pay[0] << 8) | pay[1]);
    if(code != 1000)
        return 1;
    uint8_t cp[8];
    int     hl = ws_frame_build_header(cp, 1, WS_OPCODE_CLOSE, NULL, 2);
    cp[hl]     = pay[0];
    cp[hl + 1] = pay[1];
    WS_WRITE(sfd, cp, (size_t)(hl + 2));
    g_ev = 2;
    for(int i = 0; i < 50; i++) {
        sevent_run_once(ctx);
        if(g_ev == 3)
            break;
    }
    if(g_ev != 3)
        return 1;
    close(sfd);
    sevent_ws_destroy(ws);
    sevent_destroy(ctx);
    return 0;
}

/* 分片测试 */
static int t_fragmentation(void) {
    sevent_context *ctx = sevent_create();
    if(!ctx)
        return 1;
    sevent_ws_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host        = "127.0.0.1";
    cfg.path        = "/";
    cfg.on_open     = ev_open;
    cfg.on_message  = ev_msg_frag;
    g_ev            = 0;
    g_frag_count    = 0;
    g_frag_last_fin = 0;
    g_frag_len      = 0;
    g_frag_total    = 0;
    sevent_ws_conn *ws;
    int             sfd = pair(ctx, &cfg, &ws);
    if(sfd < 0)
        return 1;
    sevent_run_once(ctx);
    if(shake(sfd) < 0)
        return 1;
    for(int i = 0; i < 200; i++) {
        sevent_run_once(ctx);
        if(g_ev == 1)
            break;
    }
    if(g_ev != 1)
        return 1;

    /* 服务端发 2 组分片: Text "Hel" (FIN=0) + "lo " (FIN=0) + "World" (FIN=1) */
    uint8_t b[128];
    int     hl;
    hl = ws_frame_build_header(b, 0, WS_OPCODE_TEXT, NULL, 3);
    memcpy(b + hl, "Hel", 3);
    WS_WRITE(sfd, b, (size_t)(hl + 3));
    hl = ws_frame_build_header(b, 0, WS_OPCODE_CONT, NULL, 3);
    memcpy(b + hl, "lo ", 3);
    WS_WRITE(sfd, b, (size_t)(hl + 3));
    hl = ws_frame_build_header(b, 1, WS_OPCODE_CONT, NULL, 5);
    memcpy(b + hl, "World", 5);
    WS_WRITE(sfd, b, (size_t)(hl + 5));

    /* 驱动 loop 处理所有分片 */
    sevent_timer *_tm = sevent_timer_register(ctx, 1, ev_tick, NULL);
    for(int i = 0; i < 500; i++) {
        sevent_run_once(ctx);
        if(g_ev == 2 && g_frag_count == 1)
            break;
    }
    if(_tm)
        sevent_timer_unregister(ctx, _tm);
    if(g_frag_count != 1 || g_frag_last_fin != 1 || g_frag_total != 11 || strcmp(g_msg, "Hello World"))
        return 1;

    close(sfd);
    sevent_ws_destroy(ws);
    sevent_destroy(ctx);
    return 0;
}

/* 大分片: 4 × 3000 字节 */
static int t_frag_large(void) {
    sevent_context *ctx = sevent_create();
    if(!ctx)
        return 1;
    sevent_ws_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host        = "127.0.0.1";
    cfg.path        = "/";
    cfg.on_open     = ev_open;
    cfg.on_message  = ev_msg_frag;
    g_ev            = 0;
    g_frag_count    = 0;
    g_frag_last_fin = 0;
    g_frag_len      = 0;
    g_frag_total    = 0;
    sevent_ws_conn *ws;
    int             sfd = pair(ctx, &cfg, &ws);
    if(sfd < 0)
        return 1;
    sevent_run_once(ctx);
    if(shake(sfd) < 0)
        return 1;
    for(int i = 0; i < 200; i++) {
        sevent_run_once(ctx);
        if(g_ev == 1)
            break;
    }
    if(g_ev != 1)
        return 1;

    uint8_t buf[4096];
    int     hl;
    char    blk[3000];
    memset(blk, 'A', 3000);
    for(int i = 0; i < 3; i++) {
        hl = ws_frame_build_header(buf, 0, i ? WS_OPCODE_CONT : WS_OPCODE_TEXT, NULL, 3000);
        memcpy(buf + hl, blk, 3000);
        write_all(sfd, buf, (size_t)(hl + 3000));
    }
    hl = ws_frame_build_header(buf, 1, WS_OPCODE_CONT, NULL, 3000);
    memcpy(buf + hl, blk, 3000);
    write_all(sfd, buf, (size_t)(hl + 3000));

    sevent_timer *_tm = sevent_timer_register(ctx, 1, ev_tick, NULL);
    for(int i = 0; i < 500; i++) {
        sevent_run_once(ctx);
        if(g_frag_count == 4)
            break;
    }
    if(_tm)
        sevent_timer_unregister(ctx, _tm);
    if(g_frag_count != 4 || g_frag_last_fin != 1 || g_frag_total != 12000)
        return 1;
    close(sfd);
    sevent_ws_destroy(ws);
    sevent_destroy(ctx);
    return 0;
}

/* 多分片: 50 × 1 字节 */
static int t_frag_many(void) {
    sevent_context *ctx = sevent_create();
    if(!ctx)
        return 1;
    sevent_ws_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host        = "127.0.0.1";
    cfg.path        = "/";
    cfg.on_open     = ev_open;
    cfg.on_message  = ev_msg_frag;
    g_ev            = 0;
    g_frag_count    = 0;
    g_frag_last_fin = 0;
    g_frag_len      = 0;
    g_frag_total    = 0;
    sevent_ws_conn *ws;
    int             sfd = pair(ctx, &cfg, &ws);
    if(sfd < 0)
        return 1;
    sevent_run_once(ctx);
    if(shake(sfd) < 0)
        return 1;
    for(int i = 0; i < 200; i++) {
        sevent_run_once(ctx);
        if(g_ev == 1)
            break;
    }
    if(g_ev != 1)
        return 1;

    uint8_t buf[16];
    int     hl;
    for(int i = 0; i < 49; i++) {
        hl      = ws_frame_build_header(buf, 0, i ? WS_OPCODE_CONT : WS_OPCODE_TEXT, NULL, 1);
        buf[hl] = (uint8_t)('a' + (i % 26));
        write_all(sfd, buf, (size_t)(hl + 1));
    }
    hl      = ws_frame_build_header(buf, 1, WS_OPCODE_CONT, NULL, 1);
    buf[hl] = '!';
    write_all(sfd, buf, (size_t)(hl + 1));

    sevent_timer *_tm = sevent_timer_register(ctx, 1, ev_tick, NULL);
    for(int i = 0; i < 500; i++) {
        sevent_run_once(ctx);
        if(g_frag_count == 1)
            break;
    }
    if(_tm)
        sevent_timer_unregister(ctx, _tm);
    if(g_frag_count != 1 || g_frag_last_fin != 1 || g_frag_total != 50)
        return 1;
    close(sfd);
    sevent_ws_destroy(ws);
    sevent_destroy(ctx);
    return 0;
}

/* PING 穿插分片间 */
static int t_frag_interleave(void) {
    sevent_context *ctx = sevent_create();
    if(!ctx)
        return 1;
    sevent_ws_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host        = "127.0.0.1";
    cfg.path        = "/";
    cfg.on_open     = ev_open;
    cfg.on_message  = ev_msg_frag;
    g_ev            = 0;
    g_frag_count    = 0;
    g_frag_last_fin = 0;
    g_frag_len      = 0;
    g_frag_total    = 0;
    sevent_ws_conn *ws;
    int             sfd = pair(ctx, &cfg, &ws);
    if(sfd < 0)
        return 1;
    sevent_run_once(ctx);
    if(shake(sfd) < 0)
        return 1;
    for(int i = 0; i < 200; i++) {
        sevent_run_once(ctx);
        if(g_ev == 1)
            break;
    }
    if(g_ev != 1)
        return 1;

    uint8_t b[128];
    int     hl;
    hl = ws_frame_build_header(b, 0, WS_OPCODE_TEXT, NULL, 5);
    memcpy(b + hl, "Hello", 5);
    write_all(sfd, b, (size_t)(hl + 5));
    hl = ws_frame_build_header(b, 1, WS_OPCODE_PING, NULL, 4);
    memcpy(b + hl, "ping", 4);
    write_all(sfd, b, (size_t)(hl + 4));
    hl = ws_frame_build_header(b, 0, WS_OPCODE_CONT, NULL, 3);
    memcpy(b + hl, " wo", 3);
    write_all(sfd, b, (size_t)(hl + 3));
    hl = ws_frame_build_header(b, 1, WS_OPCODE_CONT, NULL, 4);
    memcpy(b + hl, "rld\n", 4);
    write_all(sfd, b, (size_t)(hl + 4));

    sevent_timer *_tm = sevent_timer_register(ctx, 1, ev_tick, NULL);
    for(int i = 0; i < 500; i++) {
        sevent_run_once(ctx);
        if(g_frag_count == 1)
            break;
    }
    if(_tm)
        sevent_timer_unregister(ctx, _tm);
    if(g_frag_count != 1 || g_frag_last_fin != 1 || g_frag_total != 12)
        return 1;
    close(sfd);
    sevent_ws_destroy(ws);
    sevent_destroy(ctx);
    return 0;
}

/* 协议错误: 无 pendding 时收到 CONTINUATION */
static int t_frag_proto_error(void) {
    sevent_context *ctx = sevent_create();
    if(!ctx)
        return 1;
    sevent_ws_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host     = "127.0.0.1";
    cfg.path     = "/";
    cfg.on_open  = ev_open;
    cfg.on_error = ev_error;
    g_ev         = 0;
    sevent_ws_conn *ws;
    int             sfd = pair(ctx, &cfg, &ws);
    if(sfd < 0)
        return 1;
    sevent_run_once(ctx);
    if(shake(sfd) < 0)
        return 1;
    for(int i = 0; i < 200; i++) {
        sevent_run_once(ctx);
        if(g_ev == 1)
            break;
    }
    if(g_ev != 1)
        return 1;

    uint8_t b[16];
    int     hl = ws_frame_build_header(b, 1, WS_OPCODE_CONT, NULL, 3);
    memcpy(b + hl, "abc", 3);
    write_all(sfd, b, (size_t)(hl + 3));

    sevent_timer *_tm = sevent_timer_register(ctx, 1, ev_tick, NULL);
    for(int i = 0; i < 100; i++) {
        sevent_run_once(ctx);
        if(g_ev == 3)
            break;
    }
    if(_tm)
        sevent_timer_unregister(ctx, _tm);
    if(g_ev != 3)
        return 1;
    close(sfd);
    sevent_ws_destroy(ws);
    sevent_destroy(ctx);
    return 0;
}

/* HTTP 101 + WS 帧粘包测试 */
static int t_sticky_packet(void) {
    sevent_context *ctx = sevent_create();
    if(!ctx)
        return 1;
    sevent_ws_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host       = "127.0.0.1";
    cfg.path       = "/";
    cfg.on_open    = ev_open;
    cfg.on_message = ev_msg;
    g_ev           = 0;
    g_msg[0]       = 0;
    sevent_ws_conn *ws;
    int             sfd = pair(ctx, &cfg, &ws);
    if(sfd < 0)
        return 1;
    sevent_run_once(ctx);

    /* 读 HTTP 请求 */
    char    req[4096];
    ssize_t rn = read(sfd, req, sizeof(req) - 1);
    if(rn <= 0)
        return 1;
    req[rn] = 0;
    /* 提取 key */
    char *k = strstr(req, "Sec-WebSocket-Key:");
    if(!k)
        return 1;
    k += 19;
    while(*k == ' ')
        k++;
    char *e = strstr(k, "\r\n");
    if(!e)
        return 1;
    size_t kl = (size_t)(e - k);
    if(kl > 255)
        kl = 255;
    char ke[256];
    memcpy(ke, k, kl);
    ke[kl] = 0;
    /* 计算 accept */
    char cat[384];
    snprintf(cat, sizeof(cat), "%s%s", ke, WS_GUID);
    uint8_t dg[20];
    ws_sha1(cat, strlen(cat), dg);
    char ac[64];
    ws_base64_encode(dg, 20, ac, sizeof(ac));
    /* 构造 HTTP 101 + WS TEXT 帧粘包 */
    char    resp[1024];
    int     resp_len = snprintf(resp,
                            sizeof(resp),
                            "HTTP/1.1 101 Switching Protocols\r\n"
                                "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                                "Sec-WebSocket-Accept: %s\r\n\r\n",
                            ac);
    uint8_t wsf[16];
    int     hl = ws_frame_build_header(wsf, 1, WS_OPCODE_TEXT, NULL, 5);
    memcpy(wsf + hl, "Stick", 5);
    memcpy(resp + resp_len, wsf, (size_t)(hl + 5)); /* HTTP + WS 拼在一起 */
    write_all(sfd, resp, (size_t)(resp_len + hl + 5));

    /* 驱动 loop — 握手成功后 WS 帧应自动被解析 */
    sevent_timer *_tm = sevent_timer_register(ctx, 1, ev_tick, NULL);
    for(int i = 0; i < 500; i++) {
        sevent_run_once(ctx);
        if(g_ev == 2)
            break;
    }
    if(_tm)
        sevent_timer_unregister(ctx, _tm);
    if(g_ev != 2 || strcmp(g_msg, "Stick") || g_last_total != 5)
        return 1;

    close(sfd);
    sevent_ws_destroy(ws);
    sevent_destroy(ctx);
    return 0;
}

/* HTTP 非 101 响应测试: 验证 on_http_response 触发 */
static int t_http_fail(void) {
    sevent_context *ctx = sevent_create();
    if(!ctx)
        return 1;
    sevent_ws_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host             = "127.0.0.1";
    cfg.path             = "/";
    cfg.on_open          = ev_open;
    cfg.on_http_response = ev_http_resp;
    g_ev                 = 0;
    g_http_status        = 0;
    sevent_ws_conn *ws;
    int             sfd = pair(ctx, &cfg, &ws);
    if(sfd < 0)
        return 1;
    sevent_run_once(ctx);
    /* 读 HTTP 请求, 回 404 */
    char    req[4096];
    ssize_t rn = read(sfd, req, sizeof(req) - 1);
    if(rn <= 0)
        return 1;
    char resp[] = "HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nNot Found";
    write_all(sfd, resp, strlen(resp));
    /* 驱动 — on_http_response 应被调用 */
    sevent_timer *_tm = sevent_timer_register(ctx, 1, ev_tick, NULL);
    for(int i = 0; i < 500; i++) {
        sevent_run_once(ctx);
        if(g_ev == 4)
            break;
    }
    if(_tm)
        sevent_timer_unregister(ctx, _tm);
    if(g_ev != 4 || g_http_status != 404)
        return 1;
    close(sfd);
    sevent_ws_destroy(ws);
    sevent_destroy(ctx);
    return 0;
}

static int t_http_fail_with_body(void) {
    /* 升级失败, 验证 on_http_response 能拿到 body */
    sevent_context *ctx = sevent_create();
    if(!ctx) return 1;
    sevent_ws_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host             = "127.0.0.1";
    cfg.path             = "/";
    cfg.on_open          = ev_open;
    cfg.on_http_response = ev_http_resp;
    g_ev                 = 0;
    g_http_status        = 0;
    g_http_body[0]       = 0;
    g_http_body_len      = 0;
    sevent_ws_conn *ws;
    int             sfd = pair(ctx, &cfg, &ws);
    if(sfd < 0) return 1;
    sevent_run_once(ctx);
    char    req[4096];
    ssize_t rn = read(sfd, req, sizeof(req) - 1);
    if(rn <= 0) return 1;
    char resp[] = "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello";
    write_all(sfd, resp, strlen(resp));
    sevent_timer *_tm = sevent_timer_register(ctx, 1, ev_tick, NULL);
    for(int i = 0; i < 500; i++) {
        sevent_run_once(ctx);
        if(g_ev == 4) break;
    }
    if(_tm) sevent_timer_unregister(ctx, _tm);
    if(g_ev != 4 || g_http_status != 400) return 1;
    if(g_http_body_len != 5 || strcmp(g_http_body, "hello") != 0) return 1;
    close(sfd);
    sevent_ws_destroy(ws);
    sevent_destroy(ctx);
    return 0;
}

/* 多帧粘包: 两次 TEXT 帧同一次 read */
static int t_sticky_multi_frame(void) {
    sevent_context *ctx = sevent_create();
    if(!ctx)
        return 1;
    sevent_ws_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host       = "127.0.0.1";
    cfg.path       = "/";
    cfg.on_open    = ev_open;
    cfg.on_message = ev_msg_count;
    g_ev           = 0;
    g_call_count   = 0;
    g_frag_total   = 0;
    g_frag_len     = 0;
    g_msg[0]       = 0;
    sevent_ws_conn *ws;
    int             sfd = pair(ctx, &cfg, &ws);
    if(sfd < 0)
        return 1;
    sevent_run_once(ctx);
    if(shake(sfd) < 0)
        return 1;
    for(int i = 0; i < 200; i++) {
        sevent_run_once(ctx);
        if(g_ev == 1)
            break;
    }
    if(g_ev != 1)
        return 1;
    /* 一次写入 2 帧: "Hello" + "WS" */
    uint8_t b[64];
    int     off = 0, hl;
    hl          = ws_frame_build_header(b + off, 1, WS_OPCODE_TEXT, NULL, 5);
    memcpy(b + off + hl, "Hello", 5);
    off += hl + 5;
    hl  = ws_frame_build_header(b + off, 1, WS_OPCODE_TEXT, NULL, 2);
    memcpy(b + off + hl, "WS", 2);
    off += hl + 2;
    write_all(sfd, b, off);
    sevent_timer *_tm = sevent_timer_register(ctx, 1, ev_tick, NULL);
    for(int i = 0; i < 500; i++) {
        sevent_run_once(ctx);
        if(g_call_count == 2)
            break;
    }
    if(_tm)
        sevent_timer_unregister(ctx, _tm);
    if(g_call_count != 2 || g_last_total != 2)
        return 1;
    close(sfd);
    sevent_ws_destroy(ws);
    sevent_destroy(ctx);
    return 0;
}

/* 大流帧 + 小帧粘包: >recv_cap 帧流完后紧跟 TEXT */
static int t_sticky_stream_tail(void) {
    sevent_context *ctx = sevent_create();
    if(!ctx)
        return 1;
    sevent_ws_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host          = "127.0.0.1";
    cfg.path          = "/";
    cfg.on_open       = ev_open;
    cfg.on_message    = ev_msg_count;
    cfg.recv_buf_size = 4096;
    g_ev              = 0;
    g_call_count      = 0;
    g_frag_total      = 0;
    g_frag_len        = 0;
    g_msg[0]          = 0;
    sevent_ws_conn *ws;
    int             sfd = pair(ctx, &cfg, &ws);
    if(sfd < 0)
        return 1;
    sevent_run_once(ctx);
    if(shake(sfd) < 0)
        return 1;
    for(int i = 0; i < 200; i++) {
        sevent_run_once(ctx);
        if(g_ev == 1)
            break;
    }
    if(g_ev != 1)
        return 1;
    /* 大帧 5000 字节 + 小帧 "Tail" */
    uint8_t b[8192];
    int     off = 0, hl;
    char    big[5000];
    memset(big, 'X', 5000);
    hl = ws_frame_build_header(b + off, 1, WS_OPCODE_TEXT, NULL, 5000);
    memcpy(b + off + hl, big, 5000);
    off += hl + 5000;
    hl  = ws_frame_build_header(b + off, 1, WS_OPCODE_TEXT, NULL, 4);
    memcpy(b + off + hl, "Tail", 4);
    off += hl + 4;
    write_all(sfd, b, off);
    /* recv_cap=4096, 大帧触发流式: 4096+904 两段, 然后紧跟小帧 */
    sevent_timer *_tm = sevent_timer_register(ctx, 1, ev_tick, NULL);
    for(int i = 0; i < 1000; i++) {
        sevent_run_once(ctx);
        if(g_call_count == 3)
            break;
    }
    if(_tm)
        sevent_timer_unregister(ctx, _tm);
    if(g_call_count != 3 || g_frag_total != 5004 || g_last_total != 4)
        return 1;
    close(sfd);
    sevent_ws_destroy(ws);
    sevent_destroy(ctx);
    return 0;
}

/* 大帧流式 total 验证: 单帧 5000 字节 > recv_cap, 每块 total=5000 */
static int t_stream_total(void) {
    sevent_context *ctx = sevent_create();
    if(!ctx)
        return 1;
    sevent_ws_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host          = "127.0.0.1";
    cfg.path          = "/";
    cfg.on_open       = ev_open;
    cfg.on_message    = ev_msg_count;
    cfg.recv_buf_size = 4096;
    g_ev              = 0;
    g_call_count      = 0;
    g_frag_len        = 0;
    g_frag_total      = 0;
    g_msg[0]          = 0;
    sevent_ws_conn *ws;
    int             sfd = pair(ctx, &cfg, &ws);
    if(sfd < 0)
        return 1;
    sevent_run_once(ctx);
    if(shake(sfd) < 0)
        return 1;
    for(int i = 0; i < 200; i++) {
        sevent_run_once(ctx);
        if(g_ev == 1)
            break;
    }
    if(g_ev != 1)
        return 1;
    /* 单帧 5000 字节 */
    uint8_t b[8192];
    char    big[5000];
    memset(big, 'X', 5000);
    int hl = ws_frame_build_header(b, 1, WS_OPCODE_TEXT, NULL, 5000);
    memcpy(b + hl, big, 5000);
    write_all(sfd, b, (size_t)(hl + 5000));
    /* 驱动 — 流式分块, 每块 total 应为 5000 */
    sevent_timer *_tm = sevent_timer_register(ctx, 1, ev_tick, NULL);
    for(int i = 0; i < 1000; i++) {
        sevent_run_once(ctx);
        if(g_call_count == 2)
            break;
    }
    if(_tm)
        sevent_timer_unregister(ctx, _tm);
    if(g_call_count != 2 || g_last_total != 5000)
        return 1;
    close(sfd);
    sevent_ws_destroy(ws);
    sevent_destroy(ctx);
    return 0;
}

/* 分包: 一帧分两次 read 收完 */
static int t_split_frame(void) {
    sevent_context *ctx = sevent_create();
    if(!ctx)
        return 1;
    sevent_ws_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host       = "127.0.0.1";
    cfg.path       = "/";
    cfg.on_open    = ev_open;
    cfg.on_message = ev_msg;
    g_ev           = 0;
    g_msg[0]       = 0;
    sevent_ws_conn *ws;
    int             sfd = pair(ctx, &cfg, &ws);
    if(sfd < 0)
        return 1;
    sevent_run_once(ctx);
    if(shake(sfd) < 0)
        return 1;
    for(int i = 0; i < 200; i++) {
        sevent_run_once(ctx);
        if(g_ev == 1)
            break;
    }
    if(g_ev != 1)
        return 1;
    /* 只发帧头 + 部分 payload (2/5 字节) */
    uint8_t b[64];
    int     hl = ws_frame_build_header(b, 1, WS_OPCODE_TEXT, NULL, 5);
    memcpy(b + hl, "He", 2);
    write_all(sfd, b, (size_t)(hl + 2));
    /* 驱动 — 数据不足, process_frames 应 break 等待 */
    {
        sevent_timer *_t2 = sevent_timer_register(ctx, 1, ev_tick, NULL);
        for(int i = 0; i < 10; i++) {
            sevent_run_once(ctx);
            if(g_ev == 2)
                break;
        }
        if(_t2)
            sevent_timer_unregister(ctx, _t2);
    }
    if(g_ev == 2)
        return 1; /* 不可能已回调 */
    /* 补充剩余 payload */
    memcpy(b, "llo", 3);
    write_all(sfd, b, 3);
    sevent_timer *_tm = sevent_timer_register(ctx, 1, ev_tick, NULL);
    for(int i = 0; i < 500; i++) {
        sevent_run_once(ctx);
        if(g_ev == 2)
            break;
    }
    if(_tm)
        sevent_timer_unregister(ctx, _tm);
    if(g_ev != 2 || strcmp(g_msg, "Hello") || g_last_total != 5)
        return 1;
    close(sfd);
    sevent_ws_destroy(ws);
    sevent_destroy(ctx);
    return 0;
}

/* 完整帧 + 不完整帧粘包 */
static int t_sticky_partial(void) {
    sevent_context *ctx = sevent_create();
    if(!ctx)
        return 1;
    sevent_ws_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host       = "127.0.0.1";
    cfg.path       = "/";
    cfg.on_open    = ev_open;
    cfg.on_message = ev_msg;
    g_ev           = 0;
    g_msg[0]       = 0;
    sevent_ws_conn *ws;
    int             sfd = pair(ctx, &cfg, &ws);
    if(sfd < 0)
        return 1;
    sevent_run_once(ctx);
    if(shake(sfd) < 0)
        return 1;
    for(int i = 0; i < 200; i++) {
        sevent_run_once(ctx);
        if(g_ev == 1)
            break;
    }
    if(g_ev != 1)
        return 1;
    /* 完整帧 "Full" + 不完整帧 "Partial!" 只发帧头+2 payload */
    uint8_t b[128];
    int     off = 0, hl;
    hl          = ws_frame_build_header(b + off, 1, WS_OPCODE_TEXT, NULL, 4);
    memcpy(b + off + hl, "Full", 4);
    off += hl + 4;
    hl  = ws_frame_build_header(b + off, 1, WS_OPCODE_TEXT, NULL, 8);
    memcpy(b + off + hl, "Pa", 2);
    off += hl + 2;
    write_all(sfd, b, off);
    /* 第一帧完整应被处理, 第二帧等待 */
    sevent_timer *_tm = sevent_timer_register(ctx, 1, ev_tick, NULL);
    for(int i = 0; i < 500; i++) {
        sevent_run_once(ctx);
        if(g_ev == 2)
            break;
    }
    if(_tm)
        sevent_timer_unregister(ctx, _tm);
    if(g_ev != 2 || strcmp(g_msg, "Full") || g_last_total != 4)
        return 1;
    /* 补充第二帧剩余 */
    g_ev = 0;
    memcpy(b, "rtial!", 6);
    write_all(sfd, b, 6);
    _tm = sevent_timer_register(ctx, 1, ev_tick, NULL);
    for(int i = 0; i < 500; i++) {
        sevent_run_once(ctx);
        if(g_ev == 2)
            break;
    }
    if(_tm)
        sevent_timer_unregister(ctx, _tm);
    if(g_ev != 2 || strcmp(g_msg, "Partial!") || g_last_total != 8)
        return 1;
    close(sfd);
    sevent_ws_destroy(ws);
    sevent_destroy(ctx);
    return 0;
}

/* 分片跨 read 边界: 分片 1 先到, 分片 2/3 后到 */
static int t_frag_split_read(void) {
    sevent_context *ctx = sevent_create();
    if(!ctx)
        return 1;
    sevent_ws_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host       = "127.0.0.1";
    cfg.path       = "/";
    cfg.on_open    = ev_open;
    cfg.on_message = ev_msg_count;
    g_ev           = 0;
    g_call_count   = 0;
    g_frag_total   = 0;
    g_frag_len     = 0;
    g_msg[0]       = 0;
    sevent_ws_conn *ws;
    int             sfd = pair(ctx, &cfg, &ws);
    if(sfd < 0)
        return 1;
    sevent_run_once(ctx);
    if(shake(sfd) < 0)
        return 1;
    for(int i = 0; i < 200; i++) {
        sevent_run_once(ctx);
        if(g_ev == 1)
            break;
    }
    if(g_ev != 1)
        return 1;
    /* 分片 1: "Hel" (FIN=0) */
    uint8_t b[64];
    int     hl = ws_frame_build_header(b, 0, WS_OPCODE_TEXT, NULL, 3);
    memcpy(b + hl, "Hel", 3);
    write_all(sfd, b, (size_t)(hl + 3));
    /* 等它被处理 (frag_pending=1 但还没完成) */
    {
        sevent_timer *_t2 = sevent_timer_register(ctx, 1, ev_tick, NULL);
        for(int i = 0; i < 10; i++) {
            sevent_run_once(ctx);
            if(g_call_count > 0)
                break;
        }
        if(_t2)
            sevent_timer_unregister(ctx, _t2);
    }
    /* 分片 2 + 3: "lo " (FIN=0) + "World" (FIN=1) */
    hl = ws_frame_build_header(b, 0, WS_OPCODE_CONT, NULL, 3);
    memcpy(b + hl, "lo ", 3);
    write_all(sfd, b, (size_t)(hl + 3));
    hl = ws_frame_build_header(b, 1, WS_OPCODE_CONT, NULL, 5);
    memcpy(b + hl, "World", 5);
    write_all(sfd, b, (size_t)(hl + 5));
    sevent_timer *_tm = sevent_timer_register(ctx, 1, ev_tick, NULL);
    for(int i = 0; i < 500; i++) {
        sevent_run_once(ctx);
        if(g_call_count == 1)
            break;
    }
    if(_tm)
        sevent_timer_unregister(ctx, _tm);
    if(g_call_count != 1 || g_frag_total != 11 || g_last_total != 11 || strcmp(g_msg, "Hello World"))
        return 1;
    close(sfd);
    sevent_ws_destroy(ws);
    sevent_destroy(ctx);
    return 0;
}

static int t_state_checks(void) {
    sevent_context *ctx = sevent_create();
    if(!ctx)
        return 1;
    int fds[2];
    if(socketpair(AF_UNIX, SOCK_STREAM, 0, fds))
        return 1;
    struct sevent_ws_conn *c = calloc(1, sizeof(*c));
    if(!c)
        return 1;
    c->ev    = ctx;
    c->fd    = fds[1];
    c->state = 4; /* WS_STATE_CLOSED */
    if(sevent_ws_send_text(c, "x", 1) != -1)
        return 1;
    if(sevent_ws_send_binary(c, "x", 1) != -1)
        return 1;
    if(sevent_ws_ping(c, NULL, 0) != -1)
        return 1;
    if(sevent_ws_close(c, 1000, "") != -1)
        return 1;
    c->state = 0; /* CONNECTING */
    if(sevent_ws_send_text(c, "x", 1) != -1)
        return 1;
    close(fds[0]);
    c->fd = -1;
    sevent_ws_destroy(c);
    sevent_destroy(ctx);
    return 0;
}

#ifdef SEVENT_WS_THREAD_SAFE
struct thr_arg {
    sevent_ws_conn *ws;
    int             result;
};

static void *thr_send_text(void *a) {
    struct thr_arg *ta = (struct thr_arg *)a;
    ta->result         = sevent_ws_send_text(ta->ws, "cross", 5);
    return NULL;
}

static void *thr_close(void *a) {
    struct thr_arg *ta = (struct thr_arg *)a;
    ta->result         = sevent_ws_close(ta->ws, 1000, "");
    return NULL;
}

/* 跨线程 send_text: 从工作线程调用, 验证数据到达 */
static int t_cross_thread_send(void) {
    sevent_context *ctx = sevent_create();
    if(!ctx)
        return 1;
    sevent_ws_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host       = "127.0.0.1";
    cfg.path       = "/";
    cfg.on_open    = ev_open;
    cfg.on_message = ev_msg;
    g_ev           = 0;
    sevent_ws_conn *ws;
    int             sfd = pair(ctx, &cfg, &ws);
    if(sfd < 0)
        return 1;
    sevent_run_once(ctx);
    if(shake(sfd) < 0)
        return 1;
    for(int i = 0; i < 200; i++) {
        sevent_run_once(ctx);
        if(g_ev == 1)
            break;
    }
    if(g_ev != 1)
        return 1;

    struct thr_arg a = {ws, -1};
    pthread_t      thr;
    if(pthread_create(&thr, NULL, thr_send_text, &a) != 0)
        return 1;
    pthread_join(thr, NULL);
    if(a.result != 0)
        return 1;

    /* 读服务端收到的帧 */
    ws_frame_header h;
    uint8_t         pay[128];
    int             pl = -1;
    for(int i = 0; i < 50; i++) {
        pl = wread(sfd, &h, pay, sizeof(pay));
        if(pl >= 0)
            break;
        sevent_run_once(ctx);
    }
    if(pl < 1 || h.opcode != WS_OPCODE_TEXT || memcmp(pay, "cross", 5))
        return 1;

    close(sfd);
    sevent_ws_destroy(ws);
    sevent_destroy(ctx);
    return 0;
}

/* 跨线程 close: 从工作线程调用, 验证 on_close 触发 */
static int t_cross_thread_close(void) {
    sevent_context *ctx = sevent_create();
    if(!ctx)
        return 1;
    sevent_ws_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host     = "127.0.0.1";
    cfg.path     = "/";
    cfg.on_open  = ev_open;
    cfg.on_close = ev_close;
    g_ev         = 0;
    sevent_ws_conn *ws;
    int             sfd = pair(ctx, &cfg, &ws);
    if(sfd < 0)
        return 1;
    sevent_run_once(ctx);
    if(shake(sfd) < 0)
        return 1;
    for(int i = 0; i < 200; i++) {
        sevent_run_once(ctx);
        if(g_ev == 1)
            break;
    }
    if(g_ev != 1)
        return 1;

    struct thr_arg a = {ws, -1};
    pthread_t      thr;
    if(pthread_create(&thr, NULL, thr_close, &a) != 0)
        return 1;
    pthread_join(thr, NULL);
    if(a.result != 0)
        return 1;

    /* 读服务端收到的 Close 帧 */
    ws_frame_header h;
    uint8_t         pay[128];
    int             pl = -1;
    for(int i = 0; i < 50; i++) {
        pl = wread(sfd, &h, pay, sizeof(pay));
        if(pl >= 0)
            break;
        sevent_run_once(ctx);
    }
    if(pl < 1 || h.opcode != WS_OPCODE_CLOSE)
        return 1;

    /* 回 Close 帧 */
    uint8_t cp[4];
    int     hl = ws_frame_build_header(cp, 1, WS_OPCODE_CLOSE, NULL, 2);
    cp[hl]     = pay[0];
    cp[hl + 1] = pay[1];
    WS_WRITE(sfd, cp, (size_t)(hl + 2));
    g_ev = 2;
    for(int i = 0; i < 50; i++) {
        sevent_run_once(ctx);
        if(g_ev == 3)
            break;
    }
    if(g_ev != 3)
        return 1;

    close(sfd);
    sevent_ws_destroy(ws);
    sevent_destroy(ctx);
    return 0;
}
#else
static int t_cross_thread_send(void) { return 0; }
static int t_cross_thread_close(void) { return 0; }
#endif

/* ==================== 协议校验测试 ==================== */

static int t_recv_invalid_control_payload(void) {
    /* 模拟对端发送 payload > 125 的 PING → on_error 触发 */
    sevent_context *ctx = sevent_create();
    if(!ctx) return 1;
    sevent_ws_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host     = "127.0.0.1";
    cfg.path     = "/";
    cfg.on_open  = ev_open;
    cfg.on_error = ev_error;
    g_ev         = 0;
    sevent_ws_conn *ws;
    int sfd = pair(ctx, &cfg, &ws);
    if(sfd < 0) return 1;
    sevent_run_once(ctx);
    if(shake(sfd) < 0) return 1;
    for(int i = 0; i < 200; i++) {
        sevent_run_once(ctx);
        if(g_ev == 1) break;
    }
    if(g_ev != 1) return 1;

    /* 构造 PING 帧 payload = 200 字节 > 125 */
    uint8_t ping_pay[200];
    memset(ping_pay, 'p', sizeof(ping_pay));
    uint8_t hdr[16];
    int hl = ws_frame_build_header(hdr, 0, WS_OPCODE_PING, NULL, sizeof(ping_pay));
    if(hl < 0) return 1;
    uint8_t *raw = malloc((size_t)hl + sizeof(ping_pay));
    memcpy(raw, hdr, (size_t)hl);
    memcpy(raw + hl, ping_pay, sizeof(ping_pay));
    write_all(sfd, raw, (size_t)hl + sizeof(ping_pay));
    free(raw);

    g_ev = 0;
    sevent_timer *_tm = sevent_timer_register(ctx, 1, ev_tick, NULL);
    for(int i = 0; i < 100; i++) {
        sevent_run_once(ctx);
        if(g_ev == 3) break; /* on_error 触发 */
    }
    if(_tm) sevent_timer_unregister(ctx, _tm);
    if(g_ev != 3) return 1;
    close(sfd);
    sevent_ws_destroy(ws);
    sevent_destroy(ctx);
    return 0;
}

static int t_recv_invalid_close_code(void) {
    /* 模拟对端发送非法 Close 码 → on_error 触发 */
    sevent_context *ctx = sevent_create();
    if(!ctx) return 1;
    sevent_ws_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host     = "127.0.0.1";
    cfg.path     = "/";
    cfg.on_open  = ev_open;
    cfg.on_error = ev_error;
    g_ev         = 0;
    sevent_ws_conn *ws;
    int sfd = pair(ctx, &cfg, &ws);
    if(sfd < 0) return 1;
    sevent_run_once(ctx);
    if(shake(sfd) < 0) return 1;
    for(int i = 0; i < 200; i++) {
        sevent_run_once(ctx);
        if(g_ev == 1) break;
    }
    if(g_ev != 1) return 1;

    /* 构造 CLOSE 帧 payload = 非法码 999 */
    uint8_t cp[2] = {0x03, 0xE7}; /* 999 */
    uint8_t hdr[16];
    int hl = ws_frame_build_header(hdr, 0, WS_OPCODE_CLOSE, NULL, 2);
    if(hl < 0) return 1;
    uint8_t *raw = malloc((size_t)hl + 2);
    memcpy(raw, hdr, (size_t)hl);
    memcpy(raw + hl, cp, 2);
    write_all(sfd, raw, (size_t)hl + 2);
    free(raw);

    g_ev = 0;
    sevent_timer *_tm = sevent_timer_register(ctx, 1, ev_tick, NULL);
    for(int i = 0; i < 100; i++) {
        sevent_run_once(ctx);
        if(g_ev == 3) break; /* on_error 触发 */
    }
    if(_tm) sevent_timer_unregister(ctx, _tm);
    if(g_ev != 3) return 1;
    close(sfd);
    sevent_ws_destroy(ws);
    sevent_destroy(ctx);
    return 0;
}

static int t_invalid_ping_payload(void) {
    /* RFC 6455 §5.5: 控制帧 payload 不得超过 125 */
    sevent_context *ctx = sevent_create();
    if(!ctx) return 1;
    sevent_ws_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host    = "127.0.0.1";
    cfg.path    = "/";
    cfg.on_open = ev_open;
    g_ev        = 0;
    sevent_ws_conn *ws;
    int sfd = pair(ctx, &cfg, &ws);
    if(sfd < 0) return 1;
    sevent_run_once(ctx);
    if(shake(sfd) < 0) return 1;
    for(int i = 0; i < 200; i++) {
        sevent_run_once(ctx);
        if(g_ev == 1) break;
    }
    if(g_ev != 1) return 1;

    /* ping payload > 125 → 应拒绝 */
    uint8_t big[200];
    memset(big, 'x', sizeof(big));
    if(sevent_ws_ping(ws, big, sizeof(big)) != SEVENT_ERR_INVAL) return 1;

    /* 短 ping → 应正常 */
    if(sevent_ws_ping(ws, "ok", 2) != 0) return 1;

    close(sfd);
    sevent_ws_destroy(ws);
    sevent_destroy(ctx);
    return 0;
}

static int t_invalid_close_code(void) {
    /* RFC 6455 §7.4: 非法 Close 码 → send_frame 拒绝 */
    sevent_context *ctx = sevent_create();
    if(!ctx) return 1;
    sevent_ws_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host    = "127.0.0.1";
    cfg.path    = "/";
    cfg.on_open = ev_open;
    g_ev        = 0;
    sevent_ws_conn *ws;
    int sfd = pair(ctx, &cfg, &ws);
    if(sfd < 0) return 1;
    sevent_run_once(ctx);
    if(shake(sfd) < 0) return 1;
    for(int i = 0; i < 200; i++) {
        sevent_run_once(ctx);
        if(g_ev == 1) break;
    }
    if(g_ev != 1) return 1;

    /* 非法码 999 (0-999 保留) → 拒绝 */
    if(sevent_ws_close(ws, 999, "") != SEVENT_ERR_INVAL) return 1;
    /* 非法码 1005 (仅内部) → 拒绝 */
    if(sevent_ws_close(ws, 1005, "") != SEVENT_ERR_INVAL) return 1;
    /* 非法码 1006 (仅内部) → 拒绝 */
    if(sevent_ws_close(ws, 1006, "") != SEVENT_ERR_INVAL) return 1;
    /* 非法码 2000 (1016-2999 未分配) → 拒绝 */
    if(sevent_ws_close(ws, 2000, "") != SEVENT_ERR_INVAL) return 1;
    /* 非法码 5000 (> 4999) → 拒绝 */
    if(sevent_ws_close(ws, 5000, "") != SEVENT_ERR_INVAL) return 1;

    /* 合法码 1000 → 正常关闭 */
    if(sevent_ws_close(ws, 1000, "") != 0) return 1;

    close(sfd);
    sevent_ws_destroy(ws);
    sevent_destroy(ctx);
    return 0;
}

/* ==================== 连接超时测试 ==================== */

static int t_connect_timeout(void) {
    /* 连不通的地址 + 超时 → 触发 on_error */
    sevent_context *ctx = sevent_create();
    if(!ctx) return 1;
    sevent_ws_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host              = "10.0.0.1"; /* 不可达 */
    cfg.path              = "/";
    cfg.on_error          = ev_error;
    cfg.connect_timeout_ms = 10;
    g_ev                  = 0;
    sevent_ws_conn *ws = sevent_ws_connect(ctx, &cfg);
    if(!ws) return 1;
    for(int i = 0; i < 200; i++) {
        sevent_run_once(ctx);
        if(g_ev == 3) break;
    }
    if(g_ev != 3) return 1;
    sevent_ws_destroy(ws);
    sevent_destroy(ctx);
    return 0;
}

static int t_connect_timeout_not_reached(void) {
    /* 连自环 + 超时很长 → 正常连接成功, 不触发超时 */
    sevent_context *ctx = sevent_create();
    if(!ctx) return 1;
    sevent_ws_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host              = "127.0.0.1";
    cfg.path              = "/";
    cfg.on_open           = ev_open;
    cfg.connect_timeout_ms = 5000;
    g_ev                  = 0;
    sevent_ws_conn *ws;
    int sfd = pair(ctx, &cfg, &ws);
    if(sfd < 0) return 1;
    sevent_run_once(ctx);
    if(shake(sfd) < 0) return 1;
    for(int i = 0; i < 200; i++) {
        sevent_run_once(ctx);
        if(g_ev == 1) break;
    }
    if(g_ev != 1) return 1;
    close(sfd);
    sevent_ws_destroy(ws);
    sevent_destroy(ctx);
    return 0;
}

static int t_connect_timeout_disabled(void) {
    /* timeout=-1 → 不设超时, 正常连接 */
    sevent_context *ctx = sevent_create();
    if(!ctx) return 1;
    sevent_ws_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host              = "127.0.0.1";
    cfg.path              = "/";
    cfg.on_open           = ev_open;
    cfg.connect_timeout_ms = -1;
    g_ev                  = 0;
    sevent_ws_conn *ws;
    int sfd = pair(ctx, &cfg, &ws);
    if(sfd < 0) return 1;
    sevent_run_once(ctx);
    if(shake(sfd) < 0) return 1;
    for(int i = 0; i < 200; i++) {
        sevent_run_once(ctx);
        if(g_ev == 1) break;
    }
    if(g_ev != 1) return 1;
    close(sfd);
    sevent_ws_destroy(ws);
    sevent_destroy(ctx);
    return 0;
}

int main(void) {
    struct {
        const char *n;
        int (*f)(void);
    } tests[] = {{"connect_timeout", t_connect_timeout},
                 {"connect_timeout_not_reached", t_connect_timeout_not_reached},
                 {"connect_timeout_disabled", t_connect_timeout_disabled},
                 {"recv_invalid_control_payload", t_recv_invalid_control_payload},
                 {"recv_invalid_close_code", t_recv_invalid_close_code},
                 {"invalid_ping_payload", t_invalid_ping_payload},
                 {"invalid_close_code", t_invalid_close_code},
                 {"lifecycle", t_lifecycle},
                 {"client_send_text", t_client_send_text},
                 {"client_send_binary", t_client_send_binary},
                 {"auto_pong", t_auto_pong},
                 {"on_pong", t_on_pong},
                 {"large_msg", t_large_msg},
                 {"client_ping", t_client_ping},
                 {"client_close", t_client_close},
                 {"fragmentation", t_fragmentation},
                 {"frag_large", t_frag_large},
                 {"frag_many", t_frag_many},
                 {"frag_interleave", t_frag_interleave},
                 {"frag_proto_error", t_frag_proto_error},
                 {"sticky_packet", t_sticky_packet},
                 {"http_fail", t_http_fail},
                 {"http_fail_with_body", t_http_fail_with_body},
                 {"sticky_multi_frame", t_sticky_multi_frame},
                 {"sticky_stream_tail", t_sticky_stream_tail},
                 {"stream_total", t_stream_total},
                 {"split_frame", t_split_frame},
                 {"sticky_partial", t_sticky_partial},
                 {"frag_split_read", t_frag_split_read},
                 {"state_checks", t_state_checks},
                 {"cross_thread_send", t_cross_thread_send},
                 {"cross_thread_close", t_cross_thread_close},
                 {NULL, NULL}};
    printf("ws_conn tests\n");
    printf("=============\n");
    int ok = 0, fail = 0;
    for(int i = 0; tests[i].n; i++) {
        printf("  %-24s ", tests[i].n);
        int r = tests[i].f();
        if(r) {
            printf("×\n");
            fail++;
        } else {
            printf("✓\n");
            ok++;
        }
    }
    printf("\n%d/%d passed\n", ok, ok + fail);
    return fail ? 1 : 0;
}
