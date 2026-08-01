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
static void ev_msg(void *d, const void *m, size_t l, bool b, bool fin, uint64_t total) {
    (void)d;
    (void)b;
    (void)fin;
    g_last_total = total;
    g_ev         = 2;
    if(l == 0)
        return; /* 压缩消息的 fin 通知 (0 字节), 不覆盖数据 */
    size_t c = l < 255 ? l : 255;
    memcpy(g_msg, m, c);
    g_msg[c] = 0;
}

/* 分片测试专用回调: 累计调用次数 + 总长度 */
static void ev_msg_frag(void *d, const void *m, size_t l, bool b, bool fin, uint64_t total) {
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
static int  g_err; /* ev_error 记录的最近错误码 */
static void ev_error(void *d, int err) {
    (void)d;
    g_err = err;
    g_ev  = 3;
}
static void ev_tick(void *d) { (void)d; }

/* PONG 回调记录 */
static int    g_pong_fired;
static char   g_pong_payload[256];
static size_t g_pong_len;
static void   ev_pong(void *d, const void *p, size_t l) {
    (void)d;
    g_pong_fired = 1;
    g_pong_len   = l < sizeof(g_pong_payload) ? l : sizeof(g_pong_payload) - 1;
    if(l > 0 && p)
        memcpy(g_pong_payload, p, g_pong_len);
    g_pong_payload[g_pong_len] = '\0';
}

/* HTTP 响应回调记录 */
static int    g_http_status;
static char   g_http_body[256];
static size_t g_http_body_len;
static void   ev_http_resp(void *d, int code, const char *h, size_t hl, const char *b, size_t bl) {
    (void)d;
    (void)h;
    (void)hl;
    g_ev            = 4;
    g_http_status   = code;
    g_http_body_len = bl < sizeof(g_http_body) ? bl : sizeof(g_http_body) - 1;
    if(bl > 0 && b)
        memcpy(g_http_body, b, g_http_body_len);
    g_http_body[g_http_body_len] = '\0';
}

/* 粘包/分包测试专用: 计数 + 累积内容 */
static int  g_call_count;
static void ev_msg_count(void *d, const void *m, size_t l, bool b, bool fin, uint64_t total) {
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
    int     h = ws_frame_build_header(b, 1, 0, op, NULL, l);
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
    int     hl = ws_frame_build_header(cp, 1, 0, WS_OPCODE_CLOSE, NULL, 2);
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
    if(!ctx)
        return 1;
    sevent_ws_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host     = "127.0.0.1";
    cfg.path     = "/";
    cfg.on_open  = ev_open;
    cfg.on_pong  = ev_pong;
    g_ev         = 0;
    g_pong_fired = 0;
    g_pong_len   = 0;
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

    /* 服务端发 PONG (payload = "pongdata") */
    wsend(sfd, WS_OPCODE_PONG, "pongdata", 8);
    g_pong_fired = 0;
    for(int i = 0; i < 50; i++) {
        sevent_run_once(ctx);
        if(g_pong_fired)
            break;
    }
    if(!g_pong_fired)
        return 1;
    if(g_pong_len != 8 || strcmp(g_pong_payload, "pongdata") != 0)
        return 1;
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
    if(sevent_ws_shutdown(ws, 1000, "bye") != 0)
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
    int     hl = ws_frame_build_header(cp, 1, 0, WS_OPCODE_CLOSE, NULL, 2);
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
    hl = ws_frame_build_header(b, 0, 0, WS_OPCODE_TEXT, NULL, 3);
    memcpy(b + hl, "Hel", 3);
    WS_WRITE(sfd, b, (size_t)(hl + 3));
    hl = ws_frame_build_header(b, 0, 0, WS_OPCODE_CONT, NULL, 3);
    memcpy(b + hl, "lo ", 3);
    WS_WRITE(sfd, b, (size_t)(hl + 3));
    hl = ws_frame_build_header(b, 1, 0, WS_OPCODE_CONT, NULL, 5);
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
        hl = ws_frame_build_header(buf, 0, 0, i ? WS_OPCODE_CONT : WS_OPCODE_TEXT, NULL, 3000);
        memcpy(buf + hl, blk, 3000);
        write_all(sfd, buf, (size_t)(hl + 3000));
    }
    hl = ws_frame_build_header(buf, 1, 0, WS_OPCODE_CONT, NULL, 3000);
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
        hl      = ws_frame_build_header(buf, 0, 0, i ? WS_OPCODE_CONT : WS_OPCODE_TEXT, NULL, 1);
        buf[hl] = (uint8_t)('a' + (i % 26));
        write_all(sfd, buf, (size_t)(hl + 1));
    }
    hl      = ws_frame_build_header(buf, 1, 0, WS_OPCODE_CONT, NULL, 1);
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
    hl = ws_frame_build_header(b, 0, 0, WS_OPCODE_TEXT, NULL, 5);
    memcpy(b + hl, "Hello", 5);
    write_all(sfd, b, (size_t)(hl + 5));
    hl = ws_frame_build_header(b, 1, 0, WS_OPCODE_PING, NULL, 4);
    memcpy(b + hl, "ping", 4);
    write_all(sfd, b, (size_t)(hl + 4));
    hl = ws_frame_build_header(b, 0, 0, WS_OPCODE_CONT, NULL, 3);
    memcpy(b + hl, " wo", 3);
    write_all(sfd, b, (size_t)(hl + 3));
    hl = ws_frame_build_header(b, 1, 0, WS_OPCODE_CONT, NULL, 4);
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
    int     hl = ws_frame_build_header(b, 1, 0, WS_OPCODE_CONT, NULL, 3);
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
    int     hl = ws_frame_build_header(wsf, 1, 0, WS_OPCODE_TEXT, NULL, 5);
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
    g_http_body[0]       = 0;
    g_http_body_len      = 0;
    sevent_ws_conn *ws;
    int             sfd = pair(ctx, &cfg, &ws);
    if(sfd < 0)
        return 1;
    sevent_run_once(ctx);
    char    req[4096];
    ssize_t rn = read(sfd, req, sizeof(req) - 1);
    if(rn <= 0)
        return 1;
    char resp[] = "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello";
    write_all(sfd, resp, strlen(resp));
    sevent_timer *_tm = sevent_timer_register(ctx, 1, ev_tick, NULL);
    for(int i = 0; i < 500; i++) {
        sevent_run_once(ctx);
        if(g_ev == 4)
            break;
    }
    if(_tm)
        sevent_timer_unregister(ctx, _tm);
    if(g_ev != 4 || g_http_status != 400)
        return 1;
    if(g_http_body_len != 5 || strcmp(g_http_body, "hello") != 0)
        return 1;
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
    hl          = ws_frame_build_header(b + off, 1, 0, WS_OPCODE_TEXT, NULL, 5);
    memcpy(b + off + hl, "Hello", 5);
    off += hl + 5;
    hl  = ws_frame_build_header(b + off, 1, 0, WS_OPCODE_TEXT, NULL, 2);
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
    hl = ws_frame_build_header(b + off, 1, 0, WS_OPCODE_TEXT, NULL, 5000);
    memcpy(b + off + hl, big, 5000);
    off += hl + 5000;
    hl  = ws_frame_build_header(b + off, 1, 0, WS_OPCODE_TEXT, NULL, 4);
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
    int hl = ws_frame_build_header(b, 1, 0, WS_OPCODE_TEXT, NULL, 5000);
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
    int     hl = ws_frame_build_header(b, 1, 0, WS_OPCODE_TEXT, NULL, 5);
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
    hl          = ws_frame_build_header(b + off, 1, 0, WS_OPCODE_TEXT, NULL, 4);
    memcpy(b + off + hl, "Full", 4);
    off += hl + 4;
    hl  = ws_frame_build_header(b + off, 1, 0, WS_OPCODE_TEXT, NULL, 8);
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
    int     hl = ws_frame_build_header(b, 0, 0, WS_OPCODE_TEXT, NULL, 3);
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
    hl = ws_frame_build_header(b, 0, 0, WS_OPCODE_CONT, NULL, 3);
    memcpy(b + hl, "lo ", 3);
    write_all(sfd, b, (size_t)(hl + 3));
    hl = ws_frame_build_header(b, 1, 0, WS_OPCODE_CONT, NULL, 5);
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
    c->state = WS_STATE_CLOSED;
    if(sevent_ws_send_text(c, "x", 1) != -1)
        return 1;
    if(sevent_ws_send_binary(c, "x", 1) != -1)
        return 1;
    if(sevent_ws_ping(c, NULL, 0) != -1)
        return 1;
    if(sevent_ws_shutdown(c, 1000, "") != -1)
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
    ta->result         = sevent_ws_shutdown(ta->ws, 1000, "");
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
    int     hl = ws_frame_build_header(cp, 1, 0, WS_OPCODE_CLOSE, NULL, 2);
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

    /* 构造 PING 帧 payload = 200 字节 > 125 */
    uint8_t ping_pay[200];
    memset(ping_pay, 'p', sizeof(ping_pay));
    uint8_t hdr[16];
    int     hl = ws_frame_build_header(hdr, 0, 0, WS_OPCODE_PING, NULL, sizeof(ping_pay));
    if(hl < 0)
        return 1;
    uint8_t *raw = malloc((size_t)hl + sizeof(ping_pay));
    memcpy(raw, hdr, (size_t)hl);
    memcpy(raw + hl, ping_pay, sizeof(ping_pay));
    write_all(sfd, raw, (size_t)hl + sizeof(ping_pay));
    free(raw);

    g_ev              = 0;
    sevent_timer *_tm = sevent_timer_register(ctx, 1, ev_tick, NULL);
    for(int i = 0; i < 100; i++) {
        sevent_run_once(ctx);
        if(g_ev == 3)
            break; /* on_error 触发 */
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

static int t_recv_invalid_close_code(void) {
    /* 模拟对端发送非法 Close 码 → on_error 触发 */
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

    /* 构造 CLOSE 帧 payload = 非法码 999 */
    uint8_t cp[2] = {0x03, 0xE7}; /* 999 */
    uint8_t hdr[16];
    int     hl = ws_frame_build_header(hdr, 0, 0, WS_OPCODE_CLOSE, NULL, 2);
    /* fin=0 不表示分包, 只测非法 close code */
    if(hl < 0)
        return 1;
    uint8_t *raw = malloc((size_t)hl + 2);
    memcpy(raw, hdr, (size_t)hl);
    memcpy(raw + hl, cp, 2);
    write_all(sfd, raw, (size_t)hl + 2);
    free(raw);

    g_ev              = 0;
    sevent_timer *_tm = sevent_timer_register(ctx, 1, ev_tick, NULL);
    for(int i = 0; i < 100; i++) {
        sevent_run_once(ctx);
        if(g_ev == 3)
            break; /* on_error 触发 */
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

static int t_invalid_ping_payload(void) {
    /* RFC 6455 §5.5: 控制帧 payload 不得超过 125 */
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

    /* ping payload > 125 → 应拒绝 */
    uint8_t big[200];
    memset(big, 'x', sizeof(big));
    if(sevent_ws_ping(ws, big, sizeof(big)) != SEVENT_ERR_INVAL)
        return 1;

    /* 短 ping → 应正常 */
    if(sevent_ws_ping(ws, "ok", 2) != 0)
        return 1;

    close(sfd);
    sevent_ws_destroy(ws);
    sevent_destroy(ctx);
    return 0;
}

static int t_invalid_close_code(void) {
    /* RFC 6455 §7.4: 非法 Close 码 → send_frame 拒绝 */
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

    /* 非法码 999 (0-999 保留) → 拒绝 */
    if(sevent_ws_shutdown(ws, 999, "") != SEVENT_ERR_INVAL)
        return 1;
    /* 非法码 1005 (仅内部) → 拒绝 */
    if(sevent_ws_shutdown(ws, 1005, "") != SEVENT_ERR_INVAL)
        return 1;
    /* 非法码 1006 (仅内部) → 拒绝 */
    if(sevent_ws_shutdown(ws, 1006, "") != SEVENT_ERR_INVAL)
        return 1;
    /* 非法码 2000 (1016-2999 未分配) → 拒绝 */
    if(sevent_ws_shutdown(ws, 2000, "") != SEVENT_ERR_INVAL)
        return 1;
    /* 非法码 5000 (> 4999) → 拒绝 */
    if(sevent_ws_shutdown(ws, 5000, "") != SEVENT_ERR_INVAL)
        return 1;

    /* 合法码 1000 → 正常关闭 */
    if(sevent_ws_shutdown(ws, 1000, "") != 0)
        return 1;

    close(sfd);
    sevent_ws_destroy(ws);
    sevent_destroy(ctx);
    return 0;
}

/* ==================== 连接超时测试 ==================== */

static int t_connect_timeout(void) {
    /* 连不通的地址 + 超时 → 触发 on_error */
    sevent_context *ctx = sevent_create();
    if(!ctx)
        return 1;
    sevent_ws_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host               = "10.0.0.1"; /* 不可达 */
    cfg.path               = "/";
    cfg.on_error           = ev_error;
    cfg.connect_timeout_ms = 10;
    g_ev                   = 0;
    sevent_ws_conn *ws     = sevent_ws_connect(ctx, &cfg);
    if(!ws)
        return 1;
    for(int i = 0; i < 200; i++) {
        sevent_run_once(ctx);
        if(g_ev == 3)
            break;
    }
    if(g_ev != 3)
        return 1;
    sevent_ws_destroy(ws);
    sevent_destroy(ctx);
    return 0;
}

static int t_connect_timeout_not_reached(void) {
    /* 连自环 + 超时很长 → 正常连接成功, 不触发超时 */
    sevent_context *ctx = sevent_create();
    if(!ctx)
        return 1;
    sevent_ws_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host               = "127.0.0.1";
    cfg.path               = "/";
    cfg.on_open            = ev_open;
    cfg.connect_timeout_ms = 5000;
    g_ev                   = 0;
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
    close(sfd);
    sevent_ws_destroy(ws);
    sevent_destroy(ctx);
    return 0;
}

static int t_connect_timeout_disabled(void) {
    /* timeout=-1 → 不设超时, 正常连接 */
    sevent_context *ctx = sevent_create();
    if(!ctx)
        return 1;
    sevent_ws_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host               = "127.0.0.1";
    cfg.path               = "/";
    cfg.on_open            = ev_open;
    cfg.connect_timeout_ms = -1;
    g_ev                   = 0;
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
    close(sfd);
    sevent_ws_destroy(ws);
    sevent_destroy(ctx);
    return 0;
}

/* ===== permessage-deflate 测试 ===== */
#ifdef SEVENT_WS_DEFLATE
#include <zlib.h>

/* shake_deflate_full: 握手回复, extensions 为完整扩展头值 */
static int shake_deflate_full(int sfd, const char *extensions) {
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
                       "Sec-WebSocket-Accept: %s\r\n"
                       "Sec-WebSocket-Extensions: %s\r\n\r\n",
                      ac,
                      extensions ? extensions : "");
    WS_WRITE(sfd, resp, (size_t)rn);
    return 0;
}
/* shake_deflate_ext: 扩展值追加到 permessage-deflate 后 (可为空串) */
static int shake_deflate_ext(int sfd, const char *ext) {
    char full[192];
    snprintf(full, sizeof(full), "permessage-deflate%s", ext ? ext : "");
    return shake_deflate_full(sfd, full);
}
static int shake_deflate(int sfd) { return shake_deflate_ext(sfd, ""); }

/* wsend_compressed: 服务端发压缩 WS 帧 (rsv1=1) */
static void wsend_compressed(int fd, uint8_t op, const void *p, uint64_t l) {
    ws_deflate       *df     = NULL;
    ws_deflate_params params = {0};
    if(!ws_deflate_create(&df, &params) || !df)
        return;
    size_t   cap  = ws_deflate_compress_maxlen(df, l);
    uint8_t *comp = (uint8_t *)malloc(cap);
    if(comp && ws_deflate_compress(df, p, l, comp, &cap)) {
        uint8_t b[4096];
        int     h = ws_frame_build_header(b, 1, 1, op, NULL, cap);
        memcpy(b + h, comp, (size_t)cap);
        WS_WRITE(fd, b, (size_t)(h + (int)cap));
    }
    free(comp);
    ws_deflate_destroy(df);
}

static int t_deflate_create(void) {
    /* 验证 enable_deflate=true 时握手协商创建了 deflate */
    sevent_context *ctx = sevent_create();
    if(!ctx)
        return 1;
    sevent_ws_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host           = "127.0.0.1";
    cfg.path           = "/";
    cfg.enable_deflate = true;
    cfg.on_open        = ev_open;
    g_ev               = 0;
    sevent_ws_conn *ws;
    int             sfd = pair(ctx, &cfg, &ws);
    if(sfd < 0)
        return 1;
    sevent_run_once(ctx);
    if(shake_deflate(sfd) < 0)
        return 1;
    for(int i = 0; i < 200; i++) {
        sevent_run_once(ctx);
        if(g_ev == 1)
            break;
    }
    if(g_ev != 1)
        return 1;
    if(!ws->deflate)
        return 1;
    close(sfd);
    sevent_ws_destroy(ws);
    sevent_destroy(ctx);
    return 0;
}

static int t_deflate_client_win_ok(void) {
    /* 服务器响应 client_max_window_bits=9 → 本端发送窗口受限为 9
     * (RFC 7692 §7.1.2.2: 客户端 MUST NOT 使用更大窗口). */
    sevent_context *ctx = sevent_create();
    if(!ctx)
        return 1;
    sevent_ws_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host           = "127.0.0.1";
    cfg.path           = "/";
    cfg.enable_deflate = true;
    cfg.on_open        = ev_open;
    g_ev               = 0;
    sevent_ws_conn *ws;
    int             sfd = pair(ctx, &cfg, &ws);
    if(sfd < 0)
        return 1;
    sevent_run_once(ctx);
    if(shake_deflate_ext(sfd, "; " WS_EXT_CLIENT_MAX_WB "=9") < 0)
        return 1;
    for(int i = 0; i < 200; i++) {
        sevent_run_once(ctx);
        if(g_ev == 1)
            break;
    }
    if(g_ev != 1)
        return 1;
    if(!ws->deflate)
        return 1;
    /* 发送窗口受限为 9; 未协商 server 侧保持默认 15 */
    if(ws->deflate->client_window_bits != 9)
        return 1;
    if(ws->deflate->server_window_bits != 15)
        return 1;
    close(sfd);
    sevent_ws_destroy(ws);
    sevent_destroy(ctx);
    return 0;
}

static int t_deflate_client_win_bad(void) {
    /* 服务器响应非法 client_max_window_bits 值 (范围外/非数字/空)
     * → 服务器违规 → Fail the Connection (RFC 7692 §7.1.2) */
    const char *bad[] = {"=7", "=16", "=abc", "="};
    for(size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        sevent_context *ctx = sevent_create();
        if(!ctx)
            return 1;
        sevent_ws_config cfg;
        memset(&cfg, 0, sizeof(cfg));
        cfg.host           = "127.0.0.1";
        cfg.path           = "/";
        cfg.enable_deflate = true;
        cfg.on_open        = ev_open;
        cfg.on_error       = ev_error;
        g_ev               = 0;
        g_err              = 0;
        sevent_ws_conn *ws;
        int             sfd = pair(ctx, &cfg, &ws);
        if(sfd < 0)
            return 1;
        sevent_run_once(ctx);
        char ext[64];
        snprintf(ext, sizeof(ext), "; " WS_EXT_CLIENT_MAX_WB "%s", bad[i]);
        if(shake_deflate_ext(sfd, ext) < 0)
            return 1;
        for(int j = 0; j < 200; j++) {
            sevent_run_once(ctx);
            if(g_ev == 3)
                break;
        }
        if(g_ev != 3 || g_err != SEVENT_WS_ERR_PROTOCOL)
            return 1;
        close(sfd);
        sevent_ws_destroy(ws);
        sevent_destroy(ctx);
    }
    return 0;
}

static int t_nct_config(void) {
    /* request_client_no_context_takeover=true: 自我承诺本地生效 —
     * 服务器响应不带该参数也应生效 (offer 字符串由 test_ws.c 单测覆盖);
     * request_server_no_context_takeover=true: 服务器未同意则不生效. */
    sevent_context *ctx = sevent_create();
    if(!ctx)
        return 1;
    sevent_ws_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host                               = "127.0.0.1";
    cfg.path                               = "/";
    cfg.enable_deflate                     = true;
    cfg.request_client_no_context_takeover = true;
    cfg.request_server_no_context_takeover = true;
    cfg.on_open                            = ev_open;
    g_ev                                   = 0;
    sevent_ws_conn *ws;
    int             sfd = pair(ctx, &cfg, &ws);
    if(sfd < 0)
        return 1;
    sevent_run_once(ctx);
    if(shake_deflate(sfd) < 0)
        return 1;
    for(int i = 0; i < 200; i++) {
        sevent_run_once(ctx);
        if(g_ev == 1)
            break;
    }
    if(g_ev != 1)
        return 1;
    if(!ws->deflate)
        return 1;
    /* 自我承诺: 服务器响应未带 client_no_context_takeover 也应生效 */
    if(!ws->deflate->client_no_context_takeover)
        return 1;
    /* 请求: 服务器响应未带 server_no_context_takeover → 不生效 */
    if(ws->deflate->server_no_context_takeover)
        return 1;
    close(sfd);
    sevent_ws_destroy(ws);
    sevent_destroy(ctx);
    return 0;
}

static int t_win_client_offer(void) {
    /* request_client_max_window_bits=9: offer 带值自我承诺 —
     * 响应不带该参数也应生效 (RFC 7692 §7.1.2.2); 响应带 =9 同样生效 */
    const char *exts[] = {"", "; " WS_EXT_CLIENT_MAX_WB "=9"};
    for(size_t i = 0; i < sizeof(exts) / sizeof(exts[0]); i++) {
        sevent_context *ctx = sevent_create();
        if(!ctx)
            return 1;
        sevent_ws_config cfg;
        memset(&cfg, 0, sizeof(cfg));
        cfg.host                           = "127.0.0.1";
        cfg.path                           = "/";
        cfg.enable_deflate                 = true;
        cfg.request_client_max_window_bits = 9;
        cfg.on_open                        = ev_open;
        g_ev                               = 0;
        sevent_ws_conn *ws;
        int             sfd = pair(ctx, &cfg, &ws);
        if(sfd < 0)
            return 1;
        sevent_run_once(ctx);
        if(shake_deflate_ext(sfd, exts[i]) < 0)
            return 1;
        for(int j = 0; j < 200; j++) {
            sevent_run_once(ctx);
            if(g_ev == 1)
                break;
        }
        if(g_ev != 1)
            return 1;
        if(!ws->deflate || ws->deflate->client_window_bits != 9)
            return 1; /* 自我承诺/响应均应为 9 */
        close(sfd);
        sevent_ws_destroy(ws);
        sevent_destroy(ctx);
    }
    return 0;
}

static int t_win_client_exceed(void) {
    /* offer 带值 =9, 响应 =10 (大于 offer 值) → 服务器违约 → fail
     * (RFC 7692 §7.1.2.2: 响应值 MUST be no larger than offer value) */
    sevent_context *ctx = sevent_create();
    if(!ctx)
        return 1;
    sevent_ws_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host                           = "127.0.0.1";
    cfg.path                           = "/";
    cfg.enable_deflate                 = true;
    cfg.request_client_max_window_bits = 9;
    cfg.on_open                        = ev_open;
    cfg.on_error                       = ev_error;
    g_ev                               = 0;
    g_err                              = 0;
    sevent_ws_conn *ws;
    int             sfd = pair(ctx, &cfg, &ws);
    if(sfd < 0)
        return 1;
    sevent_run_once(ctx);
    if(shake_deflate_ext(sfd, "; " WS_EXT_CLIENT_MAX_WB "=10") < 0)
        return 1;
    for(int i = 0; i < 200; i++) {
        sevent_run_once(ctx);
        if(g_ev == 3)
            break;
    }
    if(g_ev != 3 || g_err != SEVENT_WS_ERR_PROTOCOL)
        return 1;
    close(sfd);
    sevent_ws_destroy(ws);
    sevent_destroy(ctx);
    return 0;
}

static int t_win_server_offer(void) {
    /* request_server_max_window_bits=9: 响应带 =9 → 解压窗口受限为 9;
     * 响应不带 → 服务器拒绝降窗 → 保持 15 (RFC 7692 §7.1.2.1 decline) */
    const char *exts[]    = {"; " WS_EXT_SERVER_MAX_WB "=9", ""};
    const int   expects[] = {9, 15};
    for(size_t i = 0; i < sizeof(exts) / sizeof(exts[0]); i++) {
        sevent_context *ctx = sevent_create();
        if(!ctx)
            return 1;
        sevent_ws_config cfg;
        memset(&cfg, 0, sizeof(cfg));
        cfg.host                           = "127.0.0.1";
        cfg.path                           = "/";
        cfg.enable_deflate                 = true;
        cfg.request_server_max_window_bits = 9;
        cfg.on_open                        = ev_open;
        g_ev                               = 0;
        sevent_ws_conn *ws;
        int             sfd = pair(ctx, &cfg, &ws);
        if(sfd < 0)
            return 1;
        sevent_run_once(ctx);
        if(shake_deflate_ext(sfd, exts[i]) < 0)
            return 1;
        for(int j = 0; j < 200; j++) {
            sevent_run_once(ctx);
            if(g_ev == 1)
                break;
        }
        if(g_ev != 1)
            return 1;
        if(!ws->deflate || ws->deflate->server_window_bits != expects[i])
            return 1;
        close(sfd);
        sevent_ws_destroy(ws);
        sevent_destroy(ctx);
    }
    return 0;
}

static int t_win_server_active(void) {
    /* 未请求 server_max_window_bits, 服务器主动带 =9 (RFC 7692 §7.1.2.1
     * 允许) → 客户端解压窗口随之用 9 (服务器承诺压缩窗口 ≤9) */
    sevent_context *ctx = sevent_create();
    if(!ctx)
        return 1;
    sevent_ws_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host           = "127.0.0.1";
    cfg.path           = "/";
    cfg.enable_deflate = true;
    cfg.on_open        = ev_open;
    g_ev               = 0;
    sevent_ws_conn *ws;
    int             sfd = pair(ctx, &cfg, &ws);
    if(sfd < 0)
        return 1;
    sevent_run_once(ctx);
    if(shake_deflate_ext(sfd, "; " WS_EXT_SERVER_MAX_WB "=9") < 0)
        return 1;
    for(int i = 0; i < 200; i++) {
        sevent_run_once(ctx);
        if(g_ev == 1)
            break;
    }
    if(g_ev != 1)
        return 1;
    if(!ws->deflate || ws->deflate->server_window_bits != 9)
        return 1;
    close(sfd);
    sevent_ws_destroy(ws);
    sevent_destroy(ctx);
    return 0;
}

static int t_win_server_exceed(void) {
    /* offer 请求 =9, 响应 =10 (大于请求值) → 服务器违约 → fail
     * (RFC 7692 §7.1.2.1: 响应值 MUST be no larger than offer value) */
    sevent_context *ctx = sevent_create();
    if(!ctx)
        return 1;
    sevent_ws_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host                           = "127.0.0.1";
    cfg.path                           = "/";
    cfg.enable_deflate                 = true;
    cfg.request_server_max_window_bits = 9;
    cfg.on_open                        = ev_open;
    cfg.on_error                       = ev_error;
    g_ev                               = 0;
    g_err                              = 0;
    sevent_ws_conn *ws;
    int             sfd = pair(ctx, &cfg, &ws);
    if(sfd < 0)
        return 1;
    sevent_run_once(ctx);
    if(shake_deflate_ext(sfd, "; " WS_EXT_SERVER_MAX_WB "=10") < 0)
        return 1;
    for(int i = 0; i < 200; i++) {
        sevent_run_once(ctx);
        if(g_ev == 3)
            break;
    }
    if(g_ev != 3 || g_err != SEVENT_WS_ERR_PROTOCOL)
        return 1;
    close(sfd);
    sevent_ws_destroy(ws);
    sevent_destroy(ctx);
    return 0;
}

static int t_win_server_bad(void) {
    /* 服务器主动带非法 server_max_window_bits 值 (范围外/非数字) → fail
     * (RFC 7692 §7.1.2: 值必须为 8-15 数字) */
    const char *bad[] = {"=7", "=16", "=abc"};
    for(size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        sevent_context *ctx = sevent_create();
        if(!ctx)
            return 1;
        sevent_ws_config cfg;
        memset(&cfg, 0, sizeof(cfg));
        cfg.host           = "127.0.0.1";
        cfg.path           = "/";
        cfg.enable_deflate = true;
        cfg.on_open        = ev_open;
        cfg.on_error       = ev_error;
        g_ev               = 0;
        g_err              = 0;
        sevent_ws_conn *ws;
        int             sfd = pair(ctx, &cfg, &ws);
        if(sfd < 0)
            return 1;
        sevent_run_once(ctx);
        char ext[64];
        snprintf(ext, sizeof(ext), "; " WS_EXT_SERVER_MAX_WB "%s", bad[i]);
        if(shake_deflate_ext(sfd, ext) < 0)
            return 1;
        for(int j = 0; j < 200; j++) {
            sevent_run_once(ctx);
            if(g_ev == 3)
                break;
        }
        if(g_ev != 3 || g_err != SEVENT_WS_ERR_PROTOCOL)
            return 1;
        close(sfd);
        sevent_ws_destroy(ws);
        sevent_destroy(ctx);
    }
    return 0;
}

static int t_deflate_unoffered_ext(void) {
    /* enable_deflate=false (未 offer 任何扩展), 服务器响应却带 permessage-deflate
     * → 握手失败 (RFC 6455 §4.1 第 5 条: 未请求的扩展 MUST fail) */
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
    g_err        = 0;
    sevent_ws_conn *ws;
    int             sfd = pair(ctx, &cfg, &ws);
    if(sfd < 0)
        return 1;
    sevent_run_once(ctx);
    /* 服务端通告了 deflate, 但客户端未 offer → 必须失败 */
    if(shake_deflate(sfd) < 0)
        return 1;
    for(int i = 0; i < 200; i++) {
        sevent_run_once(ctx);
        if(g_ev == 3)
            break;
    }
    if(g_ev != 3 || g_err != SEVENT_WS_ERR_HANDSHAKE)
        return 1;
    if(ws->deflate)
        return 1; /* 协商失败不应创建 deflate */
    close(sfd);
    sevent_ws_destroy(ws);
    sevent_destroy(ctx);
    return 0;
}

static int t_deflate_unoffered_unknown(void) {
    /* enable_deflate=true, 但响应含未 offer 的扩展名 → 握手失败
     * (RFC 6455 §4.1 第 5 条); 参数层宽容 (server_max_window_bits 可主动带,
     * RFC 7692 §7.1.2.1) 由 nct_config/client_win_ok 的带参数响应路径覆盖 */
    const char *bad[] = {"x-foo", "x-foo, permessage-deflate", "permessage-deflate, x-foo"};
    for(size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        sevent_context *ctx = sevent_create();
        if(!ctx)
            return 1;
        sevent_ws_config cfg;
        memset(&cfg, 0, sizeof(cfg));
        cfg.host           = "127.0.0.1";
        cfg.path           = "/";
        cfg.enable_deflate = true;
        cfg.on_open        = ev_open;
        cfg.on_error       = ev_error;
        g_ev               = 0;
        g_err              = 0;
        sevent_ws_conn *ws;
        int             sfd = pair(ctx, &cfg, &ws);
        if(sfd < 0)
            return 1;
        sevent_run_once(ctx);
        if(shake_deflate_full(sfd, bad[i]) < 0)
            return 1;
        for(int j = 0; j < 200; j++) {
            sevent_run_once(ctx);
            if(g_ev == 3)
                break;
        }
        if(g_ev != 3 || g_err != SEVENT_WS_ERR_HANDSHAKE)
            return 1;
        close(sfd);
        sevent_ws_destroy(ws);
        sevent_destroy(ctx);
    }
    return 0;
}

static int t_deflate_recv(void) {
    /* 服务端发压缩 TEXT → 客户端解压后 on_message */
    sevent_context *ctx = sevent_create();
    if(!ctx)
        return 1;
    sevent_ws_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host           = "127.0.0.1";
    cfg.path           = "/";
    cfg.enable_deflate = true;
    cfg.on_open        = ev_open;
    cfg.on_message     = ev_msg;
    g_ev               = 0;
    g_msg[0]           = 0;
    sevent_ws_conn *ws;
    int             sfd = pair(ctx, &cfg, &ws);
    if(sfd < 0)
        return 1;
    sevent_run_once(ctx);
    if(shake_deflate(sfd) < 0) {
        return 1;
    }
    for(int i = 0; i < 200; i++) {
        sevent_run_once(ctx);
        if(g_ev == 1)
            break;
    }
    if(g_ev != 1) {
        return 1;
    }
    if(!ws->deflate) {
        return 1;
    }
    wsend_compressed(sfd, WS_OPCODE_TEXT, "HelloDeflate", 12);
    g_ev = 1;
    for(int i = 0; i < 100; i++) {
        sevent_run_once(ctx);
        if(g_ev == 2)
            break;
    }
    if(g_ev != 2)
        return 1;
    if(strcmp(g_msg, "HelloDeflate") != 0)
        return 1;
    /* 压缩路径 total 一律传 0 (解压前无法预知原始长度) */
    if(g_last_total != 0) {
        return 1;
    }
    close(sfd);
    sevent_ws_destroy(ws);
    sevent_destroy(ctx);
    return 0;
}

static int t_deflate_recv_large(void) {
    /* 验证大负载压缩解压正确 */
    sevent_context *ctx = sevent_create();
    if(!ctx)
        return 1;
    sevent_ws_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host           = "127.0.0.1";
    cfg.path           = "/";
    cfg.enable_deflate = true;
    cfg.on_open        = ev_open;
    cfg.on_message     = ev_msg;
    g_ev               = 0;
    g_msg[0]           = 0;
    sevent_ws_conn *ws;
    int             sfd = pair(ctx, &cfg, &ws);
    if(sfd < 0)
        return 1;
    sevent_run_once(ctx);
    if(shake_deflate(sfd) < 0)
        return 1;
    for(int i = 0; i < 200; i++) {
        sevent_run_once(ctx);
        if(g_ev == 1)
            break;
    }
    if(g_ev != 1)
        return 1;

    /* 发送压缩的大负载 (> recv_cap 触发流式) */
    char big[5000];
    memset(big, 'A', 5000);
    wsend_compressed(sfd, WS_OPCODE_TEXT, big, 5000);
    g_ev = 1;
    for(int i = 0; i < 500; i++) {
        sevent_run_once(ctx);
        if(g_ev == 2)
            break;
    }
    if(g_ev != 2)
        return 1;
    close(sfd);
    sevent_ws_destroy(ws);
    sevent_destroy(ctx);
    return 0;
}

static int t_deflate_send(void) {
    /* 客户端发 TEXT → send_message 压缩, 服务端收到 RSV1=1 + 压缩数据 */
    sevent_context *ctx = sevent_create();
    if(!ctx)
        return 1;
    sevent_ws_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host           = "127.0.0.1";
    cfg.path           = "/";
    cfg.enable_deflate = true;
    cfg.on_open        = ev_open;
    g_ev               = 0;
    g_msg[0]           = 0;
    cfg.on_message     = ev_msg;
    sevent_ws_conn *ws;
    int             sfd = pair(ctx, &cfg, &ws);
    if(sfd < 0)
        return 1;
    sevent_run_once(ctx);
    if(shake_deflate(sfd) < 0)
        return 1;
    for(int i = 0; i < 200; i++) {
        sevent_run_once(ctx);
        if(g_ev == 1)
            break;
    }
    if(g_ev != 1)
        return 1;
    if(!ws->deflate)
        return 1;

    /* 客户端发送 TEXT, send_message 压缩 */
    if(sevent_ws_send_text(ws, "SendCompress", 12) != 0)
        return 1;
    /* 服务端直接读原始帧 */
    ws_frame_header h;
    uint8_t         pay[256];
    int             pl = 0;
    for(int i = 0; i < 50; i++) {
        pl = wread(sfd, &h, pay, sizeof(pay));
        if(pl >= 0)
            break;
        sevent_run_once(ctx);
    }
    if(pl < 1)
        return 1;
    if(h.opcode != WS_OPCODE_TEXT || !h.rsv1)
        return 1;
    if(pl == 12 && memcmp(pay, "SendCompress", 12) == 0)
        return 1;
    close(sfd);
    sevent_ws_destroy(ws);
    sevent_destroy(ctx);
    return 0;
}

static int t_deflate_send_bin(void) {
    /* 客户端发 BINARY → send_message 压缩 */
    sevent_context *ctx = sevent_create();
    if(!ctx)
        return 1;
    sevent_ws_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host           = "127.0.0.1";
    cfg.path           = "/";
    cfg.enable_deflate = true;
    cfg.on_open        = ev_open;
    g_ev               = 0;
    sevent_ws_conn *ws;
    int             sfd = pair(ctx, &cfg, &ws);
    if(sfd < 0)
        return 1;
    sevent_run_once(ctx);
    if(shake_deflate(sfd) < 0)
        return 1;
    for(int i = 0; i < 200; i++) {
        sevent_run_once(ctx);
        if(g_ev == 1)
            break;
    }
    if(g_ev != 1)
        return 1;

    uint8_t bin[] = {0x00, 0x01, 0xFF, 0xFE};
    if(sevent_ws_send_binary(ws, bin, 4) != 0)
        return 1;
    ws_frame_header h;
    uint8_t         pay[256];
    int             pl = 0;
    for(int i = 0; i < 50; i++) {
        pl = wread(sfd, &h, pay, sizeof(pay));
        if(pl >= 0)
            break;
        sevent_run_once(ctx);
    }
    if(pl < 1)
        return 1;
    if(h.opcode != WS_OPCODE_BINARY || !h.rsv1)
        return 1;
    if(pl == 4 && memcmp(pay, bin, 4) == 0)
        return 1; /* 不应是明文 */
    close(sfd);
    sevent_ws_destroy(ws);
    sevent_destroy(ctx);
    return 0;
}

/* 读一完整帧 (循环读, 支持部分读/64-bit 长度), 返回 payload 长度 */
static int read_frame_full(int fd, ws_frame_header *h, uint8_t *pay, size_t cap) {
    uint8_t b[4096];
    size_t  got = 0;
    int     hdr = -1;
    for(;;) {
        ssize_t n = read(fd, b + got, sizeof(b) - got);
        if(n <= 0)
            return -1;
        got += (size_t)n;
        hdr = ws_frame_parse_header(b, got, h);
        if(hdr > 0)
            break;
        if(got >= sizeof(b))
            return -1;
    }
    size_t pl = (size_t)h->payload_len;
    if(pl > cap)
        return -1;
    if(pl + (size_t)hdr > got) {
        /* payload 未读完: 先搬已到的, 再补读 */
        memcpy(pay, b + hdr, got - (size_t)hdr);
        size_t have = got - (size_t)hdr;
        while(have < pl) {
            ssize_t n = read(fd, pay + have, pl - have);
            if(n <= 0)
                return -1;
            have += (size_t)n;
        }
    } else {
        memcpy(pay, b + hdr, pl);
    }
    if(h->mask)
        ws_frame_apply_mask(pay, pl, h->mask_key);
    return (int)pl;
}

/* 独立 15 位窗口解压 (补 tail, RFC 7692 §7.2.2), 返回 0=成功且内容完整 */
static int decompress_payload(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_cap, size_t *out_used) {
    uint8_t *buf = (uint8_t *)malloc(in_len + 4);
    if(!buf)
        return -1;
    memcpy(buf, in, in_len);
    memcpy(buf + in_len, "\x00\x00\xff\xff", 4);
    z_stream zi;
    memset(&zi, 0, sizeof(zi));
    if(inflateInit2(&zi, -15) != Z_OK) {
        free(buf);
        return -1;
    }
    zi.next_in  = buf;
    zi.avail_in = (uInt)(in_len + 4);
    size_t used = 0;
    int    rc   = Z_OK;
    for(;;) {
        if(used >= out_cap) {
            inflateEnd(&zi);
            free(buf);
            return -1; /* 输出不足 */
        }
        zi.next_out   = out + used;
        zi.avail_out  = (uInt)(out_cap - used);
        size_t before = zi.avail_out;
        rc            = inflate(&zi, Z_SYNC_FLUSH);
        used          += before - zi.avail_out;
        if(rc != Z_OK || zi.avail_out > 0)
            break; /* 到达 sync 点 (输出未满) */
    }
    inflateEnd(&zi);
    free(buf);
    *out_used = used;
    return (rc == Z_OK) ? 0 : -1;
}

static int t_deflate_send_large(void) {
    /* 发送 >64KB 不可压缩数据: 帧头走 64-bit 长度 + 压缩帧解压还原一致 */
    sevent_context *ctx = sevent_create();
    if(!ctx)
        return 1;
    sevent_ws_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host           = "127.0.0.1";
    cfg.path           = "/";
    cfg.enable_deflate = true;
    cfg.on_open        = ev_open;
    g_ev               = 0;
    sevent_ws_conn *ws;
    int             sfd = pair(ctx, &cfg, &ws);
    if(sfd < 0)
        return 1;
    sevent_run_once(ctx);
    if(shake_deflate(sfd) < 0)
        return 1;
    for(int i = 0; i < 200; i++) {
        sevent_run_once(ctx);
        if(g_ev == 1)
            break;
    }
    if(g_ev != 1)
        return 1;

    const size_t BIG = 70000;
    uint8_t     *big = (uint8_t *)malloc(BIG);
    uint8_t     *pay = (uint8_t *)malloc(BIG + 4096);
    if(!big || !pay) {
        free(big);
        free(pay);
        return 1;
    }
    /* 确定性伪随机 (不可压缩 → 压缩后仍 >65535, 触发 64-bit 长度头) */
    unsigned int seed = 98765;
    for(size_t i = 0; i < BIG; i++) {
        seed   = seed * 1103515245u + 12345u;
        big[i] = (uint8_t)(seed >> 24);
    }
    if(sevent_ws_send_binary(ws, big, BIG) != 0) {
        free(big);
        free(pay);
        return 1;
    }
    ws_frame_header h;
    int             pl = 0;
    for(int i = 0; i < 200; i++) {
        pl = read_frame_full(sfd, &h, pay, BIG + 4096);
        if(pl >= 0)
            break;
        sevent_run_once(ctx);
    }
    if(pl < 1) {
        free(big);
        free(pay);
        return 1;
    }
    /* 压缩帧 + 64-bit 长度头 (随机数据压缩后 ~70000 > 65535) */
    if(h.opcode != WS_OPCODE_BINARY || !h.rsv1 || h.payload_len <= 65535) {
        free(big);
        free(pay);
        return 1;
    }
    uint8_t *dec = (uint8_t *)malloc(BIG + 64);
    if(!dec) {
        free(big);
        free(pay);
        return 1;
    }
    size_t used = 0;
    int    dr   = decompress_payload(pay, (size_t)pl, dec, BIG + 64, &used);
    int    ok   = (dr == 0 && used == BIG && memcmp(dec, big, BIG) == 0);
    free(dec);
    free(big);
    free(pay);
    if(!ok)
        return 1;
    close(sfd);
    sevent_ws_destroy(ws);
    sevent_destroy(ctx);
    return 0;
}

static int t_deflate_frag(void) {
    /* 压缩分片: rsv1=1 TEXT fin=0 + CONT fin=1 */
    sevent_context *ctx = sevent_create();
    if(!ctx)
        return 1;
    sevent_ws_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host           = "127.0.0.1";
    cfg.path           = "/";
    cfg.enable_deflate = true;
    cfg.on_open        = ev_open;
    cfg.on_message     = ev_msg_frag;
    g_ev               = 0;
    g_msg[0]           = 0;
    g_frag_len         = 0;
    g_frag_total       = 0;
    sevent_ws_conn *ws;
    int             sfd = pair(ctx, &cfg, &ws);
    if(sfd < 0)
        return 1;
    sevent_run_once(ctx);
    if(shake_deflate(sfd) < 0)
        return 1;
    for(int i = 0; i < 200; i++) {
        sevent_run_once(ctx);
        if(g_ev == 1)
            break;
    }
    if(g_ev != 1)
        return 1;

    /* 服务端压缩 "HelloWorld" */
    ws_deflate       *df     = NULL;
    ws_deflate_params params = {0};
    if(!ws_deflate_create(&df, &params) || !df)
        return 1;
    size_t   cap  = ws_deflate_compress_maxlen(df, 10);
    uint8_t *comp = (uint8_t *)malloc(cap);
    int      ok   = 0;
    if(comp && ws_deflate_compress(df, (const uint8_t *)"HelloWorld", 10, comp, &cap)) {
        uint8_t b[128];
        int     hl;
        /* 分片 1: rsv1=1, TEXT, fin=0 */
        size_t  half = cap / 2;
        if(half == 0)
            half = 1;
        hl = ws_frame_build_header(b, 0, 1, WS_OPCODE_TEXT, NULL, half);
        memcpy(b + hl, comp, half);
        WS_WRITE(sfd, b, (size_t)(hl + (int)half));
        /* 分片 2: CONT, fin=1 */
        hl = ws_frame_build_header(b, 1, 0, WS_OPCODE_CONT, NULL, cap - half);
        memcpy(b + hl, comp + half, (size_t)(cap - half));
        WS_WRITE(sfd, b, (size_t)(hl + (int)(cap - half)));

        g_ev = 1;
        for(int i = 0; i < 200; i++) {
            sevent_run_once(ctx);
            if(g_ev == 2)
                break;
        }
        if(g_ev == 2 && strcmp(g_msg, "HelloWorld") == 0 && g_frag_total == 10)
            ok = 1;
    }
    free(comp);
    ws_deflate_destroy(df);
    if(!ok)
        return 1;
    close(sfd);
    sevent_ws_destroy(ws);
    sevent_destroy(ctx);
    return 0;
}

static int t_deflate_rsv_reject(void) {
    /* RSV2/RSV3 置位 → 协议错误 → on_error */
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

    /* 构造 TEXT 帧但 rsv2=1 */
    uint8_t b[16];
    int     hl = ws_frame_build_header(b, 1, 0, WS_OPCODE_TEXT, NULL, 3);
    b[0]       |= 0x20; /* 设 RSV2 位 */
    memcpy(b + hl, "abc", 3);
    WS_WRITE(sfd, b, (size_t)(hl + 3));
    g_ev              = 0;
    sevent_timer *_tm = sevent_timer_register(ctx, 1, ev_tick, NULL);
    for(int i = 0; i < 100; i++) {
        sevent_run_once(ctx);
        if(g_ev == 3)
            break;
    }
    if(_tm)
        sevent_timer_unregister(ctx, _tm);
    int ok = (g_ev == 3);
    close(sfd);
    sevent_ws_destroy(ws);
    sevent_destroy(ctx);
    return ok ? 0 : 1;
}

#else /* !SEVENT_WS_DEFLATE */
static int t_deflate_create(void) { return 0; }
static int t_deflate_client_win_ok(void) { return 0; }
static int t_deflate_client_win_bad(void) { return 0; }
static int t_nct_config(void) { return 0; }
static int t_win_client_offer(void) { return 0; }
static int t_win_client_exceed(void) { return 0; }
static int t_win_server_offer(void) { return 0; }
static int t_win_server_active(void) { return 0; }
static int t_win_server_exceed(void) { return 0; }
static int t_win_server_bad(void) { return 0; }
static int t_deflate_unoffered_ext(void) { return 0; }
static int t_deflate_unoffered_unknown(void) { return 0; }
static int t_deflate_recv(void) { return 0; }
static int t_deflate_recv_large(void) { return 0; }
static int t_deflate_send(void) { return 0; }
static int t_deflate_send_bin(void) { return 0; }
static int t_deflate_send_large(void) { return 0; }
static int t_deflate_frag(void) { return 0; }
static int t_deflate_rsv_reject(void) { return 0; }
#endif

/* ===== close 在 on_message 中调用的测试 ===== */
static sevent_ws_conn *g_close_ws;
static int             g_close_msg_count;
static void            ev_msg_close_first(void *d, const void *m, size_t l, bool b, bool fin, uint64_t total) {
    (void)d;
    (void)m;
    (void)l;
    (void)b;
    (void)fin;
    (void)total;
    g_close_msg_count++;
    if(g_close_msg_count == 1 && g_close_ws)
        sevent_ws_close(g_close_ws);
}
static int t_close_in_on_message(void) {
    /* 验证 on_message 中调 sevent_ws_close 后不再收到后续帧回调 */
    sevent_context *ctx = sevent_create();
    if(!ctx)
        return 1;
    sevent_ws_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host          = "127.0.0.1";
    cfg.path          = "/";
    cfg.on_open       = ev_open;
    cfg.on_message    = ev_msg_close_first;
    cfg.on_close      = ev_close;
    cfg.on_error      = ev_error;
    g_ev              = 0;
    g_close_msg_count = 0;
    g_close_ws        = NULL;
    sevent_ws_conn *ws;
    int             sfd = pair(ctx, &cfg, &ws);
    if(sfd < 0)
        return 1;
    g_close_ws = ws;
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
    g_ev = 0;
    /* 一次写入 3 帧: "A", "B", "C" — 第 1 帧回调中调 close */
    uint8_t b[128];
    int     off = 0, hl;
    hl          = ws_frame_build_header(b + off, 1, 0, WS_OPCODE_TEXT, NULL, 1);
    b[off + hl] = 'A';
    off         += hl + 1;
    hl          = ws_frame_build_header(b + off, 1, 0, WS_OPCODE_TEXT, NULL, 1);
    b[off + hl] = 'B';
    off         += hl + 1;
    hl          = ws_frame_build_header(b + off, 1, 0, WS_OPCODE_TEXT, NULL, 1);
    b[off + hl] = 'C';
    off         += hl + 1;
    write_all(sfd, b, off);
    for(int i = 0; i < 50; i++) {
        sevent_run_once(ctx);
        if(g_close_msg_count >= 2)
            break;
    }
    /* 验证: 只有第 1 帧触发了 on_message, close 后不再处理后续帧 */
    int ok = (g_close_msg_count == 1);
    /* 确认连接已关闭: send 应返回错误 */
    ok     = ok && (sevent_ws_send_text(ws, "x", 1) != 0);
    close(sfd);
    sevent_ws_destroy(ws);
    sevent_destroy(ctx);
    return ok ? 0 : 1;
}

/* ===== 握手 + 粘包无效 WS 帧 → on_error ===== */
static int  g_pipe_err;
static void ev_error_pipe(void *d, int err) {
    (void)d;
    g_pipe_err = err;
    g_ev       = 3;
}
static int t_pipelined_proto_error(void) {
    /* HTTP 101 响应后附带无效 WS 帧数据 → on_error 应触发 */
    sevent_context *ctx = sevent_create();
    if(!ctx)
        return 1;
    sevent_ws_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host     = "127.0.0.1";
    cfg.path     = "/";
    cfg.on_open  = ev_open;
    cfg.on_error = ev_error_pipe;
    g_ev         = 0;
    g_pipe_err   = 0;
    sevent_ws_conn *ws;
    int             sfd = pair(ctx, &cfg, &ws);
    if(sfd < 0)
        return 1;
    sevent_run_once(ctx);
    /* 读 HTTP 请求, 计算 accept key, 回复 101 + 粘包无效数据 */
    char    b[4096];
    ssize_t n = read(sfd, b, sizeof(b) - 1);
    if(n <= 0)
        return 1;
    b[n]    = 0;
    char *k = strstr(b, "Sec-WebSocket-Key:");
    if(!k)
        return 1;
    k += 19;
    while(*k == ' ')
        k++;
    char  ke[256];
    char *e = strstr(k, "\r\n");
    if(!e)
        return 1;
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
    /* 101 响应 + 无效 WS 帧 (opcode = 0xFF 非法, 长度为 0) */
    char resp[1024];
    int  rn      = snprintf(resp,
                      sizeof(resp),
                      "HTTP/1.1 101 Switching Protocols\r\n"
                            "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                            "Sec-WebSocket-Accept: %s\r\n\r\n",
                      ac);
    resp[rn]     = (char)0xFF;
    resp[rn + 1] = 0;
    WS_WRITE(sfd, resp, (size_t)(rn + 2));
    for(int i = 0; i < 200; i++) {
        sevent_run_once(ctx);
        if(g_ev == 3)
            break;
    }
    int ok = (g_ev == 3 && g_pipe_err != 0);
    close(sfd);
    sevent_ws_destroy(ws);
    sevent_destroy(ctx);
    return ok ? 0 : 1;
}

/* ===== EOF + 流式 + 后续 CLOSE 帧 ===== */
static uint16_t g_close_code;
static void     ev_close_code(void *d, uint16_t co, const char *r, size_t rl) {
    (void)d;
    (void)r;
    (void)rl;
    g_close_code = co;
    g_ev         = 3;
}
static int t_eof_stream_trailing_close(void) {
    /* 大帧(> recv_cap) + 后续 CLOSE 帧一起写入, 然后关闭服务端连接
       验证缓冲区中 CLOSE 帧仍被正确处理 */
    sevent_context *ctx = sevent_create();
    if(!ctx)
        return 1;
    sevent_ws_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host          = "127.0.0.1";
    cfg.path          = "/";
    cfg.on_open       = ev_open;
    cfg.on_message    = ev_msg_frag;
    cfg.on_close      = ev_close_code;
    cfg.recv_buf_size = 4096;
    g_ev              = 0;
    g_frag_count      = 0;
    g_frag_total      = 0;
    g_frag_len        = 0;
    g_close_code      = 0;
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
    g_ev = 0;
    /* 一次写入: 大帧 5000 字节 + CLOSE 帧 (code 1000) */
    uint8_t b[8192];
    int     off = 0, hl;
    char    big[5000];
    memset(big, 'X', 5000);
    hl = ws_frame_build_header(b + off, 1, 0, WS_OPCODE_TEXT, NULL, 5000);
    memcpy(b + off + hl, big, 5000);
    off += hl + 5000;
    uint8_t cp[8];
    hl         = ws_frame_build_header(cp, 1, 0, WS_OPCODE_CLOSE, NULL, 2);
    cp[hl]     = (uint8_t)(1000 >> 8);
    cp[hl + 1] = (uint8_t)(1000);
    memcpy(b + off, cp, (size_t)(hl + 2));
    off += hl + 2;
    write_all(sfd, b, off);
    /* 立刻关服务端 fd 模拟 EOF */
    close(sfd);
    sfd = -1;
    for(int i = 0; i < 500; i++) {
        sevent_run_once(ctx);
        if(g_ev == 3)
            break;
    }
    /* on_close(code=1000) 应触发 (CLOSE 帧被处理, 而非 1006) */
    int ok = (g_close_code == 1000);
    if(sfd >= 0)
        close(sfd);
    sevent_ws_destroy(ws);
    sevent_destroy(ctx);
    return ok ? 0 : 1;
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
                 {"close_in_on_message", t_close_in_on_message},
                 {"pipelined_proto_error", t_pipelined_proto_error},
                 {"eof_stream_trailing_close", t_eof_stream_trailing_close},
                 {"deflate_create", t_deflate_create},
                 {"deflate_client_win_ok", t_deflate_client_win_ok},
                 {"deflate_client_win_bad", t_deflate_client_win_bad},
                 {"nct_config", t_nct_config},
                 {"win_client_offer", t_win_client_offer},
                 {"win_client_exceed", t_win_client_exceed},
                 {"win_server_offer", t_win_server_offer},
                 {"win_server_active", t_win_server_active},
                 {"win_server_exceed", t_win_server_exceed},
                 {"win_server_bad", t_win_server_bad},
                 {"deflate_unoffered_ext", t_deflate_unoffered_ext},
                 {"deflate_unoffered_unknown", t_deflate_unoffered_unknown},
                 {"deflate_recv", t_deflate_recv},
                 {"deflate_recv_large", t_deflate_recv_large},
                 {"deflate_send", t_deflate_send},
                 {"deflate_send_bin", t_deflate_send_bin},
                 {"deflate_send_large", t_deflate_send_large},
                 {"deflate_frag", t_deflate_frag},
                 {"deflate_rsv_reject", t_deflate_rsv_reject},
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
