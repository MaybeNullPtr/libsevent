/**
 *  autobahn_echo_server.c — Kosoku/Autobahn 合规测试 echo 服务端
 *
 *  用 libsevent 做事件循环 + ws_frame.c 做帧编解码。
 *  Kosoku 以 fuzzingclient 模式连入，发送各种帧组合，
 *  本服务端回显，Kosoku 验证帧层正确性。
 *
 *  用法: ./autobahn_echo_server [port]
 */

#include "sevent.h"
#include "ws_frame.h"
#include "ws_sha1.h"
#include "ws_base64.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* ---- 每个客户端连接的状态 ---- */
typedef struct client {
    struct client *next;
    int            fd;
    sevent_io     *io;
    uint8_t        recv_buf[65536];
    size_t         recv_len;
    int            handshake_done; /* 0=等待握手, 1=WS 已建立 */
} client_t;

static sevent_context *g_ctx;
static int             g_listen_fd;
static client_t       *g_clients;
static int             g_quit;

/* ---------------------------------------------------------------
 *  SHA1 + Base64: 计算 Sec-WebSocket-Accept
 * --------------------------------------------------------------- */
static void compute_accept(const char *key, char *out, size_t out_cap) {
    char concat[256];
    int  n = snprintf(concat, sizeof(concat), "%s%s", key, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    if(n < 0 || (size_t)n >= sizeof(concat))
        return;

    uint8_t digest[20];
    ws_sha1(concat, (size_t)n, digest);
    ws_base64_encode(digest, 20, out, out_cap);
}

/* ---------------------------------------------------------------
 *  构造 WS 升级响应
 * --------------------------------------------------------------- */
static int build_101_response(const uint8_t *req, size_t req_len, char *resp, size_t resp_cap) {
    /* 找 Sec-WebSocket-Key */
    const char *key_hdr = "Sec-WebSocket-Key:";
    const char *p       = (const char *)req;
    const char *end     = p + req_len;

    while(p && p < end) {
        const char *line = p;
        const char *nl   = (const char *)memchr(p, '\n', (size_t)(end - p));
        if(!nl)
            break;

        size_t llen = (size_t)(nl - p);
        if(llen > 0 && p[llen - 1] == '\r')
            llen--;

        /* 大小写不敏感比较 */
        if(llen > strlen(key_hdr)) {
            int match = 1;
            for(size_t i = 0; key_hdr[i]; i++) {
                char a = line[i], b = key_hdr[i];
                if(a >= 'A' && a <= 'Z')
                    a += 0x20;
                if(b >= 'A' && b <= 'Z')
                    b += 0x20;
                if(a != b) {
                    match = 0;
                    break;
                }
            }
            if(match) {
                const char *val_start = line + strlen(key_hdr);
                while(val_start < nl && (*val_start == ' ' || *val_start == '\t'))
                    val_start++;
                size_t vlen = (size_t)(nl - val_start);
                if(vlen > 0 && val_start[vlen - 1] == '\r')
                    vlen--;
                if(vlen > 128)
                    vlen = 128;
                char key[128] = {0};
                memcpy(key, val_start, vlen);
                key[vlen] = '\0';

                char accept[32];
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

/* ---------------------------------------------------------------
 *  帧回显: 收到的 TEXT/BINARY 原样发回, 控制帧让库自动处理
 * --------------------------------------------------------------- */
static void echo_payload(client_t *cl, const ws_frame_header *hdr, const uint8_t *payload) {
    if((hdr->opcode == WS_OPCODE_TEXT || hdr->opcode == WS_OPCODE_BINARY) && hdr->fin) {
        /* 向客户端发回 echo (server→client, 无掩码) */
        uint8_t hdr_buf[16];
        int     hlen = ws_frame_build_header(hdr_buf, 1, 0, hdr->opcode, NULL, hdr->payload_len);
        if(hlen <= 0)
            return;

        uint8_t *resp = (uint8_t *)malloc((size_t)hlen + (size_t)hdr->payload_len);
        if(!resp)
            return;
        memcpy(resp, hdr_buf, (size_t)hlen);
        memcpy(resp + hlen, payload, (size_t)hdr->payload_len);

        write(cl->fd, resp, (size_t)(hlen + hdr->payload_len));
        free(resp);
    }
    /* 控制帧 (CLOSE/PING/PONG) 的回显:
       - PING: 自动回 PONG（对方跟踪）
       - CLOSE: 回 CLOSE 帧（对方也跟踪）*/
    if(hdr->opcode == WS_OPCODE_PING) {
        uint8_t hdr_buf[16];
        int     hlen = ws_frame_build_header(hdr_buf, 1, 0, WS_OPCODE_PONG, NULL, hdr->payload_len);
        if(hlen <= 0)
            return;
        uint8_t *resp = (uint8_t *)malloc((size_t)hlen + (size_t)hdr->payload_len);
        if(!resp)
            return;
        memcpy(resp, hdr_buf, (size_t)hlen);
        memcpy(resp + hlen, payload, (size_t)hdr->payload_len);
        write(cl->fd, resp, (size_t)(hlen + hdr->payload_len));
        free(resp);
    }
    if(hdr->opcode == WS_OPCODE_CLOSE) {
        uint8_t hdr_buf[16];
        int     hlen = ws_frame_build_header(hdr_buf, 1, 0, WS_OPCODE_CLOSE, NULL, hdr->payload_len);
        if(hlen <= 0)
            return;
        uint8_t *resp = (uint8_t *)malloc((size_t)hlen + (size_t)hdr->payload_len);
        if(!resp)
            return;
        memcpy(resp, hdr_buf, (size_t)hlen);
        memcpy(resp + hlen, payload, (size_t)hdr->payload_len);
        write(cl->fd, resp, (size_t)(hlen + hdr->payload_len));
        free(resp);
    }
}

/* ---------------------------------------------------------------
 *  IO 回调: 客户端可读
 * --------------------------------------------------------------- */
static void on_client_read(void *data) {
    client_t *cl = (client_t *)data;

    ssize_t n = read(cl->fd, cl->recv_buf + cl->recv_len, sizeof(cl->recv_buf) - cl->recv_len);
    if(n <= 0) {
        /* 关闭连接 */
        if(cl->io) {
            sevent_io_unregister(g_ctx, cl->io);
            cl->io = NULL;
        }
        close(cl->fd);
        /* 从链表移除 */
        client_t **pp = &g_clients;
        while(*pp) {
            if(*pp == cl) {
                *pp = cl->next;
                break;
            }
            pp = &(*pp)->next;
        }
        free(cl);
        if(g_quit && !g_clients)
            sevent_stop(g_ctx);
        return;
    }
    cl->recv_len += (size_t)n;

    if(!cl->handshake_done) {
        /* 尝试握手 */
        char resp[512];
        int  rlen = build_101_response(cl->recv_buf, cl->recv_len, resp, sizeof(resp));
        if(rlen < 0) {
            /* 数据不足暂等或非法 */
            return;
        }
        write(cl->fd, resp, (size_t)rlen);
        cl->handshake_done = 1;
        cl->recv_len       = 0;
        return;
    }

    /* WS 帧处理: 循环解析所有完整帧 */
    size_t pos = 0;
    while(pos < cl->recv_len) {
        ws_frame_header hdr;
        int             hlen = ws_frame_parse_header(cl->recv_buf + pos, cl->recv_len - pos, &hdr);
        if(hlen == 0)
            break; /* 帧不完整 */
        if(hlen < 0) {
            /* 协议错误 → 断开 */
            if(cl->io) {
                sevent_io_unregister(g_ctx, cl->io);
                cl->io = NULL;
            }
            close(cl->fd);
            client_t **pp = &g_clients;
            while(*pp) {
                if(*pp == cl) {
                    *pp = cl->next;
                    break;
                }
                pp = &(*pp)->next;
            }
            free(cl);
            return;
        }
        size_t frame_size = (size_t)hlen + (size_t)hdr.payload_len;
        if(cl->recv_len - pos < frame_size)
            break;

        uint8_t *payload = cl->recv_buf + pos + hlen;
        if(hdr.mask)
            ws_frame_apply_mask(payload, hdr.payload_len, hdr.mask_key);

        echo_payload(cl, &hdr, payload);
        pos += frame_size;
    }

    if(pos > 0) {
        if(pos < cl->recv_len)
            memmove(cl->recv_buf, cl->recv_buf + pos, cl->recv_len - pos);
        cl->recv_len -= pos;
    }
}

/* ---------------------------------------------------------------
 *  监听 socket 可读: accept 新连接
 * --------------------------------------------------------------- */
static void on_accept(void *data) {
    (void)data;
    struct sockaddr_in addr;
    socklen_t          addrlen = sizeof(addr);
    int                cfd     = accept(g_listen_fd, (struct sockaddr *)&addr, &addrlen);
    if(cfd < 0)
        return;

    fcntl(cfd, F_SETFL, fcntl(cfd, F_GETFL) | O_NONBLOCK);

    client_t *cl = (client_t *)calloc(1, sizeof(client_t));
    if(!cl) {
        close(cfd);
        return;
    }
    cl->fd = cfd;

    sevent_io_handler h;
    h.fd       = cfd;
    h.io_read  = on_client_read;
    h.io_write = NULL;
    h.data     = cl;
    cl->io     = sevent_io_register(g_ctx, &h);
    if(!cl->io) {
        close(cfd);
        free(cl);
        return;
    }

    cl->next  = g_clients;
    g_clients = cl;
}

int main(int argc, char **argv) {
    int port = argc > 1 ? atoi(argv[1]) : 9001;
    if(port <= 0)
        port = 9001;

    g_ctx = sevent_create();
    if(!g_ctx) {
        fprintf(stderr, "create fail\n");
        return 1;
    }
    sevent_ignore_sigpipe();

    g_listen_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if(g_listen_fd < 0) {
        perror("socket");
        return 1;
    }

    int opt = 1;
    setsockopt(g_listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons((uint16_t)port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if(bind(g_listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(g_listen_fd);
        return 1;
    }
    if(listen(g_listen_fd, 5) < 0) {
        perror("listen");
        close(g_listen_fd);
        return 1;
    }

    /* 把 listen_fd 注册到事件循环 */
    {
        sevent_io_handler h;
        h.fd       = g_listen_fd;
        h.io_read  = on_accept;
        h.io_write = NULL;
        h.data     = NULL;
        if(!sevent_io_register(g_ctx, &h)) {
            fprintf(stderr, "io_register fail\n");
            close(g_listen_fd);
            return 1;
        }
    }

    printf("Echo server ready on port %d\n", port);
    printf("Run: kosoku -m fuzzingclient ws://127.0.0.1:%d\n", port);
    fflush(stdout);

    sevent_run(g_ctx);

    /* 清理 */
    while(g_clients) {
        client_t *cl = g_clients;
        g_clients    = cl->next;
        if(cl->io)
            sevent_io_unregister(g_ctx, cl->io);
        close(cl->fd);
        free(cl);
    }
    close(g_listen_fd);
    sevent_destroy(g_ctx);
    return 0;
}
