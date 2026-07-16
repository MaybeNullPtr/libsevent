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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#ifdef SEVENT_WS_THREAD_SAFE
#include <pthread.h>
#endif

static int g_ev;
static char g_msg[256];

static void ev_open(void*d){(void)d;g_ev=1;}
static void ev_msg(void*d,const void*m,size_t l,int b){(void)d;(void)b;g_ev=2;size_t c=l<255?l:255;memcpy(g_msg,m,c);g_msg[c]=0;}
static void ev_close(void*d,uint16_t co,const char*r,size_t rl){(void)d;(void)co;(void)r;(void)rl;g_ev=3;}

/* pair: 创建 TCP 连接, 返回 sfd */
static int pair(sevent_context *ctx, struct sevent_ws_config *cfg, sevent_ws_conn **ws)
{
    int lfd=socket(AF_INET,SOCK_STREAM|SOCK_NONBLOCK,0);
    int o=1; setsockopt(lfd,SOL_SOCKET,SO_REUSEADDR,&o,sizeof(o));
    struct sockaddr_in ba; memset(&ba,0,sizeof(ba));
    ba.sin_family=AF_INET; ba.sin_port=htons(0);
    ba.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if(bind(lfd,(struct sockaddr*)&ba,sizeof(ba))<0||listen(lfd,1)<0){close(lfd);return -1;}
    struct sockaddr_in ga; socklen_t gl=sizeof(ga);
    getsockname(lfd,(struct sockaddr*)&ga,&gl);
    cfg->port=ntohs(ga.sin_port);
    *ws=sevent_ws_connect(ctx,cfg);
    if(!*ws){close(lfd);return -1;}
    struct sockaddr_in pa; socklen_t pl=sizeof(pa);
    int sfd;
    for(int i=0;i<100;i++){sfd=accept(lfd,(struct sockaddr*)&pa,&pl);if(sfd>=0)break;sevent_run_once(ctx);}
    if(sfd<0){close(lfd);return -1;}
    fcntl(sfd,F_SETFL,fcntl(sfd,F_GETFL)|O_NONBLOCK); close(lfd);
    return sfd;
}

/* shake: 服务端读 HTTP 请求 → 回复 101 */
static int shake(int sfd)
{
    char b[4096]; ssize_t n=read(sfd,b,sizeof(b)-1);
    if(n<=0)return -1;
    b[n]=0;
    char*k=strstr(b,"Sec-WebSocket-Key:"); if(!k)return -1;
    k+=19; while(*k==' ')k++;
    char ke[256]; char*e=strstr(k,"\r\n"); if(!e)return -1;
    size_t kl=(size_t)(e-k); if(kl>255)kl=255;
    memcpy(ke,k,kl); ke[kl]=0;
    char cat[384]; snprintf(cat,sizeof(cat),"%s%s",ke,WS_GUID);
    uint8_t dg[20]; ws_sha1(cat,strlen(cat),dg);
    char ac[64]; ws_base64_encode(dg,20,ac,sizeof(ac));
    char resp[512]; int rn=snprintf(resp,sizeof(resp),
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %s\r\n\r\n",ac);
    write(sfd,resp,(size_t)rn); return 0;
}

/* wsend: 服务端发 WS 帧 (无掩码) */
static void wsend(int fd, uint8_t op, const void *p, uint64_t l)
{
    uint8_t b[4096]; int h=ws_frame_build_header(b,1,op,NULL,l);
    if(p&&l) memcpy(b+h,p,(size_t)l);
    write(fd,b,(size_t)(h+(int)l));
}

/* wread: 服务端读 WS 帧, 返回 payload 长度 */
static int wread(int fd, ws_frame_header *hdr, uint8_t *pay, size_t cap)
{
    uint8_t b[4096]; ssize_t n=read(fd,b,sizeof(b)); if(n<=0)return -1;
    int r=ws_frame_parse_header(b,(size_t)n,hdr); if(r<=0)return -1;
    size_t pl=(size_t)hdr->payload_len; if(pl>cap)pl=cap;
    if(hdr->mask) ws_frame_apply_mask(b+r,hdr->payload_len,hdr->mask_key);
    memcpy(pay,b+r,pl); return (int)pl;
}

/* ===== 测试用例 ===== */
static int t_lifecycle(void)
{
    sevent_context *ctx=sevent_create(); if(!ctx)return 1;
    struct sevent_ws_config cfg; memset(&cfg,0,sizeof(cfg));
    cfg.host="127.0.0.1"; cfg.path="/"; cfg.on_open=ev_open; cfg.on_message=ev_msg; cfg.on_close=ev_close;
    g_ev=0; sevent_ws_conn *ws; int sfd=pair(ctx,&cfg,&ws); if(sfd<0)return 1;
    sevent_run_once(ctx); if(shake(sfd)<0)return 1;
    for(int i=0;i<200;i++){sevent_run_once(ctx);if(g_ev==1)break;} if(g_ev!=1)return 1;
    wsend(sfd,WS_OPCODE_TEXT,"Hello",5); g_ev=1;
    for(int i=0;i<50;i++){sevent_run_once(ctx);if(g_ev==2)break;} if(g_ev!=2||strcmp(g_msg,"Hello"))return 1;
    uint8_t cp[6]; int hl=ws_frame_build_header(cp,1,WS_OPCODE_CLOSE,NULL,2);
    cp[hl]=0x03; cp[hl+1]=(uint8_t)0xE8; write(sfd,cp,(size_t)(hl+2)); g_ev=2;
    for(int i=0;i<100;i++){sevent_run_once(ctx);if(g_ev==3)break;} if(g_ev!=3)return 1;
    close(sfd); sevent_ws_destroy(ws); sevent_destroy(ctx); return 0;
}

static int t_client_send_text(void)
{
    sevent_context *ctx=sevent_create(); if(!ctx)return 1;
    struct sevent_ws_config cfg; memset(&cfg,0,sizeof(cfg));
    cfg.host="127.0.0.1"; cfg.path="/"; cfg.on_open=ev_open;
    g_ev=0; sevent_ws_conn *ws; int sfd=pair(ctx,&cfg,&ws); if(sfd<0)return 1;
    sevent_run_once(ctx); if(shake(sfd)<0)return 1;
    for(int i=0;i<200;i++){sevent_run_once(ctx);if(g_ev==1)break;} if(g_ev!=1)return 1;
    if(sevent_ws_send_text(ws,"Hi",2)!=0)return 1;
    ws_frame_header h; uint8_t pay[128];
    if(wread(sfd,&h,pay,sizeof(pay))<1||h.opcode!=WS_OPCODE_TEXT||memcmp("Hi",pay,2))return 1;
    close(sfd); sevent_ws_destroy(ws); sevent_destroy(ctx); return 0;
}

static int t_client_send_binary(void)
{
    sevent_context *ctx=sevent_create(); if(!ctx)return 1;
    struct sevent_ws_config cfg; memset(&cfg,0,sizeof(cfg));
    cfg.host="127.0.0.1"; cfg.path="/"; cfg.on_open=ev_open;
    g_ev=0; sevent_ws_conn *ws; int sfd=pair(ctx,&cfg,&ws); if(sfd<0)return 1;
    sevent_run_once(ctx); if(shake(sfd)<0)return 1;
    for(int i=0;i<200;i++){sevent_run_once(ctx);if(g_ev==1)break;} if(g_ev!=1)return 1;
    if(sevent_ws_send_binary(ws,"\x00\xFF\xAB",3)!=0)return 1;
    ws_frame_header h; uint8_t pay[128];
    if(wread(sfd,&h,pay,sizeof(pay))<1||h.opcode!=WS_OPCODE_BINARY)return 1;
    if(pay[0]!=0||pay[1]!=0xFF||pay[2]!=0xAB)return 1;
    close(sfd); sevent_ws_destroy(ws); sevent_destroy(ctx); return 0;
}

static int t_auto_pong(void)
{
    sevent_context *ctx=sevent_create(); if(!ctx)return 1;
    struct sevent_ws_config cfg; memset(&cfg,0,sizeof(cfg));
    cfg.host="127.0.0.1"; cfg.path="/"; cfg.on_open=ev_open;
    g_ev=0; sevent_ws_conn *ws; int sfd=pair(ctx,&cfg,&ws); if(sfd<0)return 1;
    sevent_run_once(ctx); if(shake(sfd)<0)return 1;
    for(int i=0;i<200;i++){sevent_run_once(ctx);if(g_ev==1)break;} if(g_ev!=1)return 1;
    wsend(sfd,WS_OPCODE_PING,NULL,0);
    ws_frame_header h; uint8_t pay[128]; int pl=-1;
    for(int i=0;i<50;i++){pl=wread(sfd,&h,pay,sizeof(pay));if(pl>=0&&h.opcode==WS_OPCODE_PONG)break;sevent_run_once(ctx);}
    if(pl<0||h.opcode!=WS_OPCODE_PONG)return 1;
    close(sfd); sevent_ws_destroy(ws); sevent_destroy(ctx); return 0;
}

static int t_large_msg(void)
{
    sevent_context *ctx=sevent_create(); if(!ctx)return 1;
    struct sevent_ws_config cfg; memset(&cfg,0,sizeof(cfg));
    cfg.host="127.0.0.1"; cfg.path="/"; cfg.on_open=ev_open; cfg.on_message=ev_msg;
    g_ev=0; sevent_ws_conn *ws; int sfd=pair(ctx,&cfg,&ws); if(sfd<0)return 1;
    sevent_run_once(ctx); if(shake(sfd)<0)return 1;
    for(int i=0;i<200;i++){sevent_run_once(ctx);if(g_ev==1)break;} if(g_ev!=1)return 1;
    char big[200]; memset(big,'X',200); wsend(sfd,WS_OPCODE_TEXT,big,200); g_ev=1;
    for(int i=0;i<50;i++){sevent_run_once(ctx);if(g_ev==2)break;} if(g_ev!=2||strlen(g_msg)!=200)return 1;
    close(sfd); sevent_ws_destroy(ws); sevent_destroy(ctx); return 0;
}

static int t_client_ping(void)
{
    sevent_context *ctx=sevent_create(); if(!ctx)return 1;
    struct sevent_ws_config cfg; memset(&cfg,0,sizeof(cfg));
    cfg.host="127.0.0.1"; cfg.path="/"; cfg.on_open=ev_open;
    g_ev=0; sevent_ws_conn *ws; int sfd=pair(ctx,&cfg,&ws); if(sfd<0)return 1;
    sevent_run_once(ctx); if(shake(sfd)<0)return 1;
    for(int i=0;i<200;i++){sevent_run_once(ctx);if(g_ev==1)break;} if(g_ev!=1)return 1;
    if(sevent_ws_ping(ws,"ping",4)!=0)return 1;
    ws_frame_header h; uint8_t pay[128];
    if(wread(sfd,&h,pay,sizeof(pay))<0||h.opcode!=WS_OPCODE_PING)return 1;
    close(sfd); sevent_ws_destroy(ws); sevent_destroy(ctx); return 0;
}

static int t_client_close(void)
{
    sevent_context *ctx=sevent_create(); if(!ctx)return 1;
    struct sevent_ws_config cfg; memset(&cfg,0,sizeof(cfg));
    cfg.host="127.0.0.1"; cfg.path="/"; cfg.on_open=ev_open; cfg.on_close=ev_close;
    g_ev=0; sevent_ws_conn *ws; int sfd=pair(ctx,&cfg,&ws); if(sfd<0)return 1;
    sevent_run_once(ctx); if(shake(sfd)<0)return 1;
    for(int i=0;i<200;i++){sevent_run_once(ctx);if(g_ev==1)break;} if(g_ev!=1)return 1;
    if(sevent_ws_close(ws,1000,"bye")!=0)return 1;
    ws_frame_header h; uint8_t pay[128]; int plen=wread(sfd,&h,pay,sizeof(pay));
    if(plen<1||h.opcode!=WS_OPCODE_CLOSE)return 1;
    uint16_t code=(uint16_t)((pay[0]<<8)|pay[1]); if(code!=1000)return 1;
    uint8_t cp[8]; int hl=ws_frame_build_header(cp,1,WS_OPCODE_CLOSE,NULL,2);
    cp[hl]=pay[0]; cp[hl+1]=pay[1]; write(sfd,cp,(size_t)(hl+2)); g_ev=2;
    for(int i=0;i<50;i++){sevent_run_once(ctx);if(g_ev==3)break;} if(g_ev!=3)return 1;
    close(sfd); sevent_ws_destroy(ws); sevent_destroy(ctx); return 0;
}

static int t_state_checks(void)
{
    sevent_context *ctx=sevent_create(); if(!ctx)return 1;
    int fds[2]; if(socketpair(AF_UNIX,SOCK_STREAM,0,fds))return 1;
    struct sevent_ws_conn *c=calloc(1,sizeof(*c)); if(!c)return 1;
    c->ev=ctx; c->fd=fds[1];
    c->state=4; /* WS_STATE_CLOSED */
    if(sevent_ws_send_text(c,"x",1)!=-1)return 1;
    if(sevent_ws_send_binary(c,"x",1)!=-1)return 1;
    if(sevent_ws_ping(c,NULL,0)!=-1)return 1;
    if(sevent_ws_close(c,1000,"")!=-1)return 1;
    c->state=0; /* CONNECTING */
    if(sevent_ws_send_text(c,"x",1)!=-1)return 1;
    close(fds[0]); c->fd=-1;
    sevent_ws_destroy(c); sevent_destroy(ctx); return 0;
}

#ifdef SEVENT_WS_THREAD_SAFE
struct thr_arg { sevent_ws_conn *ws; int result; };

static void *thr_send_text(void *a)
{
    struct thr_arg *ta = (struct thr_arg *)a;
    ta->result = sevent_ws_send_text(ta->ws, "cross", 5);
    return NULL;
}

static void *thr_close(void *a)
{
    struct thr_arg *ta = (struct thr_arg *)a;
    ta->result = sevent_ws_close(ta->ws, 1000, "");
    return NULL;
}

/* 跨线程 send_text: 从工作线程调用, 验证数据到达 */
static int t_cross_thread_send(void)
{
    sevent_context *ctx = sevent_create(); if (!ctx) return 1;
    struct sevent_ws_config cfg; memset(&cfg,0,sizeof(cfg));
    cfg.host="127.0.0.1"; cfg.path="/"; cfg.on_open=ev_open; cfg.on_message=ev_msg;
    g_ev=0; sevent_ws_conn *ws; int sfd=pair(ctx,&cfg,&ws); if(sfd<0)return 1;
    sevent_run_once(ctx); if(shake(sfd)<0)return 1;
    for(int i=0;i<200;i++){sevent_run_once(ctx);if(g_ev==1)break;} if(g_ev!=1)return 1;

    struct thr_arg a = {ws, -1};
    pthread_t thr;
    if (pthread_create(&thr, NULL, thr_send_text, &a) != 0) return 1;
    pthread_join(thr, NULL);
    if (a.result != 0) return 1;

    /* 读服务端收到的帧 */
    ws_frame_header h; uint8_t pay[128]; int pl=-1;
    for (int i=0;i<50;i++){pl=wread(sfd,&h,pay,sizeof(pay));if(pl>=0)break;sevent_run_once(ctx);}
    if(pl<1||h.opcode!=WS_OPCODE_TEXT||memcmp(pay,"cross",5))return 1;

    close(sfd); sevent_ws_destroy(ws); sevent_destroy(ctx); return 0;
}

/* 跨线程 close: 从工作线程调用, 验证 on_close 触发 */
static int t_cross_thread_close(void)
{
    sevent_context *ctx = sevent_create(); if (!ctx) return 1;
    struct sevent_ws_config cfg; memset(&cfg,0,sizeof(cfg));
    cfg.host="127.0.0.1"; cfg.path="/"; cfg.on_open=ev_open; cfg.on_close=ev_close;
    g_ev=0; sevent_ws_conn *ws; int sfd=pair(ctx,&cfg,&ws); if(sfd<0)return 1;
    sevent_run_once(ctx); if(shake(sfd)<0)return 1;
    for(int i=0;i<200;i++){sevent_run_once(ctx);if(g_ev==1)break;} if(g_ev!=1)return 1;

    struct thr_arg a = {ws, -1};
    pthread_t thr;
    if (pthread_create(&thr, NULL, thr_close, &a) != 0) return 1;
    pthread_join(thr, NULL);
    if (a.result != 0) return 1;

    /* 读服务端收到的 Close 帧 */
    ws_frame_header h; uint8_t pay[128]; int pl=-1;
    for (int i=0;i<50;i++){pl=wread(sfd,&h,pay,sizeof(pay));if(pl>=0)break;sevent_run_once(ctx);}
    if(pl<1||h.opcode!=WS_OPCODE_CLOSE)return 1;

    /* 回 Close 帧 */
    uint8_t cp[4]; int hl=ws_frame_build_header(cp,1,WS_OPCODE_CLOSE,NULL,2);
    cp[hl]=pay[0]; cp[hl+1]=pay[1]; write(sfd,cp,(size_t)(hl+2));
    g_ev=2;
    for(int i=0;i<50;i++){sevent_run_once(ctx);if(g_ev==3)break;}
    if(g_ev!=3)return 1;

    close(sfd); sevent_ws_destroy(ws); sevent_destroy(ctx); return 0;
}
#else
static int t_cross_thread_send(void) { return 0; }
static int t_cross_thread_close(void) { return 0; }
#endif

int main(void)
{
    struct {const char*n;int(*f)(void);} tests[]={
        {"lifecycle",t_lifecycle},{"client_send_text",t_client_send_text},
        {"client_send_binary",t_client_send_binary},{"auto_pong",t_auto_pong},
        {"large_msg",t_large_msg},{"client_ping",t_client_ping},
        {"client_close",t_client_close},{"state_checks",t_state_checks},
        {"cross_thread_send",t_cross_thread_send},
        {"cross_thread_close",t_cross_thread_close},
        {NULL,NULL}
    };
    printf("ws_conn tests\n"); printf("=============\n");
    int ok=0,fail=0;
    for(int i=0;tests[i].n;i++){
        printf("  %-24s ",tests[i].n);
        int r=tests[i].f();
        if(r){printf("×\n");fail++;}else{printf("✓\n");ok++;}
    }
    printf("\n%d/%d passed\n",ok,ok+fail);
    return fail?1:0;
}
