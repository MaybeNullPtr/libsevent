/* =========================================================================
 *  tls_conn.c — TLS 传输实现 (sevent_stream_conn 抽象, 组合 tcp_conn)
 *
 *  架构 (doc/ssl-design.md, F 方案):
 *    tls_conn 组合 tcp_conn 作底层字节流 — TCP 建连/事件/写队列/destroy
 *    全部复用; ssl 层 (src/ssl/) 是数据通道 (feed/drain), 不碰 fd.
 *
 *    用户 ⇄ TLS 明文 ⇄ ssl 层(加解密) ⇄ TLS 密文 ⇄ tcp_conn ⇄ fd
 *
 *  生命周期:
 *    create → open/accept → (TCP 建连 → TLS 握手 → on_open) → write
 *            → EOF/error (on_close/on_error, 状态自动回 IDLE 可重开)
 *            → close (可重开) → destroy (统一 post 延迟释放)
 *
 *  回调安全: 用户回调 (on_open/on_data/on_close/on_error) 内可调 write/close/
 *  destroy — 各循环在用户回调返回后检查 ssl 是否已被释放 (回调内 close 幂等).
 *
 *  回调映射 (tcp 回调 = tls 内部函数):
 *    tcp on_open  → 创建 ssl + 握手驱动
 *    tcp on_data  → feed 密文 + 驱动握手/读明文
 *    tcp on_close → peer_close + 耗尽剩余明文 → 用户 on_close (EOF)
 *    tcp on_error → 映射 SEVENT_ERR_* → 用户 on_error
 *
 *  写路径: 明文同步 SSL_write (drain 密文 → tcp.write 循环), 无队列;
 *  极端 WANT_READ (TLS1.3 密钥更新) 时剩余明文暂存, tcp on_data 续写.
 *  ========================================================================= */

#include <stdlib.h>
#include <string.h>

#include "sevent_i.h"
#include "sevent_stream_conn.h"
#include "sevent_stream_conn_i.h"
#include "sevent_tcp_conn.h"
#include "sevent_tls_conn.h"
#include "ssl/ssl.h"
#include "ssl/ssl_i.h" /* 壳内部布局 (get_ssl 取 impl) */

#ifdef SEVENT_WS_TLS

/* ===== 内部结构 ===== */

struct tls_conn {
    sevent_context         *ev;
    sevent_tcp_conn        *tcp;     /* 底层字节流 (组合) */
    sevent_ssl             *ssl_ctx; /* TLS 配置 (create 时创建) */
    sevent_ssl             *ssl;     /* TLS 连接 (tcp 建连后创建) */
    bool                    is_server;
    bool                    established; /* open/accept 已启动 (防重复) */
    bool                    handshake_done;
    bool                    closed_notified; /* on_close 幂等 */
    bool                    destroyed;
    char                   *hostname; /* 客户端 SNI/校验 (sevent_i_malloc 拷贝; accept=NULL) */
    sevent_stream_conn_init init;     /* 回调组 + 连接配置 (每轮建立重置) */
    /* pending 明文写 (SSL WANT_READ 时暂存, tcp on_data 续写) */
    uint8_t                *pending_buf;
    size_t                  pending_len, pending_cap;
};

/* ===== 内部函数前置声明 ===== */

static void tls_start_handshake(struct tls_conn *t);
static void tls_read_plain(struct tls_conn *t);
static int  tls_send_cipher(struct tls_conn *t); /* 0=正常; -1=tls_fail 已通知 */
static void tls_fail(struct tls_conn *t, int err);

/* ===== 错误上报 (一次性) ===== */

/* 终结后复位连接态 (EOF/error → 回 IDLE 可重开, 与 tcp_conn 契约一致).
 * 先复位再通知: on_error/on_close 回调内可直接 open.
 * 仅清连接态 — hostname (对象级) 与 ssl_ctx 保留. */
static void tls_reset_after_term(struct tls_conn *t) {
    if(t->ssl) {
        sevent_ssl_free(t->ssl);
        t->ssl = NULL;
    }
    sevent_i_free(t->pending_buf);
    t->pending_buf = NULL;
    t->pending_len = t->pending_cap = 0;
    t->established                  = false;
    t->handshake_done               = false;
    t->closed_notified              = false; /* 重开后新一轮通知 */
}

static void tls_fail(struct tls_conn *t, int err) {
    bool notify = !t->closed_notified;
    tls_reset_after_term(t);
    if(notify && t->init.on_error) {
        t->closed_notified = true;
        t->init.on_error(t->init.user_data, err);
    }
}

static void tls_notify_close(struct tls_conn *t) {
    if(t->closed_notified)
        return;
    tls_reset_after_term(t);
    t->closed_notified = true;
    if(t->init.on_close)
        t->init.on_close(t->init.user_data);
}

/* ===== 密文搬运: SSL 产出 → tcp 写队列 ===== */

/* 返回: 0=正常; -1=tls_fail 已通知 (on_error 回调内可能 close/destroy, 调用方须停止);
 *        1=tcp 已收尾 — EOF/close 后 openssl 仍会产出 close_notify/alert, 但底层
 *          已关闭无处可送, 非错误 (调用方继续让 read 走完 EOF 流程) */
static int tls_send_cipher(struct tls_conn *t) {
    if(!t->ssl)
        return 1; /* 用户回调内已 close: 连接已终结, 同 tcp 收尾语义 */
    uint8_t buf[16384];
    ssize_t n;
    while((n = sevent_ssl_drain(t->ssl, buf, sizeof(buf))) > 0) {
        int wrc = sevent_tcp_conn_write(t->tcp, buf, (size_t)n);
        if(wrc == SEVENT_ERR_INVAL)
            return 1; /* tcp 已收尾, 密文丢弃 */
        if(wrc != 0) {
            tls_fail(t, SEVENT_ERR_WRITE);
            return -1;
        }
    }
    return 0;
}

/* ===== 读明文推用户 (直到 WANT 或 EOF/错误) ===== */

static void tls_read_plain(struct tls_conn *t) {
    uint8_t buf[16384];
    for(;;) {
        /* 用户回调 (on_data) 内可能 close/destroy — ssl 已释放则停止 */
        if(t->destroyed || !t->ssl)
            return;
        ssize_t r = sevent_ssl_read(t->ssl, buf, sizeof(buf));
        if(tls_send_cipher(t) < 0) /* read 也可能产出密文 (TLS1.3 key update 等);
                                    * ==1 (tcp 已收尾) 继续走 EOF 流程 */
            return;
        if(r > 0) {
            if(t->init.on_data)
                t->init.on_data(t->init.user_data, buf, (size_t)r);
            continue; /* 循环开头检查 ssl */
        }
        if(r == 0) {
            tls_notify_close(t); /* EOF: tcp on_close 已 peer_close, 密文耗尽 */
            return;
        }
        if(sevent_ssl_want(t->ssl) != 0)
            return; /* WANT_READ/WANT_WRITE: 等事件 */
        tls_fail(t, SEVENT_ERR_READ);
        return;
    }
}

/* ===== 握手驱动 ===== */

static void tls_pump_handshake(struct tls_conn *t) {
    for(;;) {
        if(t->destroyed || !t->ssl)
            return; /* on_error/on_open 回调内可能 close/destroy */
        int rc = sevent_ssl_handshake(t->ssl);
        /* 每次驱动后取密文: WANT_READ 时 SSL 可能已产出 ClientHello 等
         * (send 缓冲), 不取则对端永远收不到 */
        if(tls_send_cipher(t) < 0)
            return;
        if(rc == 0) {
            t->handshake_done = true;
            if(t->init.on_open)
                t->init.on_open(t->init.user_data);
            tls_read_plain(t); /* 对端可能立即发数据; 内部检查 ssl */
            return;
        }
        if(rc == SEVENT_SSL_WANT_READ)
            return; /* 等 tcp on_data (密文) */
        if(rc == SEVENT_SSL_WANT_WRITE)
            continue; /* 通道已清空, 重试 */
        tls_fail(t, SEVENT_ERR_HANDSHAKE);
        return;
    }
}

static void tls_start_handshake(struct tls_conn *t) {
    if(t->destroyed)
        return;
    t->ssl = sevent_ssl_new(t->ssl_ctx, t->is_server, t->hostname);
    if(!t->ssl) {
        tls_fail(t, SEVENT_ERR_HANDSHAKE);
        return;
    }
    tls_pump_handshake(t);
}

/* ===== pending 明文写 (极端 WANT_READ) ===== */

static bool tls_park_write(struct tls_conn *t, const uint8_t *data, size_t len) {
    if(len > t->pending_cap) {
        uint8_t *nb = (uint8_t *)sevent_i_malloc(len); /* 无 realloc 先例: 手动扩 */
        if(!nb)
            return false;
        sevent_i_free(t->pending_buf);
        t->pending_buf = nb;
        t->pending_cap = len;
    }
    memcpy(t->pending_buf, data, len);
    t->pending_len = len;
    return true;
}

/* 续写 pending 明文 (tcp on_data 时调用 — SSL 需要读密文才能继续写) */
static void tls_flush_pending(struct tls_conn *t) {
    if(!t->pending_len || t->destroyed)
        return;
    const uint8_t *p    = t->pending_buf;
    size_t         left = t->pending_len;
    while(left > 0) {
        if(t->destroyed || !t->ssl)
            break; /* 回调内 close/destroy */
        ssize_t n = sevent_ssl_write(t->ssl, p, left);
        if(n > 0) {
            p    += n;
            left -= (size_t)n;
            if(tls_send_cipher(t) != 0)
                break;
            continue;
        }
        if(n == 0) {
            if(tls_send_cipher(t) != 0) /* WANT_WRITE: 清通道重试 */
                break;
            continue;
        }
        tls_fail(t, SEVENT_ERR_WRITE);
        break;
    }
    t->pending_len = 0; /* 剩余丢弃 (fail 时同) */
}

/* ===== tcp 内部回调 (密文层) ===== */

static void tcp_cb_open(void *d) {
    struct tls_conn *t = (struct tls_conn *)d;
    tls_start_handshake(t);
}

static void tcp_cb_data(void *d, const uint8_t *data, size_t len) {
    struct tls_conn *t = (struct tls_conn *)d;
    if(t->destroyed || !t->ssl)
        return;
    if(sevent_ssl_feed(t->ssl, data, len) != 0) {
        tls_fail(t, SEVENT_ERR_READ);
        return;
    }
    if(!t->handshake_done) {
        tls_pump_handshake(t); /* 完成后会 on_open + 读明文 */
        return;
    }
    tls_read_plain(t);
    tls_flush_pending(t);
}

static void tcp_cb_close(void *d) {
    struct tls_conn *t = (struct tls_conn *)d;
    if(t->destroyed)
        return;
    if(t->ssl)
        sevent_ssl_peer_close(t->ssl);
    if(!t->handshake_done) {
        tls_fail(t, SEVENT_ERR_CONNECT); /* 握手期对端关闭 */
        return;
    }
    tls_read_plain(t); /* 耗尽已 feed 密文 → EOF → 用户 on_close */
}

static void tcp_cb_error(void *d, int err) {
    struct tls_conn *t = (struct tls_conn *)d;
    (void)err;
    if(t->destroyed)
        return;
    /* tcp 层错误: 建连期=CONNECT, 数据期=READ/WRITE (tcp 层不细分, 统一映射) */
    tls_fail(t, t->handshake_done ? SEVENT_ERR_READ : SEVENT_ERR_CONNECT);
}

/* ===== tcp 回调组 ===== */

static const sevent_stream_conn_init tcp_cb_init(void) {
    sevent_stream_conn_init i;
    memset(&i, 0, sizeof(i));
    i.on_open  = tcp_cb_open;
    i.on_data  = tcp_cb_data;
    i.on_close = tcp_cb_close;
    i.on_error = tcp_cb_error;
    return i;
}

/* ===== 公开 API (stream ops) ===== */

int sevent_tls_conn_open(sevent_tls_conn *c, const char *host, uint16_t port, const sevent_stream_conn_init *init) {
    struct tls_conn *t = (struct tls_conn *)c;
    if(!t || !host || !init || !init->on_open || !init->on_data || t->established || t->destroyed)
        return SEVENT_ERR_INVAL;
    t->is_server            = false;
    t->established          = true;
    t->init                 = *init; /* 回调组 + 超时/缓冲配置拷贝 */
    /* 校验名 (对象级, create 时定): t->hostname ?: open 的 host — TCP 目标与
     * 校验名分离 (DNS 应用层做); NULL=用 host (默认校验连接目标) */
    const char *verify_name = t->hostname ? t->hostname : host;
    size_t      hl          = strlen(verify_name);
    char       *hn          = (char *)sevent_i_malloc(hl + 1);
    if(!hn) {
        tls_reset_after_term(t); /* 同步失败回 IDLE, 可重试 (与 tcp 契约一致) */
        return SEVENT_ERR_NOMEM;
    }
    memcpy(hn, verify_name, hl + 1);
    sevent_i_free(t->hostname);
    t->hostname                 = hn;
    sevent_stream_conn_init tci = tcp_cb_init();
    tci.user_data               = t;
    tci.connect_timeout_ms      = init->connect_timeout_ms;
    tci.recv_buf_size           = init->recv_buf_size;
    int rc                      = sevent_tcp_conn_open(t->tcp, host, port, &tci);
    if(rc < 0)
        tls_reset_after_term(t); /* 同步失败 (立即 CONNECT 错误) → 回 IDLE 可重试 */
    return rc;
}

int sevent_tls_conn_accept(sevent_tls_conn *c, int fd, const sevent_stream_conn_init *init) {
    struct tls_conn *t = (struct tls_conn *)c;
    if(!t || !init || !init->on_open || !init->on_data || t->established || t->destroyed || fd < 0)
        return SEVENT_ERR_INVAL;
    t->is_server                = true;
    t->established              = true;
    t->init                     = *init;
    /* 服务端期望名已在 create 时存入 t->hostname (config) */
    sevent_stream_conn_init tci = tcp_cb_init();
    tci.user_data               = t;
    tci.connect_timeout_ms      = init->connect_timeout_ms;
    tci.recv_buf_size           = init->recv_buf_size;
    int rc                      = sevent_tcp_conn_accept(t->tcp, fd, &tci);
    if(rc < 0)
        tls_reset_after_term(t); /* 同步失败回 IDLE, 可重试 */
    return rc;
}

int sevent_tls_conn_write(sevent_tls_conn *c, const void *data, size_t len) {
    struct tls_conn *t = (struct tls_conn *)c;
    if(!t || t->destroyed || !t->established || !t->handshake_done || !t->ssl)
        return SEVENT_ERR_INVAL;
    if(t->pending_len)
        return SEVENT_ERR_INVAL; /* pending 明文未清 (极端状态, 等待续写) */
    const uint8_t *p   = (const uint8_t *)data;
    size_t         off = 0;
    while(off < len) {
        if(t->destroyed || !t->ssl)
            return SEVENT_ERR_INVAL; /* 回调内已终结 (极端, 幂等保护) */
        ssize_t n = sevent_ssl_write(t->ssl, p + off, len - off);
        if(n > 0) {
            off    += (size_t)n;
            int sc = tls_send_cipher(t);
            if(sc < 0)
                return SEVENT_ERR_WRITE;
            if(sc > 0)
                return SEVENT_ERR_INVAL; /* tcp 已收尾 */
            continue;
        }
        if(n == 0) {
            if(sevent_ssl_want(t->ssl) == SEVENT_SSL_WANT_READ) {
                /* 罕见: TLS1.3 密钥更新需读 — 剩余明文暂存, tcp on_data 续写 */
                if(!tls_park_write(t, p + off, len - off))
                    return SEVENT_ERR_NOMEM;
                return 0; /* 已接受 */
            }
            int sc = tls_send_cipher(t); /* WANT_WRITE: 清通道重试 */
            if(sc < 0)
                return SEVENT_ERR_WRITE;
            if(sc > 0)
                return SEVENT_ERR_INVAL;
            continue;
        }
        tls_fail(t, SEVENT_ERR_WRITE);
        return SEVENT_ERR_WRITE;
    }
    return 0;
}

void sevent_tls_conn_close(sevent_tls_conn *c) {
    struct tls_conn *t = (struct tls_conn *)c;
    if(!t)
        return;
    /* 无 destroyed 守卫: destroy 路径 (destroyed=true 后) 也经本函数清理;
     * 幂等由 tls_reset_after_term 的 ssl 判空 + tcp_conn_close 幂等保证.
     * 清理复用终结复位 (同一套释放, 不重复); hostname 是对象级 (create 时定),
     * close 不清 — 重开 (open/accept) 继续用同一校验名, 释放归 tls_cleanup */
    tls_reset_after_term(t);
    sevent_tcp_conn_close(t->tcp);
}

/* cleanup 在 run_posts 执行: 释放组合对象 + 配置 + 壳 */
static void tls_cleanup(void *d) {
    struct tls_conn *t = (struct tls_conn *)d;
    sevent_tcp_conn_destroy(t->tcp); /* 其内部再 post, 队列顺序保证安全 */
    sevent_ssl_ctx_free(t->ssl_ctx);
    sevent_i_free(t->hostname);
    sevent_i_free(t);
}

void sevent_tls_conn_destroy(sevent_tls_conn *c) {
    struct tls_conn *t = (struct tls_conn *)c;
    if(!t || t->destroyed)
        return;
    t->destroyed = true; /* 防重复 destroy → 重复 post → double free */
    sevent_tls_conn_close(c);
    /* 统一 post 延迟释放 (与 tcp_conn 同纪律): 回调栈内 destroy 后库代码
     * 仍访问对象; sevent_destroy 丢弃未执行 post 前须推进循环. */
    if(sevent_post(t->ev, tls_cleanup, t) != SEVENT_SUCCESS)
        tls_cleanup(t); /* OOM: 立即释放 (极端情况) */
}

/* ===== stream_conn 适配层 (ws 模块经 sevent_stream_* 使用) ===== */

static int tls_s_open(sevent_stream_conn *s, const char *host, uint16_t port, const sevent_stream_conn_init *init) {
    return sevent_tls_conn_open((sevent_tls_conn *)s->impl, host, port, init);
}

static int tls_s_accept(sevent_stream_conn *s, int fd, const sevent_stream_conn_init *init) {
    return sevent_tls_conn_accept((sevent_tls_conn *)s->impl, fd, init);
}

static int tls_s_write(sevent_stream_conn *s, const void *data, size_t len) {
    return sevent_tls_conn_write((sevent_tls_conn *)s->impl, data, len);
}

static void tls_s_close(sevent_stream_conn *s) { sevent_tls_conn_close((sevent_tls_conn *)s->impl); }

static void tls_s_destroy(sevent_stream_conn *s) {
    sevent_tls_conn_destroy((sevent_tls_conn *)s->impl);
    sevent_i_free(s); /* 壳立即释放: destroy 后对象作废 */
}

static const sevent_stream_ops tls_stream_ops = {
        .open    = tls_s_open,
        .accept  = tls_s_accept,
        .write   = tls_s_write,
        .close   = tls_s_close,
        .destroy = tls_s_destroy,
};

/* ===== 工厂 (公开 + stream 分发) ===== */

sevent_tls_conn *sevent_tls_conn_create(sevent_context *ev, const sevent_stream_conn_config *cfg) {
    if(!ev || !cfg)
        return NULL;
    struct tls_conn *t = (struct tls_conn *)sevent_i_calloc(1, sizeof(*t));
    if(!t)
        return NULL;
    t->ev  = ev;
    t->tcp = sevent_tcp_conn_create(ev);
    if(!t->tcp)
        goto fail;
    /* stream_conn_config 的 TLS 字段 → ssl config (U6 后含 PEM 三件套) */
    sevent_ssl_config scfg;
    memset(&scfg, 0, sizeof(scfg));
    scfg.ca_path                = cfg->ca_path;
    scfg.cert_path              = cfg->cert_path;
    scfg.key_path               = cfg->key_path;
    scfg.enable_peer_verify     = cfg->enable_peer_verify;
    scfg.enable_hostname_verify = cfg->enable_hostname_verify;
    if(cfg->tls_hostname) { /* 对象级校验名: create 时确定, 存对象 */
        size_t hl   = strlen(cfg->tls_hostname);
        t->hostname = (char *)sevent_i_malloc(hl + 1);
        if(!t->hostname)
            goto fail;
        memcpy(t->hostname, cfg->tls_hostname, hl + 1);
    }
    t->ssl_ctx = sevent_ssl_ctx_new(&scfg);
    if(!t->ssl_ctx)
        goto fail;
    return (sevent_tls_conn *)t;

fail:
    if(t->tcp)
        sevent_tcp_conn_destroy(t->tcp);
    if(t->ssl_ctx)
        sevent_ssl_ctx_free(t->ssl_ctx);
    sevent_i_free(t);
    return NULL;
}

/* 供 stream_conn.c 工厂分发: 创建 TLS 实现 + 包壳挂接 ops */
sevent_stream_conn *tls_stream_create(sevent_context *ev, const sevent_stream_conn_config *cfg) {
    struct tls_conn *t = (struct tls_conn *)sevent_tls_conn_create(ev, cfg);
    if(!t)
        return NULL;
    sevent_stream_conn *s = (sevent_stream_conn *)sevent_i_malloc(sizeof(*s));
    if(!s) {
        sevent_tls_conn_destroy((sevent_tls_conn *)t);
        return NULL;
    }
    s->ops  = &tls_stream_ops;
    s->impl = t;
    return s;
}

/* 底层 SSL 对象 (供特殊需求; 内部实现指针) */
void *sevent_tls_conn_get_ssl(sevent_tls_conn *c) {
    struct tls_conn *t = (struct tls_conn *)c;
    if(!t)
        return NULL;
    return t->ssl ? t->ssl->impl : NULL;
}

#endif /* SEVENT_WS_TLS */
