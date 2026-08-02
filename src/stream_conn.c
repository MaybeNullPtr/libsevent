/* =========================================================================
 *  sevent_stream_conn.c — 传输流抽象: 公共转发层 + 工厂分发
 *
 *  struct sevent_stream_conn 是统一壳 (ops 表 + impl 指针), tcp_conn.c /
 *  tls_conn.c 各自实现 ops 并导出创建函数, 头文件保持不透明.
 *  ========================================================================= */

#include <stdlib.h>

#include "sevent_i.h"
#include "sevent_stream_conn.h"
#include "sevent_stream_conn_i.h"

/* tcp_conn.c / tls_conn.c: 创建具体实现并包壳挂接 ops */
sevent_stream_conn *tcp_stream_create(sevent_context *ev);
#ifdef SEVENT_WS_TLS
sevent_stream_conn *tls_stream_create(sevent_context *ev, const sevent_stream_conn_config *cfg);
#endif

/* ===== 工厂: enable_tls 分发 ===== */

sevent_stream_conn *sevent_stream_create(sevent_context *ev, const sevent_stream_conn_config *cfg) {
    if(!ev || !cfg)
        return NULL;
    if(cfg->enable_tls) {
#ifdef SEVENT_WS_TLS
        return tls_stream_create(ev, cfg);
#else
        return NULL; /* 未编译 TLS 支持 (SEVENT_WS_TLS=OFF) */
#endif
    }
    return tcp_stream_create(ev);
}

/* ===== 公共转发 ===== */

int sevent_stream_open(sevent_stream_conn *s, const char *host, uint16_t port, const sevent_stream_conn_init *cb) {
    if(!s || !s->ops)
        return SEVENT_ERR_INVAL;
    return s->ops->open(s, host, port, cb);
}

int sevent_stream_accept(sevent_stream_conn *s, int fd, const sevent_stream_conn_init *cb) {
    if(!s || !s->ops)
        return SEVENT_ERR_INVAL;
    return s->ops->accept(s, fd, cb);
}

int sevent_stream_write(sevent_stream_conn *s, const void *data, size_t len) {
    if(!s || !s->ops)
        return SEVENT_ERR_INVAL;
    return s->ops->write(s, data, len);
}

int sevent_stream_shutdown(sevent_stream_conn *s, int flag) {
    if(!s || !s->ops || !s->ops->shutdown)
        return SEVENT_ERR_INVAL;
    return s->ops->shutdown(s, flag);
}

void sevent_stream_close(sevent_stream_conn *s) {
    if(!s || !s->ops)
        return;
    s->ops->close(s);
}

void sevent_stream_destroy(sevent_stream_conn *s) {
    if(!s || !s->ops)
        return;
    s->ops->destroy(s);
}

void sevent_stream_set_no_delay(sevent_stream_conn *s, bool on) {
    if(!s || !s->ops || !s->ops->set_no_delay)
        return;
    s->ops->set_no_delay(s, on);
}
