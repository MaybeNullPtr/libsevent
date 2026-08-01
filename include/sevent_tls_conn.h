/* =========================================================================
 *  tls_conn.h — TLS 传输实现 (sevent_stream_conn 抽象, 需要 OpenSSL)
 *
 *  直接使用: sevent_tls_conn_create(ev, &cfg) → sevent_stream_* 接口操作
 *  (握手/WANT_*/SNI/证书验证均在内部消化, 上层用法与 tcp_conn 完全一致).
 *  ws 模块统一经 sevent_stream_create 分发, 不需要本头文件.
 *
 *  SEVENT_WS_TLS=ON 时编译 (CMake find_package(OpenSSL)).
 *  ========================================================================= */

#ifndef SEVENT_TLS_CONN_H
#define SEVENT_TLS_CONN_H

#include "sevent_stream_conn.h"

#ifdef SEVENT_WS_TLS

#ifdef __cplusplus
extern "C" {
#endif

    /* 创建 TLS 传输对象. cfg 必须非 NULL:
     *  - 服务端 (accept) 必须提供 cert_path/key_path, 否则建立时报 SEVENT_ERR_INVAL
     *  - 客户端 (open) 默认校验服务器证书链与主机名 (verify_peer/verify_hostname
     *    默认 true), ca_path=NULL 时用系统默认信任库; 自签证书测试设 verify_peer=false
     * 线程: [loop 线程] */
    sevent_stream_conn *sevent_tls_conn_create(sevent_context * ev, const sevent_stream_conn_config *cfg);

    /* 获取底层 SSL 对象 (供 ALPN/会话复用/证书信息等特殊需求; NULL=非 TLS 连接) */
    void *sevent_tls_conn_get_ssl(sevent_stream_conn * s);

#ifdef __cplusplus
}
#endif

#endif /* SEVENT_WS_TLS */
#endif /* SEVENT_TLS_CONN_H */
