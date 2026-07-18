/* =========================================================================
 *  sevent_dns.h — DNS 解析 (内部工具)
 *
 *  基于 getaddrinfo 的域名解析模块, 同步阻塞.
 *  供内部模块 (如 WebSocket) 在连接建立前调用.
 *  ========================================================================= */

#ifndef SEVENT_DNS_H
#define SEVENT_DNS_H

#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * 解析 host:port → sockaddr.
 *
 * host      — 域名或 IP 字符串 (v4/v6)
 * port      — 端口号
 * out_addr  — 输出 sockaddr_storage, 可直接用于 connect()
 * out_addrlen — 输出 addr 的实际长度
 *
 * 快速路径: host 是字面 IP 时直接 inet_pton, 不走 getaddrinfo.
 * 返回: 0=成功, <0=解析失败.
 * 线程: 同步阻塞, 调用方自行确保不在 loop 热路径中调用.
 */
int sevent_dns_resolve(const char *host, uint16_t port,
                       struct sockaddr_storage *out_addr,
                       socklen_t *out_addrlen);

#ifdef __cplusplus
}
#endif

#endif /* SEVENT_DNS_H */
