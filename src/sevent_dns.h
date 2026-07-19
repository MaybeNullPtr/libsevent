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
 * === 阻塞说明 ===
 * 这是一个同步阻塞函数:
 *   - 字面 IP (如 "1.2.3.4"): 纯内存操作, 几乎不阻塞
 *   - 域名 (如 "example.com"): 调用 getaddrinfo, 依赖网络/DNS 服务器,
 *     可能阻塞数百毫秒到数秒
 *   - 禁止在 loop 线程的 IO/定时器回调中调用, 否则会阻塞事件循环
 *
 * host         — 域名或 IP 字符串 (v4/v6)
 * port         — 端口号
 * out_addr     — 输出 sockaddr_storage, 可直接用于 connect()
 * out_addrlen  — 输出 addr 的实际长度
 *
 * 快速路径: host 是字面 IP 时直接 inet_pton, 不走 getaddrinfo.
 * 返回: 0=成功, <0=解析失败.
 */
int sevent_dns_resolve(const char *host, uint16_t port, struct sockaddr_storage *out_addr, socklen_t *out_addrlen);

#ifdef __cplusplus
}
#endif

#endif /* SEVENT_DNS_H */
