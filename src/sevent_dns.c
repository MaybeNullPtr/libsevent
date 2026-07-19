/* =========================================================================
 *  sevent_dns.c — DNS 解析实现
 *
 *  基于 getaddrinfo, 内嵌 inet_pton 快速路径.
 *  ========================================================================= */

#include "sevent_dns.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <netdb.h>

int sevent_dns_resolve(const char *host, uint16_t port, struct sockaddr_storage *out_addr, socklen_t *out_addrlen) {
    if(!host || !out_addr || !out_addrlen)
        return -1;

    /* ---- 快速路径: host 已经是字面 IP ---- */

    /* IPv4 */
    struct sockaddr_in *sin = (struct sockaddr_in *)out_addr;
    if(inet_pton(AF_INET, host, &sin->sin_addr) == 1) {
        sin->sin_family = AF_INET;
        sin->sin_port   = htons(port);
        *out_addrlen    = sizeof(*sin);
        return 0;
    }

    /* IPv6 */
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)out_addr;
    if(inet_pton(AF_INET6, host, &sin6->sin6_addr) == 1) {
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port   = htons(port);
        *out_addrlen      = sizeof(*sin6);
        return 0;
    }

    /* ---- 慢速路径: getaddrinfo ---- */

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[8];
    int  n = snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);
    if(n < 0 || (size_t)n >= sizeof(port_str))
        return -1;

    struct addrinfo *result = NULL;
    int              rc     = getaddrinfo(host, port_str, &hints, &result);
    if(rc != 0 || !result)
        return -1;

    /* 取第一个可用地址 */
    memcpy(out_addr, result->ai_addr, result->ai_addrlen);
    *out_addrlen = result->ai_addrlen;
    freeaddrinfo(result);
    return 0;
}
