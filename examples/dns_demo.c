/**
 *  dns_demo.c — DNS 解析示例
 *
 *  用法: ./example-dns-demo <hostname> [port]
 *        ./example-dns-demo baidu.com 80
 *        ./example-dns-demo localhost
 *        ./example-dns-demo 127.0.0.1   (走 fast-path)
 */

#include "../src/sevent_dns.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

int main(int argc, char **argv) {
    if(argc < 2) {
        fprintf(stderr, "Usage: %s <hostname> [port]\n", argv[0]);
        return 1;
    }

    const char *host = argv[1];
    uint16_t    port = argc > 2 ? (uint16_t)atoi(argv[2]) : 80;

    printf("Resolving %s:%u ...\n", host, (unsigned)port);

    struct sockaddr_storage addr;
    socklen_t               addrlen = sizeof(addr);

    int rc = sevent_dns_resolve(host, port, &addr, &addrlen);
    if(rc != 0) {
        fprintf(stderr, "  [ERROR] resolution failed\n");
        return 1;
    }

    /* 打印 IP */
    char ip_str[INET6_ADDRSTRLEN];
    if(addr.ss_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)&addr;
        inet_ntop(AF_INET, &sin->sin_addr, ip_str, sizeof(ip_str));
        printf("  AF_INET   %s:%u\n", ip_str, ntohs(sin->sin_port));
    } else if(addr.ss_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&addr;
        inet_ntop(AF_INET6, &sin6->sin6_addr, ip_str, sizeof(ip_str));
        printf("  AF_INET6  [%s]:%u\n", ip_str, ntohs(sin6->sin6_port));
    } else {
        printf("  unknown address family %d\n", addr.ss_family);
    }

    return 0;
}
