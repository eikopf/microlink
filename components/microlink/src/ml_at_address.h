#pragma once

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

/* Validate the supplied length before reading an address or formatting AT commands. */
static inline bool ml_at_address(const struct sockaddr *addr, socklen_t addrlen,
                                 char *text, size_t capacity, uint16_t *port) {
    const size_t family_end = offsetof(struct sockaddr, sa_family) + sizeof(addr->sa_family);
    if (!addr || !text || !port || addrlen < family_end) {
        errno = EINVAL;
        return false;
    }
    struct sockaddr header = {0};
    memcpy(&header, addr, family_end);
    if (header.sa_family == AF_INET) {
        if (addrlen < sizeof(struct sockaddr_in)) { errno = EINVAL; return false; }
        struct sockaddr_in ipv4;
        memcpy(&ipv4, addr, sizeof(ipv4));
        if (!inet_ntop(AF_INET, &ipv4.sin_addr, text, capacity)) return false;
        *port = ntohs(ipv4.sin_port);
        return true;
    }
    if (header.sa_family == AF_INET6) {
        if (addrlen < sizeof(struct sockaddr_in6)) { errno = EINVAL; return false; }
        struct sockaddr_in6 ipv6;
        memcpy(&ipv6, addr, sizeof(ipv6));
        if (!inet_ntop(AF_INET6, &ipv6.sin6_addr, text, capacity)) return false;
        *port = ntohs(ipv6.sin6_port);
        return true;
    }
    errno = EAFNOSUPPORT;
    return false;
}
