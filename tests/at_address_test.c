#include "ml_at_address.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

static void truncations(const void *addr, size_t size) {
    char text[INET6_ADDRSTRLEN];
    for (size_t length = 0; length < size; ++length) {
        void *short_addr = malloc(length ? length : 1);
        assert(short_addr);
        memcpy(short_addr, addr, length);
        uint16_t port = 123;
        errno = 0;
        assert(!ml_at_address(short_addr, length, text, sizeof(text), &port));
        assert(errno == EINVAL && port == 123);
        free(short_addr);
    }
}

int main(void) {
    char text[INET6_ADDRSTRLEN];
    uint16_t port = 123;
    struct sockaddr_in ipv4 = {.sin_family = AF_INET, .sin_port = htons(8765)};
    assert(inet_pton(AF_INET, "100.98.63.7", &ipv4.sin_addr) == 1);
    assert(ml_at_address((void *)&ipv4, sizeof(ipv4), text, sizeof(text), &port));
    assert(port == 8765 && !strcmp(text, "100.98.63.7"));
    truncations(&ipv4, sizeof(ipv4));
    struct sockaddr_in6 ipv6 = {.sin6_family = AF_INET6, .sin6_port = htons(65535)};
    assert(inet_pton(AF_INET6, "2001:db8::1", &ipv6.sin6_addr) == 1);
    assert(ml_at_address((void *)&ipv6, sizeof(ipv6), text, sizeof(text), &port));
    assert(port == 65535 && !strcmp(text, "2001:db8::1"));
    truncations(&ipv6, sizeof(ipv6));
    unsigned char unaligned[sizeof(ipv6) + 1];
    memcpy(unaligned + 1, &ipv6, sizeof(ipv6));
    assert(ml_at_address((void *)(unaligned + 1), sizeof(ipv6), text, sizeof(text), &port));
    struct sockaddr unsupported = {.sa_family = AF_UNSPEC};
    assert(!ml_at_address(&unsupported, sizeof(unsupported), text, sizeof(text), &port));
    assert(errno == EAFNOSUPPORT);
    assert(!ml_at_address(NULL, sizeof(ipv4), text, sizeof(text), &port));
    assert(errno == EINVAL);
    port = 123;
    assert(!ml_at_address((void *)&ipv4, sizeof(ipv4), text, 1, &port));
    assert(port == 123);
    assert(!ml_at_address((void *)&ipv4, sizeof(ipv4), NULL, 1, &port));
    assert(!ml_at_address((void *)&ipv4, sizeof(ipv4), text, sizeof(text), NULL));
    puts("AT address validation tests passed");
    return 0;
}
