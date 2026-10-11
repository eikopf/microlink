#include "ml_control_url.h"
#include <string.h>
#include <strings.h>
#include <stdio.h>

int ml_parse_control_url(const char *input, char *host, size_t host_size,
                         char *port, size_t port_size, bool *tls) {
    if (tls) *tls = false;
    if (!input || !host || !port || !host_size || !port_size) return -1;
    host[0] = '\0'; port[0] = '\0';
    const char *start = input;
    if (strncasecmp(start, "https://", 8) == 0) start += 8;
    else if (strstr(start, "://")) return -1;

    /* Keep the existing DNS/IPv4 host syntax; URL credentials and paths are unsupported. */
    const char *end = start;
    while (*end && *end != ':' && *end != '/') {
        char c = *end;
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_')) return -1;
        ++end;
    }
    size_t host_len = (size_t)(end - start);
    if (!host_len || host_len >= host_size) return -1;
    unsigned number = 443;
    if (*end == ':') {
        ++end;
        if (*end < '0' || *end > '9') return -1;
        number = 0;
        while (*end >= '0' && *end <= '9') {
            number = number * 10 + (unsigned)(*end++ - '0');
            if (number > 65535) return -1;
        }
        if (!number) return -1;
    }
    if (*end == '/') ++end;
    if (*end) return -1;
    char formatted[6];
    int length = snprintf(formatted, sizeof(formatted), "%u", number);
    if (length <= 0 || (size_t)length >= port_size) return -1;
    memcpy(host, start, host_len); host[host_len] = '\0';
    memcpy(port, formatted, (size_t)length + 1);
    if (tls) *tls = true;
    return 0;
}
