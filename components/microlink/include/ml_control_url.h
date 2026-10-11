#pragma once
#include <stdbool.h>
#include <stddef.h>

/* Custom coordinators require HTTPS. Bare names default to port 443. */
int ml_parse_control_url(const char *input, char *host, size_t host_size,
                         char *port, size_t port_size, bool *tls);
