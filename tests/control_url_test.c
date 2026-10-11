#include "ml_control_url.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    const struct { const char *input, *host, *port; } valid[] = {
        {"headscale.example", "headscale.example", "443"},
        {"headscale.example:8443", "headscale.example", "8443"},
        {"https://headscale.example", "headscale.example", "443"},
        {"HTTPS://Headscale.Example/", "Headscale.Example", "443"},
        {"https://192.0.2.1:00443/", "192.0.2.1", "443"},
        {"https://example:65535", "example", "65535"},
        {"https://example:80", "example", "80"},
    };
    char host[64], port[6];
    bool tls;
    for (unsigned i = 0; i < sizeof(valid) / sizeof(*valid); ++i) {
        tls = false;
        assert(ml_parse_control_url(valid[i].input, host, sizeof(host), port, sizeof(port), &tls) == 0);
        assert(tls && !strcmp(host, valid[i].host) && !strcmp(port, valid[i].port));
    }
    const char *invalid[] = {
        "", "http://headscale.example", "HTTP://headscale.example:443",
        "ftp://example", "https://", "https://:443", "https://example:0",
        "https://example:65536", "https://example:99999999999999999999999",
        "https://example:-1", "https://example:+443", "https://example:",
        "https://example:44x", "https://example/path", "https://example//",
        "https://example?query=1", "https://example/#fragment",
        "https://user:password@example", "example\r\nInjected: yes",
        " example", "example ", "https://[::1]", "::1", "example:443:80",
    };
    for (unsigned i = 0; i < sizeof(invalid) / sizeof(*invalid); ++i) {
        tls = true;
        assert(ml_parse_control_url(invalid[i], host, sizeof(host), port, sizeof(port), &tls) == -1);
        assert(!tls && !host[0] && !port[0]);
    }
    assert(ml_parse_control_url(NULL, host, sizeof(host), port, sizeof(port), &tls) == -1);
    assert(ml_parse_control_url("example", host, 7, port, sizeof(port), &tls) == -1);
    assert(ml_parse_control_url("example", host, sizeof(host), port, 3, &tls) == -1);
    assert(ml_parse_control_url("example", host, 8, port, 4, &tls) == 0);
    assert(ml_parse_control_url("example", NULL, 0, port, sizeof(port), &tls) == -1);
    puts("control URL tests passed");
}
