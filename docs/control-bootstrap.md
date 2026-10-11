# Custom coordinator authentication

Custom coordinator connections require HTTPS with a certificate accepted by the ESP-IDF certificate bundle. Bare host names use HTTPS on port 443. An explicit port changes the port, not the TLS requirement. Explicit `http://` URLs are rejected. The plaintext `/key` fetch has been removed, so a network attacker cannot supply an unauthenticated Noise server key through that path.

An empty coordinator setting retains the default Tailscale service and its compiled Noise server key. That path still uses the existing Noise-over-HTTP transport. The pinned key authenticates the service without a key download.

Accepted custom settings include `headscale.example`, `headscale.example:8443`, and `https://headscale.example:8443/`. The parser accepts DNS names and IPv4 addresses. URL credentials, non-root paths, query strings, fragments, and IPv6 literals are unsupported. Ports must be between 1 and 65535. The public configuration field accepts at most 63 characters; invalid or longer values fail initialization instead of being truncated.

Existing custom HTTP deployments must provide a certificate-validated HTTPS endpoint before using this patch. Private CA configuration and explicit custom Noise-key pinning are not implemented. The device needs a correct clock for certificate date validation. No automatic fallback to HTTP is available.

Run `tests/run-control-url-tests` with a host C compiler that supports AddressSanitizer and UndefinedBehaviorSanitizer. The suite checks accepted HTTPS forms, explicit HTTP rejection, unsupported schemes, invalid ports, URL injection characters, paths, output-buffer limits, and stale TLS flags. These tests pass with GCC 15.3. The native ESP-IDF S3 build passes. A complete Headscale registration and private-CA deployment have not been tested.
