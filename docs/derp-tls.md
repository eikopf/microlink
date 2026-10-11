# DERP TLS verification

DERP connections require a trusted certificate chain, a certificate matching the relay hostname, and valid certificate dates. The trust anchors come from the ESP-IDF certificate bundle. A private relay CA must be included in a custom bundle through the application's ESP-IDF configuration. A failed verification closes the connection; there is no insecure fallback.

The MicroLink Kconfig selects certificate-bundle support and mbedTLS date checks.

The application must synchronize the system clock before a relay connection can succeed. The application must initialize its own clock source. An unsynchronized clock can cause certificate verification to fail; the normal relay retry loop can recover after time synchronization.

## Verification

Build with certificate-bundle support and `CONFIG_MBEDTLS_HAVE_TIME_DATE=y`. Synchronize the clock, connect to a public Tailscale relay, and verify that certificate validation precedes the DERP handshake. Verify encrypted traffic separately: successful TLS and DERP handshakes alone do not establish a working WireGuard connection.

Exercise the DERP connection path against endpoints with an untrusted issuer, a mismatched hostname, and an expired certificate. Each connection must fail during the TLS handshake. A DNS failure, connection timeout, or rejected HTTP upgrade does not demonstrate certificate rejection. Repeat failed attempts and check heap usage for retained TLS allocations.

Also test a relay whose certificate is not yet valid and a private relay with and without its CA in the configured bundle. These cases require controlled certificates and a test clock. Do not disable verification to accommodate an incorrect clock or an untrusted CA.

## Connection ownership

The reader and writer serialize each TLS call through a connection-local mutex. Only the writer sends DERP frames. The reader queues PONG replies with the connection region and generation; the writer discards replies from an earlier connection. Connection replacement waits for the reader to park before freeing or reinitializing TLS state. A blocked reader can therefore delay reconnection; checked shutdown retains the owner if workers cannot exit.

An idle socket returns WANT_READ. A fatal TLS result prevents further reads and writes on that context, and disconnect skips close-notify on the failed context. The TLS handshake has a deadline. ServerInfo and the initial NotePreferred write must complete before connectivity is published. Setup payload discard uses a 128-byte stack buffer, a 64 KiB limit, and a ten-second deadline shared across chunks. Deadline checks occur between TLS calls and can overrun by one underlying call.

These changes add one mutex per connection and eight bytes of metadata per TX queue entry (512 bytes for 64 entries on ESP32).

## Destination regions

The client retains its home connection and supports two additional region connections. Queue entries carry the destination peer's region from a synchronized route snapshot. The coordinator publishes relay endpoints under the same mutex; connection setup uses a copied hostname and port. Cached, added, patched, removed, and evicted peers update the route snapshots.

The writer opens a destination connection on demand. Background discovery uses existing connections and does not open destination connections. WireGuard traffic opens connections and can replace the least recently used slot immediately. Only two destination regions can remain connected at once; traffic across more regions can cause connection churn. Missing region endpoints drop packets. An unknown peer region retains the home-connection fallback.

Connection attempts share a five-second delay measured after each attempt completes. Failed regions also retain a retry deadline. The existing reader polls the home and destination connections in turn, with up to eight frames per connection. A partial frame can occupy the reader for five seconds. DNS, TCP, and TLS setup run in the writer and can delay other regions. Slow-server isolation remains unverified. A home reconnect currently closes all destination connections and drains the shared queue.

Extra slots remain allocated for the instance lifetime; TLS resources are allocated on connection and released on replacement, home reconnect, or destruction. Idle connections are not closed proactively. C3 and full reader memory headroom remain unverified.

The configured home region initializes the active region before registration. Coordinator echoes do not overwrite it. While connected, Hostinfo advertises the actual home connection. A later latency-based selection applies at reconnection.
