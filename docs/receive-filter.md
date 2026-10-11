# Receive filter development

The IPv4 filter in `ml_filter.c` receives authenticated coordinator map updates. A wrapper around the WireGuard netif input checks decrypted packets before delivery to lwIP. Direct and DERP receive paths converge at this callback. The netif output wrapper records reply tuples before sending UDP or SCTP packets. The implementation remains under validation.

The parser supports `PacketFilter` replacement and named `PacketFilters` updates. Missing or null policy fields preserve the current policy. Named null entries delete groups. A `"*": null` entry clears prior groups before the remaining named updates. Invalid updates, unsupported constraints, capacity exhaustion, and allocation failure clear the policy and deny all ingress. Application capability grants do not grant IP access.

Supported address expressions are IPv4 addresses, CIDRs, inclusive ranges, and `*`, including legacy prefix-length fields. IPv6 expressions are validated but do not create IPv4 rules. The filter rejects IPv6 packets, IPv4 options, and fragments. Capability-based source expressions are unsupported and reject the update. Limits are eight named groups, 63 bytes per group name, and 128 rows after expanding each source/destination pair. These limits need validation against real coordinator maps before deployment.

TCP packets other than an initial SYN pass after packet validation and the local-destination check. TCP connection state remains the host stack's responsibility. ICMP echo replies and selected error messages pass; other ICMP packets require a matching source/destination rule. UDP and SCTP reply tuples use a 32-entry cache with a 30-second idle timeout. Policy updates clear this cache. Other protocols require an explicit protocol match and the full destination-port range. This follows the main receive paths in Tailscale's `wgengine/filter/filter.go`, with bounded reply state. TSMP does not have the reference client's unconditional exception in this draft.

The integration serializes filter operations with a FreeRTOS mutex. The input wrapper checks that each destination is the local tailnet address or an advertised IPv4 subnet. Peer authentication and source-address checks remain WireGuard responsibilities. New control sessions, disconnects, failed map parsing, and dropped map messages clear prior policy. The small-memory map parser retains both policy fields. Packet rejection returns an error to WireGuard, which retains responsibility for freeing the packet.

## Host tests

Run with a host C compiler that supports AddressSanitizer and UndefinedBehaviorSanitizer. `IDF_PATH` selects the same cJSON source as the firmware build.

```sh
IDF_PATH=/path/to/esp-idf tests/run-filter-tests
```

The tests cover initial denial, omitted fields, replacement, incremental deletion, wildcard reset ordering, address and port boundaries, local-destination rejection, TCP continuation, ICMP behavior, UDP/SCTP reply expiry, malformed updates, duplicate fields, numeric validation, packet truncation, IPv4 options and fragments, and policy capacity exhaustion. They also exercise 20,000 deterministic generated headers under the sanitizers. This is a bounds check, not exhaustive fuzzing or a protocol conformance test.

The suite passed with GCC 15.3 and the ESP-IDF 5.5.2 cJSON source on 2026-10-10. The native S3 firmware build also passed. The device accepted the coordinator's initial policy and answered direct ICMP traffic. A temporary HTTP endpoint then passed deny, allow, and revoke tests with locally injected policy updates. LAN control requests succeeded in each phase. During inbound denial, the board downloaded 262,144 bytes through its tailnet address with the expected SHA-256. This tests reply traffic and direct ingress enforcement. Allocation fault injection, server-streamed policy revocation, concurrent stress tests, and forced-DERP ingress remain untested.
