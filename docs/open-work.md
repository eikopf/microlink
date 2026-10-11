# Open work

The target is a maintained ESP-IDF Tailscale client suitable for application integration. The following gaps are development work. Completion requires tests for the stated behavior. Unsupported traffic and policy must continue to fail closed while support is incomplete.

## Protocol correctness

| Work | Current evidence | Completion criteria |
| --- | --- | --- |
| Correct replay-counter arithmetic | The inherited WireGuard helper narrows a 64-bit counter difference to 32 bits. An isolated production-function test accepts an old counter after a large jump. | Test duplicate, out-of-order, large-jump, exhaustion, and wrap boundaries through the authenticated receive path. Keep counter arithmetic full width and enforce the protocol message limit. |
| Make handshake timestamps monotonic across restart | Initialization samples wall-clock time, then the platform adds total boot uptime. The unsynchronized fallback advances a persisted base by one day and ignores persistence errors. Neither establishes monotonicity across all restarts. | Test delayed initialization, clock correction, long uptime, rapid reboot, loss of power during persistence, and storage failure. A restart must not reuse an emitted timestamp for the same identity. |
| Expire previous WireGuard keys | Periodic cleanup expires the current keypair but lacks the explicit previous-key expiry present in droscy/esp_wireguard. Peer status accepts either valid keypair. | After rotation and peer loss, all expired keypairs are cleared and peer status becomes down. Test both periodic entry points and restoration after a new handshake. |
| Add protocol and cryptographic regression coverage | Current host suites concentrate on control parsing, policy, and resource ownership. They do not establish WireGuard cryptographic interoperability. | Add independent known-answer vectors, handshake and transport interoperability, malformed packet tests, and lifecycle tests with controlled clocks and network failures. Preserve attribution for imported fixtures. |

The [dependency review](dependency-review.md) and [implementation survey](implementation-survey.md) record the source evidence. The replay reproduction is a helper-level result; it does not establish practical exploitation against a deployed device. Timestamp and key-expiry findings need runtime regression cases before a fix is considered validated.

## Features and capacity

| Work | Current state | Completion criteria |
| --- | --- | --- |
| Extend receive policy and IP support | Bounded IPv4 rules are supported. IPv6, IPv4 options and fragments, and unsupported constraints are rejected. | Add explicit packet parsing and policy semantics for each supported form, with deny-path tests and comparison against Tailscale behavior. [Receive filtering](receive-filter.md). |
| Implement Tailnet Lock | Tailnet Lock is absent. | Validate peer authorization against trusted authority state, including revocation and rotation. Encoding or re-signing a node signature alone is insufficient. |
| Isolate DERP connection work | A home connection and two destination slots share a writer. Connection setup can block it; partial frames can delay reads; extra regions cause churn. | Bound cancellation and frame deadlines. Demonstrate continuing transfers during an unrelated relay failure or connection attempt, with documented memory cost. [Relay behavior](derp-tls.md). |
| Handle capacity limits predictably | Peer, cache, response-buffer, and policy limits can exclude destinations or reject updates. | Test large maps and updates at each bound, preserve safe policy on rejection, and expose actionable capacity errors. Measure runtime headroom on C3 and S3. [Capacity](LARGE_TAILNET.md). |
| Qualify coordinator compatibility | Custom bootstrap uses certificate-validated HTTPS. Full Headscale enrollment and private-CA deployment remain untested. | Exercise enrollment, map updates, renewal, and failure handling against recorded server versions. Test explicit private trust roots without weakening hostname or certificate verification. [Coordinator authentication](control-bootstrap.md). |

## Lifecycle and deployment qualification

Server-generated node-key expiry and repeated expiry need end-to-end tests. Recovery must cover fresh enrollment keys, manual approval, persistence failure, and interruption during replacement. [Key recovery](nodekey-recovery.md) describes the present recovery contract.

Shutdown can time out while resources remain live. The application must retain the owner and retry. Tests must cover repeated stop attempts during blocked TLS, relay changes, and network switching without freeing reachable state. Cellular support also needs modem validation; current evidence consists of host and compile checks. [Network switching](network-switch-shutdown.md).

NVS contains device identity material. The library does not enable flash encryption, Secure Boot, or disable debug access. Deployment work must define and test a provisioning procedure, recovery policy, and supported board configuration for protecting stored keys. Physical access can expose keys on an unprotected device. Hardware protection does not remove live-memory access by compromised firmware.

Crosspoint qualification requires a complete reader build and device test, including OPDS discovery, authenticated catalog access, application HTTPS validation, downloads to storage, rendering, cancellation, and sleep/reconnect behavior. Existing OPDS and EPUB transfer evidence covers the shared client and parser, not the complete reader. The Crosspoint prototype and native harness still require migration from the esphome-tailscale source path to a pinned revision of this fork.
