# Independent ESP32 Tailscale implementations

Review date: 2026-10-11. Discovery used GitHub searches for ESP32 Tailscale clients and the projects referenced by those results. Source, manifests, and selected host tests were inspected at the revisions below. This is a source-level comparison, not a security audit or hardware qualification. Repository activity dates include documentation and dependency changes. Independence here means no observed MicroLink client ancestry; shared cryptographic libraries and protocol references remain common.

## Implementations

| Project and reviewed revision | Relevant implementation | Result for this fork |
| --- | --- | --- |
| [TinyLink](https://github.com/bryamzxz/tinylink/tree/4baee3d6303c3e5d8484fff4fd5cf9287d7c4818) | C ESP-IDF client with host tests for cryptographic primitives, WireGuard handshake and transport, DERP, discovery, and timestamp persistence. Latest reviewed commit: 2026-09-04, a dependency update. | Strongest immediate source of test designs for the existing C client. The sanitizer target passed all 23 test programs locally. Timestamp reservation is worth adapting with stricter persistence-failure handling. |
| [0xdilo/tailscale-esp32](https://github.com/0xdilo/tailscale-esp32/tree/dbd49fe4018023ba07596e4377496718ef21d6ae) | Rust client with protocol modules, typed keys, zeroization, bounded replay tracking, packet filtering, and node-key rotation. Latest reviewed commit: 2026-07-23. | Useful protocol and ownership reference. All 49 library tests passed locally. It exposes packet transport rather than an existing ESP-IDF lwIP component replacement. Tailnet Lock signature rotation must not be equated with full authority verification. |
| [signal-slot/usb-serial-over-tailscale](https://github.com/signal-slot/usb-serial-over-tailscale/tree/9038b0a6fffe03e2631770cd7b42008bbd6f1b21) | Rust `tsnode` library with host/device transport separation and a smoltcp TCP layer. Includes legacy and named packet-filter updates. Latest reviewed commit: 2026-10-09. | Useful model for running client behavior on a host and testing TCP over WireGuard between nodes. All 22 selected library tests passed locally. Adopting it would change the language and network-stack integration. Board support and published hardware results do not establish MicroLink compatibility. |
| [punnerud/tailscale-mpe-rust](https://github.com/punnerud/tailscale-mpe-rust/tree/3af15ef8a2ab3f98522a39dfcb31afc8caa74d78) | Rust `no_std` plus allocation core, separate firmware, and selective control-response parsing. Latest reviewed commit: 2026-07-10. | Useful separation and memory-management ideas. Source-IP-only policy parsing and an absent-filter allow-all path are weaker than this fork's intended receive policy. Static-memory figures exclude runtime allocations and are not comparable with full client RAM usage. |
| [alfs/tailscale-iot](https://github.com/alfs/tailscale-iot/tree/7707cf2bb58ccd47dd296d3418692f8031a6cbff) | C/C++ ESPHome proof of concept with a separate Noise implementation and lwIP integration. Latest reviewed commit: 2025-12-01. | Useful small-device reference. The inspected paths do not provide enabled DERP support or IPv6 forwarding and include insecure TLS handling for local-server use. It is not a security or feature upgrade. |
| [marcpr/esp32s3-tailscale-client](https://github.com/marcpr/esp32s3-tailscale-client/tree/5cecd524b3d15cd52951514e3bc68566abddea9a) | Independent C client with control, DERP, and WireGuard modules; depends on smartalock/wireguard-lwip. Latest reviewed commit: 2026-05-21. | Useful alternative integration reference, but inherits the same WireGuard dependency. No local hardware or regression result establishes superiority. |
| [CrisAlva1414/IOT-Tailscale](https://github.com/CrisAlva1414/IOT-Tailscale/tree/31ee2b797e0072ff93f04edf8ad6ab0541a0c4bf) | Independent C implementation inspired by tailscale-iot. Direct UDP transport and host protocol-vector tests; no DERP in the documented scope. Latest reviewed commit: 2026-09-06. | Useful additional vector and parser reference. Missing relay transport prevents it from covering the current use case on its own. Its tests were inspected but not executed in this review. |

## Transferable work

TinyLink's [timestamp tests](https://github.com/bryamzxz/tinylink/blob/4baee3d6303c3e5d8484fff4fd5cf9287d7c4818/tools/test/test_tai64n.c) cover a persisted floor and reservation scheme. Its [implementation](https://github.com/bryamzxz/tinylink/blob/4baee3d6303c3e5d8484fff4fd5cf9287d7c4818/components/tinylink/src/wg_proto.c) still emits a timestamp when reservation persistence fails. Importing that behavior unchanged would leave a restart failure case. The relevant improvement is the testable clock and persistence interface, followed by an explicit failure policy.

The [WireGuard module in 0xdilo](https://github.com/0xdilo/tailscale-esp32/blob/dbd49fe4018023ba07596e4377496718ef21d6ae/src/wireguard.rs) separates replay eligibility from acceptance after decryption and uses a larger replay window. This provides a comparison for large-counter and out-of-order tests. Its [Tailnet Lock module](https://github.com/0xdilo/tailscale-esp32/blob/dbd49fe4018023ba07596e4377496718ef21d6ae/src/tailnet_lock.rs) implements canonical signature encoding and rotation. The inspected re-signing entry point validates the signature's shape; that is not evidence of a complete trusted-authority state machine.

The [tsnode tests and source](https://github.com/signal-slot/usb-serial-over-tailscale/tree/9038b0a6fffe03e2631770cd7b42008bbd6f1b21/crates/tsnode/src) demonstrate a useful host-test boundary: control, relay, filtering, and TCP behavior can run without flashing a board. A comparable MicroLink harness would make disconnect, timeout, policy-update, and key-lifecycle regressions cheaper to exercise. Named filter-set replacement and deletion also deserve explicit compatibility fixtures in this fork.

The [policy parser in tailscale-mpe-rust](https://github.com/punnerud/tailscale-mpe-rust/blob/3af15ef8a2ab3f98522a39dfcb31afc8caa74d78/core/src/peers.rs) documents an allow-all result when no packet filter exists. This is a reason to review semantics before importing a compact parser. Memory reductions must preserve default-deny behavior and update semantics.

## Local validation

The following commands passed on an x86_64 Linux host. They exercise each project's tests, not interoperability with this fork or a live tailnet.

| Snapshot | Command | Result |
| --- | --- | --- |
| TinyLink | `make -C tools/test asan` in the MicroLink Nix development environment | 23 test programs passed under the project's sanitizer target. |
| 0xdilo/tailscale-esp32 | `cargo test --locked --lib` with Nix-provided Cargo, Rust, and GCC | 49 passed, 0 failed. |
| signal-slot/usb-serial-over-tailscale | `cargo test --locked -p tsnode --lib` with the same host tools | 22 passed, 0 failed. |

No replacement client's firmware was flashed. Rust host tools were supplied separately from the pinned MicroLink ESP-IDF environment. Successful host tests do not establish ESP32 memory use, radio behavior, flash wear, or deployment security.

## Exclusions and recommendation

[esp32-tailnet](https://github.com/bagdeabhishek/esp32-tailnet) identifies MicroLink and esphome-tailscale ancestry and is excluded from the independent comparison. [esp32-tailbridge](https://github.com/pierrejay/esp32-tailbridge) uses a WireGuard connection to a separate Tailscale gateway; it is an alternative deployment architecture rather than an on-device Tailscale client. The discovered finlet repository had no commits and supplied no implementation to evaluate. Application wrappers around MicroLink were not counted as independent clients.

Keep the current C/ESP-IDF integration and import test designs and individually reviewed fixes. Prioritize replay arithmetic, reboot-safe timestamps, previous-key expiry, and host protocol tests. Reconsider a Rust implementation only after a measured S3 prototype demonstrates a material benefit in correctness, memory use, and application integration. The available source and host-test evidence does not yet justify replacing the client.
