# Open work

The target is a maintained ESP-IDF Tailscale client suitable for application integration. The following gaps are development work. Completion requires tests for the stated behavior. Unsupported traffic and policy must continue to fail closed while support is incomplete.

## Protocol correctness

| Work | Current evidence | Completion criteria |
| --- | --- | --- |
| Qualify replay and transport fixes | Full-width counter arithmetic, authenticated replay checks for data and keepalives, preserved replay state on key promotion, and short-payload guards pass host sanitizer tests. | Retain device interoperability coverage and add independent cryptographic vectors and malformed-packet fuzzing. |
| Qualify persistent handshake timestamps | A checked NVS epoch and serialized sequence replace wall-clock-plus-uptime generation. Host tests cover reboot, rollback, concurrent callers, rollover, and storage failures. | Physical power-interruption tests and an explicit migration procedure for legacy identities whose last timestamp was not persisted. |
| Qualify key and handshake expiry | All transport-key slots expire independently. Abandoned handshakes are erased at 540 seconds. Response processing checks expiry even without periodic maintenance. Boundary and timer-wrap tests pass. | Retain device interoperability coverage and test long outages, scheduling delays, disconnect, and recovery. |
| Make map updates transactional | Key decoding now rejects malformed input without partial writes. Full-list omission removes peers whose keys cannot be decoded; the sliced path skips its sweep on incomplete input. Queue/allocation failure can still drop updates and revocations. | Define failure and resynchronization behavior that prevents stale authorization while recovering from malformed or incomplete updates. Test bounded queues, memory exhaustion, replacement, and revocation. |
| Add protocol and cryptographic regression coverage | Host tests exercise production WireGuard crypto and receive processing with controlled clocks and lwIP stubs. Collision allocation and initiation rate limiting also have regression cases. | Extend the X25519 and BLAKE2s known-answer coverage with independent handshake and AEAD fixtures, malformed packet fuzzing, and lifecycle tests with controlled network failures. Preserve attribution for imported fixtures. |

The [protocol fixes](protocol-fixes.md) describe the implementation and coverage boundaries. The [dependency review](dependency-review.md) and [implementation survey](implementation-survey.md) record source evidence. Tests establish the identified defects and selected regressions; they do not establish practical exploitation of a deployed device or complete protocol correctness.

The S3 retest on 2026-10-11 observed a catalog timeout after repeated client initialization and reboot: emitted timestamps fell below the prior successful session's value, and the handshake completed after that value was passed. An unchanged-firmware retry succeeded. The logs support the timestamp diagnosis, although the remote peer's rejection log was not captured. Legacy migration remains distinct from monotonic allocation after the new persistent epoch exists.

## Features and capacity

| Work | Current state | Completion criteria |
| --- | --- | --- |
| Extend receive policy and IP support | Bounded IPv4 rules are supported. IPv6, IPv4 options and fragments, and unsupported constraints are rejected. | Add explicit packet parsing and policy semantics for each supported form, with deny-path tests and comparison against Tailscale behavior. [Receive filtering](receive-filter.md). |
| Implement Tailnet Lock | Tailnet Lock is absent. | Validate peer authorization against trusted authority state, including revocation and rotation. Encoding or re-signing a node signature alone is insufficient. |
| Isolate DERP connection work | A home connection and two destination slots share a writer. Connection setup can block it; partial frames can delay reads; extra regions cause churn. | Bound cancellation and frame deadlines. Demonstrate continuing transfers during an unrelated relay failure or connection attempt, with documented memory cost. [Relay behavior](derp-tls.md). |
| Decouple connection resources from tailnet size | The client imports a bounded peer table and creates WireGuard state for visible peers. Unrelated peers can consume every slot and exclude the requested server. Increasing `MAX_PEERS` does not correct this architecture. | Bound active connection state independently of tailnet membership. Resolve requested destinations without retaining a WireGuard session for every visible peer. Test a requested server beyond the first map entries, large map updates, eviction, revocation, and reconnect while measuring RAM and background traffic. Preserve default-deny policy throughout. [Capacity](LARGE_TAILNET.md). |
| Qualify coordinator compatibility | Custom bootstrap uses certificate-validated HTTPS. Full Headscale enrollment and private-CA deployment remain untested. | Exercise enrollment, map updates, renewal, and failure handling against recorded server versions. Test explicit private trust roots without weakening hostname or certificate verification. [Coordinator authentication](control-bootstrap.md). |

## Lifecycle and deployment qualification

Peer discovery needs a design decision before the capacity work is implemented. A bounded active-peer cache still needs a way to resolve missing destinations and process changes to their keys, routes, and policy. Streaming a full map can bound retained memory but still consumes time and traffic proportional to the received update. The implementation must distinguish active-session limits from directory processing and must not present a tailnet membership limit as an application connection limit.

Server-generated node-key expiry and repeated expiry need end-to-end tests. Recovery must cover fresh enrollment keys, manual approval, persistence failure, and interruption during replacement. [Key recovery](nodekey-recovery.md) describes the present recovery contract.

Shutdown can time out while resources remain live. The application must retain the owner and retry. Tests must cover repeated stop attempts during blocked TLS, relay changes, and network switching without freeing reachable state. Cellular support also needs modem validation; current evidence consists of host and compile checks. [Network switching](network-switch-shutdown.md).

NVS contains device identity material. The library does not enable flash encryption, Secure Boot, or disable debug access. Deployment work must define and test a provisioning procedure, recovery policy, and supported board configuration for protecting stored keys. Physical access can expose keys on an unprotected device. Hardware protection does not remove live-memory access by compromised firmware.

Crosspoint qualification requires a complete reader build and device test, including OPDS discovery, authenticated catalog access, application HTTPS validation, downloads to storage, rendering, cancellation, and sleep/reconnect behavior. Existing OPDS and EPUB transfer evidence covers the shared client and parser, not the complete reader. The Crosspoint prototype and native harness now build from this fork. Their current local checkout paths still need a reproducible revision pin for release integration.
