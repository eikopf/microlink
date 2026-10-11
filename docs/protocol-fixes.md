# WireGuard protocol fixes

The regression suite covers the inherited WireGuard implementation and the ESP32 timestamp allocator. Host tests compile production code with AddressSanitizer and UndefinedBehaviorSanitizer. The receive test extracts the production receive function without rewriting it and supplies a small lwIP boundary fixture.

## Transport and session state

Replay arithmetic retains the full 64-bit counter difference. Counters at the protocol rejection limit are rejected before decryption. Authentication and replay validation precede endpoint changes, receive timers, link state, and key promotion. Empty keepalives follow the same replay checks as data packets. Promoting the next keypair preserves its replay state and returns the surviving current-keypair address.

An authenticated payload shorter than an IPv4 header cannot enter the IP-header reader. IPv6 remains unsupported. This guard does not establish complete IP parser coverage.

Current, previous, and next transport keys expire independently at 180 seconds. Peer status excludes expired keys. Unfinished handshakes have their own creation time and are erased after 540 seconds, including their MAC1 state. Response lookup and processing enforce this bound even if periodic maintenance is delayed. Explicit disconnect erases unfinished handshakes and cancels requested initiations. Endpoint addresses remain available after key expiry.

Session-index allocation checks every peer slot for collisions. The initiation rate limiter uses elapsed time in the correct direction, permits the first initiation at boot time zero, and handles the 32-bit millisecond timer wrapping.

Tests cover authenticated duplicates, reordering, a counter jump larger than 32 bits, forged authentication tags, nonce exhaustion, short plaintext, keepalive confirmation, key promotion, each transport-key slot, delayed handshake responses, timer boundaries, and timer wrap. The C handshake test uses the same implementation at both ends. Independent primitive tests use the X25519 vectors in [RFC 7748 sections 5.2 and 6.1](https://www.rfc-editor.org/rfc/rfc7748#section-5.2) and the BLAKE2s vector in [RFC 7693 appendix B](https://www.rfc-editor.org/rfc/rfc7693#appendix-B). Complete Noise handshake and AEAD vectors remain absent. The [WireGuard protocol](https://www.wireguard.com/protocol/) defines the relevant replay and key-lifetime requirements.

## Timestamp allocation

The ESP32 platform reserves a logical seconds value in the `microlink` NVS namespace under `wg_tai_epoch`. The commit must succeed before the value can be used. Each handshake increments a nanoseconds-field sequence within that epoch. Client recreation preserves the allocator. A physical reboot reserves a larger epoch. Sequence exhaustion reserves another epoch before emission. Ordinary handshake generation does not write flash.

The allocator serializes callers with a process-lifetime mutex. Unavailable or corrupt storage, failed commits, and integer exhaustion prevent timestamp emission. A commit that becomes durable but reports failure can leave a gap; it cannot cause reuse. Initialization failure propagates to `microlink_init`.

Tests cover clock rollback, repeated initialization, concurrent callers, rapid reboots, failed reads and writes, ambiguous commit failure, corrupt record length, sequence rollover, and exhaustion. Host failure injection models persistence outcomes. It does not replace physical power-interruption testing.

## Upgrade and recovery boundary

The monotonicity guarantee requires preservation of `wg_tai_epoch` and use of the new allocator on every boot. Erasing or restoring old NVS while retaining the node identity can violate it. Downgrading to firmware that ignores the record can also violate it.

Legacy firmware stored `wg_tai_base`, then added uptime when emitting timestamps. Some synchronized boots did not persist the base. The legacy record therefore provides only a floor, not the largest timestamp accepted by a peer. The first upgraded boot cannot reconstruct the missing value. The allocator reads the legacy floor, but this does not establish seamless migration.

If the first upgraded epoch is below a peer's old replay watermark, waiting within that boot does not repair it: the logical epoch stays fixed. A restart initialized after clock synchronization can recover if current wall time exceeds the old watermark. Otherwise recovery requires an explicit known upper bound or replacement of the node identity and corresponding peer state. The library does not rotate identity automatically. The migration regression records this limitation by comparing the new epoch with a timestamp emitted after legacy uptime. A general identity-preserving migration remains open work.

## Coordinator key decoding

Coordinator keys must contain exactly 64 hexadecimal characters after their recognized prefix. Decoding succeeds as a complete operation or leaves the output unchanged. Peer additions and key-bearing updates reject malformed keys. Authoritative-list comparisons cannot use partially initialized key bytes. The test mutates every key position with invalid characters and checks length boundaries, mixed case, null arguments, and preservation of the destination on failure.

Malformed authoritative maps still require a transaction policy. The full-list parser treats an undecodable key as absent and can remove the corresponding old peer. The sliced parser suppresses its sweep when the list is incomplete. Allocation and queue failures can also drop updates. These paths are not covered by the decoder unit test and remain [open work](open-work.md).

## X25519 input decoding

X25519 masks the top bit of the input coordinate as required by RFC 7748. The inherited implementation also copied the coordinate to aligned storage but then used the original pointer. The ladder now uses the aligned copy. Tests cover the published high-bit input vector, equivalent high-bit encodings, an unaligned byte buffer, a non-canonical coordinate, and rejection of an all-zero shared secret. The patch does not change key identifiers or normalize public keys in the coordinator.
