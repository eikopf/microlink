# WireGuard dependency review

Review date: 2026-10-11. The source snapshots below establish the comparison baseline. Commit recency is evidence of activity, not proof of correctness or future maintenance.

## Decision

Keep `wireguard-lwip` vendored and maintain the ESP-IDF and Tailscale adaptations in this repository. Track upstream changes and import reviewed fixes with regression tests. An unmodified external dependency cannot supply the current relay callbacks, external UDP transport, peer management, allocation behavior, and shutdown integration. A replacement would require another integration and hardware qualification cycle.

This decision does not establish that the inherited implementation is secure. Replay arithmetic, timestamp generation, previous-key expiry, and missing protocol tests require work before a stable release. [Open work](open-work.md) defines the completion criteria.

## Candidates

| Candidate and reviewed revision | Evidence | Assessment |
| --- | --- | --- |
| [smartalock/wireguard-lwip](https://github.com/smartalock/wireguard-lwip/tree/c54f20dbe76ac8b3411ad21e0ed7deea6f0cfd4d) | Latest reviewed commit is dated 2026-08-14. C implementation with lwIP integration and BSD-3-Clause licensing. Recent work includes a Cortex-M0 unaligned-access fix. | Retain as the source upstream. It has recent maintenance, although that alone does not qualify the protocol code. The Cortex-M0 backend is not used by this ESP-IDF build. |
| [droscy/esp_wireguard](https://github.com/droscy/esp_wireguard/tree/9b7660fed27151abdcbf32b43861044cf4a32497) | Latest reviewed commit is dated 2026-10-06. This ESPHome dependency derives from the same library. Its periodic cleanup explicitly expires previous keypairs. | Monitor for fixes. The previous-key expiry change is a concrete backport candidate. It does not replace the Tailscale integration. |
| [trombik/esp_wireguard](https://github.com/trombik/esp_wireguard/tree/9217c5be0836e908005301ad2c2d42009e560c0e) | Latest reviewed commit is dated 2024-10-10. ESP-IDF packaging of the same protocol implementation; README describes alpha status and older SDK targets. | Useful packaging reference. Switching to it would not provide an independent protocol implementation or preserve the local hooks. |
| [ciniml/WireGuard-ESP32-Arduino](https://github.com/ciniml/WireGuard-ESP32-Arduino/tree/3048281829d14a3050faa19cfbe47146e33c0765) | Latest reviewed commit is dated 2022-05-30. Arduino integration of the same library. | No maintenance or SDK advantage for this ESP-IDF project. |
| [cloudflare/boringtun](https://github.com/cloudflare/boringtun/tree/6dcc889a95ad82400932f785d874421d70308195) | Independent Rust implementation with a library and C interface. The reviewed tree includes desktop/mobile platform support and host-oriented dependencies. | A useful protocol reference and possible porting experiment. No inspected evidence establishes an ESP-IDF/Xtensa build, acceptable RAM use, or a drop-in lwIP interface. A migration is not justified yet. |

## Local delta

After line-ending normalization, the current `wireguard.c` matches the reviewed smartalock revision exactly. Seven files under `src` differ or are added, totaling 1,030 additions and 103 deletions in that comparison. Most changes are in `wireguardif.c`. The comparison revision is not a proven historical import base.

The local changes add ESP32 time and random providers, compatibility definitions, configurable peer storage, PSRAM allocation, external transport hooks, relay integration, periodic processing, and resource cleanup. The selected cryptographic backend is the reference C implementation. Licenses and original source notices remain in the component.

`components/wireguard_lwip` is now a regular directory alongside `components/microlink`. Previously it was a symlink to a nested copy inside the client component. The relocation preserves every existing file byte for byte. Consumers must supply the common `components` directory to ESP-IDF; consumers that address the old nested path need an update.

## Findings

The replay helper stores a counter difference in `uint32_t` despite using 64-bit packet counters. A local test compiled the production helper with address and undefined-behavior sanitizers and reproduced acceptance of an already accepted counter after a large jump. This is a correctness defect in the inherited helper, also present in the reviewed smartalock source. The test does not measure practical attack feasibility or bypass packet authentication.

The timestamp provider adds boot uptime to a wall-clock sample taken during client initialization. Delayed initialization therefore advances emitted time beyond the actual wall clock. The fallback of adding one day to a persisted base does not cover longer sessions or failed writes. Reboot and storage-failure tests are required. Independent clients provide useful test designs, described in the [survey](implementation-survey.md).

The [previous-key cleanup in droscy](https://github.com/droscy/esp_wireguard/blob/9b7660fed27151abdcbf32b43861044cf4a32497/src/wireguardif.c) is absent from this fork's periodic paths. Expired previous state can remain marked valid after current-key cleanup, while peer status tests either keypair's validity. This requires a focused status and key-lifecycle regression, not a wholesale wrapper replacement.

## Update policy

Record the reviewed source revision, license, local delta, and test evidence for each dependency update. Preserve local transport and lifecycle contracts. Run Nix host and firmware checks, then direct and DERP interoperability and restart tests on hardware when protocol or ownership behavior changes. Keep fixes separate from bulk upstream imports so regressions can be attributed and reverted.
