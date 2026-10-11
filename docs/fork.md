# Fork provenance

The repository retains the history of Csontikka/microlink through `6a43400e4b` (2026-10-05), derived from CamM2325/microlink. The client source baseline is the vendored `microlink/components` tree in Csontikka/esphome-tailscale at `f41c18d5ccbe9c4d9b68ca36c2eebacba615085d`. The local patches were developed and tested against that vendored tree.

The standalone and vendored trees had diverged before this fork. The tested baseline includes single-core task placement, no-PSRAM allocation paths, bounded JSON processing, and matching WireGuard/client peer limits. It does not import standalone-only additions for PeerAPI DNS advertisement, host-route query APIs, reconnect diagnostic counters, or per-emission wall-clock WireGuard timestamps. These remain available in upstream history for separate evaluation. The fork preserves the tested behavior rather than combining untested branches during extraction.

Client patches cover certificate validation, custom coordinator authentication, IPv4 receive filtering, persistent node-key replacement, registration parsing, checked shutdown, network-switch ownership, AT socket address validation, and DERP connection ownership and destination-region routing. Host regression tests accompany the extracted client. ESPHome wrapper changes remain in the separate esphome-tailscale working tree.

The component source is transferred without behavioral changes during extraction. Subsequent version labels and build integration are separate changes. The native Crosspoint transport harness remains outside this repository; its fixtures and credentials are not copied here.

Original copyright and dependency notices remain in place. Csontikka's integration fixes, the vendored no-PSRAM work credited to gbertsch, and contributions from dj-oyu and GrieferPig are retained through source attribution and history.
