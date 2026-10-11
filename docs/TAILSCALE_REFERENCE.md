# Protocol references

The original Tailscale client is available at <https://github.com/tailscale/tailscale>. Useful source directories include `control/controlclient`, `control/controlbase`, `derp`, `wgengine/magicsock`, `wgengine/filter`, and `net/netcheck`.

Implementation timing constants, queue sizes, and concurrency models are not a substitute for wire-protocol requirements. Comparisons must identify the Tailscale revision examined. MicroLink uses bounded ESP-IDF tasks and buffers; it does not reproduce the Go client's runtime architecture.

The maintained descriptions of this fork's behavior are in [architecture](ARCHITECTURE.md), [DERP transport](derp-tls.md), [receive filtering](receive-filter.md), and [registration](nodekey-recovery.md).
