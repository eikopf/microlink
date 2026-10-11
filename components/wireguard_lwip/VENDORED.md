# Vendored WireGuard component

The source derives from [smartalock/wireguard-lwip](https://github.com/smartalock/wireguard-lwip). The imported MicroLink baseline and subsequent client patches are recorded in [fork provenance](../../docs/fork.md). The exact original smartalock import revision has not been established.

This component contains local ESP-IDF and Tailscale changes. It is not interchangeable with an unmodified checkout of the upstream library. [Dependency review](../../docs/dependency-review.md) records the comparison revision, patch scope, known defects, and update policy.

The component builds the reference C cryptographic backend. The Cortex-M0 sources remain inherited source material and are not compiled by this component. Original BSD and cryptographic implementation notices remain in `LICENSE` and the source tree.
