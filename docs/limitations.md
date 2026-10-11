# Limitations

MicroLink is an experimental implementation, not a replacement for the full Tailscale client. Validation covers selected ESP32 configurations and a small tailnet.

- The receive policy supports bounded IPv4 rules. IPv6 packets, IPv4 options and fragments, and unsupported policy constraints are rejected. Tailnet Lock is not implemented. [Receive filtering](receive-filter.md).
- Peer, cached-peer, control-buffer, and policy limits can exclude required destinations or reject updates. C3 runtime memory usage and large tailnets remain unverified. [Capacity](LARGE_TAILNET.md).
- DERP uses a home connection and two destination slots. Connection setup blocks the shared writer, and a partial frame can delay the reader. More destination regions can cause churn. [Relay behavior](derp-tls.md).
- Custom coordinator bootstrap requires certificate-validated HTTPS. Full Headscale enrollment and private-CA deployments have not been validated. [Coordinator authentication](control-bootstrap.md).
- Node-key recovery can require a fresh enrollment key or manual device approval. Server-generated expiry and subsequent repeated expiry have not been exercised end to end. [Key recovery](nodekey-recovery.md).
- Checked shutdown can time out while retaining resources. The application must retain the owner and retry. Cellular paths have host and compile checks but no modem validation for these patches. [Network switching](network-switch-shutdown.md).
- NVS stores identity material. The library does not enable flash encryption, Secure Boot, or disable debug access. A physical attacker may recover keys from an unprotected device.

The OPDS experiment validates the shared client and reader parser. It does not validate a complete Crosspoint reader, storage, rendering, or application HTTPS certificate handling.
