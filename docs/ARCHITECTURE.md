# Architecture

The ESP-IDF component owns coordination, peer discovery, WireGuard, and relay transport. The application supplies the uplink, a synchronized clock, credentials, and lifecycle control.

| Module | Responsibility |
|---|---|
| `microlink.c` | Instance allocation, startup, checked shutdown, and cleanup |
| `ml_coord.c` | Noise coordination, registration, and network-map updates |
| `ml_registration.c`, `ml_nodekey.c` | Registration parsing and persisted replacement identity |
| `ml_wg_mgr.c` | Peer state, WireGuard setup, and DISCO discovery |
| `ml_net_io.c` | Direct network receive and packet dispatch |
| `ml_derp.c` | TLS relay connections, queued writes, and relay receive |
| `ml_filter.c` | Decrypted IPv4 receive policy and bounded reply tracking |
| `ml_net_switch.c` | Optional Wi-Fi/cellular lifecycle management |

Application traffic enters a WireGuard lwIP interface. Encrypted packets use a verified direct endpoint or a DERP relay. Decrypted packets pass the receive filter before delivery to lwIP. Incoming peer authentication and source-address checks remain WireGuard responsibilities.

FreeRTOS tasks exchange queued work and share explicitly synchronized state. DERP reader and writer calls use connection-local TLS mutexes. A separate mutex protects relay endpoint and peer-route snapshots. The relay writer opens destination connections on demand. [DERP ownership and limits](derp-tls.md).

Shutdown requests worker exit, waits for acknowledgements, and coordinates lwIP teardown before releasing resources. A timeout retains the instance. The caller must not free its owner or allocate a replacement while cleanup is incomplete. Application callbacks and timer callbacks must not synchronously destroy the instance.

PSRAM is used when present, with separate small-memory paths for devices without it. Allocation size depends on configured peer and control-buffer limits. Static size alone does not establish runtime headroom. [Capacity](LARGE_TAILNET.md).
