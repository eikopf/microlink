# MicroLink

MicroLink connects an ESP32 to a Tailscale network through an ESP-IDF component. The device gets its own tailnet address and can exchange TCP and UDP traffic with peers. Connections use direct WireGuard transport or DERP relays.

The client handles registration, peer discovery, relay connections, and incoming IPv4 access rules from the coordinator. Device identity persists in NVS across restarts. The application supplies the network connection, clock synchronization, credentials, and application protocol.

## Hardware and SDK

The tested configuration is an ESP32-S3 with 4 MB flash and 2 MB Quad PSRAM, running ESP-IDF 5.5.2. ESP32-C3 builds pass, but runtime operation and memory headroom remain unverified. Optional cellular support is inherited and has not been tested on hardware in this fork.

Memory use depends on peer count, coordinator responses, and active relay connections. The supplied example uses 16 peer slots and 64 KiB control-plane buffers. A peer limit that is too small can exclude the intended server, even when the application only needs one connection. [Capacity and configuration](docs/LARGE_TAILNET.md).

## Integration

The application adds the checkout's `components` directory to `EXTRA_COMPONENT_DIRS` and declares `microlink` in its component's `REQUIRES`.

After initializing NVS, connecting the uplink, and synchronizing the system clock, the application calls `microlink_init()` with its enrollment key and device name, then `microlink_start()`. Clock synchronization is required for relay certificate validation.

The [C API](components/microlink/include/microlink.h) provides connection status, peer lookup, and TCP and UDP helpers that route traffic through the WireGuard interface. Existing socket-based libraries may need application routing changes to use that interface.

The application owns the client instance and serializes lifecycle calls. If `microlink_stop()` times out, the instance retains live resources and cleanup must be retried before destruction or replacement. Node-key expiry can require a new instance and renewed authorization. [Key recovery](docs/nodekey-recovery.md).

## Example

The [minimal example](examples/minimal) connects Wi-Fi, synchronizes the clock, and starts the client. Its defaults match the tested S3 board. Flash and PSRAM settings must match the target hardware.

The Nix development shell supplies the pinned ESP-IDF toolchain. From the checkout:

```sh
nix develop
cd examples/minimal
idf.py set-target esp32s3
idf.py menuconfig
idf.py build
idf.py -p PORT flash monitor
```

Wi-Fi and enrollment credentials are configured in the MicroLink menu. `PORT` is the board's serial port. The example opens no application server; application traffic must be added separately. `nix flake check` runs host tests and a firmware build with dummy credentials. [Build commands and outputs](docs/build.md).

The project uses the `v0.x.y` release series. APIs, configuration, and persisted state may change between releases. [Open work](docs/open-work.md) tracks missing features, correctness work, and release qualification.

Direct and relayed transfers have been tested, including an OPDS catalog and EPUB download. [Validation coverage](TESTING_GUIDE.md) describes the tested paths and remaining gaps.

MIT license; see [LICENSE](LICENSE). Derived from MicroLink and the client vendored in esphome-tailscale; [fork provenance](docs/fork.md). Not affiliated with Tailscale Inc.
