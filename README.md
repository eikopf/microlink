# MicroLink

An experimental Tailscale-compatible client for ESP32 applications using ESP-IDF. It provides an IPv4 WireGuard interface, direct peer discovery, DERP relay transport, and coordinator registration. ESPHome is not required.

This fork maintains the client used by the Crosspoint Tailscale prototype. It derives from [CamM2325/microlink](https://github.com/CamM2325/microlink), [Csontikka/microlink](https://github.com/Csontikka/microlink), and the client vendored in [esphome-tailscale](https://github.com/Csontikka/esphome-tailscale). [Provenance and changes](docs/fork.md).

## Status

Development uses the `v0.x.y` release series. APIs, configuration, and persisted state may change. There is no stable release or claim of full Tailscale compatibility.

The patched client has run on an ESP32-S3 with 4 MB flash and 2 MB Quad PSRAM using ESP-IDF 5.5.2. Tests cover direct and relayed transfers, selected shutdown and recovery paths, and OPDS catalog parsing and book acquisition. ESP32-C3 has compile coverage; runtime memory headroom remains unverified. [Validation](TESTING_GUIDE.md).

Known limits include IPv4-only receive filtering, bounded peer and policy tables, no Tailnet Lock, and two additional DERP regions beyond the home connection. Slow relay setup can delay other traffic. Private keys in NVS have no physical-access protection supplied by this library. [Limitations](docs/limitations.md).

## Build

With the ESP-IDF 5.5.2 environment loaded:

```sh
git clone https://github.com/eikopf/microlink.git
cd microlink/examples/minimal
idf.py set-target esp32s3
idf.py menuconfig
idf.py build
```

The minimal example targets the tested 4 MB / 2 MB Quad PSRAM board. Configure Wi-Fi and enrollment credentials in the MicroLink menu. Adjust flash and PSRAM settings for other hardware. Generated `sdkconfig` files are ignored by Git; firmware binaries still contain configured credentials.

Flash with `idf.py -p PORT flash monitor`, using the board's actual serial port. The example connects Wi-Fi, synchronizes the clock, and starts the client. It does not open an application server.

## Embed

Add this checkout's `components` directory to the application's `EXTRA_COMPONENT_DIRS`. Depend on `microlink` from the application component. Initialize NVS and networking, connect the uplink, and synchronize the system clock before calling `microlink_init()` and `microlink_start()`.

The application owns the instance and must serialize lifecycle calls. A failed `microlink_stop()` retains live resources; retry cleanup before releasing the owner or starting another instance. See the [public header](components/microlink/include/microlink.h), [architecture](docs/ARCHITECTURE.md), and [key recovery contract](docs/nodekey-recovery.md).

## Development

Run `tests/run-host-tests` with `IDF_PATH` set to ESP-IDF 5.5.2 and a host C compiler with address and undefined-behavior sanitizers. [Release policy](docs/releases.md).

MIT license; original notices and bundled dependency licenses are retained. See [LICENSE](LICENSE). This project is not affiliated with Tailscale Inc.
