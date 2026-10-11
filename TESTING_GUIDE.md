# Validation

## Host regression tests

Use a host C compiler with AddressSanitizer and UndefinedBehaviorSanitizer. The filter and registration suites compile cJSON from the ESP-IDF checkout used by the firmware.

```sh
export IDF_PATH=/path/to/esp-idf
tests/run-host-tests
```

The suites exercise receive filtering, coordinator URL parsing, node-key storage, registration framing, network-switch ownership, and AT socket address validation. Platform stubs cover selected failure paths; they do not model RTOS scheduling or modem behavior.

## Firmware build

Load the ESP-IDF 5.5.2 environment and build `examples/minimal` as described in the README. The example defaults target the tested S3 board. Build checks do not require real credentials or a connected device. `tests/build-minimal` uses `sdkconfig.ci` placeholders in a separate build directory so the compiler retains the complete networking path. That firmware is for build validation only and must not be flashed. Configure real credentials only in the ignored `sdkconfig` before a hardware run.

The older examples remain available for reference. They have board-specific defaults and optional application services. They are not the validated entry point for this fork.

## Hardware evidence

The client patches were tested in a separate native harness on a LILYGO T3S3 LoRa SX1262 E-Paper board with 4 MB flash and 2 MB Quad PSRAM, using ESP-IDF 5.5.2. The harness tested direct and relay downloads, invalid relay certificates, selected TLS ownership interleavings, repeated shutdown, destination relay replacement, persisted key replacement with manual approval, and direct receive-policy deny/allow/revoke behavior.

A 256 KiB download matched its expected SHA-256 over direct and relayed paths. A separate test compiled Crosspoint's OPDS parser, parsed a catalog, and acquired its 1,569-byte EPUB through London and Frankfurt relays with direct transport blocked. The EPUB hash matched. Full reader UI, SD storage, and rendering were not exercised.

ESPHome builds of the patched source passed for S3 Quad PSRAM and C3. A cellular/PPP/network-switch build also passed. These are prior compile results for the extracted source, not runtime validation of those configurations or the new minimal example.

Before a release, repeat affected tests against the exact release candidate. Evidence from the earlier harness does not automatically cover later code changes. [Known gaps](docs/limitations.md).

The standalone extraction passes all six host sanitizer suites and links the minimal S3 example with the client, coordinator, DERP, and WireGuard manager present in the ELF. The build-only image is approximately 0.99 MB with ESP-IDF 5.5.2. Existing unused-variable/function warnings remain in inherited code. GitHub Actions runs the same host suites and example build; the hosted job has not run before publication.
