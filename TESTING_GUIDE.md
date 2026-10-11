# Validation

## Host regression tests

`nix flake check` runs the host suites and the S3 firmware build in isolated Nix builds. `flake.lock` pins ESP-IDF, compilers, and other build dependencies. The checks use build-only credentials and do not access a tailnet.

For a host-only run:

```sh
nix develop --command tests/run-host-tests
```

The suites exercise receive filtering, coordinator URL parsing, node-key storage, registration framing, network-switch ownership, AT socket address validation, WireGuard transport and handshake state, and persistent timestamp allocation. Platform stubs cover selected failure paths; they do not model RTOS scheduling or modem behavior. [Protocol coverage and migration limits](docs/protocol-fixes.md).

## Firmware build

Enter `nix develop` and build `examples/minimal` as described in the README. The example defaults target the tested S3 board. Build checks do not require real credentials or a connected device. `tests/build-minimal` uses `sdkconfig.ci` placeholders in a separate build directory so the compiler retains the complete networking path. That firmware is for build validation only and must not be flashed. Configure real credentials only in the ignored `sdkconfig` before a hardware run.

The older examples remain available for reference. They have board-specific defaults and optional application services. They are not the validated entry point for this fork.

## Hardware evidence

The client patches were tested in a separate native harness on a LILYGO T3S3 LoRa SX1262 E-Paper board with 4 MB flash and 2 MB Quad PSRAM, using ESP-IDF 5.5.2. The harness tested direct and relay downloads, invalid relay certificates, selected TLS ownership interleavings, repeated shutdown, destination relay replacement, persisted key replacement with manual approval, and direct receive-policy deny/allow/revoke behavior.

A 256 KiB download matched its expected SHA-256 over direct and relayed paths. A separate test compiled Crosspoint's OPDS parser, parsed a catalog, and acquired its 1,569-byte EPUB through London and Frankfurt relays with direct transport blocked. The EPUB hash matched. Full reader UI, SD storage, and rendering were not exercised.

ESPHome builds of the patched source passed for S3 Quad PSRAM and C3. A cellular/PPP/network-switch build also passed. These are prior compile results for the extracted source, not runtime validation of those configurations or the new minimal example.

Before a release, repeat affected tests against the exact release candidate. Evidence from the earlier harness does not automatically cover later code changes. [Open work](docs/open-work.md).

The standalone extraction links the minimal S3 example with the client, coordinator, DERP, and WireGuard manager present in the ELF. The build-only image is approximately 0.99 MB with ESP-IDF 5.5.2. Existing unused-variable/function warnings remain in inherited code. GitHub Actions runs `nix flake check` with the committed lock file.
