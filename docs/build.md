# Nix builds

`flake.lock` pins nixpkgs and nixpkgs-esp-dev. The latter supplies ESP-IDF 5.5.2, its Python environment, and the Xtensa toolchain. Flake outputs are provided for `x86_64-linux` and `aarch64-linux`; the current local validation is on `x86_64-linux`.

```sh
nix flake check                 # host sanitizer suites and S3 firmware
nix build                      # firmware check image in result/
nix develop                    # interactive ESP-IDF environment
nix develop --command tests/run-host-tests
```

The firmware derivation uses `examples/minimal/sdkconfig.ci`, which contains dummy credentials to prevent the compiler from removing the network path. Its output includes the application ELF, map and binary, bootloader, partition table, and flash arguments. It is a build-check image, not provisioned device firmware. It must not be flashed as a configured application.

For a device build, enter `nix develop`, change to `examples/minimal`, and use `idf.py menuconfig`, `idf.py build`, and `idf.py -p PORT flash monitor`. Credentials stay in the ignored local `sdkconfig` and resulting firmware. The Nix derivation selects only source files and the build-only defaults; it excludes local `sdkconfig`, build directories, and credentials. Real credentials must not be placed in Nix expressions or tracked defaults because Nix store contents are normally readable by other local users.

The default example targets 4 MB flash and 2 MB Quad PSRAM on ESP32-S3. Other boards require matching flash, PSRAM, and console configuration. The flake does not establish runtime support for every chip handled by ESP-IDF.

ESP-IDF component-manager downloads are disabled in Nix. Both `microlink` and the patched `wireguard_lwip` are regular sibling directories under `components`. Neither requires a submodule update or symlink.

`nix flake update` changes the toolchain baseline. Such an update requires repeating the build and affected hardware checks. The source remains usable as ordinary ESP-IDF components in an application with its own toolchain.
