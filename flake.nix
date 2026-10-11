{
  description = "MicroLink ESP-IDF client and validation builds";

  inputs = {
    esp-dev.url = "github:mirrexagon/nixpkgs-esp-dev";
    nixpkgs.follows = "esp-dev/nixpkgs";
  };

  outputs = { self, esp-dev, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
      perSystem = system:
        let
          pkgs = import nixpkgs { inherit system; };
          idf = esp-dev.packages.${system}.esp-idf-xtensa;
          source = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [
              ./components
              ./tests
              ./VERSION
              ./examples/minimal/CMakeLists.txt
              ./examples/minimal/main
              ./examples/minimal/sdkconfig.defaults
              ./examples/minimal/sdkconfig.ci
            ];
          };
          common = {
            version = pkgs.lib.removeSuffix "\n" (builtins.readFile ./VERSION);
            src = source;
            nativeBuildInputs = [ idf ];
            dontConfigure = true;
            postPatch = "patchShebangs tests";
            dontUseCmakeConfigure = true;
            dontUseNinjaBuild = true;
            dontUseNinjaInstall = true;
            dontFixup = true;
            IDF_COMPONENT_MANAGER = "0";
          };
          firmware = pkgs.stdenv.mkDerivation (common // {
            pname = "microlink-minimal-build-check";
            buildPhase = ''
              runHook preBuild
              export XDG_CACHE_HOME="$TMPDIR/cache"
              tests/build-minimal
              runHook postBuild
            '';
            installPhase = ''
              mkdir -p "$out/bootloader" "$out/partition_table"
              build_dir=examples/minimal/build/ci
              cp "$build_dir"/microlink_minimal.{bin,elf,map} "$out/"
              cp "$build_dir"/{flash_args,flasher_args.json} "$out/"
              cp "$build_dir/bootloader/bootloader.bin" "$out/bootloader/"
              cp "$build_dir/partition_table/partition-table.bin" "$out/partition_table/"
            '';
          });
          hostTests = pkgs.stdenv.mkDerivation (common // {
            pname = "microlink-host-tests";
            buildPhase = ''
              runHook preBuild
              tests/run-host-tests
              runHook postBuild
            '';
            installPhase = ''
              mkdir -p "$out"
              printf 'Host sanitizer suites passed\n' > "$out/result"
            '';
          });
        in {
          packages = { default = firmware; inherit firmware; };
          checks = { inherit firmware; host-tests = hostTests; };
          devShell = pkgs.mkShell {
            packages = [ idf ];
            IDF_COMPONENT_MANAGER = "0";
          };
        };
    in {
      packages = forAllSystems (system: (perSystem system).packages);
      checks = forAllSystems (system: (perSystem system).checks);
      devShells = forAllSystems (system: { default = (perSystem system).devShell; });
    };
}
