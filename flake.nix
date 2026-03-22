{
  description = "Bitcoin Core";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachSystem
      [ "aarch64-darwin" "x86_64-darwin" ]
      (system:
        let
          pkgs = import nixpkgs {
            inherit system;
          };

          lib = pkgs.lib;
        in
        {
          packages.default = pkgs.stdenv.mkDerivation {
            pname = "bitcoin-core";
            version = "local";

            src = ./.;

            nativeBuildInputs = with pkgs;
              [
                cmake
                ninja
                pkg-config
                python3
                installShellFiles
              ]
              ++ lib.optionals (pkgs.stdenv.hostPlatform.isDarwin && pkgs.stdenv.hostPlatform.isAarch64) [
                pkgs.darwin.autoSignDarwinBinariesHook
              ];

            buildInputs = with pkgs; [
              boost
              libevent
              zeromq
              zlib
              capnproto
              sqlite
            ];

            cmakeFlags = with lib; [
              (cmakeBool "BUILD_GUI" false)
              (cmakeBool "BUILD_TESTS" false)
              (cmakeBool "BUILD_BENCH" false)
              (cmakeBool "BUILD_FUZZ_BINARY" false)
              (cmakeBool "WITH_ZMQ" true)
              (cmakeBool "ENABLE_WALLET" true)
            ];

            doCheck = false;
            enableParallelBuilding = true;

            meta = with lib; {
              description = "Bitcoin Core built from local source on nix-darwin";
              platforms = platforms.darwin;
            };
          };

          devShells.default = pkgs.mkShell {
            packages = with pkgs; [
              cmake
              ninja
              pkg-config
              python3
              boost
              libevent
              zeromq
              zlib
              capnproto
              sqlite
            ];

          shellHook = ''
            export CMAKE_EXPORT_COMPILE_COMMANDS=1
            export CLANGD_QUERY_DRIVER="$(which clang++),$(which clang)"
          '';

          };
        });
}
