{
  description = "systemd-creds-rs";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    crane.url = "github:ipetkov/crane";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    advisory-db = {
      url = "github:rustsec/advisory-db";
      flake = false;
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      crane,
      rust-overlay,
      advisory-db,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };
        lib = pkgs.lib;
        stdenv = pkgs.stdenv;

        toolchain =
          pkgs.rust-bin.stable.latest.default.override {
            extensions = [
              "clippy"
              "rust-analyzer"
              "rust-src"
              "rustfmt"
            ];
          };

        craneLib = (crane.mkLib pkgs).overrideToolchain toolchain;

        src = lib.cleanSource ./.;
        cargoSrc = craneLib.cleanCargoSource ./.;
        consumerSrc = lib.fileset.toSource {
          root = ./.;
          fileset = lib.fileset.unions [
            ./Cargo.toml
            ./Cargo.lock
            ./LICENSE
            ./README.md
            ./src
            ./examples/consumer-app
          ];
        };

        commonArgs = {
          src = cargoSrc;
          strictDeps = true;
        };

        cargoArtifacts = craneLib.buildDepsOnly commonArgs;
        cargoVendorDir = craneLib.vendorCargoDeps { src = cargoSrc; };

        package = craneLib.mkCargoDerivation {
          pname = "systemd-creds-rs-package-check";
          version = "0.1.0";
          inherit src cargoVendorDir;
          cargoArtifacts = null;
          doInstallCargoArtifacts = false;
          buildPhaseCargoCommand = ''
            cargo package --allow-dirty --locked --offline --list > package-contents.txt
          '';
          installPhaseCommand = ''
            cp package-contents.txt "$out"
          '';
        };

        crate = craneLib.buildPackage (
          commonArgs
          // {
            inherit cargoArtifacts;
          }
        );

        consumerCommonArgs = {
          src = consumerSrc;
          pname = "consumer-app";
          cargoLock = ./examples/consumer-app/Cargo.lock;
          cargoToml = ./examples/consumer-app/Cargo.toml;
          cargoVendorDir = craneLib.vendorCargoDeps {
            cargoLock = ./examples/consumer-app/Cargo.lock;
          };
          postUnpack = ''
            sourceRoot="$sourceRoot/examples/consumer-app"
          '';
          strictDeps = true;
        };

        consumerArtifacts = craneLib.buildDepsOnly consumerCommonArgs;

        consumerApp = craneLib.buildPackage (
          consumerCommonArgs
          // {
            cargoArtifacts = consumerArtifacts;
            doCheck = false;
          }
        );

        doc = craneLib.cargoDoc (
          commonArgs
          // {
            inherit cargoArtifacts;
            env.RUSTDOCFLAGS = "--deny warnings";
          }
        );

        clippy = craneLib.cargoClippy (
          commonArgs
          // {
            inherit cargoArtifacts;
            cargoClippyExtraArgs = "--all-targets -- --deny warnings";
          }
        );

        fmt = craneLib.cargoFmt {
          inherit src;
        };

        tomlFmt = craneLib.taploFmt {
          src = lib.sources.sourceFilesBySuffices src [ ".toml" ];
        };

        audit = craneLib.cargoAudit {
          inherit src advisory-db;
        };

        deny = craneLib.cargoDeny {
          inherit src;
        };

        nextest = craneLib.cargoNextest (
          commonArgs
          // {
            inherit cargoArtifacts;
            partitions = 1;
            partitionType = "count";
            cargoNextestPartitionsExtraArgs = "--no-tests=pass";
          }
        );

        consumerImage = pkgs.dockerTools.buildLayeredImage {
          name = "systemd-creds-rs-consumer";
          tag = "latest";
          contents = [ consumerApp ];
          config = {
            Cmd = [ "${consumerApp}/bin/consumer-app" ];
          };
        };

        e2ePodman = pkgs.testers.runNixOSTest {
          name = "systemd-creds-rs-e2e-podman";
          nodes.machine =
            { pkgs, ... }:
            {
              virtualisation.diskSize = 8192;
              virtualisation.containers.enable = true;
              virtualisation.podman.enable = true;
              environment.systemPackages = with pkgs; [
                podman
                systemd
              ];
            };
          testScript = ''
            machine.wait_for_unit("multi-user.target")
            machine.wait_until_succeeds("podman info")

            machine.succeed("podman load --quiet < ${consumerImage} > /dev/null")

            machine.succeed("""cat > /root/run-consumer.sh <<'EOF'
            #!${pkgs.runtimeShell}
            set -euo pipefail
            exec ${pkgs.podman}/bin/podman run \
              --rm \
              --pull=never \
              --volume "$CREDENTIALS_DIRECTORY:/run/credentials:ro" \
              --env CREDENTIALS_DIRECTORY=/run/credentials \
              systemd-creds-rs-consumer:latest
            EOF
            chmod +x /root/run-consumer.sh""")

            status, output = machine.execute(
                "systemd-run --wait --pipe --quiet --collect --service-type=exec "
                "-p LoadCredential=api-token:${pkgs.writeText "api-token" "token-123"} "
                "-p LoadCredential=db-password:${pkgs.writeText "db-password" "hunter2"} "
                "/root/run-consumer.sh"
            )

            assert status == 0, output
            assert "credential:api-token:9:token-123" in output, output
            assert "credential:db-password:7:hunter2" in output, output
          '';
        };

        e2ePodmanDriver = e2ePodman.driver;
      in
      {
        checks =
          {
            inherit
              package
              clippy
              fmt
              doc
              audit
              deny
              nextest
              ;
            "toml-fmt" = tomlFmt;
          }
          // lib.optionalAttrs stdenv.isLinux {
            "e2e-podman" = e2ePodman;
          };

        packages = {
          default = crate;
          consumer-app = consumerApp;
        } // lib.optionalAttrs stdenv.isLinux {
          e2e-podman-driver = e2ePodmanDriver;
        };

        apps = lib.optionalAttrs stdenv.isLinux {
          e2e-podman = flake-utils.lib.mkApp {
            drv = e2ePodmanDriver;
            exePath = "/bin/nixos-test-driver";
          };
        };

        devShells.default = craneLib.devShell {
          checks = self.checks.${system};
          packages =
            [
              toolchain
              pkgs.rust-analyzer
            ]
            ++ lib.optionals stdenv.isLinux [
              pkgs.podman
              pkgs.systemd
            ];
        };

        formatter = pkgs.nixfmt-tree;
      }
    );
}
