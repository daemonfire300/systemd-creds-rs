# `systemd-creds-rs`

`systemd-creds-rs` is a small Rust library for processes that receive
credentials from `systemd` through `CREDENTIALS_DIRECTORY`.

It helps with two common tasks:

- discover which credential files were provided
- load all top-level credential files into memory

## Supported model

This crate assumes the current process is started by `systemd`, or that the
caller has set `CREDENTIALS_DIRECTORY` to a directory that follows the same
layout as `systemd` credentials.

The crate does not provision credentials on its own. It reads the files exposed
to the process.

## Usage

```rust
fn main() -> Result<(), systemd_creds_rs::Error> {
    for credential in systemd_creds_rs::load_all()? {
        let (name, bytes) = credential?;
        println!("{name}: {} bytes", bytes.len());
    }

    Ok(())
}
```

## Example Consumer

A small sample application lives in
[`examples/consumer-app`](examples/consumer-app).
The Linux end-to-end test builds that binary into an OCI image and runs it in a
container started from a transient `systemd` unit with `LoadCredential=`.

## Development

Use the flake as the single development and CI entrypoint.

```bash
nix develop
nix flake check
```

For targeted checks:

```bash
nix build .#checks.x86_64-linux.clippy
nix build .#checks.x86_64-linux.nextest
nix build .#checks.x86_64-linux.e2e-podman
```

## Status

Work in progress but usable in production in general since it is so "simplistic".
