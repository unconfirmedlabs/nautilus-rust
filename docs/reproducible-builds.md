# Reproducible Builds

This repository has deterministic Rust release settings and a generic EIF builder for Nautilus apps.

## In This Repository

- `rust-toolchain.toml` pins the Rust compiler.
- `Cargo.lock` must be committed and used with `--locked`.
- Release profile uses:
  - `codegen-units = 1`
  - `lto = "fat"`
  - `panic = "abort"`
  - stripped symbols
- No crate in this repository uses `build.rs`.
- `Containerfile.eif` pins StageX build inputs by digest, including `core-rust` 1.94.0 and matching `sx2026.03.0` runtime layers.
- `eif/run.sh` is the minimal Nitro init target for TCP-on-loopback apps.
- `Makefile` emits `out/nitro.eif`, `out/nitro.pcrs`, and `out/rootfs.cpio`.

## Rust Release Build Checklist

Use a fixed checkout path or remap paths:

```shell
export SOURCE_DATE_EPOCH=0
export RUSTFLAGS="--remap-path-prefix=$(pwd)=/workspace"
cargo build --workspace --release --locked
```

## EIF Build

Build the default hash example:

```shell
make eif
cat out/nitro.pcrs
```

Build a different workspace package:

```shell
make eif ENCLAVE_PACKAGE=my-enclave-app ENCLAVE_BIN=my-enclave-app
```

The build scaffold:

- builds the selected package for `x86_64-unknown-linux-musl`
- copies the binary to `/nautilus-app`
- exposes enclave vsock port 3000 to `127.0.0.1:3000`
- normalizes initramfs file timestamps to Unix epoch 0
- sorts cpio entries
- writes gzip output without name/timestamp metadata
- writes PCRs to `out/nitro.pcrs`

The expected verification target is a reproducible EIF measurement, not just a reproducible Rust binary.

## Production Notes

The included builder is intentionally minimal. A production app should review:

- whether the app needs CA certificates or outbound host-mediated networking
- whether the app should bind only `127.0.0.1:3000`
- the exact StageX image digests and Nitro kernel version
- `ENCLAVE_PACKAGE` and `ENCLAVE_BIN` values in release automation
- PCR publication and Kagi policy updates
