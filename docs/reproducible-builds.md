# Reproducible Builds

This repository is prepared for deterministic release builds, but final EIF reproducibility also depends on the container/initramfs layer used by the consuming application.

## In This Repository

- `rust-toolchain.toml` pins the Rust compiler.
- `Cargo.lock` must be committed and used with `--locked`.
- Release profile uses:
  - `codegen-units = 1`
  - `lto = "fat"`
  - `panic = "abort"`
  - stripped symbols
- No crate in this repository uses `build.rs`.

## Release Build Checklist

Use a fixed checkout path or remap paths:

```shell
export SOURCE_DATE_EPOCH=0
export RUSTFLAGS="--remap-path-prefix=$(pwd)=/workspace"
cargo build --workspace --release --locked
```

For enclave images, also pin:

- base image digests
- Linux kernel image
- init system
- CA bundle, if present
- cpio file ordering and timestamps
- gzip timestamp settings
- EIF build tool version

The expected verification target is a reproducible EIF measurement, not just a reproducible Rust binary.
