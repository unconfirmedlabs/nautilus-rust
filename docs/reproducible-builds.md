# Reproducible Builds

The reproducibility target is the EIF measurement (PCR0, PCR1, PCR2), not the Rust binary hash. Anyone rebuilding the same commit should get the same `out/nitro.pcrs`.

## Inputs

- `rust-toolchain.toml` pins Rust 1.94.1 for local and CI builds; `Cargo.lock` is committed and every build uses `--locked`.
- Release profile: `codegen-units = 1`, `lto = "fat"`, stripped symbols, and the default `panic = "unwind"`. No crate has a `build.rs`.
- `Containerfile.eif` pins every StageX image by the digest of its `linux/amd64` manifest, all from release `sx2026.03.0`: `core-rust` is Rust 1.94.0 and `core-gcc` is GCC 15.2.0. To re-pin, take each image's `sx<release>` tag index from Docker Hub and use the `linux/amd64` entry, not the index digest. `core-libunwind` ships only `libunwind.so.1`, so the build stage symlinks the `libunwind` names the Rust toolchain links against, including `libunwind.a` to GCC's `libgcc_eh.a`; update that path when `core-gcc` changes version. Keep `workspace.package.rust-version` compatible with the image's Rust before publishing PCRs.
- Crates are fetched from the network during the image build; they are not vendored.

## Test-Utils Guard

`scripts/assert-no-test-utils.sh <package> [target]` fails if the package's dependency graph enables `nautilus/test-utils`, which would put the public development identity and fake attestation into the enclave. `Containerfile.eif` runs it before `cargo build`, so `make eif` refuses such a package. CI runs it for both examples on `x86_64-unknown-linux-musl`, and checks that it fails with `--features test-utils`.

## EIF Build

```shell
make eif
cat out/nitro.pcrs
```

```shell
make eif ENCLAVE_PACKAGE=my-enclave-app ENCLAVE_BIN=my-enclave-app
```

The default package is `nautilus-example-hash-attestor`, built without `test-utils`, so it is NSM-backed. The builder:

- builds the package for `x86_64-unknown-linux-musl` with a static, relocation-free binary;
- copies it to `/nautilus-app` with `eif/run.sh` as the init target, which brings up loopback for outbound bridges and execs the app; the app serves vsock port 3000 itself;
- puts only the app, `run.sh`, busybox, musl and nit in the initramfs. There are no CA certificates or TLS libraries, since no workspace crate makes outbound TLS connections; an app that does must add its trust roots to the image, which changes PCR2;
- sets initramfs timestamps to epoch 0, sorts entries, and writes `cpio --reproducible` through `gzip --best --no-name`;
- runs `eif_build` with a fixed kernel and command line and writes `out/nitro.eif`, `out/nitro.pcrs` and `out/rootfs.cpio`.

CI builds the workspace for `x86_64-unknown-linux-musl` but does not build the EIF.

## Before Publishing PCRs

- Build from a clean checkout of a tagged commit; rebuild on a second machine and compare `out/nitro.pcrs`.
- Review `ENCLAVE_PACKAGE`, `ENCLAVE_BIN`, the StageX digests and the kernel.
- Do not register PCRs from a debug-mode run; see [attestation.md](attestation.md#debug-mode).
