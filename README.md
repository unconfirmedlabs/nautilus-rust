# Nautilus Rust

A small Rust framework for AWS Nitro Enclave applications whose output is verified on Sui. An app crate imports `nautilus`, writes one handler, and gets a per-boot Ed25519 identity, Nitro attestation bound to that key, domain-separated signing of typed payloads, and a bounded HTTP server.

On-chain verification lives in [Kagi](https://github.com/unconfirmedlabs/kagi), the companion Move package. Nautilus Rust produces what Kagi checks: an attestation document carrying the enclave public key, and Ed25519 signatures over BCS intent messages.

## Crates

- `nautilus`: the app-facing crate, `#![forbid(unsafe_code)]`. `NautilusContext` (identity, signing, attestation), `NsmAttestor` and `NautilusContext::from_runtime()` for `/dev/nsm`, the `Signer` and `Attestor` traits, `router` / `router_async` / `serve`, and `contract` (Move-compatible BCS types and golden vectors). Test fakes are behind the `test-utils` feature.
- `nautilus-nsm`: the standalone `/dev/nsm` driver (CBOR requests, ioctl). It does not depend on `nautilus` and holds the only `unsafe` code. Apps do not need it directly; `nautilus` depends on it.

```text
crates/nautilus       app-facing crate
crates/nautilus-nsm   /dev/nsm driver
examples/hello-world  signs a typed greeting
examples/hash-attestor signs the SHA-256 and length of the request body
docs/                 guides, see below
Containerfile.eif     reproducible EIF builder
Makefile              EIF build and run targets
```

## Quick Start

Run an example locally with the development identity (public key, fake attestation, no Nitro hardware):

```shell
cargo run -p nautilus-example-hash-attestor --features test-utils
```

```shell
curl -s http://127.0.0.1:3000/health_check
curl -s -X POST --data-binary "hello" http://127.0.0.1:3000/process_data
curl -s -X POST -d '{"nonce":"0x010203"}' http://127.0.0.1:3000/attestation
```

Without `--features test-utils` the examples call `NautilusContext::from_runtime()`, which fails unless `/dev/nsm` exists.

Check suite:

```shell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --locked
cargo test --workspace --all-targets --locked --features test-utils
```

## Writing an App

`Cargo.toml`:

```toml
[features]
test-utils = ["nautilus/test-utils"]

[dependencies]
anyhow = "1"
axum = "0.8"
nautilus = { git = "https://github.com/unconfirmedlabs/nautilus-rust", tag = "v0.2.0" }
serde = { version = "1", features = ["derive"] }
sha2 = "0.10"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
tracing-subscriber = "0.3"
```

Always pin the git dependency; `rev = "<commit>"` works in place of `tag`.

`src/main.rs`:

```rust
use axum::body::Bytes;
use nautilus::{
    Intent, NautilusContext, NautilusError, ServerConfig, SignedResponse, contract::ByteVec,
};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

const HASH_ATTESTATION_INTENT: Intent = Intent(0);

#[derive(Debug, Clone, Serialize)]
struct HashAttestation {
    digest: ByteVec,
    length: u64,
}

fn process_data(
    bytes: Bytes,
    ctx: &NautilusContext,
) -> Result<SignedResponse<HashAttestation>, NautilusError> {
    let payload = HashAttestation {
        digest: ByteVec::from(Sha256::digest(&bytes).to_vec()),
        length: bytes.len() as u64,
    };
    ctx.sign_intent(HASH_ATTESTATION_INTENT, &payload)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().init();
    #[cfg(feature = "test-utils")]
    let ctx = NautilusContext::development();
    #[cfg(not(feature = "test-utils"))]
    let ctx = NautilusContext::from_runtime()?;
    let config = ServerConfig::default();
    let app = nautilus::router(ctx, config.clone(), process_data)?;
    nautilus::serve("127.0.0.1:3000".parse()?, app, config).await?;
    Ok(())
}
```

The handler runs on the blocking thread pool. The matching Move struct is `HashAttestation { digest: vector<u8>, length: u64 }`; see [docs/contract.md](docs/contract.md) for the type mapping. `Containerfile.eif` builds a package of this workspace, so add the app as a workspace member and run `make eif ENCLAVE_PACKAGE=my-enclave-app ENCLAVE_BIN=my-enclave-app`.

## Routes

| Route | Body | Response |
| --- | --- | --- |
| `GET /health_check` | none | `{"pk": "<hex>", "address": "0x<hex>"}` |
| `POST /attestation` | `{"nonce": "<hex>", "user_data": "<hex>"}`, nonce required | `{"attestation": "<hex>"}` |
| `POST /process_data` | raw bytes | the handler's JSON |
| `GET /attestation` | none | only when `ServerConfig::allow_unnonced_attestation` is set |

`nonce` and `user_data` are at most 512 bytes each (`MAX_ATTESTATION_DATA_BYTES`, Sui's limit). `/attestation` and `/process_data` share the `max_concurrent` limit; `/health_check` does not.

Errors are JSON `{"error": "<code>", "message": "..."}`:

| Code | Status | Meaning |
| --- | --- | --- |
| `invalid_request` | 400 | framework validation failed: hex, JSON, missing nonce, attestation bounds |
| `body_read_failed` | 400 | the request body could not be read |
| `not_found` | 404 | no route matches the path |
| `method_not_allowed` | 405 | the route does not accept the method |
| `request_timeout` | 408 | `request_timeout` elapsed |
| `body_read_timeout` | 408 | the body did not arrive within `body_read_timeout` |
| `body_too_large` | 413 | body exceeds `max_body_bytes` |
| `application_error` | 422 | handler returned `NautilusError::Application`; `message` is the app's |
| `overloaded` | 429 | `max_concurrent` requests already in flight |
| `internal_error` | 500 | any other failure |
| `attestation_unavailable` | 503 | the attestation provider failed |

Internal and attestation error details are logged, never returned.

## Security

- Fail-closed identity. `from_runtime()` opens `/dev/nsm`, mixes 32 bytes of NSM entropy into the per-boot key, and errors if the device is missing. It never falls back to a development identity.
- `test-utils` is off by default. It gates `development()` (seed `[42; 32]`, public), `FakeAttestor`, `EnclaveIdentity::from_seed` and `sign_intent_at`. `Containerfile.eif` runs `scripts/assert-no-test-utils.sh` and refuses to build an enclave package that enables it.
- Intent domain separation. Every signature covers BCS `(intent: u8, timestamp_ms: u64, payload)`. There is no API that signs raw bytes, so a client cannot get an arbitrary message signed. Give each message kind its own intent value.
- Timestamps are enclave-claimed. `sign_intent` stamps `now_ms()`, the enclave's system clock, which the host controls. It is not attested time.
- Replay protection is the consumer's job. Neither Nautilus Rust nor Kagi checks freshness or uniqueness; the consuming Move module must enforce a window against `Clock` and/or a uniqueness key.

What an attestation does and does not prove: [docs/attestation.md](docs/attestation.md#what-attestation-proves).

## Host Side

Enclaves have no network; the only I/O is vsock to the parent instance. `eif/run.sh` bridges enclave vsock port 3000 to the app on `127.0.0.1:3000` with `socat`. Parent-side orchestration, proxying and outbound networking are out of scope here.

[Argonaut](https://github.com/miraicloud/argonaut) is a separate Go companion binary for Nitro vsock bridging, config delivery and NSM proxying, maintained under the miraicloud organization. It is not part of this repository.

## Deterministic Builds

- `rust-toolchain.toml` pins Rust 1.94.1; `Cargo.lock` is committed and CI uses `--locked`.
- Release builds use one codegen unit, fat LTO and stripped symbols, and unwind on panic so a panicking handler returns 500 instead of ending the enclave. No crate has a `build.rs`.
- `Containerfile.eif` pins StageX images by digest, builds for `x86_64-unknown-linux-musl`, normalizes initramfs timestamps and runs `eif_build`. `make eif` writes `out/nitro.eif`, `out/nitro.pcrs` and `out/rootfs.cpio`.
- The StageX pins currently mix two releases: `core-rust` 1.94.0, `core-libunwind`, `core-libcxx` and `core-libcxxabi` are `sx2026.03.0`; musl, busybox, gcc, llvm, openssl, ca-certificates, socat, eif_build, nit and the Nitro kernel are `sx2025.08.0`. Re-pinning to one release is pending.

The reproducibility target is the EIF measurement (PCRs), not the Rust binary hash. See [docs/reproducible-builds.md](docs/reproducible-builds.md).

## Docs

- [docs/app-development.md](docs/app-development.md): API walkthrough, server limits, memory sizing, logging
- [docs/attestation.md](docs/attestation.md): PCRs, debug mode, certificate window, Sui limits, what attestation proves
- [docs/kagi.md](docs/kagi.md): on-chain registration and verification with Kagi
- [docs/contract.md](docs/contract.md): Rust to Move payload types and golden vectors
- [docs/signing-vectors.md](docs/signing-vectors.md): the shared Kagi vector
- [docs/reproducible-builds.md](docs/reproducible-builds.md): EIF build and the test-utils guard

## License

Apache-2.0
