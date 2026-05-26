# Nautilus Rust

Nautilus Rust is a small framework for building application-specific AWS Nitro Enclave binaries in Rust.

It provides the reusable enclave pieces that should be common across Nautilus projects:

- an app-facing `nautilus` crate
- a real Nitro Secure Module provider in `nautilus-nsm`
- per-boot Ed25519 enclave identity
- Sui address derivation from the enclave public key
- signed application responses
- Kagi-compatible BCS intent signing
- attestation request plumbing
- local deterministic test fakes
- Axum route helpers for simple enclave services
- deterministic EIF build scaffolding

Application developers should import `nautilus` into their own enclave app crate. They should not edit the framework crate for app-specific business logic.

## Project Scope

This repository is intentionally generic. It does not include proprietary Nautilus application logic, including the audio ingester.

Nautilus Rust owns in-enclave application primitives:

- identity generation
- signing
- attestation interfaces
- NSM integration
- process-data route scaffolding
- test support
- release-build conventions

Nautilus Rust does not own parent-instance orchestration, host-side services, S3 access, outbound networking, or general host-to-enclave transport.

Nautilus Rust also does not own on-chain verification. Use Kagi for the Sui Move side:

https://github.com/unconfirmedlabs/kagi

Kagi is the companion Move package for registering Nitro enclave public keys against PCR policy and verifying enclave-signed messages on-chain. Nautilus Rust produces the in-enclave artifacts Kagi expects: a Nitro attestation document bound to an Ed25519 public key, plus signatures over Kagi-compatible BCS intent messages.

For parent host to enclave communication over vsock, and for host-mediated outbound networking, use Argonaut:

https://github.com/unconfirmedlabs/argonaut

The split is deliberate. Nautilus Rust should own code that must be measured inside the enclave. Kagi should own on-chain verification. Argonaut should own parent-host transport, proxying, lifecycle, and outbound integration.

## Repository Layout

```text
crates/
  nautilus/      # app-facing framework crate
  nautilus-nsm/  # AWS Nitro Secure Module attestation provider
examples/
  hello-world/   # minimal signed response service
  hash-attestor/ # hashes uploaded bytes and signs the digest
docs/
  app-development.md
  attestation.md
  kagi.md
  reproducible-builds.md
  signing-vectors.md
Containerfile.eif # generic reproducible EIF builder
Makefile          # EIF build targets
```

## Crates

### `nautilus`

The framework crate imported by app developers.

It includes:

- `NautilusContext`: shared enclave context passed to business logic
- `EnclaveIdentity`: Ed25519 identity and Sui address helper
- `Attestor`: trait for attestation providers
- `router`: standard HTTP route scaffold
- `IntentResponse`: signed BCS payload response helper
- `testing::FakeAttestor`: deterministic local attestation provider

The core crate uses `#![forbid(unsafe_code)]`.

### `nautilus-nsm`

The Nitro-specific attestation provider.

It includes:

- `NsmAttestor`
- CBOR request and response encoding for NSM requests
- `/dev/nsm` ioctl integration
- NSM-backed random bytes
- `NsmAttestor::into_context()` for production enclave contexts

This crate contains the hardware-specific unsafe boundary. Keeping it separate makes the reusable app framework easier to test and audit.

## Quick Start

Run the full local check suite:

```shell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets --locked
```

Run the hash example locally:

```shell
cargo run -p nautilus-example-hash-attestor
```

Then call it:

```shell
curl -s http://127.0.0.1:3000/health_check
curl -s -X POST --data-binary "hello" http://127.0.0.1:3000/process_data
```

The examples use `NautilusContext::development()`, which is deterministic and does not require Nitro hardware.

## App Development Pattern

A Nautilus application should be its own Rust crate:

```text
my-enclave-app/
  Cargo.toml
  src/main.rs
```

Depend on the framework:

```toml
[dependencies]
anyhow = "1"
axum = "0.8"
hex = "0.4"
nautilus = { git = "https://github.com/unconfirmedlabs/nautilus-rust" }
nautilus-nsm = { git = "https://github.com/unconfirmedlabs/nautilus-rust" }
serde = { version = "1", features = ["derive"] }
sha2 = "0.10"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

Write application logic as a handler:

```rust
use axum::body::Bytes;
use nautilus::{NautilusContext, NautilusError, router};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

#[derive(Serialize)]
struct Output {
    digest: String,
    signature: String,
}

async fn process_data(bytes: Bytes, ctx: NautilusContext) -> Result<Output, NautilusError> {
    let digest = Sha256::digest(bytes.as_ref());
    let signature = ctx.sign_hex(&digest)?;

    Ok(Output {
        digest: hex::encode(digest),
        signature,
    })
}
```

Use the fake context locally:

```rust
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let app = router(NautilusContext::development(), process_data);
    nautilus::serve("127.0.0.1:3000".parse()?, app).await
}
```

Use the real NSM provider in the enclave:

```rust
use nautilus::router;
use nautilus_nsm::NsmAttestor;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let ctx = NsmAttestor::default().into_context()?;
    let app = router(ctx, process_data);
    nautilus::serve("127.0.0.1:3000".parse()?, app).await
}
```

In a production project, choose the context from configuration or compile-time feature flags so local tests do not require `/dev/nsm`.

## Kagi Integration

Use Kagi when a Sui Move contract needs to verify Nautilus Rust output.

The intended split is:

- `nautilus-rust`: enclave identity, attestation request, and signed response generation
- `kagi`: PCR policy, attestation-document validation, enclave registration, and Ed25519 verification on-chain

The signing contract is a BCS intent message containing `intent: u8`, `timestamp_ms: u64`, and the app payload. `NautilusContext::sign_bcs_payload` signs the same layout Kagi verifies in Move.

See [docs/kagi.md](docs/kagi.md) and [docs/signing-vectors.md](docs/signing-vectors.md).

## Standard Routes

`nautilus::router` creates four routes:

- `GET /health_check`
- `GET /attestation`
- `POST /attestation`
- `POST /process_data`

`GET /health_check` returns the enclave public key and derived Sui address.

`GET /attestation` returns an attestation document without verifier-provided freshness. It is useful for diagnostics.

`POST /attestation` accepts optional hex-encoded `nonce` and `user_data` fields:

```json
{
  "nonce": "0x010203",
  "user_data": "0xfeed"
}
```

`POST /process_data` receives raw bytes and passes them to the application handler.

## Attestation Model

Nautilus binds application signatures to Nitro attestation:

1. The enclave creates a per-boot Ed25519 identity.
2. The public key is exposed by `/health_check`.
3. The public key is included in NSM attestation requests.
4. A verifier requests `POST /attestation` with a fresh nonce.
5. The verifier validates the Nitro attestation document, PCRs, nonce, and public key.
6. The verifier accepts `/process_data` signatures only from the attested public key.

The current framework returns raw Nitro attestation document bytes as lowercase hex. Verifier-side COSE and certificate-chain validation belongs in the client, host system, or Kagi/Sui Move code that consumes the document.

## Argonaut Integration

Nitro enclaves do not have normal external networking. The practical boundary is vsock between the parent instance and the enclave.

Use Argonaut for host-side integration:

- parent host to enclave communication
- vsock transport
- host-mediated outbound networking
- proxying data from services such as S3 into the enclave
- keeping networking policy outside the app EIF when the app does not need direct outbound behavior

Nautilus Rust should remain focused on code that must be measured inside the enclave. Argonaut should own code that runs on the parent host.

## Deterministic Build Groundwork

This repository includes deterministic release-build settings and a generic EIF build scaffold:

- `rust-toolchain.toml` pins the local development compiler version.
- `Cargo.lock` is committed and CI uses `--locked`.
- The workspace uses resolver v2.
- Release builds use one codegen unit, full LTO, stripped symbols, and `panic = "abort"`.
- The core framework crate forbids unsafe code.
- The NSM unsafe boundary is isolated to `nautilus-nsm`.
- There are no `build.rs` scripts.
- CI enforces formatting, clippy, and locked tests.
- `Containerfile.eif` uses pinned StageX inputs, normalized initramfs timestamps, and `eif_build`.
- `make eif` emits `out/nitro.eif`, `out/nitro.pcrs`, and `out/rootfs.cpio`.

For Rust-only release builds, use a fixed build environment and path remapping:

```shell
export SOURCE_DATE_EPOCH=0
export RUSTFLAGS="--remap-path-prefix=$(pwd)=/workspace"
cargo build --workspace --release --locked
```

The EIF builder pins StageX `core-rust` to Rust 1.94.0 and includes the matching `sx2026.03.0` runtime layers needed by that toolchain. Keep `workspace.package.rust-version` compatible with the pinned Rust toolchain before publishing PCRs.

Build the default example EIF:

```shell
make eif
cat out/nitro.pcrs
```

Build a different workspace package:

```shell
make eif ENCLAVE_PACKAGE=my-enclave-app ENCLAVE_BIN=my-enclave-app
```

For enclave release artifacts, the reproducibility target is the EIF measurement, not just the Rust binary hash. Keep the container base image, kernel, initramfs contents, file ordering, timestamps, compression settings, and EIF build tool version pinned.

See [docs/reproducible-builds.md](docs/reproducible-builds.md).

## Testing

The test suite covers:

- deterministic identity creation
- Ed25519 signing and verification
- Sui address formatting
- intent message layout
- Kagi-compatible signing vector
- BCS payload signing
- fake attestation request recording
- attestation public-key binding
- HTTP route behavior
- body-size enforcement
- bad hex rejection
- NSM CBOR request encoding
- NSM response decoding
- NSM error mapping
- public-key length validation

Run:

```shell
cargo test --workspace --all-targets --locked
```

## Security Boundaries

Keep application-specific business logic in a consuming app crate. Keep reusable enclave primitives in this repository.

Recommended boundaries:

- inside EIF: Nautilus app binary, app business logic, signing, attestation
- outside EIF: Argonaut, S3 clients, outbound networking, host orchestration, durable storage
- verifier/client side: Nitro attestation document validation, PCR allowlists, nonce freshness checks

This keeps the measured enclave surface smaller and makes it easier to reason about what exactly is being attested.

## Current Status

This is an initial framework repository. It is ready for local app prototyping and crate-level testing. Before using it for production enclaves, add project-specific:

- Kagi PCR policy and on-chain registration
- project-specific EIF build review
- release signing
- deployment automation
- parent-host Argonaut configuration

## License

Apache-2.0
