# App Development

An app is its own crate that depends on `nautilus` and supplies one `/process_data` handler. The README has a complete minimal app; this page covers the API around it.

## Context

`NautilusContext` holds a `Signer` and an `Attestor` behind `Arc`s and is cheap to clone.

- `NautilusContext::from_runtime()`: production. Opens `/dev/nsm` (`NsmAttestor`), mixes 32 bytes of NSM entropy into a fresh per-boot Ed25519 key, and errors if the device is missing.
- `NautilusContext::development()` (feature `test-utils`): seed `[42; 32]` and `testing::FakeAttestor`. The key is public; it logs a warning and must never be deployed.
- `NautilusContext::with_signer(signer, attestor)`: any `Signer` with any `Attestor`.

Every constructor logs the attestor name, public key and Sui address at `info`.

Pick the context at compile time with an app feature `test-utils = ["nautilus/test-utils"]`, as the examples do. Do not choose at runtime by probing for `/dev/nsm`: a missing device would then silently produce a forgeable identity.

### Custom Signer

Implement `Signer` to sign with a key that outlives one boot, for example one restored from Seal after the enclave proves its PCRs:

```rust
use ed25519_dalek::{Signer as _, SigningKey};
use nautilus::{NautilusContext, NautilusError, NsmAttestor, PublicKeyBytes, SignatureBytes, Signer};

struct RestoredKey(SigningKey);

impl Signer for RestoredKey {
    fn public_key(&self) -> PublicKeyBytes {
        self.0.verifying_key().to_bytes()
    }

    fn sign(&self, message: &[u8]) -> Result<SignatureBytes, NautilusError> {
        Ok(self.0.sign(message).to_bytes())
    }
}

fn restored(seed: [u8; 32]) -> Result<NautilusContext, NautilusError> {
    Ok(NautilusContext::with_signer(
        RestoredKey(SigningKey::from_bytes(&seed)),
        NsmAttestor::open()?,
    ))
}
```

Two-phase bootstrap: start with `from_runtime()`, attest its per-boot key to the key service, receive the secret, then build the serving context with `with_signer` and pass it to `router`. Attestation documents from the new context carry the restored key. A key delivered by the host without such a check is unmeasured input; see [attestation.md](attestation.md#what-attestation-proves).

`attestation()` binds only 32-byte Ed25519 keys, so flows that need another key type in the document (AWS KMS `Recipient` requires an RSA key) are not supported by the context.

## Signing

```rust
use nautilus::{Intent, NautilusContext, NautilusError, SignedResponse};
use serde::Serialize;

#[repr(u8)]
enum AppIntent {
    Price = 0,
    Settlement = 1,
}

impl From<AppIntent> for Intent {
    fn from(intent: AppIntent) -> Self {
        Intent(intent as u8)
    }
}

#[derive(Clone, Serialize)]
struct Price {
    value: u64,
}

fn sign_price(ctx: &NautilusContext) -> Result<SignedResponse<Price>, NautilusError> {
    ctx.sign_intent(AppIntent::Price, &Price { value: 1 })
}
```

- `sign_intent(intent, &payload)` signs BCS `(intent, now_ms(), payload)` and returns `SignedResponse { response: IntentMessage { intent, timestamp_ms, data }, signature }` with a hex signature. The payload must be `Serialize + Clone`.
- `now_ms()` is Unix milliseconds from the system clock, never lower than a previous call in the process. It is the enclave's claim, not attested time.
- `intent_message(intent, timestamp_ms, &payload)` returns the exact signed bytes.
- `sign_intent_at` (feature `test-utils`) takes a fixed timestamp for vectors.
- There is no raw-bytes signing API.

Pick payload field types from [contract.md](contract.md) so the BCS matches the Move struct.

### Verifying Off Chain

Clients that read `/process_data` responses verify them against the attested key:

```rust
use nautilus::verify_signed_response;

verify_signed_response(&public_key, AppIntent::Price.into(), &response)?;
```

It checks the intent, re-encodes the BCS message and verifies Ed25519. Freshness and replay checks remain the client's job.

## Server

- `router(ctx, config, handler)`: `handler: Fn(Bytes, &NautilusContext) -> Result<T, NautilusError>`, run on the blocking thread pool, so CPU-heavy work does not stall the runtime.
- `router_async(ctx, config, handler)`: `handler: Fn(Bytes, NautilusContext) -> impl Future<Output = Result<T, NautilusError>>`, run on the runtime. Do not block in it.
- `T: Serialize` is returned as JSON.
- `serve(addr, app)` binds and serves until SIGTERM or Ctrl-C, then drains in-flight requests. `serve_with_shutdown(listener, app, signal)` takes your own listener and shutdown future.

### ServerConfig

| Field | Default | Effect |
| --- | --- | --- |
| `max_body_bytes` | 8 MiB (`DEFAULT_MAX_BODY_BYTES`) | larger bodies get 413 |
| `max_concurrent` | available parallelism, or 1 | in-flight `/attestation` + `/process_data`; extra requests get 429 |
| `request_timeout` | 30 s (`DEFAULT_REQUEST_TIMEOUT`) | slower requests get 408 |
| `allow_unnonced_attestation` | false | enables `GET /attestation` and nonce-less `POST` |

```rust
use std::time::Duration;
use nautilus::ServerConfig;

let config = ServerConfig {
    max_body_bytes: 64 * 1024 * 1024,
    max_concurrent: 2,
    request_timeout: Duration::from_secs(120),
    ..ServerConfig::default()
};
```

A blocking handler that times out keeps its concurrency slot until it actually returns, so a stuck handler cannot be replaced by unbounded new work.

### Memory Sizing

The initramfs, including your binary, lives in enclave RAM. Size enclave memory to cover:

- the unpacked initramfs (`out/rootfs.cpio` is its gzip-compressed form),
- plus `max_concurrent * max_body_bytes` of buffered bodies,
- plus the handler's working set per request.

`nitro-cli` reserves enclave resources from `/etc/nitro_enclaves/allocator.yaml` (`memory_mib`, `cpu_count`; default 512 MiB and 2 vCPUs). `run-enclave --memory` must not exceed that reservation, and on SMT parents `--cpu-count` must be even. `make run-eif` uses `--cpu-count 2 --memory 512M`.

### Errors

Handlers return `NautilusError`. The response is JSON `ErrorBody { error: ErrorCode, message }`:

- `NautilusError::Application` (`NautilusError::application("...")`): `application_error`, 422, with your message.
- `NautilusError::Hex`: `invalid_request`, 400.
- `NautilusError::Attestation`: `attestation_unavailable`, 503, or `invalid_request` for a request that fails validation.
- Anything else: `internal_error`, 500, with a fixed message; the details are logged.

The full code table is in the README.

## Logging

The crate logs through `tracing` and installs nothing. Install a subscriber in `main`, for example `tracing_subscriber::fmt().init()`, or boot, attestation and error logs are discarded.
