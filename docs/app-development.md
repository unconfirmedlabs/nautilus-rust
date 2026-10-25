# App Development

Application developers should import `nautilus` rather than editing the framework crate.

The usual structure is:

```text
my-enclave-app/
  Cargo.toml
  src/main.rs
```

`src/main.rs` owns application behavior. The framework owns the common enclave plumbing:

- enclave identity
- Ed25519 signing
- Sui address derivation
- attestation route helpers
- request size limits
- test fakes
- Kagi-compatible BCS intent signing

## Routes

`nautilus::router` creates:

- `GET /health_check`
- `POST /attestation` (nonce required, nonce and user data at most 512 bytes)
- `POST /process_data`
- `GET /attestation`, only with `ServerConfig::allow_unnonced_attestation`

`POST /process_data` receives raw request bytes and passes them to the handler you provide:

```rust
fn process_data(bytes: Bytes, ctx: &NautilusContext) -> Result<SignedResponse<Payload>, NautilusError> {
    ctx.sign_intent(Intent(0), &Payload::from(bytes))
}

let app = nautilus::router(ctx, ServerConfig::default(), process_data);
nautilus::serve("127.0.0.1:3000".parse()?, app).await?;
```

`router` runs the handler on the blocking thread pool, so CPU-heavy work never stalls the runtime. Use `router_async` for an async handler `Fn(Bytes, NautilusContext) -> impl Future`.

`ServerConfig` defaults: `max_body_bytes` 8 MiB, `max_concurrent` = available parallelism, `request_timeout` 30 s, `allow_unnonced_attestation` false. Peak buffered request memory is about `max_concurrent * max_body_bytes`. A blocking handler that times out keeps its concurrency slot until it returns. `serve` drains in-flight requests on SIGTERM and Ctrl-C.

## Signed Responses

Sign a typed payload under an application-defined intent; the timestamp is the enclave's `now_ms()`:

```rust
let signed = ctx.sign_intent(Intent(0), &payload)?;
```

Off-chain clients check responses with `nautilus::verify_signed_response`.

The signed bytes match Kagi's Move `IntentMessage<T>` layout. See [signing-vectors.md](signing-vectors.md).

## Error Mapping

Handlers return `Result<T, NautilusError>` where `T: serde::Serialize`.

Errors are JSON `{"error": "<code>", "message": "..."}` (`nautilus::ErrorBody`, `nautilus::ErrorCode`):

- success: `200`
- `invalid_request` `400`: invalid hex or JSON, missing nonce, attestation bounds, or a handler's `NautilusError::Hex`
- `body_read_failed` `400`: the body could not be read
- `request_timeout` `408`
- `body_too_large` `413`
- `application_error` `422`: `NautilusError::Application`, with your message
- `overloaded` `429`: `max_concurrent` reached
- `internal_error` `500`: anything else, details logged only
- `attestation_unavailable` `503`: attestation provider failure, details logged only
