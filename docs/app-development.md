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
- `GET /attestation`
- `POST /attestation`
- `POST /process_data`

`POST /process_data` receives raw request bytes and passes them to the handler you provide.

## Signed Responses

Sign a typed payload under an application-defined intent; the timestamp is the enclave's `now_ms()`:

```rust
let signed = ctx.sign_intent(Intent(0), &payload)?;
```

Off-chain clients check responses with `nautilus::verify_signed_response`.

The signed bytes match Kagi's Move `IntentMessage<T>` layout. See [signing-vectors.md](signing-vectors.md).

## Error Mapping

Handlers return `Result<T, NautilusError>` where `T: serde::Serialize`.

- success: `200`
- body too large: `413`
- invalid attestation request: `400`
- application failure: `422`
- internal framework failure: `500`
