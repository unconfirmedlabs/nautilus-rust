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

## Routes

`nautilus::router` creates:

- `GET /health_check`
- `GET /attestation`
- `POST /attestation`
- `POST /process_data`

`POST /process_data` receives raw request bytes and passes them to the handler you provide.

## Error Mapping

Handlers return `Result<T, NautilusError>` where `T: serde::Serialize`.

- success: `200`
- body too large: `413`
- invalid attestation request: `400`
- application failure: `422`
- internal framework failure: `500`
