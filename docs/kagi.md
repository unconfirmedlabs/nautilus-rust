# Kagi Integration

Kagi is the Sui Move companion for Nautilus Rust.

Nautilus Rust owns the code that runs inside the enclave:

- per-boot Ed25519 identity generation
- response signing
- NSM attestation document requests
- local fake attestation for tests
- app-facing HTTP route scaffolding

Kagi owns the on-chain verification layer:

- PCR policy objects
- Nitro attestation document validation through Sui's `NitroAttestationDocument`
- enclave public-key extraction
- registered enclave objects
- Ed25519 verification of enclave-signed intent messages

The projects should stay separate. `nautilus-rust` should not vendor Move modules, and Kagi should not need to know about Axum, NSM ioctl details, or app server internals.

## Registration Flow

1. Build a Nautilus Rust app into an EIF and record `nitro.pcrs`.
2. Create a Kagi `EnclavePolicy<T>` with the expected PCR0, PCR1, and PCR2 values.
3. Boot the enclave and request a Nitro attestation document from the Nautilus Rust app.
4. Load that document with Sui's `nitro_attestation::load_nitro_attestation` and pass it to Kagi. Kagi validates the document against the policy and stores the attested public key in an `Enclave<T>`.
5. Have the Nautilus Rust app sign response payloads with `NautilusContext::sign_bcs_payload`.
6. Have Move code call Kagi's `verify_signature` before consuming the response.

## Signing Compatibility

Kagi verifies Ed25519 signatures over a BCS-serialized intent message:

```move
public struct IntentMessage<T: drop> has copy, drop {
    intent: u8,
    timestamp_ms: u64,
    payload: T,
}
```

Nautilus Rust signs the same byte layout:

```rust
let signed = ctx.sign_bcs_payload(intent, timestamp_ms, payload)?;
```

The Rust golden vector in `crates/nautilus/src/intent.rs` is intentionally aligned with Kagi's Move `test_serde` vector. Keep those tests in sync whenever the intent-message layout changes.

See [signing-vectors.md](signing-vectors.md) for the canonical vector.
