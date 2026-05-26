# Attestation

Nautilus binds a per-boot Ed25519 public key to an AWS Nitro Enclave attestation document.

The intended verifier flow is:

1. Request `POST /attestation` with a nonce.
2. Verify the returned Nitro attestation document and PCRs.
3. Confirm the attestation document contains the app public key.
4. Accept `/process_data` signatures from that public key.

The `nautilus` crate exposes the `Attestor` trait. The `nautilus-nsm` crate implements it by calling `/dev/nsm`.

Tests and local examples use `FakeAttestor`, which makes route behavior testable without Nitro hardware.

## Nitro Runtime

Use `nautilus_nsm::NsmAttestor` inside the enclave:

```rust
use nautilus_nsm::NsmAttestor;

let ctx = NsmAttestor::default().into_context()?;
```

`into_context` generates the enclave signing identity from OS randomness mixed with NSM entropy. The resulting Ed25519 public key is included in NSM attestation requests so verifiers can bind signed application responses to the attested enclave.

## Freshness

Prefer `POST /attestation` with a random nonce supplied by the verifier. `GET /attestation` exists for simple diagnostics and does not provide replay protection by itself.
