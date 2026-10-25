# Attestation

Nautilus binds a per-boot Ed25519 public key to an AWS Nitro Enclave attestation document.

The intended verifier flow is:

1. Request `POST /attestation` with a nonce.
2. Verify the returned Nitro attestation document and PCRs.
3. Confirm the attestation document contains the app public key.
4. Accept `/process_data` signatures from that public key.

The `nautilus` crate exposes the `Attestor` trait and implements it for `/dev/nsm` as `NsmAttestor`, on top of the standalone `nautilus-nsm` driver.

Tests and local examples use `FakeAttestor` behind the `test-utils` feature, which makes route behavior testable without Nitro hardware.

## Kagi

For Sui Move verification, use Kagi:

https://github.com/unconfirmedlabs/kagi

Kagi owns PCR policy, Nitro attestation document validation, public-key registration, and Ed25519 verification on-chain. Nautilus Rust owns producing the attestation document and signing responses with the attested key.

See [kagi.md](kagi.md).

## Nitro Runtime

Create the context inside the enclave with:

```rust
let ctx = nautilus::NautilusContext::from_runtime()?;
```

`from_runtime` fails if `/dev/nsm` cannot be opened and never falls back to a development identity. It generates the enclave signing identity from OS randomness mixed with NSM entropy. The resulting Ed25519 public key is included in NSM attestation requests so verifiers can bind signed application responses to the attested enclave.

## Freshness

`POST /attestation` requires a random nonce supplied by the verifier; requests without one (or with an empty one) are rejected with `400 invalid_request`. `nonce` and `user_data` are limited to 512 bytes each (`MAX_ATTESTATION_DATA_BYTES`, Sui's `MAX_USER_DATA_LENGTH`), and the public key is always the 32-byte enclave key, so every returned document can be registered on Sui.

Setting `ServerConfig::allow_unnonced_attestation` registers `GET /attestation` and accepts nonce-less `POST /attestation` for diagnostics. Those documents carry no verifier freshness and do not provide replay protection.
