# Signing Vectors

These vectors pin the byte-level contract between Nautilus Rust and Kagi. Keep the Rust and Move tests in sync whenever the intent message layout changes.

## Kagi Weather Intent

Rust payload:

```rust
#[derive(serde::Serialize)]
struct WeatherPayload {
    location: String,
    temperature: u64,
}
```

Move payload:

```move
public struct SigningPayload has copy, drop {
    location: String,
    temperature: u64,
}
```

Inputs:

```text
intent = 0
timestamp_ms = 1744038900000
location = "San Francisco"
temperature = 13
ed25519_seed = 0x0505050505050505050505050505050505050505050505050505050505050505
```

Expected values:

```text
payload_bcs_hex = 0d53616e204672616e636973636f0d00000000000000
intent_message_hex = 0020b1d110960100000d53616e204672616e636973636f0d00000000000000
public_key_hex = 6e7a1cdd29b0b78fd13af4c5598feff4ef2a97166e3ca6f2e4fbfccd80505bf1
signature_hex = ef241b08b951a8451f9de2a414530856059ace7acbb9ff5c114839dc697252f5685163eef75db9a0ce497533638f1e66e791edcf8790005d2fa0d2c3b0c39909
```

The signature is Ed25519 over `intent_message_hex`, not over the JSON response body. Kagi's Move tests pin the same `intent_message_hex`.

## Reproducing It

`nautilus::intent_message` returns the message bytes. The signature needs a fixed key and timestamp, so it is reproduced with `NautilusContext::sign_intent_at` (feature `test-utils`) on a context built from the seed above; `kagi_weather_intent_vector_is_stable` in `crates/nautilus/src/intent.rs` does exactly this:

```rust
let ctx = NautilusContext::with_signer(EnclaveIdentity::from_seed([5u8; 32]), FakeAttestor::default());
let signed = ctx.sign_intent_at(Intent(0), 1_744_038_900_000, payload)?;
assert_eq!(signed.signature, "ef241b08b951a8451f9de2a414530856059ace7acbb9ff5c114839dc697252f5685163eef75db9a0ce497533638f1e66e791edcf8790005d2fa0d2c3b0c39909");
```

To pin the message bytes in an app crate, use `golden_vectors!` (see [contract.md](contract.md#golden-vectors)):

```rust
nautilus::golden_vectors! {
    weather_sf: (
        0,
        1_744_038_900_000,
        WeatherPayload { location: "San Francisco".to_owned(), temperature: 13 },
    ) => "0020b1d110960100000d53616e204672616e636973636f0d00000000000000";
}
```
