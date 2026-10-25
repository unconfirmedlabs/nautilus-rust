# Rust to Move Payload Contract

An enclave signs the BCS bytes of its payload, and Move re-encodes its own struct to verify the signature. The two sides agree only if every Rust field encodes to the same bytes as the matching Move field. BCS carries no field names or types, so a mismatch is not an error anywhere: the signature just fails to verify. Pick Rust types from the table below and pin each payload with a golden vector on both sides.

## Type Mapping

| Move type | Rust type | BCS bytes | JSON |
| --- | --- | --- | --- |
| `bool` | `bool` | `00` or `01` | `true` / `false` |
| `u8` | `u8` | 1 byte | number |
| `u16` | `u16` | 2 bytes, little-endian | number |
| `u32` | `u32` | 4 bytes, little-endian | number |
| `u64` | `u64` | 8 bytes, little-endian | number (see caveat) |
| `u128` | `u128` | 16 bytes, little-endian | number (see caveat) |
| `u256` | `nautilus::contract::U256Bytes` | 32 bytes, little-endian, no length prefix | `"0x"` + 64 hex digits, big-endian |
| `address`, `ID` | `[u8; 32]` | 32 raw bytes, no length prefix | array of 32 numbers |
| `vector<u8>` | `nautilus::contract::ByteVec` or `Vec<u8>`, never `[u8; N]` | ULEB128 length, then the bytes | `ByteVec`: `"0x"` + hex; `Vec<u8>`: array of numbers |
| `vector<T>` | `Vec<T>` | ULEB128 length, then each element | array |
| `String`, `ascii::String` | `String` | ULEB128 byte length, then UTF-8 bytes | string |
| `Option<T>` | `Option<T>` | `00` for none, `01` then the value for some (same bytes as Move's vector-backed `Option`) | `null` or the value |
| struct | struct | fields concatenated in declaration order; names are irrelevant | object |
| enum | enum | ULEB128 variant index, then the variant's fields | serde's enum form |

Notes:

- `[u8; N]` encodes as N raw bytes. Use it only where Move has a fixed 32-byte type (`address`, `ID`). A Move `vector<u8>` needs the length prefix, which `ByteVec` and `Vec<u8>` provide.
- Field order is the contract. Reordering fields in either struct changes the bytes without a compile error on either side.
- Serde encodes a fieldless `#[repr(u8)]` enum by its variant index, not its discriminant: `enum Kind { A = 5, B = 7 }` encodes `Kind::B` as `01`. Declare Rust variants in the same order as the Move enum.
- JSON caveat: `u64` and `u128` values above 2^53 lose precision in JavaScript numbers. Clients that need them exactly must parse with a big-integer JSON reader, or the payload should carry them as `U256Bytes` or strings. `U256Bytes` JSON parses with `BigInt("0x...")`.

## Intent Message Layout

Every signed message is the BCS encoding of Kagi's Move struct:

```move
public struct IntentMessage<Payload: drop> has copy, drop {
    intent: u8,
    timestamp_ms: u64,
    payload: Payload,
}
```

That is 1 intent byte, 8 bytes of little-endian `timestamp_ms`, then the payload's BCS bytes. `nautilus::intent_message(intent, timestamp_ms, &payload)` returns exactly these bytes, and `NautilusContext::sign_intent` signs them with Ed25519.

## Golden Vectors

`nautilus::golden_vectors!` turns each entry into a `#[test]` that builds the intent message, prints it as one JSON line and asserts its hex:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    nautilus::golden_vectors! {
        weather_sf: (
            0,
            1_744_038_900_000,
            WeatherPayload { location: "San Francisco".to_owned(), temperature: 13 },
        ) => "0020b1d110960100000d53616e204672616e636973636f0d00000000000000";
    }
}
```

Entry syntax is `name: (intent, timestamp_ms, payload) => "hex";`, repeated. `cargo test -- --nocapture` prints one record per vector:

```json
{"name":"weather_sf","intent":0,"timestamp_ms":1744038900000,"bcs_hex":"0020b1d1..."}
```

On a mismatch the failure message includes a ready Move constant, `const WEATHER_SF: vector<u8> = x"...";`. `nautilus::contract::golden_vector` builds the same `GoldenVector` outside the macro.

Pin the same hex in a Move `#[test]` with Kagi's `enclave::create_intent_message`:

```move
#[test]
fun weather_sf() {
    let message = enclave::create_intent_message(
        0,
        1744038900000,
        SigningPayload { location: b"San Francisco".to_string(), temperature: 13 },
    );
    assert!(bcs::to_bytes(&message) == x"0020b1d110960100000d53616e204672616e636973636f0d00000000000000");
}
```

When either side changes the payload layout, one of the two tests fails.
