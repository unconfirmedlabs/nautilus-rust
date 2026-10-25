//! Rust types with a fixed BCS layout matching Move, and golden vectors that pin it.

use std::{fmt, ops::Deref};

use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, SeqAccess, Visitor},
};

use crate::{Intent, NautilusError, encode_hex, intent_message};

/// Move `u256`: little-endian bytes, BCS-encoded as 32 raw bytes; JSON is `0x`-prefixed big-endian hex.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct U256Bytes(pub [u8; 32]);

impl U256Bytes {
    /// Creates a value from little-endian bytes.
    pub fn from_le_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Creates a value from big-endian bytes.
    pub fn from_be_bytes(mut bytes: [u8; 32]) -> Self {
        bytes.reverse();
        Self(bytes)
    }

    /// Returns the little-endian bytes.
    pub fn to_le_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Returns the big-endian bytes.
    pub fn to_be_bytes(self) -> [u8; 32] {
        let mut bytes = self.0;
        bytes.reverse();
        bytes
    }
}

impl From<u128> for U256Bytes {
    fn from(value: u128) -> Self {
        let mut bytes = [0u8; 32];
        bytes[..16].copy_from_slice(&value.to_le_bytes());
        Self(bytes)
    }
}

impl From<u64> for U256Bytes {
    fn from(value: u64) -> Self {
        Self::from(u128::from(value))
    }
}

impl Serialize for U256Bytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(&format!("0x{}", encode_hex(self.to_be_bytes())))
        } else {
            self.0.serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for U256Bytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if deserializer.is_human_readable() {
            let text = String::deserialize(deserializer)?;
            let digits = text.strip_prefix("0x").unwrap_or(&text);
            if digits.len() != 64 {
                return Err(de::Error::custom("u256 must be exactly 64 hex digits"));
            }
            let mut bytes = [0u8; 32];
            hex::decode_to_slice(digits, &mut bytes).map_err(de::Error::custom)?;
            Ok(Self::from_be_bytes(bytes))
        } else {
            <[u8; 32]>::deserialize(deserializer).map(Self)
        }
    }
}

/// Move `vector<u8>`: BCS-encoded with a ULEB128 length prefix; JSON is `0x`-prefixed hex.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct ByteVec(pub Vec<u8>);

impl From<Vec<u8>> for ByteVec {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl From<&[u8]> for ByteVec {
    fn from(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }
}

impl<const N: usize> From<[u8; N]> for ByteVec {
    fn from(bytes: [u8; N]) -> Self {
        Self(bytes.to_vec())
    }
}

impl Deref for ByteVec {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for ByteVec {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Serialize for ByteVec {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(&format!("0x{}", encode_hex(&self.0)))
        } else {
            serializer.serialize_bytes(&self.0)
        }
    }
}

impl<'de> Deserialize<'de> for ByteVec {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if deserializer.is_human_readable() {
            let text = String::deserialize(deserializer)?;
            hex::decode(text.strip_prefix("0x").unwrap_or(&text))
                .map(Self)
                .map_err(de::Error::custom)
        } else {
            deserializer.deserialize_byte_buf(ByteVecVisitor)
        }
    }
}

struct ByteVecVisitor;

impl<'de> Visitor<'de> for ByteVecVisitor {
    type Value = ByteVec;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a byte vector")
    }

    fn visit_bytes<E: de::Error>(self, bytes: &[u8]) -> Result<ByteVec, E> {
        Ok(ByteVec(bytes.to_vec()))
    }

    fn visit_byte_buf<E: de::Error>(self, bytes: Vec<u8>) -> Result<ByteVec, E> {
        Ok(ByteVec(bytes))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<ByteVec, A::Error> {
        let mut bytes = Vec::with_capacity(seq.size_hint().unwrap_or(0));
        while let Some(byte) = seq.next_element()? {
            bytes.push(byte);
        }
        Ok(ByteVec(bytes))
    }
}

/// A named intent message and the hex of its exact signed bytes, for pinning in Move tests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoldenVector {
    /// Vector name.
    pub name: String,
    /// Intent scope.
    pub intent: Intent,
    /// Timestamp in Unix milliseconds.
    pub timestamp_ms: u64,
    /// Lowercase hex of [`intent_message`].
    pub bcs_hex: String,
}

impl GoldenVector {
    /// Returns the vector as one line of JSON.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("golden vector serializes to JSON")
    }
}

impl fmt::Display for GoldenVector {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(
            formatter,
            "const {}: vector<u8> = x\"{}\";",
            self.name.to_uppercase(),
            self.bcs_hex
        )
    }
}

/// Builds the golden vector for `payload` signed as `intent` at `timestamp_ms`.
pub fn golden_vector<T: Serialize + ?Sized>(
    name: &str,
    intent: impl Into<Intent>,
    timestamp_ms: u64,
    payload: &T,
) -> Result<GoldenVector, NautilusError> {
    let intent = intent.into();
    Ok(GoldenVector {
        name: name.to_owned(),
        intent,
        timestamp_ms,
        bcs_hex: encode_hex(intent_message(intent, timestamp_ms, payload)?),
    })
}

/// Generates one `#[test]` per entry that prints the vector as JSON and asserts its intent message hex.
///
/// `name: (intent, timestamp_ms, payload) => "hex";`
#[macro_export]
macro_rules! golden_vectors {
    ($($name:ident: ($intent:expr, $timestamp_ms:expr, $payload:expr $(,)?) => $hex:expr;)+) => {
        $(
            #[test]
            fn $name() {
                let vector = $crate::contract::golden_vector(
                    stringify!($name),
                    $intent,
                    $timestamp_ms,
                    &$payload,
                )
                .expect("payload serializes to BCS");
                println!("{}", vector.to_json());
                assert_eq!(vector.bcs_hex, $hex, "golden vector changed: {}", vector);
            }
        )+
    };
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    use crate::{
        EnclaveIdentity, NautilusContext, SignedResponse, testing::FakeAttestor,
        verify_signed_response,
    };

    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct WeatherPayload {
        location: String,
        temperature: u64,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct BlobPayload {
        blob_id: U256Bytes,
        digest: ByteVec,
    }

    #[test]
    fn u256_bcs_is_32_raw_little_endian_bytes() {
        let bytes = bcs::to_bytes(&U256Bytes::from(1u64)).unwrap();
        let mut expected = vec![1u8];
        expected.extend([0u8; 31]);
        assert_eq!(bytes, expected);
        assert_eq!(
            bcs::from_bytes::<U256Bytes>(&bytes).unwrap(),
            U256Bytes::from(1u64)
        );
    }

    #[test]
    fn u256_json_is_big_endian_hex() {
        let value = U256Bytes::from(0x0102u64);
        let json = serde_json::to_string(&value).unwrap();
        assert_eq!(json, format!("\"0x{}0102\"", "0".repeat(60)));
        assert_eq!(serde_json::from_str::<U256Bytes>(&json).unwrap(), value);
        let bare = format!("\"{}0102\"", "0".repeat(60));
        assert_eq!(serde_json::from_str::<U256Bytes>(&bare).unwrap(), value);
        assert_eq!(value.to_be_bytes()[30..], [1, 2]);
        assert_eq!(U256Bytes::from_be_bytes(value.to_be_bytes()), value);
    }

    #[test]
    fn u256_json_rejects_bad_input() {
        for json in [
            format!("\"0x{}\"", "0".repeat(63)),
            format!("\"0x{}\"", "0".repeat(65)),
            format!("\"0x{}zz\"", "0".repeat(62)),
            "1".to_owned(),
        ] {
            assert!(serde_json::from_str::<U256Bytes>(&json).is_err(), "{json}");
        }
    }

    #[test]
    fn byte_vec_bcs_has_uleb_length_prefix() {
        let bytes = vec![0xabu8; 200];
        let encoded = bcs::to_bytes(&ByteVec::from(bytes.clone())).unwrap();
        assert_eq!(encoded[..2], [0xc8, 0x01]);
        assert_eq!(encoded, bcs::to_bytes(&bytes).unwrap());
        assert_eq!(
            bcs::from_bytes::<ByteVec>(&encoded).unwrap(),
            ByteVec(bytes)
        );
    }

    #[test]
    fn byte_vec_json_is_hex() {
        let value = ByteVec::from([0xde, 0xad]);
        let json = serde_json::to_string(&value).unwrap();
        assert_eq!(json, "\"0xdead\"");
        assert_eq!(serde_json::from_str::<ByteVec>(&json).unwrap(), value);
        assert_eq!(serde_json::from_str::<ByteVec>("\"dead\"").unwrap(), value);
        assert!(serde_json::from_str::<ByteVec>("\"0xde0\"").is_err());
    }

    #[test]
    fn fixed_byte_array_bcs_has_no_length_prefix() {
        assert_eq!(bcs::to_bytes(&[7u8; 32]).unwrap(), vec![7u8; 32]);
        assert_eq!(bcs::to_bytes(&ByteVec::from([7u8; 32])).unwrap()[0], 32);
    }

    #[test]
    fn golden_vector_displays_move_constant() {
        let vector = golden_vector("tiny", 3u8, 0, &1u8).unwrap();
        assert_eq!(
            vector.to_string(),
            "const TINY: vector<u8> = x\"03000000000000000001\";"
        );
        assert_eq!(
            vector.to_json(),
            r#"{"name":"tiny","intent":3,"timestamp_ms":0,"bcs_hex":"03000000000000000001"}"#
        );
    }

    crate::golden_vectors! {
        kagi_weather: (
            Intent(0),
            1_744_038_900_000,
            WeatherPayload { location: "San Francisco".to_owned(), temperature: 13 },
        ) => "0020b1d110960100000d53616e204672616e636973636f0d00000000000000";
    }

    #[test]
    fn signed_response_verifies_after_json_round_trip() {
        let ctx = NautilusContext::with_signer(
            EnclaveIdentity::from_seed([8u8; 32]),
            FakeAttestor::default(),
        );
        let payload = BlobPayload {
            blob_id: U256Bytes::from_be_bytes([0x11; 32]),
            digest: ByteVec::from(vec![1, 2, 3]),
        };
        let signed = ctx.sign_intent(Intent(4), &payload).unwrap();
        let json = serde_json::to_string(&signed).unwrap();
        let decoded: SignedResponse<BlobPayload> = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, signed);
        verify_signed_response(&ctx.public_key(), Intent(4), &decoded).unwrap();
    }
}
