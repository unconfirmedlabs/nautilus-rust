use serde::{Deserialize, Serialize};

use crate::{NautilusContext, NautilusError, encode_hex};

/// Response wrapper containing intent metadata and app data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntentResponse<T> {
    pub intent: u8,
    pub timestamp_ms: u64,
    pub data: T,
}

/// Signed response wrapper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedIntent<T> {
    pub response: IntentResponse<T>,
    pub signature: String,
}

/// Builds a Nautilus intent message:
///
/// `intent: u8 || timestamp_ms: u64 little-endian || payload_bcs`.
pub fn intent_message(intent: u8, timestamp_ms: u64, payload_bcs: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(1 + 8 + payload_bcs.len());
    message.push(intent);
    message.extend_from_slice(&timestamp_ms.to_le_bytes());
    message.extend_from_slice(payload_bcs);
    message
}

pub(crate) fn sign_bcs_payload<T>(
    ctx: &NautilusContext,
    intent: u8,
    timestamp_ms: u64,
    payload: T,
) -> Result<SignedIntent<T>, NautilusError>
where
    T: Serialize + Clone,
{
    let payload_bcs =
        bcs::to_bytes(&payload).map_err(|error| NautilusError::Bcs(error.to_string()))?;
    let message = intent_message(intent, timestamp_ms, &payload_bcs);
    let signature = encode_hex(ctx.sign(&message)?);
    Ok(SignedIntent {
        response: IntentResponse {
            intent,
            timestamp_ms,
            data: payload,
        },
        signature,
    })
}

#[cfg(test)]
mod tests {
    use serde::Serialize;

    use crate::{EnclaveIdentity, NautilusContext, testing::FakeAttestor};

    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    struct TestPayload {
        count: u8,
        amount: u64,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    struct WeatherPayload {
        location: String,
        temperature: u64,
    }

    #[test]
    fn intent_message_layout_is_stable() {
        let payload = [0xaa, 0xbb, 0xcc];
        let message = intent_message(7, 0x0102_0304_0506_0708, &payload);
        assert_eq!(message[0], 7);
        assert_eq!(&message[1..9], &0x0102_0304_0506_0708u64.to_le_bytes());
        assert_eq!(&message[9..], &payload);
    }

    #[test]
    fn sign_bcs_payload_can_be_verified() {
        let ctx = NautilusContext::new(
            EnclaveIdentity::from_seed([5u8; 32]),
            FakeAttestor::default(),
        );
        let payload = TestPayload {
            count: 9,
            amount: 1000,
        };
        let signed = ctx.sign_bcs_payload(1, 42, payload.clone()).unwrap();

        let payload_bcs = bcs::to_bytes(&payload).unwrap();
        let message = intent_message(1, 42, &payload_bcs);
        let signature: [u8; 64] = hex::decode(signed.signature).unwrap().try_into().unwrap();
        ctx.identity().verify(&message, &signature).unwrap();
    }

    #[test]
    fn kagi_weather_intent_vector_is_stable() {
        let ctx = NautilusContext::new(
            EnclaveIdentity::from_seed([5u8; 32]),
            FakeAttestor::default(),
        );
        let payload = WeatherPayload {
            location: "San Francisco".to_owned(),
            temperature: 13,
        };
        let payload_bcs = bcs::to_bytes(&payload).unwrap();
        let message = intent_message(0, 1_744_038_900_000, &payload_bcs);

        assert_eq!(
            hex::encode(&payload_bcs),
            "0d53616e204672616e636973636f0d00000000000000"
        );
        assert_eq!(
            hex::encode(&message),
            "0020b1d110960100000d53616e204672616e636973636f0d00000000000000"
        );
        assert_eq!(
            ctx.public_key_hex(),
            "6e7a1cdd29b0b78fd13af4c5598feff4ef2a97166e3ca6f2e4fbfccd80505bf1"
        );

        let signed = ctx.sign_bcs_payload(0, 1_744_038_900_000, payload).unwrap();
        assert_eq!(
            signed.signature,
            "ef241b08b951a8451f9de2a414530856059ace7acbb9ff5c114839dc697252f5685163eef75db9a0ce497533638f1e66e791edcf8790005d2fa0d2c3b0c39909"
        );
    }
}
