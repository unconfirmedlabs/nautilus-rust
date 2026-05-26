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
}
