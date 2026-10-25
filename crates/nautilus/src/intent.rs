use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

use crate::{NautilusError, PublicKeyBytes, crypto::verify_ed25519, decode_hex};

/// Application-defined intent scope, the first byte of every signed message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Intent(pub u8);

impl From<u8> for Intent {
    fn from(value: u8) -> Self {
        Self(value)
    }
}

/// Signed message body, matching Move `IntentMessage { intent: u8, timestamp_ms: u64, payload: T }`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntentMessage<T> {
    /// Intent scope.
    pub intent: Intent,
    /// Enclave Unix time in milliseconds when the message was signed.
    pub timestamp_ms: u64,
    /// Application payload.
    pub data: T,
}

/// An intent message with its hex-encoded Ed25519 signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedResponse<T> {
    /// The signed message.
    pub response: IntentMessage<T>,
    /// Lowercase hex Ed25519 signature over [`intent_message`].
    pub signature: String,
}

#[derive(Serialize)]
struct IntentMessageRef<'a, T: ?Sized> {
    intent: Intent,
    timestamp_ms: u64,
    data: &'a T,
}

static LAST_NOW_MS: AtomicU64 = AtomicU64::new(0);

/// Returns the exact bytes signed for `payload`: BCS of `(intent, timestamp_ms, payload)`.
pub fn intent_message<T: Serialize + ?Sized>(
    intent: Intent,
    timestamp_ms: u64,
    payload: &T,
) -> Result<Vec<u8>, NautilusError> {
    bcs::to_bytes(&IntentMessageRef {
        intent,
        timestamp_ms,
        data: payload,
    })
    .map_err(|error| NautilusError::Bcs(error.to_string()))
}

/// Verifies that `response` carries `intent` and is signed by `public_key`.
pub fn verify_signed_response<T: Serialize>(
    public_key: &PublicKeyBytes,
    intent: Intent,
    response: &SignedResponse<T>,
) -> Result<(), NautilusError> {
    let message = &response.response;
    if message.intent != intent {
        return Err(NautilusError::Crypto(format!(
            "intent mismatch: expected {}, got {}",
            intent.0, message.intent.0
        )));
    }
    let signature: [u8; 64] = decode_hex(&response.signature)?
        .try_into()
        .map_err(|_| NautilusError::Crypto("signature must be 64 bytes".to_owned()))?;
    let bytes = intent_message(message.intent, message.timestamp_ms, &message.data)?;
    verify_ed25519(public_key, &bytes, &signature)
}

/// Returns Unix time in milliseconds, never lower than a previous call in this process.
pub fn now_ms() -> Result<u64, NautilusError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| NautilusError::Clock(error.to_string()))?;
    let now = u64::try_from(elapsed.as_millis())
        .map_err(|_| NautilusError::Clock("time exceeds u64 milliseconds".to_owned()))?;
    Ok(LAST_NOW_MS.fetch_max(now, Ordering::Relaxed).max(now))
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

    fn context() -> NautilusContext {
        NautilusContext::new(
            EnclaveIdentity::from_seed([5u8; 32]),
            FakeAttestor::default(),
        )
    }

    fn payload() -> TestPayload {
        TestPayload {
            count: 9,
            amount: 1000,
        }
    }

    #[test]
    fn intent_message_layout_is_stable() {
        let message = intent_message(Intent(7), 0x0102_0304_0506_0708, &payload()).unwrap();
        assert_eq!(message[0], 7);
        assert_eq!(&message[1..9], &0x0102_0304_0506_0708u64.to_le_bytes());
        assert_eq!(&message[9..], &bcs::to_bytes(&payload()).unwrap()[..]);
    }

    #[test]
    fn intent_message_json_matches_template_field_names() {
        let message = IntentMessage {
            intent: Intent(1),
            timestamp_ms: 2,
            data: 3u8,
        };
        assert_eq!(
            serde_json::to_value(&message).unwrap(),
            serde_json::json!({ "intent": 1, "timestamp_ms": 2, "data": 3 })
        );
    }

    #[test]
    fn verify_accepts_good_response() {
        let ctx = context();
        let signed = ctx.sign_intent(Intent(1), &payload()).unwrap();
        verify_signed_response(&ctx.public_key(), Intent(1), &signed).unwrap();
    }

    #[test]
    fn verify_rejects_wrong_intent() {
        let ctx = context();
        let signed = ctx.sign_intent(Intent(1), &payload()).unwrap();
        assert!(verify_signed_response(&ctx.public_key(), Intent(2), &signed).is_err());

        let mut relabeled = signed;
        relabeled.response.intent = Intent(2);
        assert!(verify_signed_response(&ctx.public_key(), Intent(2), &relabeled).is_err());
    }

    #[test]
    fn verify_rejects_tampered_payload() {
        let ctx = context();
        let mut signed = ctx.sign_intent(Intent(1), &payload()).unwrap();
        signed.response.data.amount += 1;
        assert!(verify_signed_response(&ctx.public_key(), Intent(1), &signed).is_err());
    }

    #[test]
    fn verify_rejects_tampered_timestamp() {
        let ctx = context();
        let mut signed = ctx.sign_intent(Intent(1), &payload()).unwrap();
        signed.response.timestamp_ms += 1;
        assert!(verify_signed_response(&ctx.public_key(), Intent(1), &signed).is_err());
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let signed = context().sign_intent(Intent(1), &payload()).unwrap();
        let other = EnclaveIdentity::from_seed([6u8; 32])
            .verifying_key()
            .to_bytes();
        assert!(verify_signed_response(&other, Intent(1), &signed).is_err());
    }

    #[test]
    fn sign_intent_stamps_current_time() {
        let signed = context().sign_intent(Intent(1), &payload()).unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        assert!(signed.response.timestamp_ms.abs_diff(now) < 5_000);
    }

    #[test]
    fn now_ms_is_non_decreasing() {
        let mut previous = now_ms().unwrap();
        for _ in 0..1000 {
            let next = now_ms().unwrap();
            assert!(next >= previous);
            previous = next;
        }
    }

    #[test]
    fn kagi_weather_intent_vector_is_stable() {
        let ctx = context();
        let payload = WeatherPayload {
            location: "San Francisco".to_owned(),
            temperature: 13,
        };
        let message = intent_message(Intent(0), 1_744_038_900_000, &payload).unwrap();

        assert_eq!(
            hex::encode(bcs::to_bytes(&payload).unwrap()),
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

        let signed = ctx
            .sign_intent_at(Intent(0), 1_744_038_900_000, &payload)
            .unwrap();
        assert_eq!(
            signed.signature,
            "ef241b08b951a8451f9de2a414530856059ace7acbb9ff5c114839dc697252f5685163eef75db9a0ce497533638f1e66e791edcf8790005d2fa0d2c3b0c39909"
        );
        verify_signed_response(&ctx.public_key(), Intent(0), &signed).unwrap();
    }
}
