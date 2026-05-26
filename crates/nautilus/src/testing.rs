use std::sync::{Arc, Mutex};

use serde::Serialize;

use crate::{AttestationError, AttestationRequest, Attestor, encode_hex};

/// Fake attestor for local development and tests.
#[derive(Clone)]
pub struct FakeAttestor {
    requests: Arc<Mutex<Vec<AttestationRequest>>>,
    random_byte: u8,
}

impl Default for FakeAttestor {
    fn default() -> Self {
        Self::with_random_byte(0x42)
    }
}

impl FakeAttestor {
    /// Creates a fake attestor that returns repeated `random_byte` values.
    pub fn with_random_byte(random_byte: u8) -> Self {
        Self {
            requests: Arc::new(Mutex::new(Vec::new())),
            random_byte,
        }
    }

    /// Returns all attestation requests observed by this fake.
    pub fn requests(&self) -> Vec<AttestationRequest> {
        self.requests
            .lock()
            .expect("fake attestor request lock poisoned")
            .clone()
    }
}

#[derive(Serialize)]
struct FakeDocument {
    provider: &'static str,
    public_key: String,
    nonce: Option<String>,
    user_data: Option<String>,
}

impl Attestor for FakeAttestor {
    fn attest(&self, request: AttestationRequest) -> Result<Vec<u8>, AttestationError> {
        self.requests
            .lock()
            .expect("fake attestor request lock poisoned")
            .push(request.clone());

        let document = FakeDocument {
            provider: "fake",
            public_key: encode_hex(&request.public_key),
            nonce: request.nonce.as_ref().map(encode_hex),
            user_data: request.user_data.as_ref().map(encode_hex),
        };
        serde_json::to_vec(&document).map_err(|error| AttestationError::Backend(error.to_string()))
    }

    fn random(&self, len: usize) -> Result<Vec<u8>, AttestationError> {
        Ok(vec![self.random_byte; len])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_attestor_records_requests_and_returns_document() {
        let fake = FakeAttestor::default();
        let request = AttestationRequest::new([1u8; 32]).with_nonce([2u8; 4]);
        let doc = fake.attest(request.clone()).unwrap();
        let doc_json: serde_json::Value = serde_json::from_slice(&doc).unwrap();

        assert_eq!(fake.requests(), vec![request]);
        assert_eq!(doc_json["provider"], "fake");
        assert_eq!(doc_json["nonce"], "02020202");
    }
}
