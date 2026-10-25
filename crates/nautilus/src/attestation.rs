use crate::AttestationError;

/// Maximum nonce and user data length accepted by Sui (`MAX_USER_DATA_LENGTH`).
pub const MAX_ATTESTATION_DATA_BYTES: usize = 512;

const PUBLIC_KEY_BYTES: usize = 32;

/// Request passed to an attestation backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationRequest {
    /// Public key to bind into the attestation document.
    pub public_key: Vec<u8>,
    /// Verifier-supplied nonce for freshness.
    pub nonce: Option<Vec<u8>>,
    /// Optional user data to include in the attestation document.
    pub user_data: Option<Vec<u8>>,
}

impl AttestationRequest {
    /// Creates a request bound to a public key.
    pub fn new(public_key: impl Into<Vec<u8>>) -> Self {
        Self {
            public_key: public_key.into(),
            nonce: None,
            user_data: None,
        }
    }

    /// Adds a nonce.
    pub fn with_nonce(mut self, nonce: impl Into<Vec<u8>>) -> Self {
        self.nonce = Some(nonce.into());
        self
    }

    /// Adds user data.
    pub fn with_user_data(mut self, user_data: impl Into<Vec<u8>>) -> Self {
        self.user_data = Some(user_data.into());
        self
    }

    /// Checks that the public key is 32 bytes and nonce and user data are at most [`MAX_ATTESTATION_DATA_BYTES`].
    pub fn validate(&self) -> Result<(), AttestationError> {
        if self.public_key.len() != PUBLIC_KEY_BYTES {
            return Err(AttestationError::InvalidRequest(format!(
                "public_key must be exactly {PUBLIC_KEY_BYTES} bytes, got {}",
                self.public_key.len()
            )));
        }
        check_data_len("nonce", self.nonce.as_deref())?;
        check_data_len("user_data", self.user_data.as_deref())
    }
}

fn check_data_len(field: &str, value: Option<&[u8]>) -> Result<(), AttestationError> {
    match value {
        Some(value) if value.len() > MAX_ATTESTATION_DATA_BYTES => {
            Err(AttestationError::InvalidRequest(format!(
                "{field} must be at most {MAX_ATTESTATION_DATA_BYTES} bytes, got {}",
                value.len()
            )))
        }
        _ => Ok(()),
    }
}

/// Attestation provider abstraction.
pub trait Attestor: Send + Sync + 'static {
    /// Returns a short name identifying the provider kind.
    fn name(&self) -> &'static str;

    /// Returns a raw attestation document.
    fn attest(&self, request: AttestationRequest) -> Result<Vec<u8>, AttestationError>;

    /// Returns hardware or provider randomness.
    fn random(&self, len: usize) -> Result<Vec<u8>, AttestationError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> AttestationRequest {
        AttestationRequest::new([0u8; 32])
    }

    fn assert_invalid(request: AttestationRequest, field: &str) {
        match request.validate() {
            Err(AttestationError::InvalidRequest(message)) => assert!(message.starts_with(field)),
            other => panic!("expected invalid request, got {other:?}"),
        }
    }

    #[test]
    fn accepts_data_up_to_limit() {
        for len in [0, 511, 512] {
            request()
                .with_nonce(vec![1; len])
                .with_user_data(vec![2; len])
                .validate()
                .unwrap();
        }
        request().validate().unwrap();
    }

    #[test]
    fn rejects_oversized_nonce() {
        assert_invalid(request().with_nonce(vec![1; 513]), "nonce");
    }

    #[test]
    fn rejects_oversized_user_data() {
        assert_invalid(request().with_user_data(vec![1; 513]), "user_data");
    }

    #[test]
    fn rejects_wrong_public_key_length() {
        assert_invalid(AttestationRequest::new([0u8; 31]), "public_key");
        assert_invalid(AttestationRequest::new([0u8; 33]), "public_key");
    }
}
