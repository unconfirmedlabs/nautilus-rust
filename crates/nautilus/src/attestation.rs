use crate::AttestationError;

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
