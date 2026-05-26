use thiserror::Error;

/// Errors returned by attestation providers.
#[derive(Debug, Error)]
pub enum AttestationError {
    /// The attestation request is invalid.
    #[error("invalid attestation request: {0}")]
    InvalidRequest(String),
    /// The attestation provider is unavailable.
    #[error("attestation provider unavailable: {0}")]
    Unavailable(String),
    /// The attestation provider returned malformed data.
    #[error("malformed attestation response: {0}")]
    MalformedResponse(String),
    /// An I/O error occurred while talking to the attestation provider.
    #[error("attestation I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// The backend returned an explicit error.
    #[error("attestation backend error: {0}")]
    Backend(String),
}

/// Framework-level error type used by routes and app handlers.
#[derive(Debug, Error)]
pub enum NautilusError {
    /// Attestation failed.
    #[error(transparent)]
    Attestation(#[from] AttestationError),
    /// Signing or key handling failed.
    #[error("crypto error: {0}")]
    Crypto(String),
    /// Hex input could not be decoded.
    #[error("invalid hex: {0}")]
    Hex(String),
    /// BCS serialization failed.
    #[error("BCS serialization failed: {0}")]
    Bcs(String),
    /// User application logic failed.
    #[error("application error: {0}")]
    Application(String),
}

impl NautilusError {
    /// Creates an application error with a stable user-facing message.
    pub fn application(message: impl Into<String>) -> Self {
        Self::Application(message.into())
    }
}

impl From<anyhow::Error> for NautilusError {
    fn from(error: anyhow::Error) -> Self {
        Self::Application(error.to_string())
    }
}
