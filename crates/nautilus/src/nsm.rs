use nautilus_nsm::{Nsm, NsmError};

use crate::{AttestationError, AttestationRequest, Attestor};

/// AWS Nitro Secure Module attestation provider.
#[derive(Debug)]
pub struct NsmAttestor {
    nsm: Nsm,
}

impl NsmAttestor {
    /// Opens `/dev/nsm`, failing if the device is not present.
    pub fn open() -> Result<Self, AttestationError> {
        Ok(Self::new(Nsm::open()?))
    }

    /// Wraps an already opened NSM device.
    pub fn new(nsm: Nsm) -> Self {
        Self { nsm }
    }
}

impl Attestor for NsmAttestor {
    fn name(&self) -> &'static str {
        "nsm"
    }

    fn attest(&self, request: AttestationRequest) -> Result<Vec<u8>, AttestationError> {
        Ok(self.nsm.attestation(
            &request.public_key,
            request.nonce.as_deref(),
            request.user_data.as_deref(),
        )?)
    }

    fn random(&self, len: usize) -> Result<Vec<u8>, AttestationError> {
        Ok(self.nsm.random(len)?)
    }
}

impl From<NsmError> for AttestationError {
    fn from(error: NsmError) -> Self {
        match error {
            NsmError::Unavailable { .. } => Self::Unavailable(error.to_string()),
            NsmError::Io(error) => Self::Io(error),
            NsmError::InvalidRequest(message) => Self::InvalidRequest(message),
            NsmError::MalformedResponse(message) => Self::MalformedResponse(message),
            NsmError::Device(message) => Self::Backend(message),
        }
    }
}
