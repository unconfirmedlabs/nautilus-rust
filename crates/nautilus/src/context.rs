use std::sync::Arc;

use serde::Serialize;

use crate::{
    AttestationRequest, Attestor, EnclaveIdentity, Intent, IntentMessage, NautilusError,
    NsmAttestor, PublicKeyBytes, SignedResponse, Signer, crypto::sui_address, encode_hex,
    intent_message, now_ms,
};

/// App-facing context passed to business logic.
#[derive(Clone)]
pub struct NautilusContext {
    signer: Arc<dyn Signer>,
    attestor: Arc<dyn Attestor>,
}

impl NautilusContext {
    /// Creates a context from a signer and an attestation provider.
    pub fn with_signer(signer: impl Signer, attestor: impl Attestor) -> Self {
        let ctx = Self {
            signer: Arc::new(signer),
            attestor: Arc::new(attestor),
        };
        tracing::info!(
            attestor = ctx.attestor_name(),
            public_key = %ctx.public_key_hex(),
            address = %ctx.sui_address(),
            "nautilus context ready"
        );
        ctx
    }

    /// Creates the production context: opens `/dev/nsm` and generates a per-boot identity mixed with NSM entropy.
    pub fn from_runtime() -> Result<Self, NautilusError> {
        Self::with_entropy_from(NsmAttestor::open()?)
    }

    fn with_entropy_from(attestor: impl Attestor) -> Result<Self, NautilusError> {
        let entropy = attestor.random(32)?;
        Ok(Self::with_signer(
            EnclaveIdentity::generate_with_entropy(&entropy),
            attestor,
        ))
    }

    /// Creates a local development context with a public deterministic identity and fake attestation.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn development() -> Self {
        tracing::warn!(
            "development context: the signing key is public and fake attestation must never be deployed"
        );
        Self::with_signer(
            EnclaveIdentity::from_seed([42u8; 32]),
            crate::testing::FakeAttestor::default(),
        )
    }

    /// Returns the name of the configured attestation provider.
    pub fn attestor_name(&self) -> &'static str {
        self.attestor.name()
    }

    /// Returns the public key bytes.
    pub fn public_key(&self) -> PublicKeyBytes {
        self.signer.public_key()
    }

    /// Returns the public key as hex.
    pub fn public_key_hex(&self) -> String {
        encode_hex(self.public_key())
    }

    /// Returns the Sui address.
    pub fn sui_address(&self) -> String {
        sui_address(&self.public_key())
    }

    /// Signs `payload` as an intent message stamped with [`now_ms`] and moves it into the response.
    pub fn sign_intent<T: Serialize>(
        &self,
        intent: impl Into<Intent>,
        payload: T,
    ) -> Result<SignedResponse<T>, NautilusError> {
        self.sign_message(intent.into(), now_ms()?, payload)
    }

    /// Signs `payload` as an intent message with a fixed timestamp.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn sign_intent_at<T: Serialize>(
        &self,
        intent: impl Into<Intent>,
        timestamp_ms: u64,
        payload: T,
    ) -> Result<SignedResponse<T>, NautilusError> {
        self.sign_message(intent.into(), timestamp_ms, payload)
    }

    fn sign_message<T: Serialize>(
        &self,
        intent: Intent,
        timestamp_ms: u64,
        payload: T,
    ) -> Result<SignedResponse<T>, NautilusError> {
        let message = intent_message(intent, timestamp_ms, &payload)?;
        Ok(SignedResponse {
            signature: encode_hex(self.signer.sign(&message)?),
            response: IntentMessage {
                intent,
                timestamp_ms,
                data: payload,
            },
        })
    }

    /// Requests an attestation document bound to this context's public key after validating its bounds; blocks on the attestor.
    pub fn attestation(
        &self,
        nonce: Option<Vec<u8>>,
        user_data: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, NautilusError> {
        let mut request = AttestationRequest::new(self.public_key());
        request.nonce = nonce;
        request.user_data = user_data;
        request.validate()?;
        Ok(self.attestor.attest(request)?)
    }

    /// Returns randomness from the configured attestation provider; blocks on the attestor.
    pub fn random(&self, len: usize) -> Result<Vec<u8>, NautilusError> {
        Ok(self.attestor.random(len)?)
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use nautilus_nsm::{DEVICE_PATH, Nsm};

    use crate::{AttestationError, EnclaveIdentity, testing::FakeAttestor};

    use super::*;

    #[test]
    fn missing_nsm_device_is_unavailable() {
        let error = Nsm::open_path("/no/such/nsm")
            .map(NsmAttestor::new)
            .map_err(AttestationError::from)
            .unwrap_err();
        assert!(matches!(error, AttestationError::Unavailable(_)));
    }

    #[test]
    fn from_runtime_fails_without_nsm_device() {
        if Path::new(DEVICE_PATH).exists() {
            return;
        }
        let error = NautilusContext::from_runtime().err().unwrap();
        assert!(matches!(
            error,
            NautilusError::Attestation(AttestationError::Unavailable(_))
        ));
    }

    #[test]
    fn entropy_identity_differs_per_boot() {
        let a = NautilusContext::with_entropy_from(FakeAttestor::default()).unwrap();
        let b = NautilusContext::with_entropy_from(FakeAttestor::default()).unwrap();
        assert_eq!(a.attestor_name(), "fake");
        assert_ne!(a.public_key(), b.public_key());
    }

    #[test]
    fn development_uses_fake_attestor() {
        assert_eq!(NautilusContext::development().attestor_name(), "fake");
    }

    #[test]
    fn attestation_binds_context_public_key() {
        let fake = FakeAttestor::default();
        let ctx = NautilusContext::with_signer(EnclaveIdentity::from_seed([3u8; 32]), fake.clone());
        let nonce = vec![1, 2, 3];

        let doc = ctx.attestation(Some(nonce.clone()), None).unwrap();
        assert!(!doc.is_empty());

        let requests = fake.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].public_key, ctx.public_key().to_vec());
        assert_eq!(requests[0].nonce, Some(nonce));
    }

    #[test]
    fn attestation_rejects_oversized_nonce_before_attestor() {
        let fake = FakeAttestor::default();
        let ctx = NautilusContext::with_signer(EnclaveIdentity::from_seed([3u8; 32]), fake.clone());

        let error = ctx.attestation(Some(vec![0; 513]), None).unwrap_err();
        assert!(matches!(
            error,
            NautilusError::Attestation(AttestationError::InvalidRequest(_))
        ));
        assert!(fake.requests().is_empty());
    }

    #[test]
    fn random_comes_from_attestor() {
        let fake = FakeAttestor::with_random_byte(0xab);
        let ctx = NautilusContext::with_signer(EnclaveIdentity::from_seed([4u8; 32]), fake);
        assert_eq!(ctx.random(4).unwrap(), vec![0xab; 4]);
    }
}
