use std::sync::Arc;

use crate::{
    AttestationRequest, Attestor, EnclaveIdentity, NautilusError, NsmAttestor, PublicKeyBytes,
    SignatureBytes, Signer as _, encode_hex,
    intent::{SignedIntent, sign_bcs_payload},
};

/// App-facing context passed to business logic.
#[derive(Clone)]
pub struct NautilusContext {
    identity: EnclaveIdentity,
    attestor: Arc<dyn Attestor>,
}

impl NautilusContext {
    /// Creates a context from an identity and attestation provider.
    pub fn new(identity: EnclaveIdentity, attestor: impl Attestor) -> Self {
        let ctx = Self {
            identity,
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
        Ok(Self::new(
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
        Self::new(
            EnclaveIdentity::from_seed([42u8; 32]),
            crate::testing::FakeAttestor::default(),
        )
    }

    /// Returns the name of the configured attestation provider.
    pub fn attestor_name(&self) -> &'static str {
        self.attestor.name()
    }

    /// Returns the underlying identity.
    pub fn identity(&self) -> &EnclaveIdentity {
        &self.identity
    }

    /// Returns the public key bytes.
    pub fn public_key(&self) -> PublicKeyBytes {
        self.identity.public_key()
    }

    /// Returns the public key as hex.
    pub fn public_key_hex(&self) -> String {
        self.identity.public_key_hex()
    }

    /// Returns the Sui address.
    pub fn sui_address(&self) -> String {
        self.identity.sui_address()
    }

    /// Signs raw bytes.
    pub fn sign(&self, message: &[u8]) -> Result<SignatureBytes, NautilusError> {
        self.identity.sign(message)
    }

    /// Signs raw bytes and returns lowercase hex.
    pub fn sign_hex(&self, message: &[u8]) -> Result<String, NautilusError> {
        Ok(encode_hex(self.sign(message)?))
    }

    /// Signs a BCS-serializable payload as a Nautilus intent message.
    pub fn sign_bcs_payload<T>(
        &self,
        intent: u8,
        timestamp_ms: u64,
        payload: T,
    ) -> Result<SignedIntent<T>, NautilusError>
    where
        T: serde::Serialize + Clone,
    {
        sign_bcs_payload(self, intent, timestamp_ms, payload)
    }

    /// Requests an attestation document bound to this context's public key.
    pub fn attestation(
        &self,
        nonce: Option<Vec<u8>>,
        user_data: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, NautilusError> {
        let mut request = AttestationRequest::new(self.public_key());
        request.nonce = nonce;
        request.user_data = user_data;
        Ok(self.attestor.attest(request)?)
    }

    /// Returns randomness from the configured attestation provider.
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
        let ctx = NautilusContext::new(EnclaveIdentity::from_seed([3u8; 32]), fake.clone());
        let nonce = vec![1, 2, 3];

        let doc = ctx.attestation(Some(nonce.clone()), None).unwrap();
        assert!(!doc.is_empty());

        let requests = fake.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].public_key, ctx.public_key().to_vec());
        assert_eq!(requests[0].nonce, Some(nonce));
    }

    #[test]
    fn random_comes_from_attestor() {
        let fake = FakeAttestor::with_random_byte(0xab);
        let ctx = NautilusContext::new(EnclaveIdentity::from_seed([4u8; 32]), fake);
        assert_eq!(ctx.random(4).unwrap(), vec![0xab; 4]);
    }
}
