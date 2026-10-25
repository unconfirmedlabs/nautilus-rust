use std::sync::Arc;

use blake2::{
    Blake2bVar,
    digest::{Update, VariableOutput},
};
use ed25519_dalek::{
    Signature, SigningKey, VerifyingKey,
    ed25519::signature::{Signer as _, Verifier as _},
};
use rand::{RngCore as _, rngs::OsRng};
use zeroize::Zeroizing;

use crate::{NautilusError, encode_hex};

/// Raw Ed25519 public key bytes.
pub type PublicKeyBytes = [u8; 32];

/// Raw Ed25519 signature bytes.
pub type SignatureBytes = [u8; 64];

/// A signer used by Nautilus contexts.
pub trait Signer: Send + Sync + 'static {
    /// Returns the Ed25519 public key bytes.
    fn public_key(&self) -> PublicKeyBytes;

    /// Signs a message and returns raw Ed25519 signature bytes.
    fn sign(&self, message: &[u8]) -> Result<SignatureBytes, NautilusError>;
}

/// Per-boot enclave identity.
#[derive(Clone)]
pub struct EnclaveIdentity {
    signing_key: Arc<SigningKey>,
}

impl EnclaveIdentity {
    /// Generates a new identity from OS randomness.
    pub fn generate() -> Self {
        let mut seed = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(seed.as_mut());
        Self::from_seed_bytes(&seed)
    }

    /// Generates a new identity by XOR-mixing OS randomness with caller entropy, such as NSM output.
    pub fn generate_with_entropy(extra_entropy: &[u8]) -> Self {
        let mut seed = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(seed.as_mut());
        for (index, byte) in extra_entropy.iter().take(32).enumerate() {
            seed[index] ^= byte;
        }
        Self::from_seed_bytes(&seed)
    }

    /// Creates an identity from a fixed seed. Test-only: the key is as public as the seed.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self::from_seed_bytes(&seed)
    }

    fn from_seed_bytes(seed: &[u8; 32]) -> Self {
        Self {
            signing_key: Arc::new(SigningKey::from_bytes(seed)),
        }
    }

    /// Returns the Ed25519 verifying key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Returns the public key as lowercase hex.
    pub fn public_key_hex(&self) -> String {
        encode_hex(self.public_key())
    }

    /// Returns the Sui address for this identity.
    pub fn sui_address(&self) -> String {
        sui_address(&self.public_key())
    }

    /// Verifies a signature against this identity's public key.
    pub fn verify(&self, message: &[u8], signature: &SignatureBytes) -> Result<(), NautilusError> {
        verify_ed25519(&self.public_key(), message, signature)
    }
}

impl Signer for EnclaveIdentity {
    fn public_key(&self) -> PublicKeyBytes {
        self.signing_key.verifying_key().to_bytes()
    }

    fn sign(&self, message: &[u8]) -> Result<SignatureBytes, NautilusError> {
        Ok(self.signing_key.sign(message).to_bytes())
    }
}

pub(crate) fn verify_ed25519(
    public_key: &PublicKeyBytes,
    message: &[u8],
    signature: &SignatureBytes,
) -> Result<(), NautilusError> {
    VerifyingKey::from_bytes(public_key)
        .and_then(|key| key.verify(message, &Signature::from_bytes(signature)))
        .map_err(|error| NautilusError::Crypto(error.to_string()))
}

/// Derives the Sui address `blake2b256(0x00 || public_key)` of an Ed25519 public key.
pub fn sui_address(public_key: &PublicKeyBytes) -> String {
    let mut hasher = Blake2bVar::new(32).expect("valid Blake2b output length");
    hasher.update(&[0x00]);
    hasher.update(public_key);

    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("output length matches hasher configuration");
    format!("0x{}", encode_hex(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_identity_from_seed() {
        let a = EnclaveIdentity::from_seed([7u8; 32]);
        let b = EnclaveIdentity::from_seed([7u8; 32]);
        assert_eq!(a.public_key(), b.public_key());
        assert_eq!(a.sui_address(), b.sui_address());
    }

    #[test]
    fn signs_and_verifies() {
        let identity = EnclaveIdentity::from_seed([1u8; 32]);
        let message = b"nautilus";
        let signature = identity.sign(message).unwrap();
        identity.verify(message, &signature).unwrap();
        assert!(identity.verify(b"wrong", &signature).is_err());
    }

    #[test]
    fn public_key_and_address_formats_are_stable() {
        let identity = EnclaveIdentity::from_seed([2u8; 32]);
        assert_eq!(identity.public_key().len(), 32);
        assert_eq!(identity.public_key_hex().len(), 64);

        let address = identity.sui_address();
        assert!(address.starts_with("0x"));
        assert_eq!(address.len(), 66);
    }

    #[test]
    fn different_seeds_have_different_public_keys() {
        let base = EnclaveIdentity::from_seed([9u8; 32]);
        let mixed = EnclaveIdentity::from_seed({
            let mut seed = [9u8; 32];
            seed[0] ^= 0xaa;
            seed
        });
        assert_ne!(base.public_key(), mixed.public_key());
    }
}
