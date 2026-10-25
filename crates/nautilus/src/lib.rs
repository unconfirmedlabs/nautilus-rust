//! App-facing framework primitives for Rust Nautilus enclave applications.

#![forbid(unsafe_code)]

mod attestation;
mod context;
mod crypto;
mod error;
mod intent;
mod nsm;
mod server;
#[cfg(any(test, feature = "test-utils"))]
pub mod testing;
mod util;

pub use attestation::{AttestationRequest, Attestor, MAX_ATTESTATION_DATA_BYTES};
pub use context::NautilusContext;
pub use crypto::{EnclaveIdentity, PublicKeyBytes, SignatureBytes, Signer};
pub use error::{AttestationError, NautilusError};
pub use intent::{
    Intent, IntentMessage, SignedResponse, intent_message, now_ms, verify_signed_response,
};
pub use nsm::NsmAttestor;
pub use server::{
    AttestationBody, ErrorBody, HealthCheckBody, ServerConfig, router, router_with_config, serve,
};
pub use util::{decode_hex, encode_hex};
