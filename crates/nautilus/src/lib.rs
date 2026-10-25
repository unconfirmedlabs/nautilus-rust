//! App-facing framework primitives for Rust Nautilus enclave applications.

#![forbid(unsafe_code)]

mod attestation;
mod context;
pub mod contract;
mod crypto;
mod error;
mod intent;
mod nsm;
mod serve;
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
pub use serve::{serve, serve_with_shutdown};
pub use server::{
    AttestationBody, ConfigError, DEFAULT_BODY_READ_TIMEOUT, DEFAULT_HEADER_READ_TIMEOUT,
    DEFAULT_IDLE_TIMEOUT, DEFAULT_MAX_BODY_BYTES, DEFAULT_MAX_CONNECTIONS, DEFAULT_REQUEST_TIMEOUT,
    ErrorBody, ErrorCode, HealthCheckBody, ServerConfig, router, router_async,
};
pub use util::{decode_hex, encode_hex};
