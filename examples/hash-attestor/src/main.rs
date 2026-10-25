use axum::body::Bytes;
use nautilus::{Intent, NautilusContext, NautilusError, ServerConfig, SignedResponse};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

const HASH_ATTESTATION_INTENT: Intent = Intent(0);

#[derive(Debug, Clone, Serialize)]
struct HashAttestation {
    digest: Vec<u8>,
    length: u64,
}

fn process_data(
    bytes: Bytes,
    ctx: &NautilusContext,
) -> Result<SignedResponse<HashAttestation>, NautilusError> {
    let attestation = HashAttestation {
        digest: Sha256::digest(bytes.as_ref()).to_vec(),
        length: bytes.len() as u64,
    };
    ctx.sign_intent(HASH_ATTESTATION_INTENT, &attestation)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().init();
    #[cfg(feature = "test-utils")]
    let ctx = NautilusContext::development();
    #[cfg(not(feature = "test-utils"))]
    let ctx = NautilusContext::from_runtime()?;
    let app = nautilus::router(ctx, ServerConfig::default(), process_data);
    nautilus::serve("127.0.0.1:3000".parse()?, app).await?;
    Ok(())
}
