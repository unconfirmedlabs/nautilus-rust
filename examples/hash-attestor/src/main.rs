use axum::body::Bytes;
use nautilus::{
    Intent, NautilusContext, NautilusError, ServerConfig, SignedResponse, contract::ByteVec,
};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

const HASH_ATTESTATION_INTENT: Intent = Intent(0);

#[derive(Debug, Clone, Serialize)]
struct HashAttestation {
    digest: ByteVec,
    length: u64,
}

fn hash_attestation(bytes: &[u8]) -> HashAttestation {
    HashAttestation {
        digest: ByteVec::from(Sha256::digest(bytes).to_vec()),
        length: bytes.len() as u64,
    }
}

fn process_data(
    bytes: Bytes,
    ctx: &NautilusContext,
) -> Result<SignedResponse<HashAttestation>, NautilusError> {
    ctx.sign_intent(HASH_ATTESTATION_INTENT, &hash_attestation(&bytes))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().init();
    #[cfg(feature = "test-utils")]
    let ctx = NautilusContext::development();
    #[cfg(not(feature = "test-utils"))]
    let ctx = NautilusContext::from_runtime()?;
    let config = ServerConfig::default();
    let app = nautilus::router(ctx, config.clone(), process_data)?;
    #[cfg(feature = "test-utils")]
    nautilus::serve("127.0.0.1:3000".parse()?, app, config).await?;
    #[cfg(not(feature = "test-utils"))]
    nautilus::serve_vsock(3000, app, config).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    nautilus::golden_vectors! {
        hash_attestation_abc: (
            HASH_ATTESTATION_INTENT,
            1_700_000_000_000,
            hash_attestation(b"abc"),
        ) => "000068e5cf8b01000020ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad0300000000000000";
    }
}
