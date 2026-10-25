use axum::body::Bytes;
use nautilus::{NautilusContext, NautilusError};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

#[derive(Debug, Serialize)]
struct HashAttestation {
    algorithm: &'static str,
    digest: String,
    public_key: String,
    signature: String,
}

async fn process_data(
    bytes: Bytes,
    ctx: NautilusContext,
) -> Result<HashAttestation, NautilusError> {
    let digest = Sha256::digest(bytes.as_ref());
    Ok(HashAttestation {
        algorithm: "sha256",
        digest: hex::encode(digest),
        public_key: ctx.public_key_hex(),
        signature: ctx.sign_hex(&digest)?,
    })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().init();
    #[cfg(feature = "test-utils")]
    let ctx = NautilusContext::development();
    #[cfg(not(feature = "test-utils"))]
    let ctx = NautilusContext::from_runtime()?;
    let app = nautilus::router(ctx, process_data);
    nautilus::serve("127.0.0.1:3000".parse()?, app).await
}
