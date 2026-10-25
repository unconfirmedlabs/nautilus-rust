use axum::body::Bytes;
use nautilus::{Intent, NautilusContext, NautilusError, SignedResponse};
use serde::Serialize;

const HELLO_INTENT: Intent = Intent(0);

#[derive(Debug, Clone, Serialize)]
struct Hello {
    message: String,
    input_len: u64,
}

async fn process_data(
    bytes: Bytes,
    ctx: NautilusContext,
) -> Result<SignedResponse<Hello>, NautilusError> {
    let hello = Hello {
        message: "hello from nautilus-rust".to_owned(),
        input_len: bytes.len() as u64,
    };
    ctx.sign_intent(HELLO_INTENT, &hello)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().init();
    #[cfg(feature = "test-utils")]
    let ctx = NautilusContext::development();
    #[cfg(not(feature = "test-utils"))]
    let ctx = NautilusContext::from_runtime()?;
    let app = nautilus::router(ctx, process_data);
    nautilus::serve("127.0.0.1:3000".parse()?, app).await?;
    Ok(())
}
