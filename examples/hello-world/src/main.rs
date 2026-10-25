use axum::body::Bytes;
use nautilus::{Intent, NautilusContext, NautilusError, ServerConfig, SignedResponse};
use serde::Serialize;

const HELLO_INTENT: Intent = Intent(0);

#[derive(Debug, Clone, Serialize)]
struct Hello {
    message: String,
    input_len: u64,
}

fn hello(input: &[u8]) -> Hello {
    Hello {
        message: "hello from nautilus-rust".to_owned(),
        input_len: input.len() as u64,
    }
}

fn process_data(
    bytes: Bytes,
    ctx: &NautilusContext,
) -> Result<SignedResponse<Hello>, NautilusError> {
    ctx.sign_intent(HELLO_INTENT, &hello(&bytes))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().init();
    #[cfg(feature = "test-utils")]
    let ctx = NautilusContext::development();
    #[cfg(not(feature = "test-utils"))]
    let ctx = NautilusContext::from_runtime()?;
    let app = nautilus::router(ctx, ServerConfig::default(), process_data)?;
    nautilus::serve("127.0.0.1:3000".parse()?, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    nautilus::golden_vectors! {
        hello_abc: (HELLO_INTENT, 1_700_000_000_000, hello(b"abc")) => "000068e5cf8b0100001868656c6c6f2066726f6d206e617574696c75732d727573740300000000000000";
    }
}
