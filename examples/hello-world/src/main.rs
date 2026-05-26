use axum::body::Bytes;
use nautilus::{NautilusContext, NautilusError};
use serde::Serialize;

#[derive(Debug, Serialize)]
struct HelloResponse {
    message: &'static str,
    input_len: usize,
    public_key: String,
    signature: String,
}

async fn process_data(bytes: Bytes, ctx: NautilusContext) -> Result<HelloResponse, NautilusError> {
    Ok(HelloResponse {
        message: "hello from nautilus-rust",
        input_len: bytes.len(),
        public_key: ctx.public_key_hex(),
        signature: ctx.sign_hex(bytes.as_ref())?,
    })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let ctx = NautilusContext::development();
    let app = nautilus::router(ctx, process_data);
    nautilus::serve("127.0.0.1:3000".parse()?, app).await
}
