use std::{future::Future, net::SocketAddr, sync::Arc};

use axum::{
    Json, Router,
    body::{Body, Bytes, to_bytes},
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};

use crate::{NautilusContext, NautilusError, decode_hex, encode_hex};

/// Default maximum request body size for `/process_data`.
pub const DEFAULT_MAX_BODY_BYTES: usize = 64 * 1024 * 1024;

/// Server configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerConfig {
    /// Maximum accepted body size for `/process_data`.
    pub max_body_bytes: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
        }
    }
}

/// `/health_check` response body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthCheckBody {
    pub pk: String,
    pub address: String,
}

/// `/attestation` JSON request body.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationBody {
    /// Optional hex-encoded nonce.
    pub nonce: Option<String>,
    /// Optional hex-encoded user data.
    pub user_data: Option<String>,
}

/// JSON error body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    pub error: String,
    pub message: String,
}

#[derive(Clone)]
struct ServerState<F> {
    ctx: NautilusContext,
    config: ServerConfig,
    process_data: F,
}

/// Builds a Nautilus router with default configuration.
pub fn router<F, Fut, T>(ctx: NautilusContext, process_data: F) -> Router
where
    F: Fn(Bytes, NautilusContext) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Result<T, NautilusError>> + Send + 'static,
    T: Serialize + Send + 'static,
{
    router_with_config(ctx, ServerConfig::default(), process_data)
}

/// Builds a Nautilus router with explicit configuration.
pub fn router_with_config<F, Fut, T>(
    ctx: NautilusContext,
    config: ServerConfig,
    handler: F,
) -> Router
where
    F: Fn(Bytes, NautilusContext) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Result<T, NautilusError>> + Send + 'static,
    T: Serialize + Send + 'static,
{
    let state = Arc::new(ServerState {
        ctx,
        config,
        process_data: handler,
    });

    Router::new()
        .route("/health_check", get(health_check::<F>))
        .route("/attestation", get(get_attestation::<F>))
        .route("/attestation", post(post_attestation::<F>))
        .route("/process_data", post(handle_process_data::<F, Fut, T>))
        .with_state(state)
}

/// Serves a router on a TCP address.
pub async fn serve(addr: SocketAddr, app: Router) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await
}

async fn health_check<F>(State(state): State<Arc<ServerState<F>>>) -> Json<HealthCheckBody> {
    Json(HealthCheckBody {
        pk: state.ctx.public_key_hex(),
        address: state.ctx.sui_address(),
    })
}

async fn get_attestation<F>(State(state): State<Arc<ServerState<F>>>) -> Response {
    match state.ctx.attestation(None, None) {
        Ok(doc) => Json(serde_json::json!({ "attestation": encode_hex(doc) })).into_response(),
        Err(error) => error_response(StatusCode::INTERNAL_SERVER_ERROR, error),
    }
}

async fn post_attestation<F>(
    State(state): State<Arc<ServerState<F>>>,
    Json(body): Json<AttestationBody>,
) -> Response {
    let nonce = match decode_optional_hex(body.nonce.as_deref()) {
        Ok(value) => value,
        Err(error) => return error_response(StatusCode::BAD_REQUEST, error),
    };
    let user_data = match decode_optional_hex(body.user_data.as_deref()) {
        Ok(value) => value,
        Err(error) => return error_response(StatusCode::BAD_REQUEST, error),
    };

    match state.ctx.attestation(nonce, user_data) {
        Ok(doc) => Json(serde_json::json!({ "attestation": encode_hex(doc) })).into_response(),
        Err(error) => error_response(StatusCode::INTERNAL_SERVER_ERROR, error),
    }
}

async fn handle_process_data<F, Fut, T>(
    State(state): State<Arc<ServerState<F>>>,
    body: Body,
) -> Response
where
    F: Fn(Bytes, NautilusContext) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Result<T, NautilusError>> + Send + 'static,
    T: Serialize + Send + 'static,
{
    let bytes = match to_bytes(body, state.config.max_body_bytes).await {
        Ok(bytes) => bytes,
        Err(error) => {
            return error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                NautilusError::application(error.to_string()),
            );
        }
    };

    match (state.process_data)(bytes, state.ctx.clone()).await {
        Ok(response) => Json(response).into_response(),
        Err(NautilusError::Application(message)) => error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            NautilusError::Application(message),
        ),
        Err(error) => error_response(StatusCode::INTERNAL_SERVER_ERROR, error),
    }
}

fn decode_optional_hex(value: Option<&str>) -> Result<Option<Vec<u8>>, NautilusError> {
    value.map(decode_hex).transpose()
}

fn error_response(status: StatusCode, error: NautilusError) -> Response {
    let body = ErrorBody {
        error: match status {
            StatusCode::BAD_REQUEST => "bad_request",
            StatusCode::PAYLOAD_TOO_LARGE => "payload_too_large",
            StatusCode::UNPROCESSABLE_ENTITY => "application_error",
            _ => "internal_error",
        }
        .to_owned(),
        message: error.to_string(),
    };
    (status, Json(body)).into_response()
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
    use http_body_util::BodyExt as _;
    use serde::Serialize;
    use tower::ServiceExt as _;

    use crate::testing::FakeAttestor;
    use crate::{
        EnclaveIdentity, Intent, NautilusContext, SignedResponse, intent_message,
        verify_signed_response,
    };

    use super::*;

    async fn sign_len(
        bytes: Bytes,
        ctx: NautilusContext,
    ) -> Result<SignedResponse<u64>, NautilusError> {
        ctx.sign_intent(Intent(0), &(bytes.len() as u64))
    }

    async fn sign_body(
        bytes: Bytes,
        ctx: NautilusContext,
    ) -> Result<SignedResponse<Vec<u8>>, NautilusError> {
        ctx.sign_intent(Intent(0), &bytes.to_vec())
    }

    fn test_context() -> NautilusContext {
        NautilusContext::new(
            EnclaveIdentity::from_seed([9u8; 32]),
            FakeAttestor::default(),
        )
    }

    fn test_app() -> Router {
        router_with_config(test_context(), ServerConfig { max_body_bytes: 4 }, sign_len)
    }

    async fn response_json(response: Response) -> serde_json::Value {
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn health_check_returns_identity() {
        let response = test_app()
            .oneshot(
                Request::builder()
                    .uri("/health_check")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let json = response_json(response).await;
        assert_eq!(json["pk"].as_str().unwrap().len(), 64);
        assert!(json["address"].as_str().unwrap().starts_with("0x"));
    }

    #[tokio::test]
    async fn attestation_accepts_hex_nonce() {
        let response = test_app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/attestation")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"nonce":"0x010203"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let json = response_json(response).await;
        let doc_hex = json["attestation"].as_str().unwrap();
        let doc: serde_json::Value =
            serde_json::from_slice(&hex::decode(doc_hex).unwrap()).unwrap();
        assert_eq!(doc["nonce"], "010203");
    }

    #[tokio::test]
    async fn attestation_rejects_bad_hex() {
        let response = test_app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/attestation")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"nonce":"zz"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn process_data_calls_handler() {
        let response = test_app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/process_data")
                    .body(Body::from("abc"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let json = response_json(response).await;
        assert_eq!(json["response"]["intent"], 0);
        assert_eq!(json["response"]["data"], 3);
        assert_eq!(json["signature"].as_str().unwrap().len(), 128);
    }

    #[derive(Serialize)]
    struct WeatherPayload {
        location: String,
        temperature: u64,
    }

    #[tokio::test]
    async fn posted_intent_message_is_not_signed_as_is() {
        let ctx = test_context();
        let forged = intent_message(
            Intent(0),
            1_744_038_900_000,
            &WeatherPayload {
                location: "San Francisco".to_owned(),
                temperature: 13,
            },
        )
        .unwrap();

        let response = router(ctx.clone(), sign_body)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/process_data")
                    .body(Body::from(forged.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let signed: SignedResponse<Vec<u8>> = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(signed.response.data, forged);

        let signature: [u8; 64] = hex::decode(&signed.signature).unwrap().try_into().unwrap();
        let key = VerifyingKey::from_bytes(&ctx.public_key()).unwrap();
        assert!(
            key.verify(&forged, &Signature::from_bytes(&signature))
                .is_err()
        );
        verify_signed_response(&ctx.public_key(), Intent(0), &signed).unwrap();
    }

    #[tokio::test]
    async fn process_data_enforces_body_limit() {
        let response = test_app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/process_data")
                    .body(Body::from("abcde"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }
}
