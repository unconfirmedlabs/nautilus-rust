use std::{
    error::Error as StdError, future::Future, io, iter, net::SocketAddr, panic::AssertUnwindSafe,
    pin::Pin, sync::Arc, thread, time::Duration,
};

use axum::{
    BoxError, Json, Router,
    body::{Bytes, to_bytes},
    error_handling::HandleErrorLayer,
    extract::{Request, State},
    http::{StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use futures_util::FutureExt as _;
use http_body_util::LengthLimitError;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::{
    net::TcpListener,
    sync::{OwnedSemaphorePermit, Semaphore},
    task::{JoinError, spawn_blocking},
};
use tower::{
    ServiceBuilder,
    timeout::{TimeoutLayer, error::Elapsed},
};

use crate::{AttestationError, NautilusContext, NautilusError, decode_hex, encode_hex};

/// Default maximum request body size (8 MiB).
pub const DEFAULT_MAX_BODY_BYTES: usize = 8 * 1024 * 1024;

/// Default per-request deadline (30 s).
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Server limits; peak buffered request memory is about `max_concurrent * max_body_bytes`.
///
/// Every limit must be non-zero; [`ServerConfig::validate`] rejects a zero instead of clamping it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerConfig {
    /// Maximum accepted request body size; defaults to [`DEFAULT_MAX_BODY_BYTES`] (8 MiB).
    pub max_body_bytes: usize,
    /// Maximum in-flight `/attestation` and `/process_data` requests; defaults to the available parallelism when `default()` runs, or 1 if unknown.
    pub max_concurrent: usize,
    /// Per-request deadline; defaults to [`DEFAULT_REQUEST_TIMEOUT`] (30 s).
    pub request_timeout: Duration,
    /// Serves `GET /attestation` and nonce-less `POST /attestation` when true; defaults to false.
    pub allow_unnonced_attestation: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            max_concurrent: thread::available_parallelism().map_or(1, usize::from),
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            allow_unnonced_attestation: false,
        }
    }
}

impl ServerConfig {
    /// Fails if any limit is zero, which would make the server reject every request.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let zero = [
            ("max_body_bytes", self.max_body_bytes == 0),
            ("max_concurrent", self.max_concurrent == 0),
            ("request_timeout", self.request_timeout.is_zero()),
        ];
        match zero.into_iter().find(|&(_, is_zero)| is_zero) {
            Some((field, _)) => Err(ConfigError::Zero(field)),
            None => Ok(()),
        }
    }
}

/// An invalid [`ServerConfig`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ConfigError {
    /// The named limit is zero.
    #[error("ServerConfig::{0} must be greater than zero")]
    Zero(&'static str),
}

/// `/health_check` response body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthCheckBody {
    /// Hex-encoded Ed25519 public key.
    pub pk: String,
    /// Sui address derived from the public key.
    pub address: String,
}

/// `/attestation` JSON request body.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationBody {
    /// Hex-encoded nonce, required unless unnonced attestation is allowed.
    pub nonce: Option<String>,
    /// Optional hex-encoded user data.
    pub user_data: Option<String>,
}

/// Stable error code returned in [`ErrorBody`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// 400: the request failed framework validation.
    InvalidRequest,
    /// 400: the request body could not be read.
    BodyReadFailed,
    /// 404: no route matches the path.
    NotFound,
    /// 405: the route does not accept the method.
    MethodNotAllowed,
    /// 408: the request exceeded the configured deadline.
    RequestTimeout,
    /// 413: the request body exceeded the configured limit.
    BodyTooLarge,
    /// 422: the application handler rejected the request.
    ApplicationError,
    /// 429: the concurrency limit is exhausted.
    Overloaded,
    /// 500: an internal failure, logged server-side.
    InternalError,
    /// 503: the attestation provider failed, logged server-side.
    AttestationUnavailable,
}

impl ErrorCode {
    /// Returns the snake_case wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::BodyReadFailed => "body_read_failed",
            Self::NotFound => "not_found",
            Self::MethodNotAllowed => "method_not_allowed",
            Self::RequestTimeout => "request_timeout",
            Self::BodyTooLarge => "body_too_large",
            Self::ApplicationError => "application_error",
            Self::Overloaded => "overloaded",
            Self::InternalError => "internal_error",
            Self::AttestationUnavailable => "attestation_unavailable",
        }
    }

    /// Returns the HTTP status for this code.
    pub fn status(self) -> StatusCode {
        match self {
            Self::InvalidRequest | Self::BodyReadFailed => StatusCode::BAD_REQUEST,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
            Self::RequestTimeout => StatusCode::REQUEST_TIMEOUT,
            Self::BodyTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::ApplicationError => StatusCode::UNPROCESSABLE_ENTITY,
            Self::Overloaded => StatusCode::TOO_MANY_REQUESTS,
            Self::InternalError => StatusCode::INTERNAL_SERVER_ERROR,
            Self::AttestationUnavailable => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    fn description(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid request",
            Self::BodyReadFailed => "failed to read request body",
            Self::NotFound => "no such route",
            Self::MethodNotAllowed => "method not allowed",
            Self::RequestTimeout => "request timed out",
            Self::BodyTooLarge => "request body too large",
            Self::ApplicationError => "application error",
            Self::Overloaded => "server is at its concurrency limit",
            Self::InternalError => "internal error",
            Self::AttestationUnavailable => "attestation is unavailable",
        }
    }
}

/// JSON error body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    /// Stable error code.
    pub error: ErrorCode,
    /// Fixed description, or the app's or validation message.
    pub message: String,
}

struct ApiError(ErrorBody);

impl ApiError {
    fn new(code: ErrorCode) -> Self {
        Self::with_message(code, code.description())
    }

    fn with_message(code: ErrorCode, message: impl Into<String>) -> Self {
        Self(ErrorBody {
            error: code,
            message: message.into(),
        })
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0.error.status(), Json(self.0)).into_response()
    }
}

impl From<NautilusError> for ApiError {
    fn from(error: NautilusError) -> Self {
        match error {
            NautilusError::Attestation(AttestationError::InvalidRequest(_))
            | NautilusError::Hex(_) => {
                Self::with_message(ErrorCode::InvalidRequest, error.to_string())
            }
            NautilusError::Attestation(error) => {
                tracing::warn!(%error, "attestation failed");
                Self::new(ErrorCode::AttestationUnavailable)
            }
            NautilusError::Application(message) => {
                Self::with_message(ErrorCode::ApplicationError, message)
            }
            error => {
                tracing::error!(%error, "request failed");
                Self::new(ErrorCode::InternalError)
            }
        }
    }
}

impl From<JoinError> for ApiError {
    fn from(error: JoinError) -> Self {
        tracing::error!(%error, panic = error.is_panic(), "blocking task failed");
        Self::new(ErrorCode::InternalError)
    }
}

type HandlerFuture = Pin<Box<dyn Future<Output = Result<Response, ApiError>> + Send>>;

type Handler =
    Arc<dyn Fn(Bytes, NautilusContext, OwnedSemaphorePermit) -> HandlerFuture + Send + Sync>;

struct ServerState {
    ctx: NautilusContext,
    config: ServerConfig,
    permits: Arc<Semaphore>,
    handler: Handler,
}

impl ServerState {
    fn permit(&self) -> Result<OwnedSemaphorePermit, ApiError> {
        Arc::clone(&self.permits)
            .try_acquire_owned()
            .map_err(|_| ApiError::new(ErrorCode::Overloaded))
    }
}

/// Builds a Nautilus router whose `/process_data` handler runs on the blocking thread pool; fails on an invalid `config`.
pub fn router<F, T>(
    ctx: NautilusContext,
    config: ServerConfig,
    handler: F,
) -> Result<Router, ConfigError>
where
    F: Fn(Bytes, &NautilusContext) -> Result<T, NautilusError> + Send + Sync + 'static,
    T: Serialize + Send + 'static,
{
    let handler = Arc::new(handler);
    build_router(
        ctx,
        config,
        Arc::new(
            move |bytes: Bytes,
                  ctx: NautilusContext,
                  permit: OwnedSemaphorePermit|
                  -> HandlerFuture {
                let handler = Arc::clone(&handler);
                Box::pin(async move {
                    let value = spawn_blocking(move || {
                        let _permit = permit;
                        handler(bytes, &ctx)
                    })
                    .await??;
                    json_response(&value)
                })
            },
        ),
    )
}

/// Builds a Nautilus router whose `/process_data` handler is an async function run on the runtime; fails on an invalid `config`.
pub fn router_async<F, Fut, T>(
    ctx: NautilusContext,
    config: ServerConfig,
    handler: F,
) -> Result<Router, ConfigError>
where
    F: Fn(Bytes, NautilusContext) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<T, NautilusError>> + Send + 'static,
    T: Serialize + Send + 'static,
{
    build_router(
        ctx,
        config,
        Arc::new(
            move |bytes: Bytes,
                  ctx: NautilusContext,
                  permit: OwnedSemaphorePermit|
                  -> HandlerFuture {
                let future = handler(bytes, ctx);
                Box::pin(async move {
                    let _permit = permit;
                    json_response(&future.await?)
                })
            },
        ),
    )
}

fn build_router(
    ctx: NautilusContext,
    config: ServerConfig,
    handler: Handler,
) -> Result<Router, ConfigError> {
    config.validate()?;
    let attestation = if config.allow_unnonced_attestation {
        get(get_attestation).post(post_attestation)
    } else {
        post(post_attestation)
    };
    let timeout = config.request_timeout;
    let state = Arc::new(ServerState {
        ctx,
        permits: Arc::new(Semaphore::new(
            config.max_concurrent.min(Semaphore::MAX_PERMITS),
        )),
        config,
        handler,
    });

    Ok(Router::new()
        .route("/health_check", get(health_check))
        .route("/attestation", attestation)
        .route("/process_data", post(process_data))
        .method_not_allowed_fallback(|| async { ApiError::new(ErrorCode::MethodNotAllowed) })
        .fallback(|| async { ApiError::new(ErrorCode::NotFound) })
        .with_state(state)
        .layer(middleware::from_fn(catch_panic))
        .layer(
            ServiceBuilder::new()
                .layer(HandleErrorLayer::new(handle_middleware_error))
                .layer(TimeoutLayer::new(timeout)),
        ))
}

/// Binds `addr` and serves `app` until SIGTERM or Ctrl-C, then drains in-flight requests.
pub async fn serve(addr: SocketAddr, app: Router) -> io::Result<()> {
    serve_with_shutdown(TcpListener::bind(addr).await?, app, shutdown_signal()).await
}

/// Serves `app` on `listener` until `shutdown` completes, then drains in-flight requests.
pub async fn serve_with_shutdown(
    listener: TcpListener,
    app: Router,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> io::Result<()> {
    tracing::info!(address = %listener.local_addr()?, "nautilus server listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::warn!(%error, "failed to listen for ctrl-c");
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => {
                tracing::warn!(%error, "failed to listen for SIGTERM");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
    tracing::info!("shutdown signal received, draining requests");
}

async fn handle_middleware_error(error: BoxError) -> ApiError {
    if error.is::<Elapsed>() {
        ApiError::new(ErrorCode::RequestTimeout)
    } else {
        tracing::error!(%error, "middleware failed");
        ApiError::new(ErrorCode::InternalError)
    }
}

async fn catch_panic(request: Request, next: Next) -> Response {
    match AssertUnwindSafe(next.run(request)).catch_unwind().await {
        Ok(response) => response,
        Err(_) => {
            tracing::error!("request handler panicked");
            ApiError::new(ErrorCode::InternalError).into_response()
        }
    }
}

async fn health_check(State(state): State<Arc<ServerState>>) -> Json<HealthCheckBody> {
    Json(HealthCheckBody {
        pk: state.ctx.public_key_hex(),
        address: state.ctx.sui_address(),
    })
}

async fn get_attestation(State(state): State<Arc<ServerState>>) -> Result<Response, ApiError> {
    let permit = state.permit()?;
    attest(state.ctx.clone(), permit, None, None).await
}

async fn post_attestation(
    State(state): State<Arc<ServerState>>,
    request: Request,
) -> Result<Response, ApiError> {
    let permit = state.permit()?;
    let bytes = read_body(request, state.config.max_body_bytes).await?;
    let body: AttestationBody = serde_json::from_slice(&bytes).map_err(|error| {
        ApiError::with_message(
            ErrorCode::InvalidRequest,
            format!("invalid attestation body: {error}"),
        )
    })?;
    let nonce = decode_field("nonce", body.nonce.as_deref())?;
    let user_data = decode_field("user_data", body.user_data.as_deref())?;
    if !state.config.allow_unnonced_attestation && nonce.as_ref().is_none_or(Vec::is_empty) {
        return Err(ApiError::with_message(
            ErrorCode::InvalidRequest,
            "nonce is required",
        ));
    }
    attest(state.ctx.clone(), permit, nonce, user_data).await
}

async fn attest(
    ctx: NautilusContext,
    permit: OwnedSemaphorePermit,
    nonce: Option<Vec<u8>>,
    user_data: Option<Vec<u8>>,
) -> Result<Response, ApiError> {
    let document = spawn_blocking(move || {
        let _permit = permit;
        ctx.attestation(nonce, user_data)
    })
    .await??;
    Ok(Json(serde_json::json!({ "attestation": encode_hex(document) })).into_response())
}

async fn process_data(
    State(state): State<Arc<ServerState>>,
    request: Request,
) -> Result<Response, ApiError> {
    let permit = state.permit()?;
    let bytes = read_body(request, state.config.max_body_bytes).await?;
    (state.handler)(bytes, state.ctx.clone(), permit).await
}

async fn read_body(request: Request, limit: usize) -> Result<Bytes, ApiError> {
    let declared = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    if declared.is_some_and(|len| len > limit as u64) {
        return Err(ApiError::new(ErrorCode::BodyTooLarge));
    }
    to_bytes(request.into_body(), limit).await.map_err(|error| {
        if exceeded_limit(&error) {
            ApiError::new(ErrorCode::BodyTooLarge)
        } else {
            tracing::warn!(%error, "failed to read request body");
            ApiError::new(ErrorCode::BodyReadFailed)
        }
    })
}

fn exceeded_limit(error: &(dyn StdError + 'static)) -> bool {
    iter::successors(Some(error), |&error| error.source())
        .any(|error| error.is::<LengthLimitError>())
}

fn decode_field(field: &str, value: Option<&str>) -> Result<Option<Vec<u8>>, ApiError> {
    value.map(decode_hex).transpose().map_err(|error| {
        ApiError::with_message(ErrorCode::InvalidRequest, format!("{field}: {error}"))
    })
}

fn json_response<T: Serialize>(value: &T) -> Result<Response, ApiError> {
    match serde_json::to_vec(value) {
        Ok(body) => Ok(([(header::CONTENT_TYPE, "application/json")], body).into_response()),
        Err(error) => {
            tracing::error!(%error, "failed to serialize response");
            Err(ApiError::new(ErrorCode::InternalError))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Mutex, mpsc};

    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
    use http_body_util::BodyExt as _;
    use serde::Serialize;
    use serde_json::{Value, json};
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::TcpStream,
        sync::mpsc::{UnboundedReceiver, unbounded_channel},
    };
    use tower::ServiceExt as _;

    use crate::testing::FakeAttestor;
    use crate::{
        AttestationRequest, Attestor, EnclaveIdentity, Intent, NautilusContext, PublicKeyBytes,
        SignatureBytes, SignedResponse, Signer, intent_message, verify_signed_response,
    };

    use super::*;

    fn sign_len(bytes: Bytes, ctx: &NautilusContext) -> Result<SignedResponse<u64>, NautilusError> {
        ctx.sign_intent(Intent(0), &(bytes.len() as u64))
    }

    fn sign_body(
        bytes: Bytes,
        ctx: &NautilusContext,
    ) -> Result<SignedResponse<Vec<u8>>, NautilusError> {
        ctx.sign_intent(Intent(0), &bytes.to_vec())
    }

    fn test_context() -> NautilusContext {
        NautilusContext::with_signer(
            EnclaveIdentity::from_seed([9u8; 32]),
            FakeAttestor::default(),
        )
    }

    fn small_config() -> ServerConfig {
        ServerConfig {
            max_body_bytes: 4,
            ..ServerConfig::default()
        }
    }

    fn test_app() -> Router {
        router(test_context(), small_config(), sign_len).unwrap()
    }

    fn default_app() -> Router {
        router(test_context(), ServerConfig::default(), sign_len).unwrap()
    }

    fn unnonced_app() -> Router {
        router(
            test_context(),
            ServerConfig {
                allow_unnonced_attestation: true,
                ..ServerConfig::default()
            },
            sign_len,
        )
        .unwrap()
    }

    async fn call(app: Router, method: &str, uri: &str, body: impl Into<Body>) -> Response {
        app.oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .body(body.into())
                .unwrap(),
        )
        .await
        .unwrap()
    }

    async fn response_json(response: Response) -> Value {
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    async fn assert_error(response: Response, code: ErrorCode, message: &str) {
        assert_eq!(response.status(), code.status());
        assert_eq!(
            response_json(response).await,
            json!({ "error": code.as_str(), "message": message })
        );
    }

    fn attestation_doc(json: &Value) -> Value {
        serde_json::from_slice(&hex::decode(json["attestation"].as_str().unwrap()).unwrap())
            .unwrap()
    }

    struct Gate {
        app: Router,
        started: UnboundedReceiver<()>,
        release: mpsc::Sender<()>,
    }

    fn gated_app(config: ServerConfig) -> Gate {
        let (started_tx, started) = unbounded_channel();
        let (release, release_rx) = mpsc::channel::<()>();
        let release_rx = Mutex::new(release_rx);
        let app = router(test_context(), config, move |bytes, _ctx| {
            let _ = started_tx.send(());
            let _ = release_rx.lock().unwrap().recv();
            Ok(bytes.len() as u64)
        })
        .unwrap();
        Gate {
            app,
            started,
            release,
        }
    }

    struct FailingAttestor;

    impl Attestor for FailingAttestor {
        fn name(&self) -> &'static str {
            "failing"
        }

        fn attest(&self, _request: AttestationRequest) -> Result<Vec<u8>, AttestationError> {
            Err(AttestationError::Backend(
                "secret backend detail".to_owned(),
            ))
        }

        fn random(&self, _len: usize) -> Result<Vec<u8>, AttestationError> {
            Err(AttestationError::Backend(
                "secret backend detail".to_owned(),
            ))
        }
    }

    struct FixedKeySigner(SigningKey);

    impl Signer for FixedKeySigner {
        fn public_key(&self) -> PublicKeyBytes {
            self.0.verifying_key().to_bytes()
        }

        fn sign(&self, message: &[u8]) -> Result<SignatureBytes, NautilusError> {
            Ok(self.0.sign(message).to_bytes())
        }
    }

    struct FailingSigner;

    impl Signer for FailingSigner {
        fn public_key(&self) -> PublicKeyBytes {
            [7u8; 32]
        }

        fn sign(&self, _message: &[u8]) -> Result<SignatureBytes, NautilusError> {
            Err(NautilusError::Crypto("secret signer detail".to_owned()))
        }
    }

    #[test]
    fn default_config_matches_documented_limits() {
        let config = ServerConfig::default();
        assert_eq!(config.max_body_bytes, 8 * 1024 * 1024);
        assert!(config.max_concurrent >= 1);
        assert_eq!(config.request_timeout, Duration::from_secs(30));
        assert!(!config.allow_unnonced_attestation);
    }

    #[test]
    fn zero_limits_are_rejected() {
        let cases = [
            (
                ServerConfig {
                    max_body_bytes: 0,
                    ..ServerConfig::default()
                },
                "max_body_bytes",
            ),
            (
                ServerConfig {
                    max_concurrent: 0,
                    ..ServerConfig::default()
                },
                "max_concurrent",
            ),
            (
                ServerConfig {
                    request_timeout: Duration::ZERO,
                    ..ServerConfig::default()
                },
                "request_timeout",
            ),
        ];
        for (config, field) in cases {
            assert_eq!(config.validate(), Err(ConfigError::Zero(field)));
            assert_eq!(
                router(test_context(), config.clone(), sign_len)
                    .unwrap_err()
                    .to_string(),
                format!("ServerConfig::{field} must be greater than zero")
            );
            assert!(
                router_async(test_context(), config, |bytes, ctx| async move {
                    sign_len(bytes, &ctx)
                })
                .is_err()
            );
        }
        ServerConfig::default().validate().unwrap();
    }

    #[test]
    fn error_codes_serialize_snake_case() {
        for code in [
            ErrorCode::InvalidRequest,
            ErrorCode::BodyReadFailed,
            ErrorCode::NotFound,
            ErrorCode::MethodNotAllowed,
            ErrorCode::RequestTimeout,
            ErrorCode::BodyTooLarge,
            ErrorCode::ApplicationError,
            ErrorCode::Overloaded,
            ErrorCode::InternalError,
            ErrorCode::AttestationUnavailable,
        ] {
            assert_eq!(serde_json::to_value(code).unwrap(), code.as_str());
        }
    }

    #[tokio::test]
    async fn health_check_returns_identity() {
        let response = call(test_app(), "GET", "/health_check", Body::empty()).await;
        assert_eq!(response.status(), StatusCode::OK);
        let json = response_json(response).await;
        assert_eq!(json["pk"].as_str().unwrap().len(), 64);
        assert!(json["address"].as_str().unwrap().starts_with("0x"));
    }

    #[tokio::test]
    async fn unknown_route_and_method_are_json_errors() {
        let response = call(default_app(), "POST", "/nope", Body::empty()).await;
        assert_error(response, ErrorCode::NotFound, "no such route").await;
        let response = call(default_app(), "GET", "/process_data", Body::empty()).await;
        assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
        assert_error(response, ErrorCode::MethodNotAllowed, "method not allowed").await;
        let response = call(default_app(), "POST", "/health_check", Body::empty()).await;
        assert_error(response, ErrorCode::MethodNotAllowed, "method not allowed").await;
    }

    #[tokio::test]
    async fn attestation_accepts_hex_nonce() {
        let response = call(
            default_app(),
            "POST",
            "/attestation",
            r#"{"nonce":"0x010203"}"#,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            attestation_doc(&response_json(response).await)["nonce"],
            "010203"
        );
    }

    #[tokio::test]
    async fn unnonced_attestation_is_rejected_by_default() {
        let response = call(default_app(), "GET", "/attestation", Body::empty()).await;
        assert_error(response, ErrorCode::MethodNotAllowed, "method not allowed").await;
        for body in ["{}", r#"{"nonce":""}"#, r#"{"user_data":"0x01"}"#] {
            let response = call(default_app(), "POST", "/attestation", body).await;
            assert_error(response, ErrorCode::InvalidRequest, "nonce is required").await;
        }
    }

    #[tokio::test]
    async fn unnonced_attestation_is_served_when_allowed() {
        let response = call(unnonced_app(), "GET", "/attestation", Body::empty()).await;
        assert_eq!(response.status(), StatusCode::OK);
        let response = call(unnonced_app(), "POST", "/attestation", "{}").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            attestation_doc(&response_json(response).await)["nonce"],
            Value::Null
        );
    }

    #[tokio::test]
    async fn attestation_rejects_oversized_nonce() {
        let body = format!(r#"{{"nonce":"{}"}}"#, "00".repeat(513));
        let response = call(unnonced_app(), "POST", "/attestation", body).await;
        assert_error(
            response,
            ErrorCode::InvalidRequest,
            "invalid attestation request: nonce must be at most 512 bytes, got 513",
        )
        .await;
    }

    #[tokio::test]
    async fn attestation_rejects_bad_hex() {
        let response = call(unnonced_app(), "POST", "/attestation", r#"{"nonce":"zz"}"#).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = response_json(response).await;
        assert_eq!(json["error"], "invalid_request");
        assert!(json["message"].as_str().unwrap().starts_with("nonce: "));
    }

    #[tokio::test]
    async fn attestation_rejects_malformed_json() {
        let response = call(default_app(), "POST", "/attestation", "nope").await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response_json(response).await["error"], "invalid_request");
    }

    #[tokio::test]
    async fn attestor_failure_is_unavailable_without_details() {
        let ctx =
            NautilusContext::with_signer(EnclaveIdentity::from_seed([9u8; 32]), FailingAttestor);
        let app = router(ctx, ServerConfig::default(), sign_len).unwrap();
        let response = call(app, "POST", "/attestation", r#"{"nonce":"01"}"#).await;
        assert_error(
            response,
            ErrorCode::AttestationUnavailable,
            "attestation is unavailable",
        )
        .await;
    }

    #[tokio::test]
    async fn process_data_calls_handler() {
        let response = call(test_app(), "POST", "/process_data", "abc").await;
        assert_eq!(response.status(), StatusCode::OK);
        let json = response_json(response).await;
        assert_eq!(json["response"]["intent"], 0);
        assert_eq!(json["response"]["data"], 3);
        assert_eq!(json["signature"].as_str().unwrap().len(), 128);
    }

    #[tokio::test]
    async fn router_async_calls_handler() {
        let app = router_async(test_context(), small_config(), |bytes, ctx| async move {
            sign_len(bytes, &ctx)
        })
        .unwrap();
        let response = call(app, "POST", "/process_data", "abc").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response_json(response).await["response"]["data"], 3);
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

        let app = router(ctx.clone(), ServerConfig::default(), sign_body).unwrap();
        let response = call(app, "POST", "/process_data", forged.clone()).await;
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
    async fn declared_oversized_body_is_rejected_early() {
        let response = test_app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/process_data")
                    .header(header::CONTENT_LENGTH, "1000")
                    .body(Body::from("ab"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_error(response, ErrorCode::BodyTooLarge, "request body too large").await;
    }

    #[tokio::test]
    async fn streamed_oversized_body_is_rejected() {
        let chunks = futures_util::stream::iter([
            Ok::<_, io::Error>(Bytes::from("abc")),
            Ok(Bytes::from("de")),
        ]);
        let response = call(
            test_app(),
            "POST",
            "/process_data",
            Body::from_stream(chunks),
        )
        .await;
        assert_error(response, ErrorCode::BodyTooLarge, "request body too large").await;
    }

    #[tokio::test]
    async fn broken_body_is_read_failure() {
        let chunks = futures_util::stream::iter([
            Ok(Bytes::from("ab")),
            Err(io::Error::other("connection reset")),
        ]);
        let response = call(
            test_app(),
            "POST",
            "/process_data",
            Body::from_stream(chunks),
        )
        .await;
        assert_error(
            response,
            ErrorCode::BodyReadFailed,
            "failed to read request body",
        )
        .await;
    }

    #[tokio::test]
    async fn application_error_returns_app_message() {
        let app = router(test_context(), ServerConfig::default(), |_, _| {
            Err::<u64, _>(NautilusError::application("payload is not a song"))
        })
        .unwrap();
        let response = call(app, "POST", "/process_data", "abc").await;
        assert_error(
            response,
            ErrorCode::ApplicationError,
            "payload is not a song",
        )
        .await;
    }

    #[tokio::test]
    async fn internal_error_hides_details() {
        let app = router(test_context(), ServerConfig::default(), |_, _| {
            Err::<u64, _>(NautilusError::Crypto("secret detail".to_owned()))
        })
        .unwrap();
        let response = call(app, "POST", "/process_data", "abc").await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        assert!(!String::from_utf8_lossy(&bytes).contains("secret detail"));
        assert_eq!(
            serde_json::from_slice::<Value>(&bytes).unwrap(),
            json!({ "error": "internal_error", "message": "internal error" })
        );
    }

    async fn assert_panic_is_internal_error(app: Router) {
        let response = call(app.clone(), "POST", "/process_data", "abc").await;
        assert_error(response, ErrorCode::InternalError, "internal error").await;
        let response = call(app.clone(), "POST", "/process_data", "abcdefghijkl").await;
        assert_eq!(response.status(), StatusCode::OK);
        let response = call(app, "GET", "/health_check", Body::empty()).await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    fn eleventh_byte(bytes: &[u8]) -> u64 {
        u64::from(bytes[10])
    }

    #[tokio::test]
    async fn panicking_blocking_handler_is_internal_error() {
        let app = router(test_context(), ServerConfig::default(), |bytes, ctx| {
            ctx.sign_intent(Intent(0), &eleventh_byte(&bytes))
        })
        .unwrap();
        assert_panic_is_internal_error(app).await;
    }

    #[tokio::test]
    async fn panicking_async_handler_is_internal_error() {
        let app = router_async(
            test_context(),
            ServerConfig::default(),
            |bytes, ctx| async move { ctx.sign_intent(Intent(0), &eleventh_byte(&bytes)) },
        )
        .unwrap();
        assert_panic_is_internal_error(app).await;
    }

    #[tokio::test]
    async fn custom_signer_serves_and_signs() {
        let key = SigningKey::from_bytes(&[0x5au8; 32]);
        let public_key = key.verifying_key().to_bytes();
        assert_ne!(public_key, test_context().public_key());
        let ctx = NautilusContext::with_signer(FixedKeySigner(key), FakeAttestor::default());
        let app = router(ctx, ServerConfig::default(), sign_len).unwrap();

        let response = call(app.clone(), "GET", "/health_check", Body::empty()).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response_json(response).await["pk"], hex::encode(public_key));

        let response = call(app, "POST", "/process_data", "abc").await;
        assert_eq!(response.status(), StatusCode::OK);
        let signed: SignedResponse<u64> =
            serde_json::from_value(response_json(response).await).unwrap();
        assert_eq!(signed.response.data, 3);
        verify_signed_response(&public_key, Intent(0), &signed).unwrap();
    }

    #[tokio::test]
    async fn failing_signer_is_internal_error_without_details() {
        let ctx = NautilusContext::with_signer(FailingSigner, FakeAttestor::default());
        let app = router(ctx, ServerConfig::default(), sign_len).unwrap();
        let response = call(app, "POST", "/process_data", "abc").await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        assert!(!String::from_utf8_lossy(&bytes).contains("secret signer detail"));
        assert_eq!(
            serde_json::from_slice::<Value>(&bytes).unwrap(),
            json!({ "error": "internal_error", "message": "internal error" })
        );
    }

    #[tokio::test]
    async fn saturated_server_is_overloaded_but_healthy() {
        let mut gate = gated_app(ServerConfig {
            max_concurrent: 1,
            ..ServerConfig::default()
        });
        let first = tokio::spawn(call(gate.app.clone(), "POST", "/process_data", "abc"));
        gate.started.recv().await.unwrap();

        let response = call(gate.app.clone(), "POST", "/process_data", "abc").await;
        assert_error(
            response,
            ErrorCode::Overloaded,
            "server is at its concurrency limit",
        )
        .await;
        let response = call(
            gate.app.clone(),
            "POST",
            "/attestation",
            r#"{"nonce":"01"}"#,
        )
        .await;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        let response = call(gate.app.clone(), "GET", "/health_check", Body::empty()).await;
        assert_eq!(response.status(), StatusCode::OK);

        drop(gate.release);
        assert_eq!(first.await.unwrap().status(), StatusCode::OK);
        let response = call(gate.app, "POST", "/process_data", "abc").await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn timed_out_blocking_handler_keeps_its_permit() {
        let mut gate = gated_app(ServerConfig {
            max_concurrent: 1,
            request_timeout: Duration::from_millis(50),
            ..ServerConfig::default()
        });
        let response = call(gate.app.clone(), "POST", "/process_data", "abc").await;
        assert_error(response, ErrorCode::RequestTimeout, "request timed out").await;
        gate.started.recv().await.unwrap();

        let response = call(gate.app.clone(), "POST", "/process_data", "abc").await;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);

        drop(gate.release);
        for _ in 0..200 {
            let response = call(gate.app.clone(), "POST", "/process_data", "abc").await;
            if response.status() == StatusCode::OK {
                return;
            }
            assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("permit was never released");
    }

    #[tokio::test]
    async fn slow_async_handler_times_out() {
        let config = ServerConfig {
            request_timeout: Duration::from_millis(50),
            ..ServerConfig::default()
        };
        let app = router_async(test_context(), config, |_, _| async {
            tokio::time::sleep(Duration::from_secs(5)).await;
            Ok(0u64)
        })
        .unwrap();
        let response = call(app, "POST", "/process_data", "abc").await;
        assert_error(response, ErrorCode::RequestTimeout, "request timed out").await;
    }

    #[tokio::test]
    async fn graceful_shutdown_completes_in_flight_request() {
        let mut gate = gated_app(ServerConfig::default());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (shutdown, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(serve_with_shutdown(listener, gate.app, async {
            let _ = shutdown_rx.await;
        }));
        let client = tokio::spawn(async move {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            stream
                .write_all(
                    b"POST /process_data HTTP/1.1\r\nhost: localhost\r\ncontent-length: 3\r\nconnection: close\r\n\r\nabc",
                )
                .await
                .unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).await.unwrap();
            response
        });

        gate.started.recv().await.unwrap();
        shutdown.send(()).unwrap();
        drop(gate.release);

        assert!(client.await.unwrap().starts_with("HTTP/1.1 200"));
        server.await.unwrap().unwrap();
    }
}
