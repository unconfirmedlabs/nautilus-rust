use std::{
    fmt::Debug,
    future::Future,
    io,
    net::SocketAddr,
    pin::{Pin, pin},
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use axum::{Router, serve::Listener};
use hyper::{body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::{
    rt::{TokioIo, TokioTimer},
    server::graceful::GracefulShutdown,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpListener,
    sync::Semaphore,
    time::{Instant, sleep, sleep_until},
};
use tower::ServiceExt as _;

use crate::ServerConfig;

/// Binds `addr` and serves `app` until SIGTERM or Ctrl-C, then drains in-flight requests.
pub async fn serve(addr: SocketAddr, app: Router, config: ServerConfig) -> io::Result<()> {
    config.validate().map_err(invalid_config)?;
    serve_with_shutdown(
        TcpListener::bind(addr).await?,
        app,
        config,
        shutdown_signal(),
    )
    .await
}

/// Binds vsock `port` on any local CID and serves `app` until SIGTERM or Ctrl-C, then drains in-flight requests.
#[cfg(feature = "vsock")]
pub async fn serve_vsock(port: u32, app: Router, config: ServerConfig) -> io::Result<()> {
    config.validate().map_err(invalid_config)?;
    serve_with_shutdown(VsockListener::bind(port)?, app, config, shutdown_signal()).await
}

/// Serves `app` on `listener` with `config`'s connection limits until `shutdown` completes, then drains in-flight requests.
pub async fn serve_with_shutdown<L>(
    mut listener: L,
    app: Router,
    config: ServerConfig,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> io::Result<()>
where
    L: Listener,
    L::Addr: Debug,
{
    config.validate().map_err(invalid_config)?;
    tracing::info!(address = ?listener.local_addr()?, ?config, "nautilus server listening");

    let connections = Arc::new(Semaphore::new(
        config.max_connections.min(Semaphore::MAX_PERMITS),
    ));
    let mut http = http1::Builder::new();
    http.timer(TokioTimer::new())
        .header_read_timeout(config.header_read_timeout)
        .keep_alive(true);
    let graceful = GracefulShutdown::new();
    let mut shutdown = pin!(shutdown);

    loop {
        let (io, peer) = tokio::select! {
            accepted = listener.accept() => accepted,
            () = &mut shutdown => break,
        };
        let Ok(permit) = Arc::clone(&connections).try_acquire_owned() else {
            tracing::debug!(?peer, "connection limit reached, closing connection");
            continue;
        };

        let activity = Arc::new(Activity::new());
        let service = {
            let activity = Arc::clone(&activity);
            let app = app.clone();
            service_fn(move |request: hyper::Request<Incoming>| {
                let in_flight = InFlight::enter(Arc::clone(&activity));
                let response = app.clone().oneshot(request);
                async move {
                    let response = response.await;
                    drop(in_flight);
                    response
                }
            })
        };
        let io = TokioIo::new(TrackedIo {
            io,
            activity: Arc::clone(&activity),
        });
        let connection = graceful.watch(http.serve_connection(io, service));
        let idle_timeout = config.idle_timeout;
        tokio::spawn(async move {
            let _permit = permit;
            tokio::select! {
                result = connection => {
                    if let Err(error) = result {
                        tracing::debug!(%error, ?peer, "connection closed with an error");
                    }
                }
                () = activity.idle(idle_timeout) => {
                    tracing::debug!(?peer, "closing idle connection");
                }
            }
        });
    }

    drop(listener);
    graceful.shutdown().await;
    Ok(())
}

/// An AF_VSOCK listener for [`serve_with_shutdown`].
#[cfg(feature = "vsock")]
#[derive(Debug)]
pub struct VsockListener(tokio_vsock::VsockListener);

#[cfg(feature = "vsock")]
impl VsockListener {
    /// Binds `port` on any local CID.
    pub fn bind(port: u32) -> io::Result<Self> {
        tokio_vsock::VsockListener::bind(tokio_vsock::VsockAddr::new(
            tokio_vsock::VMADDR_CID_ANY,
            port,
        ))
        .map(Self)
    }
}

#[cfg(feature = "vsock")]
impl Listener for VsockListener {
    type Io = tokio_vsock::VsockStream;
    type Addr = tokio_vsock::VsockAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            match self.0.accept().await {
                Ok(accepted) => return accepted,
                Err(error) => handle_accept_error(error).await,
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.0.local_addr()
    }
}

#[cfg(feature = "vsock")]
async fn handle_accept_error(error: io::Error) {
    if matches!(
        error.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
    ) {
        return;
    }
    tracing::error!(%error, "vsock accept failed, retrying in 1 s");
    sleep(Duration::from_secs(1)).await;
}

fn invalid_config(error: crate::ConfigError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, error)
}

pub(crate) async fn shutdown_signal() {
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

struct Activity {
    started: Instant,
    last_ms: AtomicU64,
    in_flight: AtomicUsize,
}

impl Activity {
    fn new() -> Self {
        Self {
            started: Instant::now(),
            last_ms: AtomicU64::new(0),
            in_flight: AtomicUsize::new(0),
        }
    }

    fn touch(&self) {
        let elapsed = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.last_ms.fetch_max(elapsed, Ordering::Relaxed);
    }

    fn last(&self) -> Instant {
        self.started + Duration::from_millis(self.last_ms.load(Ordering::Relaxed))
    }

    async fn idle(&self, timeout: Duration) {
        loop {
            let deadline = self.last() + timeout;
            if Instant::now() < deadline {
                sleep_until(deadline).await;
            } else if self.in_flight.load(Ordering::Acquire) == 0 {
                return;
            } else {
                sleep(timeout).await;
            }
        }
    }
}

struct InFlight(Arc<Activity>);

impl InFlight {
    fn enter(activity: Arc<Activity>) -> Self {
        activity.in_flight.fetch_add(1, Ordering::AcqRel);
        Self(activity)
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.touch();
        self.0.in_flight.fetch_sub(1, Ordering::AcqRel);
    }
}

struct TrackedIo<I> {
    io: I,
    activity: Arc<Activity>,
}

impl<I: AsyncRead + Unpin> AsyncRead for TrackedIo<I> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let filled = buf.filled().len();
        let poll = Pin::new(&mut self.io).poll_read(cx, buf);
        if matches!(poll, Poll::Ready(Ok(()))) && buf.filled().len() > filled {
            self.activity.touch();
        }
        poll
    }
}

impl<I: AsyncWrite + Unpin> AsyncWrite for TrackedIo<I> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let poll = Pin::new(&mut self.io).poll_write(cx, buf);
        if matches!(poll, Poll::Ready(Ok(written)) if written > 0) {
            self.activity.touch();
        }
        poll
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let poll = Pin::new(&mut self.io).poll_write_vectored(cx, bufs);
        if matches!(poll, Poll::Ready(Ok(written)) if written > 0) {
            self.activity.touch();
        }
        poll
    }

    fn is_write_vectored(&self) -> bool {
        self.io.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::TcpStream,
        sync::oneshot,
        task::JoinHandle,
        time::timeout,
    };

    use crate::{EnclaveIdentity, Intent, NautilusContext, router_async, testing::FakeAttestor};

    use super::*;

    const REQUEST: &[u8] =
        b"POST /process_data HTTP/1.1\r\nhost: localhost\r\ncontent-length: 3\r\n\r\nabc";

    struct Running {
        addr: SocketAddr,
        shutdown: oneshot::Sender<()>,
        server: JoinHandle<io::Result<()>>,
    }

    async fn start(config: ServerConfig, handler_delay: Duration) -> Running {
        let ctx = NautilusContext::with_signer(
            EnclaveIdentity::from_seed([9u8; 32]),
            FakeAttestor::default(),
        );
        let app = router_async(ctx, config.clone(), move |bytes, ctx| async move {
            tokio::time::sleep(handler_delay).await;
            ctx.sign_intent(Intent(0), &(bytes.len() as u64))
        })
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (shutdown, shutdown_rx) = oneshot::channel::<()>();
        let server = tokio::spawn(serve_with_shutdown(listener, app, config, async {
            let _ = shutdown_rx.await;
        }));
        Running {
            addr,
            shutdown,
            server,
        }
    }

    async fn read_until_closed(stream: &mut TcpStream) -> String {
        let mut out = Vec::new();
        let read = timeout(Duration::from_secs(5), async {
            let mut buf = [0u8; 1024];
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => out.extend_from_slice(&buf[..n]),
                }
            }
        })
        .await;
        assert!(read.is_ok(), "connection was not closed");
        String::from_utf8_lossy(&out).into_owned()
    }

    #[tokio::test]
    async fn partial_headers_are_closed_at_the_header_deadline() {
        let running = start(
            ServerConfig {
                header_read_timeout: Duration::from_millis(200),
                ..ServerConfig::default()
            },
            Duration::ZERO,
        )
        .await;
        let mut stream = TcpStream::connect(running.addr).await.unwrap();
        stream
            .write_all(b"POST /process_data HTTP/1.1\r\nhost: x\r\n")
            .await
            .unwrap();
        let started = Instant::now();
        let response = read_until_closed(&mut stream).await;
        assert!(!response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[tokio::test]
    async fn idle_kept_alive_connection_is_closed() {
        let running = start(
            ServerConfig {
                header_read_timeout: Duration::from_millis(200),
                ..ServerConfig::default()
            },
            Duration::ZERO,
        )
        .await;
        let mut stream = TcpStream::connect(running.addr).await.unwrap();
        stream.write_all(REQUEST).await.unwrap();
        let response = read_until_closed(&mut stream).await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    }

    #[tokio::test]
    async fn silent_connection_is_closed_at_the_idle_deadline() {
        let running = start(
            ServerConfig {
                header_read_timeout: Duration::from_secs(60),
                idle_timeout: Duration::from_millis(200),
                ..ServerConfig::default()
            },
            Duration::ZERO,
        )
        .await;
        let mut stream = TcpStream::connect(running.addr).await.unwrap();
        let started = Instant::now();
        assert_eq!(read_until_closed(&mut stream).await, "");
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[tokio::test]
    async fn slow_handler_outlives_the_idle_deadline() {
        let running = start(
            ServerConfig {
                header_read_timeout: Duration::from_millis(100),
                idle_timeout: Duration::from_millis(100),
                ..ServerConfig::default()
            },
            Duration::from_millis(500),
        )
        .await;
        let mut stream = TcpStream::connect(running.addr).await.unwrap();
        stream.write_all(REQUEST).await.unwrap();
        let response = read_until_closed(&mut stream).await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    }

    #[tokio::test]
    async fn connections_beyond_the_limit_are_refused() {
        let running = start(
            ServerConfig {
                max_connections: 1,
                ..ServerConfig::default()
            },
            Duration::ZERO,
        )
        .await;
        let mut first = TcpStream::connect(running.addr).await.unwrap();
        first
            .write_all(b"POST /process_data HTTP/1.1\r\n")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut second = TcpStream::connect(running.addr).await.unwrap();
        let _ = second.write_all(REQUEST).await;
        assert_eq!(read_until_closed(&mut second).await, "");

        drop(first);
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut third = TcpStream::connect(running.addr).await.unwrap();
        third
            .write_all(b"POST /process_data HTTP/1.1\r\nhost: localhost\r\ncontent-length: 3\r\nconnection: close\r\n\r\nabc")
            .await
            .unwrap();
        let response = read_until_closed(&mut third).await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    }

    #[tokio::test]
    async fn shutdown_closes_idle_kept_alive_connections() {
        let running = start(ServerConfig::default(), Duration::ZERO).await;
        let mut stream = TcpStream::connect(running.addr).await.unwrap();
        stream.write_all(REQUEST).await.unwrap();
        let mut buf = [0u8; 12];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"HTTP/1.1 200");

        running.shutdown.send(()).unwrap();
        timeout(Duration::from_secs(5), running.server)
            .await
            .expect("server did not stop")
            .unwrap()
            .unwrap();
    }

    #[cfg(feature = "vsock")]
    #[tokio::test]
    async fn serves_over_vsock_loopback() {
        use tokio_vsock::{VMADDR_CID_LOCAL, VsockAddr, VsockStream};

        let port = 40_000 + std::process::id() % 20_000;
        let listener = match VsockListener::bind(port) {
            Ok(listener) => listener,
            Err(error) => {
                eprintln!("skipping: cannot bind AF_VSOCK ({error}); load vsock_loopback to run");
                return;
            }
        };
        let ctx = NautilusContext::with_signer(
            EnclaveIdentity::from_seed([9u8; 32]),
            FakeAttestor::default(),
        );
        let config = ServerConfig {
            max_connections: 1,
            ..ServerConfig::default()
        };
        let app = router_async(ctx, config.clone(), |bytes, ctx| async move {
            ctx.sign_intent(Intent(0), &(bytes.len() as u64))
        })
        .unwrap();
        let (shutdown, shutdown_rx) = oneshot::channel::<()>();
        let server = tokio::spawn(serve_with_shutdown(listener, app, config, async {
            let _ = shutdown_rx.await;
        }));

        let addr = VsockAddr::new(VMADDR_CID_LOCAL, port);
        let mut stream = match VsockStream::connect(addr).await {
            Ok(stream) => stream,
            Err(error) => {
                eprintln!(
                    "skipping: cannot connect to VMADDR_CID_LOCAL ({error}); load vsock_loopback to run"
                );
                return;
            }
        };
        stream
            .write_all(b"POST /process_data HTTP/1.1\r\n")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut refused = VsockStream::connect(addr).await.unwrap();
        let mut buf = [0u8; 64];
        let read = timeout(Duration::from_secs(5), refused.read(&mut buf)).await;
        assert!(matches!(read, Ok(Ok(0) | Err(_))), "{read:?}");

        stream
            .write_all(b"host: localhost\r\ncontent-length: 3\r\nconnection: close\r\n\r\nabc")
            .await
            .unwrap();
        let mut response = String::new();
        timeout(Duration::from_secs(5), stream.read_to_string(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");

        shutdown.send(()).unwrap();
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn invalid_config_is_rejected_before_serving() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let config = ServerConfig {
            max_connections: 0,
            ..ServerConfig::default()
        };
        let error = serve_with_shutdown(listener, Router::new(), config, async {})
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(
            error.to_string(),
            "ServerConfig::max_connections must be greater than zero"
        );
    }
}
