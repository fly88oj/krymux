//! krymux server: TLS termination, fingerprint-whitelist authorization, target
//! routing, and piping streams to their upstreams.

use crate::config::CompiledServer;
use crate::keys::LoadedIdentity;
use crate::mux::{MuxSession, SessionOpts, Target, TunnelStream};
use crate::router::{Decision, Router};
use crate::tls;
use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::server::TlsStream;

/// Object-safe combination of both IO directions for upstream boxing.
trait AsyncReadWrite: tokio::io::AsyncRead + tokio::io::AsyncWrite {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite> AsyncReadWrite for T {}

/// Runs the server forever: binds `listen`, terminates TLS, authorizes
/// clients by fingerprint (falling back to the WebSocket branch for
/// certificate-less browser connections), and serves each authorized
/// connection as a CMPX session.
pub async fn run_server(
    compiled: Arc<CompiledServer>,
    identity: Arc<LoadedIdentity>,
    listen: &str,
    ws_identity: Option<Arc<crate::ws::WsIdentity>>,
) -> Result<()> {
    // zstd dictionary registration must happen before any session HELLO
    // advertises its compression algorithms (config.rs owns the loader).
    crate::config::register_zstd_dictionary(&compiled.cfg.zstd_dictionary);

    let (host, port) = crate::config::parse_listen(listen)?;
    let listener = TcpListener::bind((host.as_str(), port))
        .await
        .with_context(|| format!("bind {}:{}", host, port))?;
    serve_connections(compiled, identity, listener, ws_identity).await
}

/// The accept loop over an already-bound listener (run_server is the CLI
/// entry; tests pass their own listener so the exact port is known).
pub async fn serve_connections(
    compiled: Arc<CompiledServer>,
    identity: Arc<LoadedIdentity>,
    listener: TcpListener,
    ws_identity: Option<Arc<crate::ws::WsIdentity>>,
) -> Result<()> {
    let acceptor = tls::server_acceptor(&identity)?;
    // runtime auth: hot-reloadable whitelist
    let auth = Arc::new(std::sync::Mutex::new(AuthState {
        mode: compiled.cfg.auth.mode.clone(),
        fingerprints: compiled.fingerprints.clone(),
    }));

    let local = listener.local_addr()?;
    // NOTE: keep lock() calls out of format arguments — two guards on the same
    // std Mutex in one expression self-deadlock (temporaries live to statement end).
    let (mode_str, nclients) = {
        let a = auth.lock().unwrap();
        (a.mode.clone(), a.fingerprints.len())
    };
    eprintln!(
        "krymux-server: listening on {}:{} (auth={}, clients={}, routes={})",
        local.ip(),
        local.port(),
        mode_str,
        nclients,
        compiled.routes.len()
    );

    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(_) => continue,
        };
        let acceptor = acceptor.clone();
        let compiled = compiled.clone();
        let identity = identity.clone();
        let auth = auth.clone();
        let ws_id = ws_identity.clone();
        tokio::spawn(async move {
            let _ = tcp.set_nodelay(true);
            let tls_stream = match acceptor.accept(tcp).await {
                Ok(s) => s,
                Err(_) => {
                    return;
                }
            };
            handle_conn(
                tls_stream,
                peer.to_string(),
                compiled,
                identity,
                auth,
                ws_id,
            )
            .await;
        });
    }
}

/// Runtime authorization state: auth mode plus the normalized fingerprint
/// whitelist ("open" admits any fingerprinted client).
pub struct AuthState {
    pub mode: String,
    pub fingerprints: Vec<String>,
}

/// Short display form of a fingerprint ("sha256:..." -> first hex chars).
fn short_fp(f: &str) -> &str {
    &f[7..19.min(f.len())]
}

async fn handle_conn(
    stream: TlsStream<tokio::net::TcpStream>,
    peer: String,
    compiled: Arc<CompiledServer>,
    identity: Arc<LoadedIdentity>,
    auth: Arc<std::sync::Mutex<AuthState>>,
    ws_identity: Option<Arc<crate::ws::WsIdentity>>,
) {
    // authorization: ALPN + presented client cert fingerprint (fail closed)
    let alpn_ok = stream.get_ref().1.alpn_protocol() == Some(tls::ALPN);
    let fp = tls::peer_fingerprint(stream.get_ref().1.peer_certificates())
        .ok()
        .flatten();
    let (mode, allow) = {
        let a = auth.lock().unwrap();
        (a.mode.clone(), a.fingerprints.clone())
    };
    let authorized = alpn_ok
        && match fp.as_deref() {
            None => false,
            Some(fp) => mode == "open" || allow.iter().any(|a| a == fp),
        };

    if !authorized {
        // no cert: browsers (wss:// can't set ALPN or present client certs)
        // route to the WS/HTTP handler; anything else is rejected
        let has_cert = fp.is_some();
        if let Some(ws_id) = ws_identity {
            if !has_cert {
                match crate::ws::handle_http_or_ws(stream, &ws_id, &mode, &allow).await {
                    Ok(crate::ws::WsOutcome::Static) => {
                        // page served on the raw TLS stream; nothing more to do
                        return;
                    }
                    Ok(crate::ws::WsOutcome::Session(duplex)) => {
                        // serve the WS-backed MuxSession
                        let router = Arc::new(Router::new(
                            compiled.routes.clone(),
                            compiled.fallback.clone(),
                            compiled.client_targets.clone(),
                        ));
                        let session = MuxSession::start(
                            duplex,
                            SessionOpts {
                                is_client: false,
                                name: short_fp(&identity.fingerprint).to_string(),
                                rx_window: compiled.cfg.rx_window,
                                rx_window_max: compiled.cfg.rx_window_max,
                                max_streams: compiled.cfg.max_streams,
                                keepalive_sec: compiled.cfg.keepalive_sec,
                            },
                            Some(Arc::new(move |stream: TunnelStream, target: Target| {
                                let router = router.clone();
                                tokio::spawn(handle_stream(stream, target, router));
                            })),
                        )
                        .await;
                        if let Ok(session) = session {
                            session.wait_closed().await;
                        }
                        return;
                    }
                    Err(e) => {
                        log::debug!("ws handler: {}", e);
                        return;
                    }
                }
            }
        }
        eprintln!(
            "krymux-server: rejected {} (alpn={}, fp={})",
            peer,
            alpn_ok,
            fp.as_deref()
                .map(|f| &f[7..19.min(f.len())])
                .unwrap_or("none")
        );
        return;
    }
    // authorized implies a fingerprint was presented
    let who = fp
        .as_deref()
        .map(|f| f[7..19.min(f.len())].to_string())
        .unwrap_or_default();
    eprintln!("krymux-server: client connected {} fp={}", peer, who);

    let router = Arc::new(Router::new(
        compiled.routes.clone(),
        compiled.fallback.clone(),
        compiled.client_targets.clone(),
    ));
    let session = MuxSession::start(
        stream,
        SessionOpts {
            is_client: false,
            name: identity.fingerprint[7..19.min(identity.fingerprint.len())].to_string(),
            rx_window: compiled.cfg.rx_window,
            rx_window_max: compiled.cfg.rx_window_max,
            max_streams: compiled.cfg.max_streams,
            keepalive_sec: compiled.cfg.keepalive_sec,
        },
        Some(Arc::new(move |stream: TunnelStream, target: Target| {
            let router = router.clone();
            tokio::spawn(handle_stream(stream, target, router));
        })),
    )
    .await;

    if let Ok(session) = session {
        session.wait_closed().await; // hold until the session really ends
    }
    eprintln!("krymux-server: client disconnected {}", peer);
}

async fn handle_stream(stream: TunnelStream, target: Target, router: Arc<Router>) {
    if target.hint == crate::socks5::HINT_UDP {
        // SOCKS5 UDP ASSOCIATE: relayed natively as datagrams. The router
        // has no say here — every frame carries its own per-datagram
        // destination, and TCP upstreams are meaningless for UDP.
        handle_udp_relay(stream).await;
        return;
    }

    let where_ = target
        .unix
        .as_ref()
        .map(|u| format!("unix:{}", u))
        .unwrap_or_else(|| format!("{}:{}", target.host.as_deref().unwrap_or("?"), target.port));

    let upstream = match router.resolve(&target) {
        Decision::Route { upstream, .. } => {
            log::debug!("router: route {} -> {}", where_, upstream.label());
            upstream
        }
        Decision::Dial => {
            log::debug!("router: dial {}", where_);
            crate::router::Upstream {
                host: target.host.clone(),
                port: target.port,
                unix: target.unix.clone(),
            }
        }
        Decision::Deny { reason } => {
            log::warn!("router: deny {} ({})", where_, reason);
            eprintln!(
                "krymux-server: stream denied target={} reason={}",
                where_, reason
            );
            stream.reject("denied", &reason);
            return;
        }
    };

    type BoxedIO = Box<dyn AsyncReadWrite + Unpin + Send>;

    let dial: Result<BoxedIO> = if let Some(path) = &upstream.unix {
        #[cfg(unix)]
        {
            use tokio::net::UnixStream;
            match tokio::time::timeout(std::time::Duration::from_secs(5), UnixStream::connect(path))
                .await
            {
                Ok(Ok(s)) => Ok(Box::new(s) as BoxedIO),
                Ok(Err(e)) => Err(anyhow::anyhow!("{e}")),
                Err(_) => Err(anyhow::anyhow!("dial timeout")),
            }
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            Err(anyhow::anyhow!("unix sockets unsupported on this platform"))
        }
    } else {
        let host = upstream.host.clone().unwrap_or_else(|| "127.0.0.1".into());
        match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            tokio::net::TcpStream::connect((host.as_str(), upstream.port)),
        )
        .await
        {
            Ok(Ok(s)) => Ok(Box::new(s) as BoxedIO),
            Ok(Err(e)) => Err(anyhow::anyhow!("{e}")),
            Err(_) => Err(anyhow::anyhow!("dial timeout")),
        }
    };

    let upstream_sock = match dial {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "krymux-server: upstream unreachable target={} upstream={} err={}",
                where_,
                upstream.label(),
                e
            );
            stream.reject("unreachable", &format!("dial {}: {e}", upstream.label()));
            return;
        }
    };

    stream.accept(Some(&upstream.label()));
    let mut stream = stream;
    let mut upstream_sock = upstream_sock;

    // copy_bidirectional runs both directions concurrently (never blocks the
    // reverse read on a slow write) and propagates half-close properly
    let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream_sock).await;
    // dropping a split write half does NOT signal EOF to the mux pump —
    // shutdown explicitly so the outbound pump sends FIN to the peer
    use tokio::io::AsyncWriteExt;
    let _ = stream.shutdown().await;
}

/// Server side of a SOCKS5 UDP association: one multiplexed stream carrying
/// framed datagrams (the codec lives in socks5.rs — single definition).
/// Binds an ephemeral UDP socket; each tunnel frame becomes one real
/// send_to((addr, port)) datagram, and every datagram received back is
/// framed toward the client. Ends when either side closes the stream.
async fn handle_udp_relay(stream: TunnelStream) {
    let sock = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(e) => {
            stream.reject("unreachable", &format!("udp bind: {e}"));
            return;
        }
    };
    stream.accept(Some("udp"));

    let sock = Arc::new(sock);
    let (mut rd, mut wr) = tokio::io::split(stream);

    // upstream datagrams → framed tunnel writes
    let up_sock = sock.clone();
    let responder = tokio::spawn(async move {
        use tokio::io::AsyncWriteExt as _;
        let mut buf = vec![0u8; 65536];
        while let Ok((n, peer)) = up_sock.recv_from(&mut buf).await {
            let (atyp, addr) = crate::socks5::ip_to_addr_bytes(peer.ip());
            let frame = crate::socks5::encode_udp_frame(atyp, &addr, peer.port(), &buf[..n]);
            if wr.write_all(&frame).await.is_err() {
                break;
            }
        }
        // upstream side gone: FIN so the client's relay loop ends promptly
        let _ = wr.shutdown().await;
    });

    // tunnel frames → upstream datagrams; EOF (Ok(None)) or a malformed
    // frame (Err) ends the association
    while let Ok(Some(frame)) = crate::socks5::read_udp_frame(&mut rd).await {
        if let Some(host) = crate::socks5::addr_bytes_to_host(frame.atyp, &frame.addr) {
            // per-datagram failures (e.g. unreachable port) do not tear down
            // the association — UDP has no connection state to lose
            if sock
                .send_to(&frame.payload, (host.as_str(), frame.port))
                .await
                .is_err()
            {
                log::debug!("udp relay: send_to {}:{} failed", host, frame.port);
            }
        }
    }
    responder.abort();
}
