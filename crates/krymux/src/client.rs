//! krymux client: TLS connect with server fingerprint pinning, plus the
//! stream-opening API used by the frontends and the sync engine.

use crate::keys::LoadedIdentity;
use crate::mux::{MuxSession, SessionOpts, Target, TunnelStream};
use crate::tls;
use anyhow::{anyhow, bail, Result};
use std::sync::Arc;
use tokio::net::TcpStream;

/// A connected tunnel: one multiplexed session plus the defaults applied to
/// streams opened through it.
pub struct EctunClient {
    /// The underlying multiplexed session.
    pub session: Arc<MuxSession>,
    /// Default compression request for new streams (e.g. "auto").
    pub compression: String,
}

/// Connection tunables for EctunClient::connect.
#[derive(Clone)]
pub struct ConnectParams {
    /// Default compression request ("auto", "none", an algorithm, or `algo:level`).
    pub compression: String,
    /// Keepalive interval in seconds.
    pub keepalive_sec: u64,
    /// Display name sent in the session HELLO.
    pub name: String,
    /// Initial per-stream receive window, in bytes.
    pub rx_window: u32,
    /// Upper bound for dynamic window growth, in bytes.
    pub rx_window_max: u32,
}

impl Default for ConnectParams {
    fn default() -> Self {
        ConnectParams {
            compression: "auto".into(),
            keepalive_sec: 30,
            name: "client".into(),
            rx_window: 262_144,
            rx_window_max: 4_194_304,
        }
    }
}

impl EctunClient {
    /// Connects to `endpoint`, verifies the pinned `server_fingerprint`
    /// (fail closed), and starts the multiplexed session. Every resolved
    /// address is tried in turn with its own timeout, so one unreachable
    /// address family cannot starve the connect budget.
    pub async fn connect(
        endpoint: &str,
        identity: &Arc<LoadedIdentity>,
        server_fingerprint: &str,
        params: &ConnectParams,
    ) -> Result<EctunClient> {
        let (host, port) = crate::config::parse_listen(endpoint)
            .map_err(|e| anyhow!("bad endpoint {endpoint}: {e}"))?;
        let connector = tls::client_connector(identity)?;

        // resolve every address (mDNS/DNS names may carry several, often IPv6
        // first) and try them one by one with a per-address timeout — a single
        // blackholed AAAA must not starve the whole connect budget
        let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host((host.as_str(), port))
            .await
            .map_err(|e| anyhow!("resolve {host}: {e}"))?
            .collect();
        if addrs.is_empty() {
            return Err(anyhow!("no addresses for {host}"));
        }
        let mut tcp = None;
        let mut last_err = String::new();
        for addr in &addrs {
            match tokio::time::timeout(std::time::Duration::from_secs(5), TcpStream::connect(addr))
                .await
            {
                Ok(Ok(s)) => {
                    tcp = Some(s);
                    break;
                }
                Ok(Err(e)) => last_err = format!("{addr}: {e}"),
                Err(_) => last_err = format!("{addr}: timeout"),
            }
        }
        let tcp = tcp.ok_or_else(|| {
            anyhow!(
                "connect {host}:{port} failed on all {} addresses; last: {last_err}",
                addrs.len()
            )
        })?;
        let _ = tcp.set_nodelay(true);

        let tls_stream = connector
            .connect(rustls::pki_types::ServerName::try_from(host.clone())?, tcp)
            .await
            .map_err(|e| anyhow!("tls handshake: {e}"))?;

        // pin verification (fail closed) before the session takes ownership
        let fp = tls::peer_fingerprint(tls_stream.get_ref().1.peer_certificates())
            .map_err(|e| anyhow!("parse server cert: {e}"))?;
        match fp.as_deref() {
            Some(fp) if fp == server_fingerprint => {}
            Some(fp) => {
                bail!(
                    "server verification failed: fingerprint mismatch (got {}…)",
                    &fp[7..19.min(fp.len())]
                );
            }
            None => {
                bail!("server did not present a certificate");
            }
        }

        let session = MuxSession::start(
            tls_stream,
            SessionOpts {
                is_client: true,
                name: params.name.clone(),
                rx_window: params.rx_window,
                rx_window_max: params.rx_window_max,
                max_streams: 1024,
                keepalive_sec: params.keepalive_sec,
            },
            None,
        )
        .await?;

        Ok(EctunClient {
            session,
            compression: params.compression.clone(),
        })
    }

    /// Opens a tunneled stream to `host:port`; `compression` overrides the
    /// client default when given.
    pub async fn open_stream(
        &self,
        host: &str,
        port: u16,
        compression: Option<&str>,
    ) -> Result<TunnelStream> {
        let comp = compression.unwrap_or(&self.compression).to_string();
        self.session
            .open_stream(
                Target {
                    host: if host.is_empty() {
                        None
                    } else {
                        Some(host.to_string())
                    },
                    port,
                    unix: None,
                    hint: "raw".into(),
                },
                &comp,
            )
            .await
    }
}
