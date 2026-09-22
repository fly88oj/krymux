//! `krymux` is an encrypted, compressed, multiplexed TCP tunnel and reverse
//! proxy — secure service access over reverse tunnels — wire-compatible with
//! the Node reference implementation.
//!
//! A client and a server mutually authenticate over TLS 1.3 using Ed25519
//! identities pinned by SHA-256 SPKI fingerprints (no PKI), then speak the
//! CMPX multiplexing protocol: many logical streams — SOCKS5/HTTP proxying,
//! file sync, browser WebSocket sessions — flow over the single encrypted
//! connection with per-stream compression and credit-based flow control.
//!
//! # Example
//!
//! Connect a tunnel and open a stream through it:
//!
//! ```no_run
//! use std::sync::Arc;
//! use krymux::client::{ConnectParams, EctunClient};
//! use krymux::keys::load_identity;
//! use tokio::io::{AsyncReadExt, AsyncWriteExt};
//!
//! # async fn connect() -> anyhow::Result<()> {
//! let identity =
//!     Arc::new(load_identity("client.key.pem".as_ref(), "client.crt.pem".as_ref())?);
//! let client = EctunClient::connect(
//!     "tunnel.example.com:7000",
//!     &identity,
//!     "sha256:<fingerprint reported by `krymux-tunnel probe`>",
//!     &ConnectParams::default(),
//! )
//! .await?;
//!
//! // A full-duplex stream to any destination the server may route to:
//! let mut stream = client.open_stream("internal.example.com", 5432, Some("auto")).await?;
//! stream.write_all(b"ping").await?;
//! let mut buf = [0u8; 4];
//! stream.read_exact(&mut buf).await?;
//! # Ok(())
//! # }
//! ```
//!
//! The crate is a pure library SDK. Applications build on top of it — in
//! this workspace, `krymux-tunnel` (tunnel operations CLI: `keygen`,
//! `fingerprint`, `server`, `client`, `probe`) and `krymux-sync`
//! (bidirectional file sync: `sync-server`, `sync-client`).

pub mod client;
pub mod compress;
pub mod config;
pub mod frame;
pub mod httpproxy;
pub mod keys;
pub mod mux;
pub mod router;
pub mod server;
pub mod socks5;
pub mod tls;
pub mod ws;
