//! WebSocket frontend for the krymux server — mirrors the Node implementation's
//! WS module.
//!
//! Browsers cannot present TLS client certificates or set ALPN, so the TLS
//! listener detects a certificate-less HTTP connection and branches here.
//! After a P-256 challenge-response authentication, WS binary frames are
//! bridged to a `MuxSession` via a duplex pair.
//!
//! Static routes (plain GET, no upgrade — same set as the Node server):
//!   GET /                      -> built-in launcher page (fp templated)
//!   GET /sdk/ectun-browser.mjs -> the browser SDK, embedded at build time

use anyhow::{anyhow, Context, Result};
use base64::Engine;
use ring::signature::{
    EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING,
};
use sha1::{Digest as Sha1Digest, Sha1};
use sha2::Sha256 as Sha256Hash;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;

const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const MAX_AUTH_JSON: usize = 4096;
const MAX_HEADER: usize = 16 * 1024;
const AUTH_TIMEOUT_MS: u64 = 10_000;
const MAX_WS_MESSAGE: usize = 2 * 1024 * 1024;

/// Concurrent connections sitting in the UNAUTHENTICATED window (WS upgrade
/// accepted, identity not yet proven). A browser or script reconnect storm
/// must not be able to hold unbounded server memory before proving who it
/// is, so admission to that window is capped; over-cap attempts get an
/// HTTP 503 and are dropped.
static UNAUTH_WS_CONNS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
/// Cap for [`UNAUTH_WS_CONNS`].
const MAX_UNAUTH_WS_CONNS: usize = 256;

/// One slot in the unauthenticated-connection cap. Acquired before the auth
/// exchange begins, released on drop — auth success, auth failure, and a
/// plain disconnect all release it, because all of them end this function.
struct UnauthSlot;

impl UnauthSlot {
    /// Increments the counter unless it is already at the cap (CAS loop: an
    /// over-cap attempt never increments at all, so the counter cannot drift
    /// upward under refusal storms).
    fn try_acquire() -> Option<UnauthSlot> {
        use std::sync::atomic::Ordering;
        let mut cur = UNAUTH_WS_CONNS.load(Ordering::Acquire);
        loop {
            if cur >= MAX_UNAUTH_WS_CONNS {
                return None;
            }
            match UNAUTH_WS_CONNS.compare_exchange_weak(
                cur,
                cur + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(UnauthSlot),
                Err(c) => cur = c,
            }
        }
    }
}

impl Drop for UnauthSlot {
    fn drop(&mut self) {
        UNAUTH_WS_CONNS.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

// ---------------- embedded browser SDK ----------------

/// The browser SDK served at `GET /sdk/ectun-browser.mjs`.
///
/// PROVENANCE: these bytes are the vendored browser SDK at
/// `browser/ectun-browser.mjs` in this repository (copied from the Node
/// reference repo), copied into `$OUT_DIR` by `build.rs` on every build and
/// served at the same path the Node server serves it at runtime.
///
/// When the SDK file is missing at build time (neither the vendored copy nor
/// the legacy sibling fallback), `build.rs` writes a small self-describing
/// placeholder instead (detected via
/// [`SDK_PLACEHOLDER_PREFIX`]) so this `include_bytes!` and the route always
/// stay well-defined.
static BROWSER_SDK: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/ectun-browser.mjs"));

/// First bytes of the placeholder build.rs writes when the real SDK is
/// absent (keep in sync with `PLACEHOLDER` in `build.rs`).
const SDK_PLACEHOLDER_PREFIX: &[u8] = b"// ectun-browser placeholder";

/// True when the embedded SDK bytes are the build-time placeholder rather
/// than the real module (used only to word the launcher-page note; the
/// placeholder is still served — it explains itself).
fn sdk_is_placeholder() -> bool {
    BROWSER_SDK.starts_with(SDK_PLACEHOLDER_PREFIX)
}

// ---------------- P-256 WS identity ----------------

/// Fixed DER prefix of a P-256 `SubjectPublicKeyInfo`: AlgorithmIdentifier
/// (id-ecPublicKey, prime256v1) + BIT STRING header. Every WebCrypto /
/// Node `exportKey('spki')` for P-256 produces exactly this prefix plus
/// the 65-byte uncompressed point.
const P256_SPKI_PREFIX: &[u8] = &[
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

/// Wraps a raw 65-byte uncompressed P-256 point in a SPKI DER blob — the
/// exact byte layout browsers produce via `crypto.subtle.exportKey('spki')`
/// and import back with `importKey('spki')` (ring deals in raw points, the
/// WebCrypto/Node world deals in SPKI DER; this is the bridge).
fn p256_spki_der(raw_point: &[u8]) -> Vec<u8> {
    debug_assert_eq!(raw_point.len(), 65, "uncompressed P-256 point");
    let mut spki = Vec::with_capacity(P256_SPKI_PREFIX.len() + raw_point.len());
    spki.extend_from_slice(P256_SPKI_PREFIX);
    spki.extend_from_slice(raw_point);
    spki
}

/// The server's P-256 WebSocket identity: used to sign the auth challenge
/// and to whitelist browser clients by fingerprint.
pub struct WsIdentity {
    /// Signing key pair.
    pub key_pair: Arc<EcdsaKeyPair>,
    /// Public key as DER SubjectPublicKeyInfo (as browsers expect it).
    pub public_key_spki: Vec<u8>,
    /// Canonical `sha256:<hex>` SPKI fingerprint.
    pub fingerprint: String,
    /// PKCS#8 DER encoding of the private key (for export).
    pub pkcs8: Vec<u8>,
}

impl WsIdentity {
    /// Generates a fresh P-256 identity.
    pub fn generate() -> Result<Self> {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|e| anyhow!("generate P-256 key: {e}"))?;
        let pkcs8_bytes = pkcs8.as_ref().to_vec();
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
                .map_err(|e| anyhow!("load P-256 key: {e}"))?;
        // ring exposes the raw uncompressed point; the wire format (and the
        // fingerprint basis Node uses) is SPKI DER — wrap it
        let public_key_spki = p256_spki_der(key_pair.public_key().as_ref());
        let fingerprint = fingerprint_of_spki(&public_key_spki);
        Ok(WsIdentity {
            key_pair: Arc::new(key_pair),
            public_key_spki,
            fingerprint,
            pkcs8: pkcs8_bytes,
        })
    }

    fn sign(&self, data: &[u8]) -> Vec<u8> {
        let rng = ring::rand::SystemRandom::new();
        self.key_pair
            .sign(&rng, data)
            .map(|s| s.as_ref().to_vec())
            .unwrap_or_default()
    }
}

/// Computes the canonical `sha256:<hex>` fingerprint of an SPKI DER blob.
pub fn fingerprint_of_spki(spki: &[u8]) -> String {
    let hash = Sha256Hash::digest(spki);
    format!("sha256:{}", hex::encode(hash))
}

/// Verifies a P-256 SHA-256 (fixed, ieee-p1363) signature over `data` with
/// a public key given either as SPKI DER (what browsers/WebCrypto send) or
/// as a raw 65-byte uncompressed point (ring's native form); both are
/// accepted so server-internal and wire-format keys verify identically.
pub fn verify_p256(spki: &[u8], signature: &[u8], data: &[u8]) -> bool {
    let key = if spki.len() == P256_SPKI_PREFIX.len() + 65 && spki.starts_with(P256_SPKI_PREFIX) {
        &spki[P256_SPKI_PREFIX.len()..]
    } else {
        spki // raw point (or garbage: ring will reject it)
    };
    let peer = ring::signature::UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, key);
    peer.verify(data, signature).is_ok()
}

// ---------------- auth transcript (v2 signature binding) ----------------

/// Domain-separation label prefixing the auth transcript.
const WS_AUTH_LABEL: &[u8] = b"ectun-ws-auth-v1";

/// The v1 signed message: the bare nonce concatenation.
///
/// This is byte-for-byte what the Node browser SDK signs and verifies today
/// (`browser/ectun-browser.mjs`: `concatBytes(nonceC, nonceS)`,
/// WebCrypto ECDSA P-256 / ieee-p1363) and what the Node server accepts
/// (`../ectun/lib/ws.mjs`: `createSign('sha256')` over `nonceC || nonceS`,
/// `dsaEncoding: 'ieee-p1363'`). Keep as a named helper because both sides
/// of the exchange use it: the server signs it in its challenge (v1
/// clients), and the dual-accept verifier falls back to it.
fn legacy_auth_message(nonce_c: &[u8], nonce_s: &[u8]) -> Vec<u8> {
    let mut data = Vec::with_capacity(nonce_c.len() + nonce_s.len());
    data.extend_from_slice(nonce_c);
    data.extend_from_slice(nonce_s);
    data
}

/// Computes the v2 auth transcript digest.
///
/// ```text
/// transcript = b"ectun-ws-auth-v1"
///     || u32be(client_spki.len())  || client_spki
///     || u32be(server_spki.len())  || server_spki
///     || u32be(client_nonce.len()) || client_nonce
///     || u32be(server_nonce.len()) || server_nonce
/// digest = SHA-256(transcript)
/// ```
///
/// The ECDSA sign/verify message is this 32-byte `digest` — NOT the raw
/// concatenation. ring's `ECDSA_P256_SHA256_FIXED_*` (like WebCrypto's
/// `subtle.sign({hash:'SHA-256'})` and Node's `createSign('sha256')`)
/// internally hashes whatever message it is given, so a signature "over the
/// digest" is produced by passing the digest as the message on every stack.
///
/// Why a v2 at all: the v1 message covers both fresh nonces (each handshake
/// is replay-safe) but binds NEITHER identity — the signatures do not
/// commit to the SPKIs involved. v2 signs the transcript above, binding
/// both identities and both nonces under a domain-separation label. The two
/// formats cannot be confused: their signed inputs differ in length (64 vs
/// 32 bytes) and the v2 domain is labeled, so a signature valid for one has
/// negligible probability of validating for the other.
fn ws_auth_transcript(
    client_spki: &[u8],
    server_spki: &[u8],
    client_nonce: &[u8],
    server_nonce: &[u8],
) -> [u8; 32] {
    let mut buf = Vec::with_capacity(
        WS_AUTH_LABEL.len()
            + 16
            + client_spki.len()
            + server_spki.len()
            + client_nonce.len()
            + server_nonce.len(),
    );
    buf.extend_from_slice(WS_AUTH_LABEL);
    for part in [client_spki, server_spki, client_nonce, server_nonce] {
        buf.extend_from_slice(&(part.len() as u32).to_be_bytes());
        buf.extend_from_slice(part);
    }
    Sha256Hash::digest(&buf).into()
}

/// Verifies a client auth signature: the v2 transcript digest first, then —
/// only for clients that did not explicitly claim `"v":2` — the legacy
/// `nonceC || nonceS` form the Node browser SDK signs today. A client that
/// declares v2 must use the transcript form (no silent downgrade for
/// versioned clients); a v1 client may use either (transcript signatures
/// are strictly stronger and always accepted).
fn verify_client_sig(
    client_spki: &[u8],
    server_spki: &[u8],
    nonce_c: &[u8],
    nonce_s: &[u8],
    sig: &[u8],
    msg_v: u64,
) -> bool {
    if verify_p256(
        client_spki,
        sig,
        &ws_auth_transcript(client_spki, server_spki, nonce_c, nonce_s),
    ) {
        return true;
    }
    if msg_v >= 2 {
        return false;
    }
    verify_p256(client_spki, sig, &legacy_auth_message(nonce_c, nonce_s))
}

// ---------------- HTTP parsing / handshake ----------------

/// A parsed HTTP request head, plus any bytes already read past it.
pub struct HttpHead {
    /// The request line, e.g. `GET / HTTP/1.1`.
    pub req_line: String,
    /// Headers as (lowercased name, value) pairs, in order.
    pub headers: Vec<(String, String)>,
    /// Bytes that followed the blank line.
    pub rest: Vec<u8>,
}

/// Parses a request head once its terminating blank line is present in `buf`.
pub fn parse_http_head(buf: &[u8]) -> Option<HttpHead> {
    let idx = buf.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = String::from_utf8_lossy(&buf[..idx]).to_string();
    let mut lines = head.split("\r\n");
    let req_line = lines.next()?.to_string();
    let mut headers = Vec::new();
    for l in lines {
        if let Some(c) = l.find(':') {
            headers.push((l[..c].trim().to_lowercase(), l[c + 1..].trim().to_string()));
        }
    }
    Some(HttpHead {
        req_line,
        headers,
        rest: buf[idx + 4..].to_vec(),
    })
}

/// Returns the first value of a header (names already lowercased).
pub fn header<'a>(head: &'a HttpHead, name: &str) -> Option<&'a str> {
    head.headers
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

/// Computes the `Sec-WebSocket-Accept` reply for a client key.
pub fn ws_accept_key(client_key: &str) -> String {
    let mut h = Sha1::new();
    h.update(client_key.as_bytes());
    h.update(WS_GUID.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(h.finalize())
}

// ---------------- WS frame codec ----------------

/// One decoded WebSocket frame (masking already removed).
#[derive(Debug)]
pub struct WsFrame {
    /// Opcode: 0x0 continuation, 0x1 text, 0x2 binary, 0x8 close, 0x9 ping.
    pub opcode: u8,
    /// True when the FIN bit is set.
    pub fin: bool,
    /// Unmasked payload bytes.
    pub payload: Vec<u8>,
}

/// Encodes one unmasked (server-to-client) frame.
pub fn ws_encode(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let len = payload.len();
    let mut out = Vec::with_capacity(len + 10);
    out.push(0x80 | (opcode & 0x0f));
    if len < 126 {
        out.push(len as u8);
    } else if len < 65536 {
        out.push(126);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(127);
        out.extend_from_slice(&(len as u64).to_be_bytes());
    }
    out.extend_from_slice(payload);
    out
}

/// Decodes as many complete frames as `buf` holds. Returns the frames, the
/// number of bytes consumed, and whether an oversized frame was seen.
pub fn ws_decode(buf: &[u8]) -> (Vec<WsFrame>, usize, bool) {
    let mut frames = Vec::new();
    let mut off = 0;
    while off + 2 <= buf.len() {
        let b0 = buf[off];
        let b1 = buf[off + 1];
        let opcode = b0 & 0x0f;
        let fin = (b0 & 0x80) != 0;
        let masked = (b1 & 0x80) != 0;
        let mut len = (b1 & 0x7f) as usize;
        let mut ptr = off + 2;
        if len == 126 {
            if ptr + 2 > buf.len() {
                break;
            }
            len = u16::from_be_bytes([buf[ptr], buf[ptr + 1]]) as usize;
            ptr += 2;
        } else if len == 127 {
            if ptr + 8 > buf.len() {
                break;
            }
            let mut b = [0u8; 8];
            b.copy_from_slice(&buf[ptr..ptr + 8]);
            len = u64::from_be_bytes(b) as usize;
            ptr += 8;
        }
        if len > MAX_WS_MESSAGE {
            return (frames, 0, true);
        }
        let mask_len = if masked { 4 } else { 0 };
        if ptr + mask_len + len > buf.len() {
            break;
        }
        let mut payload = buf[ptr + mask_len..ptr + mask_len + len].to_vec();
        if masked {
            let mask = &buf[ptr..ptr + 4];
            for (i, b) in payload.iter_mut().enumerate() {
                *b ^= mask[i & 3];
            }
        }
        frames.push(WsFrame {
            opcode,
            fin,
            payload,
        });
        off = ptr + mask_len + len;
    }
    (frames, off, false)
}

// ---------------- connection handler ----------------

/// Outcome of handling a certificate-less TLS connection whose first bytes
/// are HTTP — an explicit contract instead of sentinel duplex objects.
pub enum WsOutcome {
    /// A static page was served on the raw TLS stream; no session follows.
    Static,
    /// An authenticated WS bridge; feed this to MuxSession.
    Session(tokio::io::DuplexStream),
}

/// Handle a certificate-less TLS connection whose first bytes are HTTP.
/// After auth, bridges WS binary frames to a duplex pair for MuxSession.
pub async fn handle_http_or_ws(
    tls_stream: TlsStream<TcpStream>,
    ws_identity: &Arc<WsIdentity>,
    auth_mode: &str,
    fingerprints: &[String],
) -> Result<WsOutcome> {
    let (mut read_half, mut write_half) = tokio::io::split(tls_stream);
    let mut buf: Vec<u8> = Vec::new();

    // read headers
    loop {
        let mut chunk = [0u8; 4096];
        let n = read_half.read(&mut chunk).await.context("read headers")?;
        if n == 0 {
            anyhow::bail!("closed before headers");
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > MAX_HEADER {
            anyhow::bail!("header flood");
        }
        if parse_http_head(&buf).is_some() {
            break;
        }
    }

    let head = parse_http_head(&buf).ok_or_else(|| anyhow!("bad headers"))?;
    let upgrade = header(&head, "upgrade")
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);

    if !upgrade {
        serve_static(&mut write_half, &head.req_line, &ws_identity.fingerprint).await?;
        return Ok(WsOutcome::Static);
    }

    let key = header(&head, "sec-websocket-key")
        .ok_or_else(|| anyhow!("no ws key"))?
        .to_string();

    // admission control for the unauthenticated window (before the upgrade
    // completes, so the refusal is still plain HTTP)
    let _unauth_slot = match UnauthSlot::try_acquire() {
        Some(s) => s,
        None => {
            write_http(
                &mut write_half,
                "503 Service Unavailable",
                "text/plain",
                b"too many concurrent websocket auth attempts\n",
            )
            .await
            .ok();
            anyhow::bail!("unauthenticated ws connection cap reached");
        }
    };

    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
        ws_accept_key(&key),
    );
    write_half.write_all(response.as_bytes()).await?;
    write_half.flush().await?;

    // auth phase
    let mut rest = head.rest;
    auth_phase(
        &mut read_half,
        &mut write_half,
        &mut rest,
        ws_identity,
        auth_mode,
        fingerprints,
    )
    .await
    .map_err(|e| anyhow!("{e}"))?;

    // bridge: spawn two tasks connecting WS <-> duplex
    let (duplex_a, duplex_b) = tokio::io::duplex(64 * 1024);
    let (duplex_read, duplex_write) = tokio::io::split(duplex_a);

    // The TLS write half lives in the writer task below; the reader task is
    // the only side that sees incoming pings, so pongs cross this small
    // channel to be written by the task that owns the write half.
    let (pong_tx, pong_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(16);

    // ws -> cmpx: decode WS binary frames, push payload into duplex
    tokio::spawn(async move {
        let mut read = read_half;
        let mut dw = duplex_write;
        let mut buf = rest;
        let pong_tx = pong_tx;
        let mut fragment: Option<Vec<u8>> = None;
        loop {
            let (frames, consumed, oversize) = ws_decode(&buf);
            buf.drain(..consumed);
            if oversize {
                break;
            }
            let mut done = false;
            for f in frames {
                match f.opcode {
                    0x2 | 0x0 => {
                        // binary / continuation
                        let cur = match fragment.take() {
                            Some(prev) => {
                                let mut v = prev;
                                v.extend_from_slice(&f.payload);
                                v
                            }
                            None => f.payload.clone(),
                        };
                        // a client streaming endless non-FIN continuations
                        // must not grow the assembled message without bound
                        if cur.len() > MAX_WS_MESSAGE {
                            log::warn!("ws: assembled message exceeds cap; dropping connection");
                            done = true;
                            break;
                        }
                        if f.fin {
                            if dw.write_all(&cur).await.is_err() {
                                done = true;
                                break;
                            }
                        } else {
                            fragment = Some(cur);
                        }
                    }
                    0x8 => {
                        done = true;
                        break;
                    }
                    // mid-session ping (browsers normally don't, but proxies
                    // may forward one): hand the pong to the writer task.
                    // try_send so a full pong queue can never stall reads —
                    // a dropped pong is retried by the peer's ping timer.
                    0x9 => {
                        let _ = pong_tx.try_send(ws_encode(0xA, &f.payload));
                    }
                    _ => {} // 0xA pong and unknown opcodes: ignore
                }
            }
            if done {
                break;
            }
            let mut chunk = [0u8; 64 * 1024];
            match read.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
        let _ = dw.shutdown().await;
    });

    // cmpx -> ws: encode duplex reads as WS binary frames, and flush any
    // queued pong frames through the same write half
    tokio::spawn(async move {
        let mut dr = duplex_read;
        let mut w = write_half;
        let mut pongs = pong_rx;
        // false once the reader task is gone (its pong_tx dropped): the recv
        // arm must then disable itself or it would spin on a closed channel
        let mut pongs_open = true;
        let mut chunk = [0u8; 64 * 1024];
        loop {
            tokio::select! {
                frame = pongs.recv(), if pongs_open => {
                    match frame {
                        Some(frame) => {
                            if w.write_all(&frame).await.is_err() { break; }
                            let _ = w.flush().await;
                        }
                        None => pongs_open = false,
                    }
                }
                r = dr.read(&mut chunk) => {
                    match r {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            let frame = ws_encode(0x2, &chunk[..n]);
                            if w.write_all(&frame).await.is_err() { break; }
                            let _ = w.flush().await;
                        }
                    }
                }
            }
        }
        let _ = w.shutdown().await;
    });

    Ok(WsOutcome::Session(duplex_b))
}

async fn auth_phase(
    read_half: &mut (impl AsyncReadExt + Unpin + Send),
    write_half: &mut (impl AsyncWriteExt + Unpin + Send),
    rest: &mut Vec<u8>,
    ws_identity: &Arc<WsIdentity>,
    auth_mode: &str,
    fingerprints: &[String],
) -> Result<(), String> {
    let mut client_spki: Option<Vec<u8>> = None;
    let mut nonce_c: Option<Vec<u8>> = None;
    let mut nonce_s: Option<Vec<u8>> = None;

    let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(AUTH_TIMEOUT_MS);

    loop {
        let (frames, consumed, oversize) = ws_decode(rest);
        rest.drain(..consumed);
        // an oversized frame can never become valid: bail instead of letting
        // the buffer keep growing while the client streams the rest of it
        if oversize {
            return Err("oversized auth frame".into());
        }
        for f in frames {
            // tolerate control frames during auth: reply to pings on the
            // write half (an idle browser may ping while waiting on user
            // interaction), silently ignore unsolicited pongs — only text
            // frames carry the auth exchange itself
            if f.opcode == 0x9 {
                let pong = ws_encode(0xA, &f.payload);
                write_half
                    .write_all(&pong)
                    .await
                    .map_err(|e| e.to_string())?;
                write_half.flush().await.map_err(|e| e.to_string())?;
                continue;
            }
            if f.opcode == 0xA {
                continue;
            }
            if f.opcode != 0x1 {
                return Err("binary before auth".into());
            }
            if f.payload.len() > MAX_AUTH_JSON {
                return Err("auth too large".into());
            }
            let msg: serde_json::Value =
                serde_json::from_slice(&f.payload).map_err(|e| e.to_string())?;
            let t = msg["t"].as_str().unwrap_or("");

            if t == "init" {
                let spki = b64d(msg["spki"].as_str().unwrap_or(""));
                let nc = unhex(msg["nonce"].as_str().unwrap_or(""));
                if nc.len() != 32 {
                    return Err("bad nonce".into());
                }
                let fp = fingerprint_of_spki(&spki);
                if auth_mode != "open" && !fingerprints.contains(&fp) {
                    return Err("client fingerprint not whitelisted".into());
                }
                let mut ns = vec![0u8; 32];
                use ring::rand::SecureRandom;
                let _ = ring::rand::SystemRandom::new().fill(&mut ns);
                // protocol version: absent = 1 (what the Node browser SDK
                // speaks today — unknown "v" values are tolerated); 2 opts
                // into transcript-bound signatures
                let negotiated = if msg["v"].as_u64().unwrap_or(1) >= 2 {
                    2u64
                } else {
                    1u64
                };
                let sig_s = if negotiated >= 2 {
                    ws_identity.sign(&ws_auth_transcript(
                        &spki,
                        &ws_identity.public_key_spki,
                        &nc,
                        &ns,
                    ))
                } else {
                    // v1: Sign(nonceC||nonceS) — the exact bytes the Node
                    // browser SDK verifies for the server's challenge sig
                    ws_identity.sign(&legacy_auth_message(&nc, &ns))
                };
                let challenge = serde_json::json!({
                    "t": "challenge",
                    "v": negotiated,
                    "nonceS": hex::encode(&ns),
                    "sigS": b64e(&sig_s),
                    "spki": b64e(&ws_identity.public_key_spki),
                });
                let frame = ws_encode(0x1, challenge.to_string().as_bytes());
                write_half
                    .write_all(&frame)
                    .await
                    .map_err(|e| e.to_string())?;
                write_half.flush().await.map_err(|e| e.to_string())?;
                client_spki = Some(spki);
                nonce_c = Some(nc);
                nonce_s = Some(ns);
            } else if t == "response" {
                let (spki, nc, ns) = match (&client_spki, &nonce_c, &nonce_s) {
                    (Some(a), Some(b), Some(c)) => (a.clone(), b.clone(), c.clone()),
                    _ => return Err("protocol order".into()),
                };
                let sig_c = b64d(msg["sig"].as_str().unwrap_or(""));
                // dual-accept: transcript-bound (v2) first, then the legacy
                // nonceC||nonceS form — see verify_client_sig. A response
                // explicitly claiming "v":2 gets transcript-only.
                let msg_v = msg["v"].as_u64().unwrap_or(1);
                if !verify_client_sig(&spki, &ws_identity.public_key_spki, &nc, &ns, &sig_c, msg_v)
                {
                    return Err("bad signature".into());
                }
                let ok = serde_json::json!({"t": "ok"});
                let frame = ws_encode(0x1, ok.to_string().as_bytes());
                write_half
                    .write_all(&frame)
                    .await
                    .map_err(|e| e.to_string())?;
                write_half.flush().await.map_err(|e| e.to_string())?;
                return Ok(());
            } else {
                return Err("unknown message".into());
            }
        }

        // one deadline for the whole auth exchange (per-read timeouts would
        // only re-arm the same total budget)
        let mut chunk = [0u8; 4096];
        let n = tokio::time::timeout_at(deadline, read_half.read(&mut chunk))
            .await
            .map_err(|_| "auth timeout".to_string())?
            .map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("closed during auth".into());
        }
        rest.extend_from_slice(&chunk[..n]);
        // unauthenticated buffer stays small; growth beyond any plausible
        // auth exchange is an attack, not a slow client
        if rest.len() > MAX_WS_MESSAGE {
            return Err("auth buffer overflow".into());
        }
    }
}

fn b64d(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .unwrap_or_default()
}
fn b64e(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}
fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap_or_default()
}

// ---------------- static routes ----------------

async fn serve_static(
    write_half: &mut (impl AsyncWriteExt + Unpin),
    req_line: &str,
    ws_fingerprint: &str,
) -> Result<()> {
    let path = req_line.split(' ').nth(1).unwrap_or("/");
    let path = path.split('?').next().unwrap_or("/");
    if path == "/" {
        let body = launcher_page(ws_fingerprint);
        write_http(
            write_half,
            "200 OK",
            "text/html; charset=utf-8",
            body.as_bytes(),
        )
        .await?;
    } else if path == "/sdk/ectun-browser.mjs" {
        // the vendored browser SDK, embedded by build.rs (see BROWSER_SDK);
        // the placeholder self-describes
        write_http(
            write_half,
            "200 OK",
            "text/javascript; charset=utf-8",
            BROWSER_SDK,
        )
        .await?;
    } else {
        write_http(write_half, "404 Not Found", "text/plain", b"not found\n").await?;
    }
    write_half.shutdown().await?;
    Ok(())
}

async fn write_http(
    w: &mut (impl AsyncWriteExt + Unpin),
    status: &str,
    ct: &str,
    body: &[u8],
) -> Result<()> {
    let head = format!(
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: no-store\r\n\r\n",
        status,
        ct,
        body.len()
    );
    w.write_all(head.as_bytes()).await?;
    w.write_all(body).await?;
    w.flush().await?;
    Ok(())
}

fn launcher_page(ws_fp: &str) -> String {
    let sdk_note = if sdk_is_placeholder() {
        "The browser SDK was not found at build time (<code>browser/ectun-browser.mjs</code> is \
         missing from this repository): <code>/sdk/ectun-browser.mjs</code> currently serves a \
         placeholder. Restore that file and rebuild."
    } else {
        "The browser SDK is built into this binary: <code>/sdk/ectun-browser.mjs</code>"
    };
    format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>krymux (Rust)</title>
<style>body{{font:14px/1.6 system-ui,sans-serif;max-width:720px;margin:40px auto;padding:0 16px}}pre{{background:#f4f4f4;padding:12px;border-radius:4px;font-size:12px}}</style>
</head><body>
<h2>krymux browser access (Rust server)</h2>
<p>Browser WebSocket access is enabled on this server. Server WS fingerprint:</p>
<pre>{}</pre>
<p>{}</p>
</body></html>"#,
        ws_fp, sdk_note
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transcript_matches_spec_byte_for_byte() {
        let spki_c = [1u8; 91];
        let spki_s = [2u8; 91];
        let nc = [3u8; 32];
        let ns = [4u8; 32];
        // rebuild the spec'd encoding independently of the implementation
        let mut expected = Vec::new();
        expected.extend_from_slice(b"ectun-ws-auth-v1");
        for part in [&spki_c[..], &spki_s[..], &nc[..], &ns[..]] {
            expected.extend_from_slice(&(part.len() as u32).to_be_bytes());
            expected.extend_from_slice(part);
        }
        let digest: [u8; 32] = Sha256Hash::digest(&expected).into();
        assert_eq!(ws_auth_transcript(&spki_c, &spki_s, &nc, &ns), digest);
        // deterministic and order-sensitive (client/server swap differs)
        assert_eq!(
            ws_auth_transcript(&spki_c, &spki_s, &nc, &ns),
            ws_auth_transcript(&spki_c, &spki_s, &nc, &ns)
        );
        assert_ne!(ws_auth_transcript(&spki_s, &spki_c, &nc, &ns), digest);
        // any single field flipping changes the digest
        let mut nc2 = nc;
        nc2[0] ^= 0xff;
        assert_ne!(ws_auth_transcript(&spki_c, &spki_s, &nc2, &ns), digest);
    }

    #[test]
    fn client_sig_dual_accept_and_binding() {
        let client = WsIdentity::generate().unwrap();
        let server = WsIdentity::generate().unwrap();
        let other_server = WsIdentity::generate().unwrap();
        let nc = [5u8; 32];
        let ns = [6u8; 32];
        let check = |sig: &[u8], v: u64, srv: &WsIdentity| {
            verify_client_sig(
                &client.public_key_spki,
                &srv.public_key_spki,
                &nc,
                &ns,
                sig,
                v,
            )
        };

        // v1 legacy signer (the Node browser SDK's format: nonceC||nonceS)
        let legacy = client.sign(&legacy_auth_message(&nc, &ns));
        assert!(check(&legacy, 1, &server), "legacy accepted for v1");
        assert!(
            check(&legacy, 1, &other_server),
            "v1 does not bind server identity (documented)"
        );
        assert!(
            !check(&legacy, 2, &server),
            "explicit v2 must not fall back to legacy"
        );

        // v2 transcript signer
        let sig_t = client.sign(&ws_auth_transcript(
            &client.public_key_spki,
            &server.public_key_spki,
            &nc,
            &ns,
        ));
        assert!(check(&sig_t, 2, &server), "transcript accepted for v2");
        assert!(check(&sig_t, 1, &server), "transcript also accepted for v1");
        assert!(
            !check(&sig_t, 2, &other_server),
            "v2 binds the server identity"
        );

        // garbage never passes
        assert!(!check(&[0u8; 64], 1, &server));
        assert!(!check(&[0u8; 64], 2, &server));
    }

    #[test]
    fn embedded_sdk_present() {
        // build.rs guarantees OUT_DIR/ectun-browser.mjs always exists (real
        // file or placeholder), so the route always has a body to serve
        assert!(!BROWSER_SDK.is_empty());
    }

    #[test]
    fn identity_spki_is_browser_wire_format() {
        let id = WsIdentity::generate().unwrap();
        // exactly what WebCrypto/Node exportKey('spki') emits for P-256:
        // fixed 26-byte DER prefix + 65-byte uncompressed point
        assert_eq!(id.public_key_spki.len(), 91);
        assert!(id.public_key_spki.starts_with(P256_SPKI_PREFIX));
        assert_eq!(id.fingerprint, fingerprint_of_spki(&id.public_key_spki));
        // signature verifies through BOTH accepted key forms
        let msg = b"wire-format probe";
        let sig = id.sign(msg);
        assert!(verify_p256(&id.public_key_spki, &sig, msg), "SPKI DER form");
        assert!(
            verify_p256(id.key_pair.public_key().as_ref(), &sig, msg),
            "raw point form"
        );
        // junk keys fail closed
        assert!(!verify_p256(&[0u8; 91], &sig, msg));
    }
}
