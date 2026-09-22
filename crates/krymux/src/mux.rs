//! CMPX multiplexing session: many logical full-duplex streams over one
//! ordered encrypted byte stream. Wire-compatible with the Node reference
//! implementation.
//!
//! Tasks per session: socket reader (frame dispatch), socket writer (ordered
//! frame emission), per-stream inbound pump (decompress + deliver + credits),
//! per-stream outbound pump (compress + credit-gated framing), credit ticker,
//! keepalive. Ordering per stream is guaranteed by construction.

use crate::compress::{looks_precompressed, negotiate, parse_level, Compressor, Decompressor};
use crate::frame::*;
use anyhow::{anyhow, bail, Result};
use serde_json::json;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot, watch, Notify};
use tokio::time::{timeout, Duration};

type DuplexStream = tokio::io::DuplexStream;
type ReadHalf = tokio::io::ReadHalf<DuplexStream>;
type WriteHalf = tokio::io::WriteHalf<DuplexStream>;

const PROTOCOL_VERSION: u32 = 1;

const DEFAULT_WINDOW: u32 = 262_144;
const DUPLEX_BUF: usize = 64 * 1024;
const OPEN_ACK_TIMEOUT: Duration = Duration::from_secs(12);
const CREDIT_TICK: Duration = Duration::from_millis(5);
/// We advertise `frame::DEFAULT_MAX_DATA` as our per-frame receive cap; a peer
/// DATA frame larger than this is a protocol violation and gets a GOAWAY.
const OUR_MAX_DATA: usize = DEFAULT_MAX_DATA as usize;
/// Upper bound on one decompressed chunk: a crafted 64 KiB compressed frame
/// can expand ~1000:1, so expansion beyond this is treated as an attack.
const MAX_EXPANSION: usize = 32 * 1024 * 1024;
/// Backpressure for per-stream inbound delivery (bounded so a silent app
/// handler cannot grow memory without limit; the reader parks, TCP absorbs).
const INBOUND_QUEUE: usize = 128;

/// Temporary deep-trace for the truncation/stall hunt (KRYMUX_MUX_TRACE=1).
pub(crate) fn trace(args: std::fmt::Arguments<'_>) {
    if std::env::var_os("KRYMUX_MUX_TRACE").is_some() {
        eprintln!("[mux-trace] {}", args);
    }
}

/// Where a stream should end up, as requested by the opener.
#[derive(Clone, Debug)]
pub struct Target {
    /// Remote host (absent for unix-socket or port-only targets).
    pub host: Option<String>,
    /// Remote TCP port (0 when `unix` is set).
    pub port: u16,
    /// Unix domain socket path, when the target is a socket.
    pub unix: Option<String>,
    /// Routing hint, e.g. `"raw"` or a service name like `"sync"`.
    pub hint: String,
}

enum Inbound {
    /// wire payload + COMPRESSED flag
    Data(Vec<u8>, bool),
    Eof,
    Abort,
}

struct StreamInner {
    id: u32,
    inbound_tx: mpsc::Sender<Inbound>,
    credits: AtomicI64,
    credit_notify: Notify,
    pending_credit: AtomicU32,
    // dynamic window right-sizing state (receiver side)
    granted: AtomicU32,
    consumed_since_grow: AtomicU32,
    grow_at: std::sync::Mutex<std::time::Instant>,
    ack: Mutex<Option<oneshot::Sender<Result<String, String>>>>,
    ack_done: AtomicBool,
    compression: &'static str,
    requested_level: Option<i32>,
    // stream retirement state: a stream stays registered in `streams` until
    // the app handle is gone AND the outbound pump has finished, so WINDOW
    // credit grants keep reaching a pump that is still draining buffered
    // data (unregistering early parks it on credits forever — the stream
    // stalls and the peer sees a truncated transfer).
    app_gone: AtomicBool,
    out_done: AtomicBool,
}

/// Unregisters the stream once neither the app handle nor the outbound pump
/// needs it anymore. Caller must not hold the streams lock.
fn try_retire(shared: &Arc<Shared>, inner: &Arc<StreamInner>) {
    if !(inner.app_gone.load(Ordering::Acquire) && inner.out_done.load(Ordering::Acquire)) {
        return;
    }
    {
        // NOTE: one lock scope only — re-locking the same std Mutex here
        // self-deadlocks (non-reentrant).
        let mut m = shared.streams.lock().unwrap();
        if m.get(&inner.id).is_some_and(|x| Arc::ptr_eq(x, inner)) {
            m.remove(&inner.id);
        }
    }
    // the inbound pump may still be parked on recv(): end it now (FIFO —
    // after any already-queued data; its shutdown targets a dropped duplex
    // and is a harmless no-op).
    let _ = inner.inbound_tx.try_send(Inbound::Abort);
}

/// Tunables for one multiplexed session.
pub struct SessionOpts {
    /// True on the client side (odd stream ids), false on the server side.
    pub is_client: bool,
    /// Display name exchanged in HELLO.
    pub name: String,
    /// Initial per-stream receive window, in bytes.
    pub rx_window: u32,
    /// Upper bound the dynamic window may grow to.
    pub rx_window_max: u32,
    /// Maximum concurrent streams per session.
    pub max_streams: usize,
    /// Keepalive interval in seconds (0 disables).
    pub keepalive_sec: u64,
}

type StreamHandler = Arc<dyn Fn(TunnelStream, Target) + Send + Sync>;

/// State shared between the session handle, the socket tasks, and the
/// per-stream pumps.
pub struct Shared {
    is_client: bool,
    writer: mpsc::Sender<Vec<u8>>,
    streams: Mutex<HashMap<u32, Arc<StreamInner>>>,
    next_id: AtomicU32,
    peer_max_data: AtomicU32,
    peer_window: AtomicU32,
    peer_supported: Mutex<Vec<String>>,
    ready_tx: watch::Sender<bool>,
    ready_rx: watch::Receiver<bool>,
    closed: AtomicBool,
    max_streams: usize,
    rx_window: u32,
    rx_window_max: u32,
    our_supported: Vec<String>,
    on_stream: Mutex<Option<StreamHandler>>,
    pings: Mutex<HashMap<[u8; 16], oneshot::Sender<std::time::Instant>>>,
    last_pong_ms: AtomicU64,
}

/// A multiplexed session over one ordered byte stream.
pub struct MuxSession {
    shared: Arc<Shared>,
}

/// A logical full-duplex stream inside a session; implements `AsyncRead` and
/// `AsyncWrite` for use with any generic IO code.
pub struct TunnelStream {
    rd: ReadHalf,
    wr: Option<WriteHalf>,
    inner: Arc<StreamInner>,
    shared: Arc<Shared>,
    pub target: Target,
}

impl TunnelStream {
    /// The compression algorithm negotiated for this stream.
    pub fn compression(&self) -> &'static str {
        self.inner.compression
    }

    /// Current receive-window grant for this stream (dynamic right-sizing state).
    pub fn rx_granted(&self) -> u32 {
        self.inner.granted.load(Ordering::Acquire)
    }

    /// Shareable probe of rx_granted (readable while halves are split out).
    pub fn rx_granted_arc(self: &Arc<Self>) -> impl Fn() -> u32 + Send + Sync + 'static {
        let inner = Arc::clone(&self.inner);
        move || inner.granted.load(Ordering::Acquire)
    }

    /// Human-readable description of the stream's target.
    pub fn remote_address(&self) -> String {
        if let Some(u) = &self.target.unix {
            format!("unix:{}", u)
        } else {
            format!(
                "{}:{}",
                self.target.host.as_deref().unwrap_or(""),
                self.target.port
            )
        }
    }

    /// Server side: acknowledge the stream (sends OPEN_ACK ok).
    pub fn accept(&self, upstream: Option<&str>) {
        if self.inner.ack_done.swap(true, Ordering::AcqRel) {
            return;
        }
        let body =
            json!({ "ok": true, "compression": self.inner.compression, "upstream": upstream });
        let _ = send_control(
            &self.shared,
            FT_OPEN_ACK,
            self.inner.id,
            body.to_string().as_bytes(),
        );
    }

    /// Server side: reject the stream.
    pub fn reject(&self, code: &str, reason: &str) {
        if self.inner.ack_done.swap(true, Ordering::AcqRel) {
            return;
        }
        let body = json!({ "ok": false, "code": code, "reason": reason });
        let _ = send_control(
            &self.shared,
            FT_OPEN_ACK,
            self.inner.id,
            body.to_string().as_bytes(),
        );
        // surface as a closed inbound so any pump exits
        let _ = self.inner.inbound_tx.try_send(Inbound::Abort);
    }
}

impl Drop for TunnelStream {
    fn drop(&mut self) {
        trace(format_args!("TS  drop sid={}", self.inner.id));
        // App handle gone. Dropping the split halves also fully drops the
        // app-side duplex, so the outbound pump observes write-side EOF after
        // draining (its FIN still goes out). Do NOT unregister the stream
        // here: the outbound pump may still be draining buffered data and
        // needs WINDOW credits to reach it — retire only once it is done.
        self.inner.app_gone.store(true, Ordering::Release);
        try_retire(&self.shared, &self.inner);
    }
}

impl AsyncRead for TunnelStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let me = self.get_mut();
        std::pin::Pin::new(&mut me.rd).poll_read(cx, buf)
    }
}

impl AsyncWrite for TunnelStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.wr.as_mut() {
            Some(w) => std::pin::Pin::new(w).poll_write(cx, buf),
            None => std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "stream write side shut down",
            ))),
        }
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.wr.as_mut() {
            Some(w) => std::pin::Pin::new(w).poll_flush(cx),
            None => std::task::Poll::Ready(Ok(())),
        }
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // NOTE: merely dropping a split WriteHalf does NOT signal EOF (the shared
        // lock keeps the duplex alive) — we must actually shutdown the duplex,
        // which the outbound pump observes as EOF and turns into a FIN frame.
        match self.wr.as_mut() {
            Some(w) => std::pin::Pin::new(w).poll_shutdown(cx),
            None => std::task::Poll::Ready(Ok(())),
        }
    }
}

fn send_control(shared: &Arc<Shared>, ft: u8, sid: u32, payload: &[u8]) -> bool {
    if shared.closed.load(Ordering::Acquire) && ft != FT_GOAWAY {
        return true;
    }
    let frame = encode_frame(ft, 0, sid, payload);
    shared.writer.try_send(frame).is_ok() // control frames are tiny & rare
}

async fn wait_send(shared: &Arc<Shared>, frame: Vec<u8>) -> Result<()> {
    shared
        .writer
        .send(frame)
        .await
        .map_err(|_| anyhow!("session writer gone"))
}

impl MuxSession {
    /// Starts a session on `io`: sends HELLO, spawns the reader, writer,
    /// credit-ticker and keepalive tasks, and waits (up to 10 s) for the
    /// peer's HELLO. `on_stream` receives streams the peer opens (server
    /// side); the client passes `None`.
    pub async fn start<IO>(
        io: IO,
        opts: SessionOpts,
        on_stream: Option<StreamHandler>,
    ) -> Result<Arc<MuxSession>>
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (writer_tx, writer_rx) = mpsc::channel::<Vec<u8>>(1024);
        let (ready_tx, ready_rx) = watch::channel(false);
        let shared = Arc::new(Shared {
            is_client: opts.is_client,
            writer: writer_tx,
            streams: Mutex::new(HashMap::new()),
            next_id: AtomicU32::new(if opts.is_client { 1 } else { 2 }),
            peer_max_data: AtomicU32::new(DEFAULT_MAX_DATA),
            peer_window: AtomicU32::new(DEFAULT_WINDOW),
            peer_supported: Mutex::new(vec!["none".to_string()]),
            ready_tx,
            ready_rx,
            closed: AtomicBool::new(false),
            max_streams: opts.max_streams,
            rx_window: opts.rx_window,
            rx_window_max: opts.rx_window_max.max(opts.rx_window),
            our_supported: crate::compress::supported()
                .iter()
                .map(|s| s.to_string())
                .collect(),
            on_stream: Mutex::new(on_stream),
            pings: Mutex::new(HashMap::new()),
            last_pong_ms: AtomicU64::new(now_ms()),
        });

        // HELLO
        let hello = json!({
            "v": PROTOCOL_VERSION,
            "mode": if opts.is_client { "client" } else { "server" },
            "name": opts.name,
            "maxDataFrame": DEFAULT_MAX_DATA,
            "rxWindow": opts.rx_window,
            "maxStreams": opts.max_streams,
            "compression": shared.our_supported,
        });
        let _ = shared
            .writer
            .try_send(encode_frame(FT_HELLO, 0, 0, hello.to_string().as_bytes()));

        let (rd, wr) = tokio::io::split(io);
        let tasks = vec![
            tokio::spawn(writer_task(shared.clone(), writer_rx, wr)),
            tokio::spawn(reader_task(shared.clone(), rd)),
            tokio::spawn(credit_ticker(shared.clone())),
        ];
        let keepalive = if opts.keepalive_sec > 0 {
            Some(tokio::spawn(keepalive_task(
                shared.clone(),
                opts.keepalive_sec,
            )))
        } else {
            None
        };

        // wait for the peer HELLO
        let mut rx = shared.ready_rx.clone();
        let ok = timeout(Duration::from_secs(10), async move {
            loop {
                if *rx.borrow() {
                    return true;
                }
                if rx.changed().await.is_err() {
                    return false;
                }
            }
        })
        .await
        .unwrap_or(false);
        if !ok {
            // the session never came up: kill the socket tasks too, or a
            // silent peer parks the reader/writer (and the TLS socket) forever
            for t in tasks {
                t.abort();
            }
            if let Some(t) = keepalive {
                t.abort();
            }
            teardown(&shared);
            bail!("peer did not send HELLO");
        }
        Ok(Arc::new(MuxSession { shared }))
    }

    /// Opens a new stream toward `target` and waits for the peer's OPEN_ACK.
    /// `compression_req` selects the algorithm ("auto", "none", an algorithm
    /// name, or `algo:level`) and is negotiated down to what the peer supports.
    pub async fn open_stream(&self, target: Target, compression_req: &str) -> Result<TunnelStream> {
        let shared = &self.shared;
        if shared.closed.load(Ordering::Acquire) {
            bail!("session is gone");
        }
        let count = shared.streams.lock().unwrap().len();
        if count >= shared.max_streams {
            bail!("max streams reached ({})", shared.max_streams);
        }
        let sid = shared.next_id.fetch_add(2, Ordering::AcqRel);
        let ps = shared.peer_supported.lock().unwrap().clone();
        let peer_supported: Vec<&str> = ps.iter().map(|s| s.as_str()).collect();
        let algo = negotiate(compression_req, &peer_supported);

        let stream = build_stream(
            shared,
            sid,
            target.clone(),
            algo,
            parse_level(compression_req),
        )?;
        let (ack_tx, ack_rx) = oneshot::channel();
        *stream.inner.ack.lock().unwrap() = Some(ack_tx);

        shared
            .streams
            .lock()
            .unwrap()
            .insert(sid, stream.inner.clone());

        let open = json!({
            "host": target.host,
            "port": target.port,
            "unix": target.unix,
            "hint": target.hint,
            "meta": serde_json::Value::Null,
            "compression": algo,
        });
        wait_send(
            shared,
            encode_frame(FT_OPEN, 0, sid, open.to_string().as_bytes()),
        )
        .await?;

        match timeout(OPEN_ACK_TIMEOUT, ack_rx).await {
            Ok(Ok(Ok(upstream))) => {
                let _ = upstream;
                Ok(stream)
            }
            Ok(Ok(Err(reason))) => {
                shared.streams.lock().unwrap().remove(&sid);
                Err(anyhow!("open rejected: {}", reason))
            }
            Ok(Err(_)) => {
                shared.streams.lock().unwrap().remove(&sid);
                Err(anyhow!("session closed while opening"))
            }
            Err(_) => {
                shared.streams.lock().unwrap().remove(&sid);
                Err(anyhow!("open stream timeout"))
            }
        }
    }

    /// Tears the session down, telling the peer why via GOAWAY.
    pub fn close(&self, reason: &str) {
        if self.shared.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        let _ = send_control(
            &self.shared,
            FT_GOAWAY,
            0,
            json!({ "reason": reason }).to_string().as_bytes(),
        );
        teardown(&self.shared);
    }

    /// True once the session has been torn down (by either side).
    pub fn is_closed(&self) -> bool {
        self.shared.closed.load(Ordering::Acquire)
    }

    /// Resolve when the session ends (peer disconnect, GOAWAY, or close()).
    /// Connection holders should await this instead of parking forever.
    pub async fn wait_closed(&self) {
        let mut rx = self.shared.ready_rx.clone();
        loop {
            if !*rx.borrow() {
                return; // ready watch flips false on teardown
            }
            if rx.changed().await.is_err() {
                return;
            }
        }
    }

    /// Measures round-trip latency with a PING/PONG exchange.
    pub async fn ping(&self) -> Result<Duration> {
        let nonce: [u8; 16] = rand_bytes();
        let (tx, rx) = oneshot::channel();
        self.shared.pings.lock().unwrap().insert(nonce, tx);
        wait_send(&self.shared, encode_frame(FT_PING, 0, 0, &nonce)).await?;
        match timeout(OPEN_ACK_TIMEOUT, rx).await {
            // the pong handler sends back its arrival Instant
            Ok(Ok(t0)) => Ok(t0.elapsed()),
            Ok(Err(_)) => bail!("ping channel closed"),
            Err(_) => {
                self.shared.pings.lock().unwrap().remove(&nonce);
                bail!("ping timeout")
            }
        }
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn rand_bytes() -> [u8; 16] {
    use ring::rand::SecureRandom;
    let mut out = [0u8; 16];
    ring::rand::SystemRandom::new()
        .fill(&mut out)
        .expect("system rng");
    out
}

fn build_stream(
    shared: &Arc<Shared>,
    sid: u32,
    target: Target,
    algo: &'static str,
    level: Option<i32>,
) -> Result<TunnelStream> {
    let (app, session_side) = tokio::io::duplex(DUPLEX_BUF);
    let (session_rd, session_wr) = tokio::io::split(session_side);
    let (a_rd, a_wr) = tokio::io::split(app);
    // bounded: a stalled app handler parks the reader here instead of
    // growing memory; TCP backpressure does the rest
    let (inbound_tx, inbound_rx) = mpsc::channel(INBOUND_QUEUE);
    let inner = Arc::new(StreamInner {
        id: sid,
        inbound_tx,
        credits: AtomicI64::new(shared.peer_window.load(Ordering::Acquire) as i64),
        credit_notify: Notify::new(),
        pending_credit: AtomicU32::new(0),
        granted: AtomicU32::new(shared.rx_window),
        consumed_since_grow: AtomicU32::new(0),
        grow_at: std::sync::Mutex::new(std::time::Instant::now()),
        ack: Mutex::new(None),
        ack_done: AtomicBool::new(false),
        compression: algo,
        requested_level: level,
        app_gone: AtomicBool::new(false),
        out_done: AtomicBool::new(false),
    });

    tokio::spawn(inbound_pump(
        inbound_rx,
        session_wr,
        inner.clone(),
        shared.clone(),
    ));
    tokio::spawn(outbound_pump(session_rd, inner.clone(), shared.clone()));

    Ok(TunnelStream {
        rd: a_rd,
        wr: Some(a_wr),
        inner,
        shared: shared.clone(),
        target,
    })
}

// ---------------- per-stream pumps ----------------

async fn inbound_pump(
    mut rx: mpsc::Receiver<Inbound>,
    mut wr: WriteHalf,
    inner: Arc<StreamInner>,
    shared: Arc<Shared>,
) {
    let mut decomp = Decompressor::new(inner.compression);
    let threshold = (shared.rx_window / 4).max(16 * 1024);
    let mut delivered: usize = 0;
    // set once the app side is gone (its duplex dropped): the pump keeps
    // consuming and granting credits — so the peer can finish cleanly
    // instead of parking forever on a frozen window — but discards bytes.
    let mut discarding = false;
    trace(format_args!("IN  start sid={}", inner.id));
    while let Some(msg) = rx.recv().await {
        match msg {
            Inbound::Data(wire, compressed) => {
                let plain = if compressed {
                    match decomp.push(&wire) {
                        Ok(p) if p.len() <= MAX_EXPANSION => p,
                        Ok(p) => {
                            log::warn!(
                                "stream {}: decompressed chunk {} B exceeds expansion cap; aborting",
                                inner.id, p.len()
                            );
                            abort_stream(&shared, &inner);
                            break;
                        }
                        Err(e) => {
                            log::warn!("stream {}: decompress error: {e}; aborting", inner.id);
                            abort_stream(&shared, &inner);
                            break;
                        }
                    }
                } else {
                    wire
                };
                if !plain.is_empty() {
                    let _ = inner
                        .consumed_since_grow
                        .fetch_add(plain.len() as u32, Ordering::AcqRel);
                    if !discarding {
                        if let Err(e) = wr.write_all(&plain).await {
                            trace(format_args!(
                                "IN  app-gone sid={} delivered={} ({e:?}); draining+discarding",
                                inner.id, delivered
                            ));
                            log::debug!("stream {}: app side gone ({e:?}); draining", inner.id);
                            discarding = true;
                        } else {
                            delivered += plain.len();
                            let _ = wr.flush().await;
                        }
                    }
                    // credit accounting lives on the atomic so the session
                    // ticker can flush the sub-threshold tail; threshold sends
                    // go through the await path (never dropped). Send exactly
                    // what we drained: if the ticker raced in between, it
                    // already sent the total and drained is 0 — sending
                    // `max(drained, p)` would double-grant the same bytes.
                    let p = inner
                        .pending_credit
                        .fetch_add(plain.len() as u32, Ordering::AcqRel)
                        + plain.len() as u32;
                    if p >= threshold {
                        let drained = inner.pending_credit.swap(0, Ordering::AcqRel);
                        if drained > 0 {
                            send_window_await(&shared, &inner, drained).await;
                        }
                    }
                    maybe_grow_window(&shared, &inner).await;
                }
            }
            Inbound::Eof => {
                trace(format_args!(
                    "IN  eof sid={} delivered={}",
                    inner.id, delivered
                ));
                // drain any lazily-held decompressor output before EOF
                if let Ok(tail) = decomp.finish() {
                    if !tail.is_empty() {
                        let _ = wr.write_all(&tail).await;
                        let _ = wr.flush().await;
                        let p = inner
                            .pending_credit
                            .fetch_add(tail.len() as u32, Ordering::AcqRel)
                            + tail.len() as u32;
                        if p >= threshold {
                            let drained = inner.pending_credit.swap(0, Ordering::AcqRel);
                            if drained > 0 {
                                send_window_await(&shared, &inner, drained).await;
                            }
                        }
                    }
                }
                let _ = wr.shutdown().await;
                break;
            }
            Inbound::Abort => {
                trace(format_args!(
                    "IN  abort sid={} delivered={}",
                    inner.id, delivered
                ));
                let _ = wr.shutdown().await;
                break;
            }
        }
    }
    trace(format_args!(
        "IN  end sid={} delivered={}",
        inner.id, delivered
    ));
    // flush any sub-threshold credit tail; restore on drop so the peer's
    // send window never loses credit
    let drained = inner.pending_credit.swap(0, Ordering::AcqRel);
    if drained > 0 && !send_window(&shared, &inner, drained) {
        inner.pending_credit.fetch_add(drained, Ordering::AcqRel);
    }
}

/// Tell the peer this stream is aborting (as opposed to a clean FIN) so it
/// does not mistake truncated data for a normal end of stream.
fn abort_stream(shared: &Arc<Shared>, inner: &Arc<StreamInner>) {
    let _ = send_control(shared, FT_CLOSE, inner.id, b"{\"code\":\"abort\"}");
    let _ = inner.inbound_tx.try_send(Inbound::Abort);
}

/// Dynamic window right-sizing (receiver side): sustained consumption of at
/// least half the grant within a 100ms interval doubles the grant, capped at
/// rx_window_max. The inbound pump only accumulates consumption after the
/// bounded duplex accepts the data, so a backpressured app naturally stops
/// the accumulation — memory stays bounded without an explicit buffer check.
async fn maybe_grow_window(shared: &Arc<Shared>, inner: &Arc<StreamInner>) {
    let granted = inner.granted.load(Ordering::Acquire);
    if granted >= shared.rx_window_max {
        return;
    }
    let csg = inner.consumed_since_grow.fetch_add(0, Ordering::AcqRel);
    if csg < granted / 2 {
        return;
    }
    let bonus = {
        let mut grow_at = inner.grow_at.lock().unwrap();
        if grow_at.elapsed() < std::time::Duration::from_millis(100) {
            return;
        }
        let bonus = granted.min(shared.rx_window_max - granted);
        if bonus == 0 {
            return;
        }
        inner.granted.fetch_add(bonus, Ordering::AcqRel);
        inner.consumed_since_grow.store(0, Ordering::Release);
        *grow_at = std::time::Instant::now();
        bonus
    };
    send_window_await(shared, inner, bonus).await;
}

fn send_window(shared: &Arc<Shared>, inner: &Arc<StreamInner>, delta: u32) -> bool {
    let mut p = [0u8; 4];
    p.copy_from_slice(&delta.to_be_bytes());
    // returns false when the writer queue was full so callers can restore
    // the delta — a dropped credit is permanently lost to the peer
    send_control(shared, FT_WINDOW, inner.id, &p)
}

/// Credit frames MUST NOT be dropped: the peer's send window depends on them.
/// Used from async contexts that can wait for writer capacity.
async fn send_window_await(shared: &Arc<Shared>, inner: &Arc<StreamInner>, delta: u32) {
    let mut p = [0u8; 4];
    p.copy_from_slice(&delta.to_be_bytes());
    let frame = encode_frame(FT_WINDOW, 0, inner.id, &p);
    let _ = wait_send(shared, frame).await;
}

async fn outbound_pump(mut rd: ReadHalf, inner: Arc<StreamInner>, shared: Arc<Shared>) {
    let algo = inner.compression;
    let comp_level = inner.requested_level;
    let mut comp = Compressor::new(algo, comp_level.unwrap_or_else(|| default_level(algo)));
    let mut sniffed = false;
    // set when the first-chunk sniff switched `comp` to 'none': the frames
    // must then go out UNFLAGGED or the peer would feed raw pre-compressed
    // bytes to its decompressor and abort the stream
    let mut bypassed = false;
    let mut buf = vec![0u8; DUPLEX_BUF];
    let mut total_logical: usize = 0;
    let mut total_wire: usize = 0;
    let mut clean = true; // FIN only for a clean app-side EOF; errors abort
    trace(format_args!(
        "OUT start sid={} credits={}",
        inner.id,
        inner.credits.load(Ordering::Acquire)
    ));
    loop {
        let n = match rd.read(&mut buf).await {
            Ok(0) => {
                trace(format_args!(
                    "OUT read-eof sid={} logical={} wire={} credits={}",
                    inner.id,
                    total_logical,
                    total_wire,
                    inner.credits.load(Ordering::Acquire)
                ));
                break; // app closed write side -> FIN
            }
            Ok(n) => n,
            Err(e) => {
                log::warn!("stream {} outbound read error: {e:?}; aborting", inner.id);
                clean = false;
                break;
            }
        };
        if n == 0 {
            continue;
        }
        // first-chunk sniffing: pre-compressed payloads bypass compression
        if !sniffed {
            sniffed = true;
            if algo != crate::compress::ALGO_NONE && looks_precompressed(&buf[..n]) {
                comp = Compressor::new(crate::compress::ALGO_NONE, 0);
                bypassed = true;
                log::debug!(
                    "stream {} content sniffed as pre-compressed; bypassing",
                    inner.id
                );
            }
        }
        // FLAG_COMPRESSED must reflect what `comp` actually emits, not the
        // negotiated algorithm: a sniffed bypass sends raw bytes that the
        // receiver would otherwise try to decompress. Level/charging are
        // unaffected — credits are charged on logical bytes either way.
        let compressed = !bypassed && inner.compression != crate::compress::ALGO_NONE;
        let wire: Vec<u8> = if !compressed {
            // uncompressed stream: the Compressor's None path is a plain
            // copy of the input — skip it and frame straight from `buf`
            // (encode_frame below is then the only copy the chunk needs)
            Vec::new()
        } else {
            match comp.push(&buf[..n]) {
                Ok(w) => w,
                Err(e) => {
                    log::warn!("stream {}: compress error: {e}; aborting", inner.id);
                    clean = false;
                    break;
                }
            }
        };
        let wlen = if compressed { wire.len() } else { n };
        if wlen == 0 {
            continue;
        }
        total_logical += n;
        total_wire += wlen;
        let max_data = shared.peer_max_data.load(Ordering::Acquire) as usize;

        // fast path: the whole chunk fits one frame (the common case —
        // reads are DUPLEX_BUF-sized and the peer cap is 64 KiB). For a
        // compressed chunk the compressor's own buffer is reused as the
        // frame buffer: the header is spliced in front of it instead of
        // allocating and copying a second Vec.
        if wlen <= max_data {
            let mut ok = true;
            // charge first (a partial grant suffices), send, then charge the
            // remainder — the same interleave as the split loop below. The
            // receiver grants credits as its app consumes, so waiting for
            // the FULL logical charge before the first byte would deadlock
            // whenever the peer's window is smaller than one chunk.
            let mut charged = match acquire_credits(&shared, &inner, n).await {
                Ok(got) => got,
                Err(_) => {
                    trace(format_args!(
                        "OUT credit-fail sid={} logical={} credits={}",
                        inner.id,
                        total_logical,
                        inner.credits.load(Ordering::Acquire)
                    ));
                    ok = false;
                    0
                }
            };
            if ok {
                let flags = if compressed { FLAG_COMPRESSED } else { 0 };
                let frame = if compressed {
                    let mut f = wire;
                    f.splice(0..0, frame_header(FT_DATA, flags, inner.id, wlen as u32));
                    f
                } else {
                    encode_frame(FT_DATA, 0, inner.id, &buf[..n])
                };
                if let Err(e) = wait_send(&shared, frame).await {
                    log::warn!("stream {} frame send failed: {e}; aborting", inner.id);
                    ok = false;
                }
            }
            while ok && charged < n {
                match acquire_credits(&shared, &inner, n - charged).await {
                    Ok(got) => charged += got,
                    Err(_) => {
                        trace(format_args!(
                            "OUT credit-fail sid={} logical={} credits={}",
                            inner.id,
                            total_logical,
                            inner.credits.load(Ordering::Acquire)
                        ));
                        ok = false;
                    }
                }
            }
            if !ok {
                clean = false;
                break;
            }
            continue;
        }

        // slow path: chunk larger than one frame (peer cap below the read
        // size, or slight compression expansion) — split as before
        let wire_bytes: &[u8] = if compressed { &wire } else { &buf[..n] };
        let mut off = 0usize;
        let mut charged = 0usize;
        let mut ok = true;
        while off < wire_bytes.len() || charged < n {
            if charged < n {
                match acquire_credits(&shared, &inner, n - charged).await {
                    Ok(got) => charged += got,
                    Err(_) => {
                        trace(format_args!(
                            "OUT credit-fail sid={} logical={} credits={}",
                            inner.id,
                            total_logical,
                            inner.credits.load(Ordering::Acquire)
                        ));
                        ok = false;
                        break;
                    }
                }
            }
            if off < wire_bytes.len() {
                let take = max_data.min(wire_bytes.len() - off);
                let flags = if compressed { FLAG_COMPRESSED } else { 0 };
                let frame = encode_frame(FT_DATA, flags, inner.id, &wire_bytes[off..off + take]);
                if let Err(e) = wait_send(&shared, frame).await {
                    log::warn!("stream {} frame send failed: {e}; aborting", inner.id);
                    ok = false;
                    break;
                }
                off += take;
            }
        }
        if !ok {
            clean = false;
            break;
        }
    }
    trace(format_args!(
        "OUT done sid={} logical={} wire={} {} credits={}",
        inner.id,
        total_logical,
        total_wire,
        if clean { "fin" } else { "close" },
        inner.credits.load(Ordering::Acquire)
    ));
    log::debug!(
        "stream {} outbound done: logical={} wire={} {}",
        inner.id,
        total_logical,
        total_wire,
        if clean { "fin" } else { "close" }
    );
    if clean {
        let _ = wait_send(&shared, encode_frame(FT_DATA, FLAG_FIN, inner.id, &[])).await;
    } else {
        // an abort, never FIN: the peer must not read truncation as EOF
        let _ = wait_send(
            &shared,
            encode_frame(FT_CLOSE, 0, inner.id, b"{\"code\":\"abort\"}"),
        )
        .await;
    }
    // This pump is the last writer for the stream: retire the registration
    // (which also ends the inbound pump) once the app handle is gone too.
    // Until then WINDOW grants must keep reaching this map entry even while
    // the pump is still draining above.
    inner.out_done.store(true, Ordering::Release);
    try_retire(&shared, &inner);
}

fn default_level(algo: &str) -> i32 {
    match algo {
        crate::compress::ALGO_DEFLATE => 6,
        crate::compress::ALGO_BROTLI => 4,
        crate::compress::ALGO_ZSTD => 3,
        _ => 0,
    }
}

async fn acquire_credits(
    shared: &Arc<Shared>,
    inner: &Arc<StreamInner>,
    want: usize,
) -> Result<usize> {
    use std::pin::pin;
    // Notify-safe pattern: register interest BEFORE re-checking the counter,
    // so a wakeup racing between load() and await() cannot be lost.
    // Fails fast once the session is gone (teardown wakes all waiters).
    let mut notified = pin!(inner.credit_notify.notified());
    loop {
        notified.as_mut().enable();
        if shared.closed.load(Ordering::Acquire) {
            bail!("session closed while waiting for credits");
        }
        let c = inner.credits.load(Ordering::Acquire);
        if c > 0 {
            let take = ((c as usize).min(want)).clamp(1, c as usize);
            // single consumer decrements: plain fetch_sub is safe
            let _prev = inner.credits.fetch_sub(take as i64, Ordering::AcqRel);
            return Ok(take);
        }
        notified.as_mut().await;
    }
}

// ---------------- session tasks ----------------

async fn writer_task<IO: AsyncWrite + Unpin>(
    shared: Arc<Shared>,
    mut rx: mpsc::Receiver<Vec<u8>>,
    mut wr: tokio::io::WriteHalf<IO>,
) {
    // Coalesce bursts: after a recv, drain whatever else is already queued
    // (up to 15 more frames) into one contiguous buffer and issue a single
    // write — under frame-heavy load (bulk DATA + interleaved WINDOW/credit
    // frames) this cuts the per-frame write syscalls without adding latency
    // for the lone-frame case (try_recv is a non-blocking check; an empty
    // queue writes the frame directly, no extra copy).
    const MAX_BATCH_FRAMES: usize = 15;
    let mut batch: Vec<u8> = Vec::with_capacity(64 * 1024);
    loop {
        let Some(frame) = rx.recv().await else {
            trace(format_args!("WR  exit reason=channel-closed"));
            break;
        };
        // lone-frame fast path: nothing else queued — write it as-is
        let Ok(second) = rx.try_recv() else {
            if wr.write_all(&frame).await.is_err() {
                trace(format_args!("WR  exit reason=write-err"));
                break;
            }
            continue;
        };
        batch.clear();
        batch.extend_from_slice(&frame);
        batch.extend_from_slice(&second);
        let mut drained = 2usize;
        while drained <= MAX_BATCH_FRAMES {
            match rx.try_recv() {
                Ok(f) => {
                    batch.extend_from_slice(&f);
                    drained += 1;
                }
                Err(_) => break,
            }
        }
        if wr.write_all(&batch).await.is_err() {
            trace(format_args!("WR  exit reason=write-err"));
            break;
        }
        if shared.closed.load(Ordering::Acquire) {
            // teardown: flush whatever is already queued, then stop — the
            // socket write half must not outlive the session by parking on
            // this channel forever
            while let Ok(frame) = rx.try_recv() {
                if wr.write_all(&frame).await.is_err() {
                    break;
                }
            }
            break;
        }
    }
    trace(format_args!("WR  shutdown-socket"));
    let _ = wr.shutdown().await;
}

async fn reader_task<IO: AsyncRead + Unpin>(shared: Arc<Shared>, mut rd: tokio::io::ReadHalf<IO>) {
    let mut header = [0u8; HEADER_SIZE];
    loop {
        if rd.read_exact(&mut header).await.is_err() {
            trace(format_args!(
                "RD  exit sid=0 reason=read-exact-err closed={}",
                shared.closed.load(Ordering::Acquire)
            ));
            break;
        }
        let fh = match FrameHeader::parse(&header) {
            Ok(h) => h,
            Err(_) => {
                let _ = send_control(&shared, FT_GOAWAY, 0, b"{\"reason\":\"bad frame\"}");
                break;
            }
        };
        // DATA frames must honor the per-frame cap we advertised in HELLO
        let data_cap = if fh.frame_type == FT_DATA {
            OUR_MAX_DATA
        } else {
            usize::MAX
        };
        let cap = match fh.frame_type {
            FT_HELLO => MAX_HELLO,
            FT_OPEN => MAX_OPEN,
            FT_WINDOW => 4,
            FT_CLOSE => 1 + 256,
            FT_PING | FT_PONG => 64,
            FT_OPEN_ACK | FT_GOAWAY => MAX_CONTROL,
            FT_DATA => data_cap,
            _ => HARD_MAX_FRAME,
        };
        if fh.length as usize > cap {
            let _ = send_control(&shared, FT_GOAWAY, 0, b"{\"reason\":\"oversized frame\"}");
            break;
        }
        let mut payload = vec![0u8; fh.length as usize];
        if !payload.is_empty() && rd.read_exact(&mut payload).await.is_err() {
            break;
        }
        log::debug!(
            "mux rx type={} sid={} len={}",
            fh.frame_type,
            fh.stream_id,
            fh.length
        );
        if fh.frame_type != FT_DATA && fh.frame_type != FT_WINDOW {
            trace(format_args!(
                "RD  rx type={} sid={} len={}",
                fh.frame_type, fh.stream_id, fh.length
            ));
        }
        if let Err(e) = handle_frame(&shared, fh, payload).await {
            log::warn!("mux handle_frame error on type={}: {e:#}", fh.frame_type);
            break;
        }
    }
    if !shared.closed.swap(true, Ordering::AcqRel) {
        teardown(&shared);
    }
}

async fn handle_frame(shared: &Arc<Shared>, fh: FrameHeader, payload: Vec<u8>) -> Result<()> {
    // pre-HELLO enforcement
    if !*shared.ready_rx.borrow() && fh.frame_type != FT_HELLO {
        bail!("frame before HELLO");
    }
    match fh.frame_type {
        FT_HELLO => {
            if *shared.ready_rx.borrow() {
                bail!("second HELLO mid-session");
            }
            let hello: serde_json::Value =
                serde_json::from_slice(&payload).map_err(|_| anyhow!("bad HELLO json"))?;
            if hello["v"].as_u64() != Some(PROTOCOL_VERSION as u64) {
                bail!("unsupported protocol version");
            }
            // clamp peer-advertised tunables: u64→u32 truncation could turn
            // them into 0 (zero-sized frames / zero-credit deadlock)
            let clamp = |v: serde_json::Value, default: u32, lo: u32, hi: u32| -> u32 {
                v.as_u64()
                    .unwrap_or(default as u64)
                    .clamp(lo as u64, hi as u64) as u32
            };
            shared.peer_max_data.store(
                clamp(
                    hello
                        .get("maxDataFrame")
                        .cloned()
                        .unwrap_or(serde_json::json!(DEFAULT_MAX_DATA)),
                    DEFAULT_MAX_DATA,
                    1024,
                    HARD_MAX_FRAME as u32,
                ),
                Ordering::Release,
            );
            shared.peer_window.store(
                clamp(
                    hello
                        .get("rxWindow")
                        .cloned()
                        .unwrap_or(serde_json::json!(DEFAULT_WINDOW)),
                    DEFAULT_WINDOW,
                    16 * 1024,
                    256 * 1024 * 1024,
                ),
                Ordering::Release,
            );
            *shared.peer_supported.lock().unwrap() = hello["compression"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_else(|| vec!["none".to_string()]);
            let _ = shared.ready_tx.send(true);
            Ok(())
        }
        FT_OPEN => {
            if shared.is_client {
                bail!("client received OPEN");
            }
            if fh.stream_id == 0 || fh.stream_id.is_multiple_of(2) {
                bail!("bad stream id in OPEN: {}", fh.stream_id);
            }
            {
                let streams = shared.streams.lock().unwrap();
                if streams.len() >= shared.max_streams {
                    let body = json!({ "ok": false, "code": "maxstreams", "reason": format!("limit {}", shared.max_streams) });
                    let _ = send_control(
                        shared,
                        FT_OPEN_ACK,
                        fh.stream_id,
                        body.to_string().as_bytes(),
                    );
                    return Ok(());
                }
                // a duplicate id must not replace a live stream: it would
                // re-route mid-flight frames, bypass the stream limit, and
                // leak the old handler's tasks
                if streams.contains_key(&fh.stream_id) {
                    let body = json!({ "ok": false, "code": "duplicate", "reason": "stream id already open" });
                    let _ = send_control(
                        shared,
                        FT_OPEN_ACK,
                        fh.stream_id,
                        body.to_string().as_bytes(),
                    );
                    return Ok(());
                }
            }
            let v: serde_json::Value =
                serde_json::from_slice(&payload).map_err(|_| anyhow!("bad OPEN json"))?;
            let target = Target {
                host: v["host"].as_str().map(String::from),
                port: v["port"].as_u64().unwrap_or(0) as u16,
                unix: v["unix"].as_str().map(String::from),
                hint: v["hint"].as_str().unwrap_or("raw").to_string(),
            };
            let requested = v["compression"].as_str().unwrap_or("auto");
            let ps = shared.peer_supported.lock().unwrap().clone();
            let peer_supported: Vec<&str> = ps.iter().map(|s| s.as_str()).collect();
            let algo = negotiate(requested, &peer_supported);

            let handler = shared.on_stream.lock().unwrap().clone(); // clones the Arc
            let Some(handler) = handler else {
                let body = json!({ "ok": false, "code": "nohandler", "reason": "server has no stream handler" });
                let _ = send_control(
                    shared,
                    FT_OPEN_ACK,
                    fh.stream_id,
                    body.to_string().as_bytes(),
                );
                return Ok(());
            };
            match build_stream(
                shared,
                fh.stream_id,
                target.clone(),
                algo,
                parse_level(requested),
            ) {
                Ok(stream) => {
                    shared
                        .streams
                        .lock()
                        .unwrap()
                        .insert(fh.stream_id, stream.inner.clone());
                    // pre-ack inbound data must still flow: registered above
                    handler(stream, target);
                    Ok(())
                }
                Err(_) => {
                    let body =
                        json!({ "ok": false, "code": "internal", "reason": "build stream failed" });
                    let _ = send_control(
                        shared,
                        FT_OPEN_ACK,
                        fh.stream_id,
                        body.to_string().as_bytes(),
                    );
                    Ok(())
                }
            }
        }
        FT_OPEN_ACK => {
            let stream = shared.streams.lock().unwrap().get(&fh.stream_id).cloned();
            if let Some(inner) = stream {
                let v: serde_json::Value = serde_json::from_slice(&payload).unwrap_or(json!({}));
                if v["ok"].as_bool() == Some(true) {
                    inner.ack_done.store(true, Ordering::Release);
                    if let Some(tx) = inner.ack.lock().unwrap().take() {
                        let _ = tx.send(Ok(v["upstream"].as_str().unwrap_or("").to_string()));
                    }
                } else {
                    inner.ack_done.store(true, Ordering::Release);
                    let reason = format!(
                        "{} {}",
                        v["code"].as_str().unwrap_or("denied"),
                        v["reason"].as_str().unwrap_or("")
                    );
                    if let Some(tx) = inner.ack.lock().unwrap().take() {
                        let _ = tx.send(Err(reason));
                    }
                }
            }
            Ok(())
        }
        FT_DATA => {
            // clone under a scoped lock: the guard must not live across .await
            let inner = {
                let streams = shared.streams.lock().unwrap();
                streams.get(&fh.stream_id).cloned()
            };
            if inner.is_none() {
                trace(format_args!(
                    "HF  data for unknown sid={} len={}",
                    fh.stream_id, fh.length
                ));
            }
            if let Some(inner) = inner {
                let compressed = fh.flags & FLAG_COMPRESSED != 0;
                let fin = fh.flags & FLAG_FIN != 0;
                if !payload.is_empty() {
                    // bounded queue: parks the reader when the app is slow,
                    // which is the intended TCP-like backpressure. A closed
                    // queue means this one stream is already over (pump gone):
                    // drop the frame rather than tearing down the session.
                    if inner
                        .inbound_tx
                        .send(Inbound::Data(payload, compressed))
                        .await
                        .is_err()
                    {
                        trace(format_args!(
                            "HF  data dropped, stream {} pump gone",
                            fh.stream_id
                        ));
                        return Ok(());
                    }
                }
                if fin {
                    let _ = inner.inbound_tx.send(Inbound::Eof).await;
                }
            }
            Ok(())
        }
        FT_WINDOW => {
            if payload.len() != 4 {
                bail!("bad WINDOW frame length {}", payload.len());
            }
            let delta = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
            let target = shared.streams.lock().unwrap().get(&fh.stream_id).cloned();
            if target.is_none() {
                trace(format_args!(
                    "HF  WINDOW for unknown sid={} delta={}",
                    fh.stream_id, delta
                ));
            }
            if let Some(inner) = target {
                inner.credits.fetch_add(delta as i64, Ordering::AcqRel);
                inner.credit_notify.notify_waiters();
            }
            Ok(())
        }
        FT_CLOSE => {
            // code/reason are informational; any CLOSE aborts the stream
            if let Some(inner) = shared.streams.lock().unwrap().get(&fh.stream_id).cloned() {
                let _ = inner.inbound_tx.try_send(Inbound::Abort);
            }
            Ok(())
        }
        FT_PING => {
            let _ = send_control(shared, FT_PONG, 0, &payload);
            Ok(())
        }
        FT_PONG => {
            if payload.len() == 16 {
                let mut nonce = [0u8; 16];
                nonce.copy_from_slice(&payload);
                shared.last_pong_ms.store(now_ms(), Ordering::Release);
                if let Some(tx) = shared.pings.lock().unwrap().remove(&nonce) {
                    let _ = tx.send(std::time::Instant::now());
                }
            }
            Ok(())
        }
        FT_GOAWAY => {
            bail!("peer sent GOAWAY");
        }
        _ => bail!("unknown frame type"),
    }
}

async fn credit_ticker(shared: Arc<Shared>) {
    let mut tick = tokio::time::interval(CREDIT_TICK);
    loop {
        tick.tick().await;
        if shared.closed.load(Ordering::Acquire) {
            return;
        }
        let streams: Vec<Arc<StreamInner>> =
            shared.streams.lock().unwrap().values().cloned().collect();
        for inner in streams {
            let pending = inner.pending_credit.swap(0, Ordering::AcqRel);
            if pending > 0 && !send_window(&shared, &inner, pending) {
                // writer queue full: put the credit back, retry next tick
                inner.pending_credit.fetch_add(pending, Ordering::AcqRel);
            }
        }
    }
}

async fn keepalive_task(shared: Arc<Shared>, interval_sec: u64) {
    let mut tick = tokio::time::interval(Duration::from_secs(interval_sec.max(1)));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        if shared.closed.load(Ordering::Acquire) {
            return;
        }
        // liveness: a TCP-alive but stuck peer (partition, frozen handler)
        // never answers PINGs — tear the session down so reconnect logic
        // upstream gets a chance to run instead of parking forever
        let last = shared.last_pong_ms.load(Ordering::Acquire);
        let deadline = interval_sec.saturating_mul(3) * 1000;
        if now_ms().saturating_sub(last) > deadline {
            log::warn!(
                "keepalive: no PONG within {}s; closing session",
                interval_sec * 3
            );
            if !shared.closed.swap(true, Ordering::AcqRel) {
                let _ = send_control(&shared, FT_GOAWAY, 0, b"{\"reason\":\"keepalive timeout\"}");
                teardown(&shared);
            }
            return;
        }
        let nonce = rand_bytes();
        if wait_send(&shared, encode_frame(FT_PING, 0, 0, &nonce))
            .await
            .is_err()
        {
            return;
        }
        // stale outstanding ping entries are reclaimed by their own timeout
        shared.pings.lock().unwrap().retain(|_, tx| !tx.is_closed());
    }
}

fn teardown(shared: &Arc<Shared>) {
    trace(format_args!(
        "TEARDOWN closed={}",
        shared.closed.load(Ordering::Acquire)
    ));
    shared.closed.store(true, Ordering::Release);
    let streams: Vec<Arc<StreamInner>> = shared.streams.lock().unwrap().values().cloned().collect();
    shared.streams.lock().unwrap().clear();
    for inner in streams {
        let _ = inner.inbound_tx.try_send(Inbound::Abort);
        inner.credit_notify.notify_waiters(); // wake any pump waiting on credits
    }
    let _ = shared.ready_tx.send(false);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compress::ALGO_DEFLATE;
    use std::sync::Arc;

    /// Regression test for the pre-compressed bypass: when the first chunk
    /// sniffs as already-compressed, `comp` switches to 'none' — and the
    /// frames must then go out WITHOUT FLAG_COMPRESSED, or the receiving side
    /// feeds the raw bytes to its decompressor, errors, and aborts the stream
    /// (observed as a truncated/failed echo instead of the payload).
    #[tokio::test]
    async fn precompressed_bypass_roundtrips_without_abort() {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let opts = |is_client: bool| SessionOpts {
            is_client,
            name: if is_client { "c" } else { "s" }.into(),
            rx_window: 262_144,
            rx_window_max: 4_194_304,
            max_streams: 8,
            keepalive_sec: 0,
        };
        // single-threaded test runtime: run the server side as a task or both
        // HELLO waits deadlock on each other
        let server_task = tokio::spawn(async move {
            MuxSession::start(
                b,
                opts(false),
                Some(Arc::new(|stream: TunnelStream, _t: Target| {
                    tokio::spawn(async move {
                        stream.accept(Some("echo"));
                        let mut s = stream;
                        let mut buf = [0u8; 4096];
                        loop {
                            match s.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => {
                                    if s.write_all(&buf[..n]).await.is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                        let _ = s.shutdown().await;
                    });
                })),
            )
            .await
        });
        let client = MuxSession::start(a, opts(true), None)
            .await
            .expect("client session");
        let server = server_task
            .await
            .expect("join server task")
            .expect("server session");

        let mut s = client
            .open_stream(
                Target {
                    host: Some("echo".into()),
                    port: 1,
                    unix: None,
                    hint: "raw".into(),
                },
                "deflate",
            )
            .await
            .expect("open stream");
        assert_eq!(s.compression(), ALGO_DEFLATE);

        // gzip magic prefix + a chunky body: the first outbound read sniffs
        // as pre-compressed and must bypass the deflate encoder
        let mut payload = vec![0x1f, 0x8b, 0x08];
        for i in 0..50_000u32 {
            payload.push((i.wrapping_mul(2654435761) >> 13) as u8);
        }
        s.write_all(&payload).await.expect("send payload");
        s.shutdown().await.expect("eof");
        let mut got = Vec::new();
        s.read_to_end(&mut got)
            .await
            .expect("echo must not abort on raw pre-compressed bytes");
        assert_eq!(
            got, payload,
            "raw pre-compressed bytes must round-trip losslessly"
        );

        client.close("done");
        server.close("done");
    }
}
