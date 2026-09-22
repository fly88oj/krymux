// Sync engine: bidirectional file synchronization over krymux streams.

pub mod daemon;
pub mod notify;
pub mod protocol;
pub mod scanner;
pub mod tombstones;

use anyhow::{anyhow, Context, Result};
use protocol::*;
use scanner::*;
use sha1::{Digest, Sha1};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const VERSION: u32 = 1;

/// Join a client-supplied relative path under root, rejecting escapes.
/// Blocks `..`, absolute paths, drive letters, and NUL bytes.
fn safe_join(root: &Path, rel: &str) -> Result<PathBuf> {
    if rel.contains('\0') {
        return Err(anyhow!("NUL in path"));
    }
    for comp in rel.split(['/', '\\']) {
        if comp.is_empty() || comp == "." || comp == ".." || comp.contains(':') {
            return Err(anyhow!("unsafe path component in {rel:?}"));
        }
    }
    let full = root.join(rel);
    if !full.starts_with(root) {
        return Err(anyhow!("path escapes root: {rel:?}"));
    }
    Ok(full)
}

/// Per-file upload cap: a declared size beyond this (or an endless stream)
/// is refused instead of being streamed to disk until it fills.
const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024 * 1024;
/// Hard cap on the server file list we will collect, whatever the count says.
const MAX_SCAN_FILES: usize = 1_000_000;
/// Per-transfer unique staging name (still matches the `*.sync-tmp` skip and
/// cleanup suffixes): same-stem files must not collide across sessions.
fn unique_tmp(full: &std::path::Path) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let name = full
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    full.with_file_name(format!("{name}.{n}.sync-tmp"))
}

/// True when this relative path cannot be materialized on a Windows target
/// (invalid chars, reserved device names, trailing dot/space components).
/// Such files are skipped with a clear reason instead of failing every pass.
#[cfg(windows)]
fn unrepresentable_on_windows(rel: &str) -> bool {
    if rel
        .chars()
        .any(|c| matches!(c, '<' | '>' | ':' | '"' | '|' | '?' | '*'))
    {
        return true;
    }
    for comp in rel.split('/') {
        if comp.is_empty() || comp.ends_with('.') || comp.ends_with(' ') {
            return true;
        }
        // CON, PRN, AUX, NUL, COM1-9, LPT1-9 (with any extension)
        let stem = comp.split('.').next().unwrap_or("").to_uppercase();
        if matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
            || matches!(
                stem.as_str(),
                "COM1"
                    | "COM2"
                    | "COM3"
                    | "COM4"
                    | "COM5"
                    | "COM6"
                    | "COM7"
                    | "COM8"
                    | "COM9"
                    | "LPT1"
                    | "LPT2"
                    | "LPT3"
                    | "LPT4"
                    | "LPT5"
                    | "LPT6"
                    | "LPT7"
                    | "LPT8"
                    | "LPT9"
            )
        {
            return true;
        }
    }
    false
}

// ---------------- server-side session handler ----------------

/// An in-flight client→server upload, streamed to a temp file.
struct IncomingFile {
    rel: String,
    tmp: PathBuf,
    file: tokio::fs::File,
    hasher: Sha1,
    expected_size: u64,
    expected_hash: String,
    mtime_ms: f64,
    received: u64,
}

/// Serves the server side of one sync session: handshake, scan exchange,
/// file downloads, upload acceptance (size + hash verified, tmp + atomic
/// rename), and completion.
pub async fn handle_sync_server(
    stream: &mut (impl AsyncReadExt + AsyncWriteExt + Unpin + Send),
    root: &Path,
    mode: &str,
    hub: &std::sync::Arc<notify::NotifyHub>,
    mut parser: SyncParser,
    first_batch: Vec<SyncMessage>,
) -> Result<()> {
    // while this session lives, the hub suppresses watcher events so our own
    // upload writes don't echo back as rescan hints
    let _session = hub.active_guard();
    let mut buf = [0u8; 64 * 1024];
    let mut local_files: Option<Vec<FileEntry>> = None;
    let mut mode = mode.to_string();
    let mut incoming: Option<IncomingFile> = None;
    let mut messages = first_batch;

    // scan in background concept (we scan on first hello)
    loop {
        for msg in messages.drain(..) {
            match msg {
                SyncMessage::Json(m) => {
                    let t = m["t"].as_str().unwrap_or("");
                    match t {
                        T_HELLO => {
                            let client_version = m["version"].as_u64().unwrap_or(0) as u32;
                            if client_version != VERSION {
                                write_json(
                                    stream,
                                    &error_msg(&format!("version mismatch: {client_version}")),
                                )
                                .await?;
                                return Ok(());
                            }
                            if let Some(cm) = m["mode"].as_str() {
                                if mode == "bidir" {
                                    mode = cm.to_string();
                                }
                            }
                            let server_time = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap()
                                .as_millis() as u64;
                            write_json(stream, &hello_ack(server_time, &mode, VERSION)).await?;

                            // merge watcher-queued tombstones into the store
                            // BEFORE anything this pass reads it (see
                            // tombstones::queue for the crash-window tradeoff)
                            tombstones::flush(root);
                            log::info!("sync server: scanning local tree…");
                            let files = scan_and_hash(root, num_cpus()).await?;
                            log::info!("sync server: scan complete: {} files", files.len());
                            local_files = Some(files);
                            // our deletions are no longer embedded here — a
                            // large tombstone store exceeded the 8 MiB frame
                            // cap; they stream after the file list instead
                            // (see T_REQUEST_SCAN below)
                            write_json(stream, &scan_ready(local_files.as_ref().unwrap().len()))
                                .await?;
                        }
                        T_REQUEST_SCAN => {
                            let files = local_files
                                .as_ref()
                                .ok_or_else(|| anyhow!("scan not ready"))?;
                            let batch_size = 100;
                            for (i, chunk) in files.chunks(batch_size).enumerate() {
                                write_json(stream, &scan_batch(chunk, i * batch_size)).await?;
                            }
                            write_json(stream, &scan_end(files.len())).await?;
                            // tombstone transport: bounded batches after the
                            // file list, ALWAYS terminated by tombstone_end —
                            // even with zero entries, because its arrival is
                            // what marks us tombstone-aware to the client.
                            // 1000 entries per batch keeps every frame far
                            // below the 8 MiB message cap.
                            tombstones::flush(root);
                            let mut tombs = tombstones::load(root);
                            tombstones::prune(&mut tombs);
                            let total = tombs.len();
                            let mut batch: BTreeMap<String, u64> = BTreeMap::new();
                            for (p, ts) in &tombs {
                                batch.insert(p.clone(), *ts);
                                if batch.len() >= 1000 {
                                    write_json(stream, &tombstone_batch(&batch)).await?;
                                    batch.clear();
                                }
                            }
                            if !batch.is_empty() {
                                write_json(stream, &tombstone_batch(&batch)).await?;
                            }
                            write_json(stream, &tombstone_end(total)).await?;
                        }
                        T_GET_FILE => {
                            let path = m["path"].as_str().unwrap_or("");
                            match safe_join(root, path) {
                                Ok(full) => serve_file(stream, &full, path).await?,
                                Err(e) => {
                                    write_json(stream, &file_error(path, &e.to_string())).await?;
                                }
                            }
                        }
                        T_DELETE_FILE => {
                            let path = m["path"].as_str().unwrap_or("").to_string();
                            let ts = m["ts"].as_u64().unwrap_or(0);
                            if mode == "readonly" {
                                write_json(stream, &delete_ack(&path, false, "server is readonly"))
                                    .await?;
                                continue;
                            }
                            let full = match safe_join(root, &path) {
                                Ok(f) => f,
                                Err(e) => {
                                    write_json(stream, &delete_ack(&path, false, &e.to_string()))
                                        .await?;
                                    continue;
                                }
                            };
                            match tokio::fs::metadata(&full).await {
                                // already gone: idempotent success, and still
                                // record the deletion so other clients hear of it
                                Err(_) => {
                                    tombstones::record(root, &path);
                                    write_json(stream, &delete_ack(&path, true, "")).await?;
                                }
                                Ok(meta) if !meta.is_file() => {
                                    write_json(stream, &delete_ack(&path, false, "not a file"))
                                        .await?;
                                }
                                Ok(meta) => {
                                    let mtime_ms = meta
                                        .modified()
                                        .ok()
                                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                                        .map(|d| d.as_secs_f64() * 1000.0)
                                        .unwrap_or(0.0);
                                    if mtime_ms > ts as f64 {
                                        // last-writer protection: the server copy
                                        // changed after the client's deletion — keep
                                        // it; the client re-pulls on its next pass
                                        write_json(
                                            stream,
                                            &delete_ack(&path, false, "modified since delete"),
                                        )
                                        .await?;
                                    } else {
                                        match tokio::fs::remove_file(&full).await {
                                            Ok(()) => {
                                                tombstones::record(root, &path);
                                                log::info!("sync server: deleted {path}");
                                                write_json(stream, &delete_ack(&path, true, ""))
                                                    .await?;
                                            }
                                            Err(e) => {
                                                write_json(
                                                    stream,
                                                    &delete_ack(&path, false, &e.to_string()),
                                                )
                                                .await?;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        T_PUT_START => {
                            let path = m["path"].as_str().unwrap_or("");
                            if mode == "readonly" {
                                reject_put(stream, path, "server is readonly").await?;
                                continue;
                            }
                            let full = match safe_join(root, path) {
                                Ok(f) => f,
                                Err(e) => {
                                    reject_put(stream, path, &e.to_string()).await?;
                                    continue;
                                }
                            };
                            if is_file_locked(&full) {
                                reject_put(stream, path, "locked").await?;
                                continue;
                            }
                            let tmp = unique_tmp(&full);
                            let parent_ok = match tmp.parent() {
                                Some(p) => tokio::fs::create_dir_all(p).await.is_ok(),
                                None => false,
                            };
                            if !parent_ok {
                                reject_put(stream, path, "cannot create directory").await?;
                                continue;
                            }
                            let declared = m["size"].as_u64().unwrap_or(0);
                            if declared > MAX_FILE_BYTES {
                                reject_put(stream, path, "file too large").await?;
                                continue;
                            }
                            match tokio::fs::File::create(&tmp).await {
                                Ok(file) => {
                                    incoming = Some(IncomingFile {
                                        rel: path.to_string(),
                                        tmp,
                                        file,
                                        hasher: Sha1::new(),
                                        expected_size: declared,
                                        expected_hash: m["hash"].as_str().unwrap_or("").to_string(),
                                        mtime_ms: m["mtimeMs"].as_f64().unwrap_or(0.0),
                                        received: 0,
                                    });
                                }
                                Err(e) => {
                                    reject_put(stream, path, &format!("create tmp: {e}")).await?;
                                }
                            }
                        }
                        T_PUT_DONE => {
                            let inc = match incoming.take() {
                                Some(i) => i,
                                None => continue,
                            };
                            let mut ok = true;
                            let mut err = String::new();
                            if inc.received != inc.expected_size {
                                ok = false;
                                err = format!(
                                    "size mismatch: expected {}, got {}",
                                    inc.expected_size, inc.received
                                );
                            }
                            let got_hash = hex::encode(inc.hasher.finalize());
                            if ok && !inc.expected_hash.is_empty() && got_hash != inc.expected_hash
                            {
                                ok = false;
                                err = format!(
                                    "hash mismatch: expected {}, got {}",
                                    inc.expected_hash, got_hash
                                );
                            }
                            let mut f = inc.file;
                            if let Err(e) = f.flush().await {
                                ok = false;
                                err = format!("flush: {e}");
                            }
                            drop(f);
                            if ok {
                                let dest = match safe_join(root, &inc.rel) {
                                    Ok(d) => d,
                                    Err(e) => {
                                        let _ = tokio::fs::remove_file(&inc.tmp).await;
                                        write_json(
                                            stream,
                                            &put_ack(&inc.rel, false, &e.to_string()),
                                        )
                                        .await?;
                                        continue;
                                    }
                                };
                                // on Windows a concurrent reader (another client
                                // pulling this file) blocks the replace for the
                                // duration of its open handle — retry briefly
                                // before rejecting; the client retries either way
                                let mut renamed = false;
                                for _ in 0..5 {
                                    if tokio::fs::rename(&inc.tmp, &dest).await.is_ok() {
                                        renamed = true;
                                        break;
                                    }
                                    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
                                }
                                if renamed {
                                    let ft = filetime::FileTime::from_unix_time(
                                        (inc.mtime_ms / 1000.0) as i64,
                                        ((inc.mtime_ms % 1000.0) * 1_000_000.0) as u32,
                                    );
                                    let _ = filetime::set_file_times(&dest, ft, ft);
                                    log::info!(
                                        "sync server: uploaded {} ({} bytes)",
                                        inc.rel,
                                        inc.received
                                    );
                                } else {
                                    ok = false;
                                    err = "rename busy (held by a concurrent reader)".into();
                                }
                            }
                            if !ok {
                                let _ = tokio::fs::remove_file(&inc.tmp).await;
                                log::warn!("sync server: upload rejected {}: {err}", inc.rel);
                            }
                            write_json(stream, &put_ack(&inc.rel, ok, &err)).await?;
                        }
                        T_SYNC_COMPLETE => {
                            log::info!("sync server: sync complete");
                            return Ok(());
                        }
                        _ => {}
                    }
                }
                SyncMessage::Bin(data) => {
                    let mut failed = false;
                    if let Some(inc) = incoming.as_mut() {
                        inc.received += data.len() as u64;
                        if inc.received > MAX_FILE_BYTES {
                            failed = true;
                        } else if let Err(e) = inc.file.write_all(&data).await {
                            failed = true;
                            log::warn!("sync server: write chunk failed: {e}");
                        } else {
                            inc.hasher.update(&data);
                            if inc.received > inc.expected_size {
                                failed = true;
                            }
                        }
                    }
                    if failed {
                        if let Some(inc) = incoming.take() {
                            let _ = tokio::fs::remove_file(&inc.tmp).await;
                            write_json(stream, &put_ack(&inc.rel, false, "aborted mid-transfer"))
                                .await?;
                        }
                    }
                }
            }
        }
        let n = stream.read(&mut buf).await.context("sync server read")?;
        if n == 0 {
            return Ok(());
        }
        messages = parser.push(&buf[..n])?;
    }
}

/// Long-lived notify session: the client asked to be told when server files
/// change, so it can rescan immediately instead of waiting out its interval.
pub async fn handle_notify_session(
    stream: &mut (impl AsyncReadExt + AsyncWriteExt + Unpin + Send),
    hub: &std::sync::Arc<notify::NotifyHub>,
) -> Result<()> {
    let mut rx = hub.subscribe();
    write_json(stream, &notify_ack()).await?;
    log::info!("sync server: notify listener attached");
    let mut buf = [0u8; 1024];
    loop {
        tokio::select! {
            fired = rx.recv() => {
                match fired {
                    Ok(()) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        write_json(stream, &rescan_hint()).await?;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return Ok(()),
                }
            }
            n = stream.read(&mut buf) => {
                // the client only keeps this stream open; data means ping/ignore
                if n? == 0 {
                    log::info!("sync server: notify listener detached");
                    return Ok(());
                }
            }
        }
    }
}

async fn reject_put(
    stream: &mut (impl AsyncWriteExt + Unpin),
    path: &str,
    err: &str,
) -> Result<()> {
    write_json(stream, &put_ack(path, false, err)).await
}

async fn serve_file(
    stream: &mut (impl AsyncWriteExt + Unpin),
    full: &Path,
    path: &str,
) -> Result<()> {
    if !full.is_file() {
        write_json(stream, &file_error(path, "not found")).await?;
        return Ok(());
    }
    if is_file_locked(full) {
        write_json(stream, &file_error(path, "locked")).await?;
        return Ok(());
    }

    // open once: hash and content come from the same handle, so a concurrent
    // replace of the path can never tear the stream against its declared hash
    let mut file = tokio::fs::File::open(full).await?;
    let meta = file.metadata().await?;
    let size = meta.len();
    let mtime_ms = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs_f64() * 1000.0)
        .unwrap_or(0.0);

    let mut hasher = Sha1::new();
    let mut hbuf = vec![0u8; 512 * 1024];
    loop {
        let n = file.read(&mut hbuf).await?;
        if n == 0 {
            break;
        }
        hasher.update(&hbuf[..n]);
    }
    let hash = hex::encode(hasher.finalize());

    write_json(stream, &file_meta(path, size, &hash, mtime_ms)).await?;

    use tokio::io::AsyncSeekExt;
    file.seek(std::io::SeekFrom::Start(0)).await?;

    // stream file content from the same handle
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        write_bin(stream, &buf[..n]).await?;
    }
    stream.flush().await?;
    write_json(stream, &file_done(path)).await?;
    Ok(())
}

fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .min(16)
}

// ---------------- client-side sync engine ----------------

/// Outcome counters of one client-side sync pass.
///
/// The per-side file counts and the clock offset are diagnostic state kept
/// for parity with the engine's logging; the pass summary reads only the
/// other counters, hence the allow.
#[allow(dead_code)]
#[derive(Debug)]
pub struct SyncStats {
    /// Files pulled from the server.
    pub downloaded: usize,
    /// Files pushed to the server.
    pub uploads: usize,
    /// Files changed on both sides with no mtime winner (left untouched).
    pub conflicts: usize,
    /// Files skipped because another process holds them locked.
    pub locked_skipped: usize,
    /// Files the server reported in its scan.
    pub server_files: usize,
    /// Files found in the local scan.
    pub client_files: usize,
    /// `serverTime - clientTime` measured at handshake, in milliseconds.
    pub time_offset_ms: f64,
}

/// Drives the client side of one sync pass: handshake, scan exchange, diff
/// (last-writer-wins by mtime with conflict detection), downloads, then
/// uploads. Returns the pass statistics.
pub async fn run_sync_client(
    stream: &mut (impl AsyncReadExt + AsyncWriteExt + Unpin + Send),
    root: &Path,
    mode: &str,
) -> Result<SyncStats> {
    let mut parser = SyncParser::new();
    let mut buf = [0u8; 64 * 1024];

    // message collection state
    let mut messages: Vec<SyncMessage> = Vec::new();

    // helper: read until we have at least one message, return it
    async fn next_message(
        stream: &mut (impl AsyncReadExt + Unpin),
        parser: &mut SyncParser,
        messages: &mut Vec<SyncMessage>,
        buf: &mut [u8],
    ) -> Result<SyncMessage> {
        loop {
            if let Some(m) = messages.pop() {
                return Ok(m);
            }
            // idle timeout: TCP keepalive only proves transport liveness, so a
            // frozen peer that never sends file_done/put_ack/scan_end would
            // otherwise park this pass forever with no reconnect trigger
            let n = tokio::time::timeout(Duration::from_secs(60), stream.read(buf))
                .await
                .map_err(|_| anyhow!("peer stalled: no sync data for 60s"))?
                .context("sync client read")?;
            if n == 0 {
                return Err(anyhow!("stream closed"));
            }
            let new = parser.push(&buf[..n])?;
            for msg in new.into_iter().rev() {
                messages.push(msg);
            }
        }
    }

    // helper: extract JSON from message
    fn as_json(m: &SyncMessage) -> Result<serde_json::Value> {
        match m {
            SyncMessage::Json(v) => Ok(v.clone()),
            SyncMessage::Bin(_) => Err(anyhow!("expected JSON, got binary")),
        }
    }

    // helper: read messages until a put_ack arrives (skipping anything else)
    async fn wait_put_ack(
        stream: &mut (impl AsyncReadExt + Unpin),
        parser: &mut SyncParser,
        messages: &mut Vec<SyncMessage>,
        buf: &mut [u8],
    ) -> Result<Option<serde_json::Value>> {
        loop {
            let msg = next_message(stream, parser, messages, buf).await?;
            if let SyncMessage::Json(m) = &msg {
                if m["t"] == T_PUT_ACK {
                    return Ok(Some(m.clone()));
                }
            }
        }
    }

    // ---- handshake ----
    log::info!("sync client: connecting…");
    write_json(stream, &hello(VERSION, mode)).await?;
    let msg = next_message(stream, &mut parser, &mut messages, &mut buf).await?;
    let ack = as_json(&msg)?;
    if ack["t"] != T_HELLO_ACK {
        return Err(anyhow!("unexpected handshake response: {}", ack["t"]));
    }

    let server_time = ack["serverTime"].as_u64().unwrap_or(0) as f64;
    let client_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as f64;
    let time_offset_ms = server_time - client_time;
    log::info!("sync client: clock offset {time_offset_ms:.0}ms");
    // the server may negotiate a stricter mode than we asked for (e.g. readonly)
    let mode = ack["mode"].as_str().unwrap_or(mode).to_string();

    // ---- wait for server scan ----
    let msg = next_message(stream, &mut parser, &mut messages, &mut buf).await?;
    let scan_ready = as_json(&msg)?;
    if scan_ready["t"] != T_SCAN_READY {
        return Err(anyhow!("expected scan_ready, got {}", scan_ready["t"]));
    }
    // tombstone transport: batched servers stream tombstone_batch frames
    // after the scan and always finish with tombstone_end (whose arrival
    // marks them tombstone-aware). Servers that predate batching embed the
    // whole map in scan_ready instead — read that legacy shape inline; and
    // pre-tombstone servers do neither, behaving exactly as before.
    let mut server_tombs: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    let mut server_knows_tombstones = false;
    if let Some(entries) = scan_ready.get("tombstones").and_then(|t| t.as_object()) {
        for (p, v) in entries {
            if let Some(ms) = v.as_u64() {
                server_tombs.insert(p.clone(), ms);
            }
        }
        server_knows_tombstones = true; // legacy inline form
    }
    // the `true` marker (not an object) positively promises a tombstone_end
    // will follow — only then does the collect loop below wait for it
    let await_tombstone_end = matches!(scan_ready.get("tombstones"), Some(v) if !v.is_object());
    let server_count = scan_ready["count"].as_u64().unwrap_or(0);
    if server_count > MAX_SCAN_FILES as u64 {
        return Err(anyhow!("server file list exceeds cap ({MAX_SCAN_FILES})"));
    }
    log::info!("sync client: server has {server_count} files");

    // ---- request scan ----
    write_json(stream, &request_scan()).await?;
    let mut server_files: Vec<FileEntry> = Vec::new();
    // collect both terminators in one loop: tombstone_end normally arrives
    // after scan_end, but tolerate either order; a stalled peer is caught
    // by the 60s idle timeout inside next_message
    let mut scan_done = false;
    let mut tombs_done = !await_tombstone_end;
    loop {
        let msg = next_message(stream, &mut parser, &mut messages, &mut buf).await?;
        let m = as_json(&msg)?;
        match m["t"].as_str().unwrap_or("") {
            T_SCAN_BATCH => {
                if let Some(files) = m["files"].as_array() {
                    for f in files {
                        // bail INSIDE the arm: an oversized list must fail the
                        // pass immediately instead of after buffering it all
                        if server_files.len() >= MAX_SCAN_FILES {
                            return Err(anyhow!("server file list exceeds cap ({MAX_SCAN_FILES})"));
                        }
                        if let Ok(entry) = serde_json::from_value(f.clone()) {
                            server_files.push(entry);
                        }
                    }
                }
            }
            T_SCAN_END => scan_done = true,
            T_TOMBSTONE_BATCH => {
                if let Some(entries) = m.get("entries").and_then(|e| e.as_object()) {
                    for (p, v) in entries {
                        if let Some(ms) = v.as_u64() {
                            server_tombs.insert(p.clone(), ms);
                        }
                        // endless batches from a misbehaving server must not
                        // grow memory without bound while we wait for the end
                        if server_tombs.len() > MAX_SCAN_FILES {
                            return Err(anyhow!("server tombstone list exceeds cap"));
                        }
                    }
                }
            }
            T_TOMBSTONE_END => {
                tombs_done = true;
                // its arrival is what marks a batched server tombstone-aware
                server_knows_tombstones = true;
            }
            _ => {}
        }
        if scan_done && tombs_done {
            break;
        }
    }

    // ---- local scan ----
    log::info!("sync client: scanning local tree…");
    let client_files = scan_and_hash(root, num_cpus()).await?;
    log::info!("sync client: client has {} files", client_files.len());

    // our own remembered deletions, pruned of anything too old to matter.
    // Flush first: this merges anything the local watcher queued since the
    // pass began into the store in one write (see tombstones::queue).
    tombstones::flush(root);
    let mut local_tombs = tombstones::load(root);
    tombstones::prune(&mut local_tombs);

    // ---- diff ----
    // paths that collide case-insensitively cannot both be materialized on a
    // case-insensitive client (Windows/macOS): warn everywhere, and on such
    // platforms skip the colliding extras instead of download-replace flapping
    let mut seen_lc = std::collections::HashSet::new();
    let mut case_collisions: std::collections::HashSet<String> = std::collections::HashSet::new();
    for f in &server_files {
        if !seen_lc.insert(f.path.to_lowercase()) {
            log::warn!(
                "sync client: case collision (not representable case-insensitively): {}",
                f.path
            );
            case_collisions.insert(f.path.clone());
        }
    }

    let server_map: std::collections::HashMap<String, &FileEntry> =
        server_files.iter().map(|f| (f.path.clone(), f)).collect();
    let client_map: std::collections::HashMap<String, &FileEntry> =
        client_files.iter().map(|f| (f.path.clone(), f)).collect();

    let representable = |p: &str| -> bool {
        if case_collisions.contains(p) && cfg!(windows) {
            return false;
        }
        #[cfg(windows)]
        if unrepresentable_on_windows(p) {
            log::warn!("sync client: path not representable on Windows, skipping: {p}");
            return false;
        }
        true
    };

    let mut downloads: Vec<&FileEntry> = Vec::new();
    let mut uploads: Vec<&FileEntry> = Vec::new();
    // deletions to apply: (path, our tombstone ts) on the server, plain paths locally
    let mut server_deletes: Vec<(String, u64)> = Vec::new();
    let mut local_deletes: Vec<String> = Vec::new();
    let mut conflicts = 0;

    for sf in &server_files {
        // an unreadable server file (locked mid-scan) is undecidable — acting
        // on a missing hash would misclassify it; leave it for a later pass
        let Some(sh) = sf.hash.as_deref() else {
            log::debug!("sync client: skip {} (unreadable on server)", sf.path);
            continue;
        };
        match client_map.get(&sf.path) {
            None => {
                // absent locally: a tombstone newer than the server copy means
                // WE deleted it — propagate the deletion instead of re-downloading.
                // Clock skew: our tombstone ts is client-clock while the server
                // entry's mtime is server-clock, so compare in ONE clock (the
                // offset-adjusted server mtime).
                if server_knows_tombstones && mode != "readonly" {
                    if let Some(ts) = local_tombs.get(&sf.path) {
                        if *ts as f64 > sf.mtime_ms - time_offset_ms {
                            server_deletes.push((sf.path.clone(), *ts));
                            continue;
                        }
                    }
                }
                downloads.push(sf);
            }
            Some(cf) => {
                // same for the local side: a locked file hashed to None must
                // not be pushed, pulled, or branded a conflict
                let Some(ch) = cf.hash.as_deref() else {
                    log::debug!(
                        "sync client: skip {} (unreadable locally — locked?)",
                        sf.path
                    );
                    continue;
                };
                if sh != ch {
                    let server_mtime_adj = sf.mtime_ms - time_offset_ms;
                    if mode == "readonly" || server_mtime_adj > cf.mtime_ms + 1.0 {
                        downloads.push(sf);
                    } else if cf.mtime_ms > server_mtime_adj + 1.0 {
                        if cf.hash.is_some() {
                            uploads.push(cf);
                        }
                    } else {
                        conflicts += 1;
                        log::warn!(
                            "sync client: conflict: {} (server: {sh:.8} client: {ch:.8})",
                            sf.path
                        );
                    }
                }
            }
        }
    }

    if mode != "readonly" {
        for cf in &client_files {
            if server_map.contains_key(&cf.path) {
                continue;
            }
            // the server deleted it after our copy's mtime → remove ours too,
            // else (never-had-there or re-created) upload. Clock skew: the
            // server tombstone ts is server-clock while our file mtime is
            // client-clock, so shift the ts into our clock before comparing.
            if let Some(sts) = server_tombs.get(&cf.path) {
                if *sts as f64 - time_offset_ms > cf.mtime_ms {
                    local_deletes.push(cf.path.clone());
                    continue;
                }
            }
            if cf.hash.is_some() {
                uploads.push(cf);
            }
        }
    }

    log::info!(
        "plan: {} download, {} upload, {} local-delete, {} server-delete, {conflicts} conflict",
        downloads.len(),
        uploads.len(),
        local_deletes.len(),
        server_deletes.len()
    );

    // drop transfers that cannot land on this platform (case collisions,
    // Windows-unrepresentable names) before doing any work
    let downloads: Vec<&FileEntry> = downloads
        .into_iter()
        .filter(|f| representable(&f.path))
        .collect();
    let uploads: Vec<&FileEntry> = uploads
        .into_iter()
        .filter(|f| representable(&f.path))
        .collect();

    // ---- delete/download race guard ----
    // The diff above ran against tombstones loaded before the scan finished;
    // a file deleted locally in the meantime looks like a plain download and
    // executing it would revert the deletion. Reload fresh (flushing anything
    // the watcher queued meanwhile) and drop any download whose path gained a
    // tombstone newer than the server entry's mtime — same rule as the diff.
    // The next pass then sends delete_file for it properly.
    tombstones::flush(root);
    let fresh_tombs = tombstones::load(root);
    let downloads: Vec<&FileEntry> = downloads
        .into_iter()
        .filter(|dl| match fresh_tombs.get(&dl.path) {
            Some(ts) if *ts as f64 > dl.mtime_ms - time_offset_ms => {
                log::info!(
                    "sync client: skipping download, tombstoned since diff: {}",
                    dl.path
                );
                false
            }
            _ => true,
        })
        .collect();

    // ---- local deletions (deleted on server after our copy) ----
    let mut downloaded = 0;
    let mut locked_skipped = 0;
    let mut deleted_local = 0;
    if mode != "readonly" {
        for path in &local_deletes {
            let full = root.join(path);
            if is_file_locked(&full) {
                locked_skipped += 1;
                log::info!("sync client: skip delete (locked): {path}");
                continue;
            }
            match tokio::fs::remove_file(&full).await {
                Ok(()) => {
                    deleted_local += 1;
                    log::info!("sync client: deleted {path} (deleted on server)");
                    // remember the deletion so it cannot resurrect from a peer.
                    // The server's tombstone ts is server-clock; convert it to
                    // OUR clock so the local store stays uniformly client-clock
                    // (every later comparison of it assumes that).
                    let ts = server_tombs
                        .get(path)
                        .map(|sts| (*sts as f64 - time_offset_ms).max(0.0) as u64)
                        .unwrap_or_else(tombstones::now_ms);
                    let mut updates = BTreeMap::new();
                    updates.insert(path.clone(), ts);
                    tombstones::record_with(root, &updates);
                    local_tombs.insert(path.clone(), ts);
                }
                Err(e) => log::warn!("sync client: cannot delete {path}: {e}"),
            }
        }
    }

    // ---- download ----
    for dl in &downloads {
        let full = root.join(&dl.path);
        if is_file_locked(&full) {
            locked_skipped += 1;
            log::info!("sync client: skip (locked): {}", dl.path);
            continue;
        }

        // a transient tear (concurrent replace on the server) retries once
        // within the pass instead of starving until the next full cycle
        let mut installed = false;
        for attempt in 0..2 {
            if attempt > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            }

            write_json(stream, &get_file(&dl.path)).await?;

            // stream metadata + chunks to a temp file until file_done
            let tmp = unique_tmp(&full);
            if let Some(parent) = tmp.parent() {
                if let Err(e) = tokio::fs::create_dir_all(parent).await {
                    // a squatted name (plain file where a dir should go) must
                    // not starve the whole pass via `?`
                    log::warn!("sync client: cannot create directory for {}: {e}", dl.path);
                    continue;
                }
            }

            let mut meta_size = 0u64;
            let mut meta_hash = String::new();
            let mut meta_mtime = 0f64;
            let mut out = match tokio::fs::File::create(&tmp).await {
                Ok(f) => f,
                Err(e) => {
                    log::warn!("sync client: cannot create temp for {}: {e}", dl.path);
                    continue;
                }
            };
            let mut received = 0u64;
            let mut failed = false;
            loop {
                let msg = next_message(stream, &mut parser, &mut messages, &mut buf).await?;
                match msg {
                    SyncMessage::Json(m) => match m["t"].as_str().unwrap_or("") {
                        T_FILE_META => {
                            meta_size = m["size"].as_u64().unwrap_or(0);
                            meta_hash = m["hash"].as_str().unwrap_or("").to_string();
                            meta_mtime = m["mtimeMs"].as_f64().unwrap_or(0.0);
                        }
                        T_FILE_DONE => break,
                        T_FILE_ERROR => {
                            log::warn!(
                                "sync client: error downloading {}: {}",
                                dl.path,
                                m["error"].as_str().unwrap_or("?")
                            );
                            failed = true;
                            break;
                        }
                        _ => {}
                    },
                    SyncMessage::Bin(data) => {
                        if !failed {
                            received += data.len() as u64;
                            // abort on overrun immediately: a server streaming
                            // past its declared size writes unbounded disk otherwise
                            let overrun = received > meta_size || received > MAX_FILE_BYTES;
                            if overrun || out.write_all(&data).await.is_err() {
                                failed = true;
                            }
                        }
                    }
                }
            }
            drop(out);

            if failed || received != meta_size {
                let _ = tokio::fs::remove_file(&tmp).await;
                if !failed {
                    log::warn!(
                        "sync client: size mismatch for {}: expected {meta_size}, got {received}",
                        dl.path
                    );
                }
                continue;
            }

            // verify hash on the temp file before atomically installing it
            let got_hash = tokio::task::spawn_blocking({
                let p = tmp.clone();
                move || hash_file(&p)
            })
            .await
            .map_err(|e| anyhow!("join: {e}"))?
            .unwrap_or_default();

            if !meta_hash.is_empty() && got_hash != meta_hash {
                let _ = tokio::fs::remove_file(&tmp).await;
                log::warn!(
                    "sync client: hash mismatch for {} (attempt {})",
                    dl.path,
                    attempt + 1
                );
                continue;
            }

            // atomic rename + set mtime; a single un-installable target (e.g. a
            // directory squatting on the name) must not starve the rest of the pass
            if let Err(e) = tokio::fs::rename(&tmp, &full).await {
                let _ = tokio::fs::remove_file(&tmp).await;
                log::warn!("sync client: install {} failed: {e} (skipped)", dl.path);
                continue;
            }
            let ft = filetime::FileTime::from_unix_time(
                (meta_mtime / 1000.0) as i64,
                ((meta_mtime % 1000.0) * 1_000_000.0) as u32,
            );
            let _ = filetime::set_file_times(&full, ft, ft);
            installed = true;
            break;
        }

        if installed {
            downloaded += 1;
            if downloaded % 10 == 0 || downloaded == downloads.len() {
                log::info!(
                    "sync client: downloading {}/{}",
                    downloaded,
                    downloads.len()
                );
            }
        }
    }

    // ---- server deletions (our tombstone newer than the server copy) ----
    let mut deleted_remote = 0;
    if mode != "readonly" {
        for (path, ts) in &server_deletes {
            // our tombstone ts is client-clock; the server's last-writer guard
            // compares it against its own (server-clock) file mtime, so shift
            // it into the server clock before sending
            let ts_server = (*ts as f64 + time_offset_ms).max(0.0) as u64;
            write_json(stream, &delete_file(path, ts_server)).await?;
            loop {
                let msg = next_message(stream, &mut parser, &mut messages, &mut buf).await?;
                if let SyncMessage::Json(m) = &msg {
                    if m["t"] == T_DELETE_ACK {
                        if m["ok"].as_bool().unwrap_or(false) {
                            deleted_remote += 1;
                            log::info!("sync client: deleted on server: {path}");
                            // keep our tombstone persisted (it exists — it is
                            // why we sent the delete), with the original ts
                            let keep = local_tombs
                                .get(path)
                                .copied()
                                .unwrap_or_else(tombstones::now_ms);
                            let mut updates = BTreeMap::new();
                            updates.insert(path.clone(), keep);
                            tombstones::record_with(root, &updates);
                            local_tombs.insert(path.clone(), keep);
                        } else {
                            log::warn!(
                                "sync client: server refused delete {path}: {}",
                                m["error"].as_str().unwrap_or("?")
                            );
                        }
                        break;
                    }
                }
            }
        }
    }

    // ---- upload ----
    let mut uploaded = 0;
    for ul in &uploads {
        let full = root.join(&ul.path);
        if is_file_locked(&full) {
            locked_skipped += 1;
            log::info!("sync client: skip upload (locked): {}", ul.path);
            continue;
        }

        write_json(
            stream,
            &put_start(
                &ul.path,
                ul.size,
                ul.hash.as_deref().unwrap_or(""),
                ul.mtime_ms,
            ),
        )
        .await?;

        let mut file = match tokio::fs::File::open(&full).await {
            Ok(f) => f,
            Err(e) => {
                log::warn!("sync client: cannot open {} for upload: {e}", ul.path);
                // the server has an open transfer; close it with an empty put_done
                // so it can reject on size mismatch and send its ack
                write_json(stream, &put_done(&ul.path)).await?;
                if let Some(m) = wait_put_ack(stream, &mut parser, &mut messages, &mut buf).await? {
                    log::warn!(
                        "sync client: upload {}: {}",
                        ul.path,
                        m["error"].as_str().unwrap_or("rejected")
                    );
                }
                continue;
            }
        };
        let mut buf2 = vec![0u8; 64 * 1024];
        loop {
            let n = file.read(&mut buf2).await?;
            if n == 0 {
                break;
            }
            write_bin(stream, &buf2[..n]).await?;
        }
        drop(file);
        stream.flush().await?;
        write_json(stream, &put_done(&ul.path)).await?;

        // wait for the server's verdict (size/hash verified there)
        if let Some(m) = wait_put_ack(stream, &mut parser, &mut messages, &mut buf).await? {
            if m["ok"].as_bool().unwrap_or(false) {
                uploaded += 1;
                if uploaded % 10 == 0 || uploaded == uploads.len() {
                    log::info!("sync client: uploading {}/{}", uploaded, uploads.len());
                }
            } else {
                log::warn!(
                    "sync client: upload {} rejected: {}",
                    ul.path,
                    m["error"].as_str().unwrap_or("?")
                );
            }
        } else {
            log::warn!("sync client: no ack for upload {}", ul.path);
        }
    }

    let stats = SyncStats {
        downloaded,
        uploads: uploaded,
        conflicts,
        locked_skipped,
        server_files: server_files.len(),
        client_files: client_files.len(),
        time_offset_ms,
    };

    write_json(
        stream,
        &sync_complete(
            stats.downloaded,
            stats.uploads,
            stats.conflicts,
            stats.locked_skipped,
        ),
    )
    .await?;

    log::info!(
        "complete: {} downloaded, {} uploads, {} local-deletes, {} server-deletes, {} conflicts, {} locked-skip",
        stats.downloaded,
        stats.uploads,
        deleted_local,
        deleted_remote,
        stats.conflicts,
        stats.locked_skipped
    );

    Ok(stats)
}
