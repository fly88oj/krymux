//! Sync protocol framing: `[4-byte BE length][1-byte type][payload]` where
//! type `0x01` is a JSON message (UTF-8) and `0x02` a binary chunk —
//! wire-compatible with the Node reference implementation.
//!
//! The JSON message vocabulary (`"t"` field values) is centralized here as
//! constants plus typed constructors, so every message name and shape has one
//! authoritative source (and future Go/Python SDKs can mirror this list).

use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use std::collections::BTreeMap;

use crate::sync::scanner::FileEntry;

/// Frame type: UTF-8 JSON message.
pub const MSG_JSON: u8 = 0x01;
/// Frame type: binary payload chunk.
pub const MSG_BIN: u8 = 0x02;
const HEADER: usize = 5;
const MAX_MSG: usize = 8 * 1024 * 1024;

// ---------------- typed message vocabulary ----------------

/// Client → server: session handshake.
pub const T_HELLO: &str = "hello";
/// Server → client: handshake acceptance (server time, negotiated mode).
pub const T_HELLO_ACK: &str = "hello_ack";
/// Server → client: local scan finished, batches may be requested.
pub const T_SCAN_READY: &str = "scan_ready";
/// Client → server: request the file-list batches.
pub const T_REQUEST_SCAN: &str = "request_scan";
/// Server → client: one batch of file entries.
pub const T_SCAN_BATCH: &str = "scan_batch";
/// Server → client: file list complete.
pub const T_SCAN_END: &str = "scan_end";
/// Server → client: one batch of the server's tombstone map.
pub const T_TOMBSTONE_BATCH: &str = "tombstone_batch";
/// Server → client: tombstone stream complete (always sent by tombstone-aware
/// servers, even with zero entries — its arrival marks awareness).
pub const T_TOMBSTONE_END: &str = "tombstone_end";
/// Client → server: request one file download.
pub const T_GET_FILE: &str = "get_file";
/// Server → client: metadata of the file about to stream.
pub const T_FILE_META: &str = "file_meta";
/// Server → client: file stream complete.
pub const T_FILE_DONE: &str = "file_done";
/// Server → client: a download could not be served.
pub const T_FILE_ERROR: &str = "file_error";
/// Client → server: begin an upload.
pub const T_PUT_START: &str = "put_start";
/// Client → server: upload stream complete.
pub const T_PUT_DONE: &str = "put_done";
/// Server → client: upload verdict (size + hash verified there).
pub const T_PUT_ACK: &str = "put_ack";
/// Client → server: delete a tombstoned file on the server.
pub const T_DELETE_FILE: &str = "delete_file";
/// Server → client: deletion verdict.
pub const T_DELETE_ACK: &str = "delete_ack";
/// Client → server: this pass is finished.
pub const T_SYNC_COMPLETE: &str = "sync_complete";
/// Client → server: subscribe to server-side change hints.
pub const T_NOTIFY_LISTEN: &str = "notify_listen";
/// Server → client: hint subscription accepted.
pub const T_NOTIFY_ACK: &str = "notify_ack";
/// Server → client: something changed, re-sync now.
pub const T_RESCAN_HINT: &str = "rescan_hint";
/// Server → client: fatal session error.
pub const T_ERROR: &str = "error";

// ---- typed constructors: the exact JSON each side puts on the wire ----

/// [`T_HELLO`] — session handshake with protocol version and desired mode.
pub fn hello(version: u32, mode: &str) -> Value {
    json!({"t": T_HELLO, "version": version, "mode": mode})
}

/// [`T_HELLO_ACK`] — carries the server clock (for offset measurement) and
/// the possibly-negotiated-down mode.
pub fn hello_ack(server_time_ms: u64, mode: &str, version: u32) -> Value {
    json!({"t": T_HELLO_ACK, "serverTime": server_time_ms, "mode": mode, "version": version})
}

/// [`T_ERROR`] — fatal session error (e.g. version mismatch).
pub fn error_msg(message: &str) -> Value {
    json!({"t": T_ERROR, "message": message})
}

/// [`T_SCAN_READY`] — the server's file count plus the tombstone-transport
/// marker. Tombstones are NOT embedded here anymore: a large store exceeded
/// the 8 MiB frame cap and killed every pass. Instead the server streams
/// [`T_TOMBSTONE_BATCH`] frames after [`T_SCAN_END`], terminated by
/// [`T_TOMBSTONE_END`] (always, even when empty).
///
/// The `tombstones` key carries `true` as its value. Compatibility: older
/// clients test only the key's presence to decide "server is tombstone-aware"
/// and read it as a map via `as_object()` (so `true` yields an empty map for
/// them); servers that predate batching embed the whole map object under the
/// same key — new clients still read that legacy shape inline and never wait
/// for a `tombstone_end` from such servers.
pub fn scan_ready(count: usize) -> Value {
    json!({"t": T_SCAN_READY, "count": count, "tombstones": true})
}

/// [`T_REQUEST_SCAN`] — ask for the file-list batches.
pub fn request_scan() -> Value {
    json!({"t": T_REQUEST_SCAN})
}

/// [`T_SCAN_BATCH`] — one chunk of the server file list.
pub fn scan_batch(files: &[FileEntry], offset: usize) -> Value {
    json!({"t": T_SCAN_BATCH, "files": files, "offset": offset})
}

/// [`T_SCAN_END`] — file list complete, `total` entries were sent.
pub fn scan_end(total: usize) -> Value {
    json!({"t": T_SCAN_END, "total": total})
}

/// [`T_TOMBSTONE_BATCH`] — one bounded chunk of the server's tombstone map
/// (path → unix ms), streamed after [`T_SCAN_END`]. Batching keeps every
/// frame far below the 8 MiB cap even with hundreds of thousands of entries.
pub fn tombstone_batch(entries: &BTreeMap<String, u64>) -> Value {
    json!({"t": T_TOMBSTONE_BATCH, "entries": entries})
}

/// [`T_TOMBSTONE_END`] — tombstone stream complete, `count` entries were sent
/// in total. Always sent by tombstone-aware servers (zero entries included):
/// its arrival is what marks the server tombstone-aware to the client.
pub fn tombstone_end(count: usize) -> Value {
    json!({"t": T_TOMBSTONE_END, "count": count})
}

/// [`T_GET_FILE`] — request one file.
pub fn get_file(path: &str) -> Value {
    json!({"t": T_GET_FILE, "path": path})
}

/// [`T_FILE_META`] — metadata preceding the binary chunks of a download.
pub fn file_meta(path: &str, size: u64, hash: &str, mtime_ms: f64) -> Value {
    json!({"t": T_FILE_META, "path": path, "size": size, "hash": hash, "mtimeMs": mtime_ms})
}

/// [`T_FILE_DONE`] — download stream complete.
pub fn file_done(path: &str) -> Value {
    json!({"t": T_FILE_DONE, "path": path})
}

/// [`T_FILE_ERROR`] — download could not be served.
pub fn file_error(path: &str, error: &str) -> Value {
    json!({"t": T_FILE_ERROR, "path": path, "error": error})
}

/// [`T_PUT_START`] — begin an upload; binary chunks follow.
pub fn put_start(path: &str, size: u64, hash: &str, mtime_ms: f64) -> Value {
    json!({"t": T_PUT_START, "path": path, "size": size, "hash": hash, "mtimeMs": mtime_ms})
}

/// [`T_PUT_DONE`] — upload stream complete; the server verifies and acks.
pub fn put_done(path: &str) -> Value {
    json!({"t": T_PUT_DONE, "path": path})
}

/// [`T_PUT_ACK`] — upload verdict.
pub fn put_ack(path: &str, ok: bool, error: &str) -> Value {
    json!({"t": T_PUT_ACK, "path": path, "ok": ok, "error": error})
}

/// [`T_DELETE_FILE`] — ask the server to delete `path`; `ts` is the tombstone
/// timestamp (unix ms) expressed in the SERVER's clock: the client converts
/// its local-clock ts by adding the measured clock offset (`serverTime -
/// clientTime` from the handshake), so the server's last-writer guard can
/// compare it directly against its own file mtime with no skew.
pub fn delete_file(path: &str, ts: u64) -> Value {
    json!({"t": T_DELETE_FILE, "path": path, "ts": ts})
}

/// [`T_DELETE_ACK`] — deletion verdict.
pub fn delete_ack(path: &str, ok: bool, error: &str) -> Value {
    json!({"t": T_DELETE_ACK, "path": path, "ok": ok, "error": error})
}

/// [`T_SYNC_COMPLETE`] — pass counters for the server log.
pub fn sync_complete(
    downloaded: usize,
    uploads: usize,
    conflicts: usize,
    locked_skipped: usize,
) -> Value {
    json!({"t": T_SYNC_COMPLETE, "stats": {
        "downloaded": downloaded, "uploads": uploads,
        "conflicts": conflicts, "lockedSkipped": locked_skipped,
    }})
}

/// [`T_NOTIFY_LISTEN`] — subscribe to change hints on a long-lived stream.
pub fn notify_listen() -> Value {
    json!({"t": T_NOTIFY_LISTEN})
}

/// [`T_NOTIFY_ACK`] — hint subscription accepted.
pub fn notify_ack() -> Value {
    json!({"t": T_NOTIFY_ACK})
}

/// [`T_RESCAN_HINT`] — pushed whenever watched files change.
pub fn rescan_hint() -> Value {
    json!({"t": T_RESCAN_HINT})
}

/// Encodes a JSON value as one framed message.
pub fn encode_json(obj: &Value) -> Vec<u8> {
    encode_frame(MSG_JSON, obj.to_string().as_bytes())
}

/// Encodes a binary chunk as one framed message.
pub fn encode_bin(chunk: &[u8]) -> Vec<u8> {
    encode_frame(MSG_BIN, chunk)
}

fn encode_frame(frame_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.push(frame_type);
    out.extend_from_slice(payload);
    out
}

/// One decoded sync-protocol message.
#[derive(Debug)]
pub enum SyncMessage {
    Json(Value),
    Bin(Vec<u8>),
}

/// Incremental parser. Feed chunks, get messages.
#[derive(Default)]
pub struct SyncParser {
    buf: Vec<u8>,
}

impl SyncParser {
    /// Creates an empty parser.
    pub fn new() -> Self {
        SyncParser { buf: Vec::new() }
    }

    /// Feeds raw socket bytes and returns every message that became complete.
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<SyncMessage>> {
        self.buf.extend_from_slice(chunk);
        let mut messages = Vec::new();
        // cursor-based parse with one compact per push: draining per message
        // is quadratic under minimal-frame floods (13k tiny frames per 64KiB
        // read would memmove the whole buffer each time)
        let mut cursor = 0usize;
        loop {
            let avail = self.buf.len() - cursor;
            if avail < HEADER {
                break;
            }
            let len = u32::from_be_bytes([
                self.buf[cursor],
                self.buf[cursor + 1],
                self.buf[cursor + 2],
                self.buf[cursor + 3],
            ]) as usize;
            if len > MAX_MSG {
                return Err(anyhow!("sync message too large: {len}"));
            }
            let frame_type = self.buf[cursor + 4];
            let total = HEADER + len;
            if avail < total {
                break;
            }
            let payload = self.buf[cursor + HEADER..cursor + total].to_vec();
            cursor += total;
            match frame_type {
                MSG_JSON => {
                    let v: Value = serde_json::from_slice(&payload)
                        .map_err(|e| anyhow!("bad sync json: {e}"))?;
                    messages.push(SyncMessage::Json(v));
                }
                MSG_BIN => messages.push(SyncMessage::Bin(payload)),
                _ => return Err(anyhow!("unknown sync frame type: {frame_type}")),
            }
        }
        if cursor > 0 {
            self.buf.copy_within(cursor.., 0);
            self.buf.truncate(self.buf.len() - cursor);
        }
        Ok(messages)
    }
}

/// Helper: write a JSON message to a stream.
pub async fn write_json(
    stream: &mut (impl tokio::io::AsyncWrite + Unpin),
    obj: &Value,
) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    stream.write_all(&encode_json(obj)).await?;
    stream.flush().await?;
    Ok(())
}

/// Helper: write a binary chunk to a stream.
pub async fn write_bin(
    stream: &mut (impl tokio::io::AsyncWrite + Unpin),
    chunk: &[u8],
) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    stream.write_all(&encode_bin(chunk)).await?;
    Ok(())
}
