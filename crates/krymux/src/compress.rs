//! Per-stream, per-direction compression with a continuous context flushed at
//! every chunk — the same semantics as the Node implementation
//! (wire-compatible).

use std::io::Write;

/// Algorithm name: no compression.
pub const ALGO_NONE: &str = "none";
/// Algorithm name: raw DEFLATE.
pub const ALGO_DEFLATE: &str = "deflate";
/// Algorithm name: Brotli.
pub const ALGO_BROTLI: &str = "brotli";
/// Algorithm name: Zstandard (requires the `zstd` feature).
pub const ALGO_ZSTD: &str = "zstd";
/// Algorithm name prefix: dictionary-accelerated Zstandard. A full name is
/// `zstdd:<8hexfp>` where `<8hexfp>` is the first 8 hex chars of the SHA-256
/// of the registered dictionary. Both peers must have registered the exact
/// same dictionary bytes for the algorithm to be negotiated.
pub const ALGO_ZSTDD: &str = "zstdd";

/// One registered zstd dictionary: its bytes plus its (leaked) wire name.
/// The bytes live behind an `Arc` so per-stream codecs share them by
/// reference instead of copying the whole dictionary per stream.
#[cfg(feature = "zstd")]
struct ZstdDictEntry {
    bytes: std::sync::Arc<Vec<u8>>,
    name: &'static str,
}

/// Process-global dictionary registry: set once at startup, read per stream.
/// The name is leaked so `supported()`/`negotiate()` can keep returning
/// `&'static str` (the mux stores algorithm names that way).
#[cfg(feature = "zstd")]
static ZSTD_DICT: std::sync::Mutex<Option<ZstdDictEntry>> = std::sync::Mutex::new(None);

/// Registers the process-global zstd dictionary and returns its wire name
/// (`"zstdd:<8hexfp>"`, the first 8 hex chars of the dictionary's SHA-256).
/// Returns an empty string when the dictionary cannot be used (empty input,
/// or this build lacks the `zstd feature`) — callers treat that as "not set".
///
/// Called once at CLI startup, before any session HELLO advertises
/// `supported()`. Calling it again replaces the dictionary (the previous
/// name stays leaked; harmless at startup scale).
pub fn set_zstd_dictionary(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    let digest = h.finalize();
    // a dictionary name without the codec behind it would be a false
    // promise: nothing would ever be advertised or negotiated
    #[cfg(not(feature = "zstd"))]
    {
        let _ = digest;
        String::new()
    }
    #[cfg(feature = "zstd")]
    {
        let fp = hex::encode(&digest[..4]); // 4 bytes -> 8 hex chars
        let name = format!("{}:{}", ALGO_ZSTDD, fp);
        let leaked: &'static str = Box::leak(name.clone().into_boxed_str());
        *ZSTD_DICT.lock().unwrap() = Some(ZstdDictEntry {
            bytes: std::sync::Arc::new(bytes.to_vec()),
            name: leaked,
        });
        name
    }
}

/// The registered dictionary's wire name, if any.
#[cfg(feature = "zstd")]
fn zstdd_name() -> Option<&'static str> {
    ZSTD_DICT.lock().unwrap().as_ref().map(|d| d.name)
}

/// The registered dictionary's bytes (shared by `Arc` clone, not copied),
/// but only when `algo` is exactly the current zstdd name. A mismatched
/// fingerprint means the peer compressed with a different dictionary;
/// refusing (falling back) is the safe answer.
#[cfg(feature = "zstd")]
fn zstdd_bytes_for(algo: &str) -> Option<std::sync::Arc<Vec<u8>>> {
    let g = ZSTD_DICT.lock().unwrap();
    let d = g.as_ref()?;
    (d.name == algo).then(|| std::sync::Arc::clone(&d.bytes))
}

/// Is `algo` a `zstdd:<8hexfp>` name?
fn is_zstdd(algo: &str) -> bool {
    match algo.strip_prefix(ALGO_ZSTDD) {
        Some(rest) => {
            rest.len() == 9
                && rest.starts_with(':')
                && rest[1..].bytes().all(|b| b.is_ascii_hexdigit())
        }
        None => false,
    }
}

/// Lists the algorithms this build supports (zstd only with the feature on;
/// `zstdd:<fp>` additionally when a dictionary has been registered).
pub fn supported() -> Vec<&'static str> {
    #[allow(unused_mut)]
    let mut v = vec![ALGO_NONE, ALGO_DEFLATE, ALGO_BROTLI];
    #[cfg(feature = "zstd")]
    {
        v.push(ALGO_ZSTD);
        if let Some(name) = zstdd_name() {
            v.push(name);
        }
    }
    v
}

/// Strip a level suffix: "zstd:9" -> "zstd".
pub fn base_algo(requested: &str) -> &str {
    match requested.find(':') {
        None => requested,
        Some(i) => &requested[..i],
    }
}

/// Parse a level suffix: "zstd:9" -> Some(9); invalid/missing -> None.
/// A `zstdd:<fp>` request never carries a level (the suffix is a
/// fingerprint, and an all-digit fingerprint must not masquerade as one).
pub fn parse_level(requested: &str) -> Option<i32> {
    if is_zstdd(requested) {
        return None;
    }
    let i = requested.find(':')?;
    let lvl: i32 = requested[i + 1..].parse().ok()?;
    (1..=22).contains(&lvl).then_some(lvl)
}

/// Dictionary upgrade common to "auto" and explicit "zstd" requests: pick
/// `zstdd:<fp>` only when a dictionary is registered AND the peer's list
/// contains the very same name (exact fingerprint match). Otherwise the
/// caller falls back to plain zstd — Node peers never advertise `zstdd`, so
/// interop is preserved.
#[cfg(feature = "zstd")]
fn pick_zstdd(peer_supported: &[&str]) -> Option<&'static str> {
    let name = zstdd_name()?;
    peer_supported.iter().find(|p| **p == name).map(|_| name)
}

/// Without the `zstd` feature there is no dictionary machinery at all.
#[cfg(not(feature = "zstd"))]
fn pick_zstdd(_peer_supported: &[&str]) -> Option<&'static str> {
    None
}

/// Pick an algorithm from a request + the peer's supported list.
pub fn negotiate(requested: &str, peer_supported: &[&str]) -> &'static str {
    let pick = |a: &str| -> Option<&'static str> {
        peer_supported.iter().find(|p| **p == a).map(|_| match a {
            ALGO_ZSTD => ALGO_ZSTD,
            ALGO_BROTLI => ALGO_BROTLI,
            ALGO_DEFLATE => ALGO_DEFLATE,
            _ => ALGO_NONE,
        })
    };
    match base_algo(requested) {
        "" | ALGO_NONE => ALGO_NONE,
        "auto" => pick_zstdd(peer_supported)
            .or_else(|| pick(ALGO_ZSTD))
            .or_else(|| pick(ALGO_DEFLATE))
            .or_else(|| pick(ALGO_BROTLI))
            .unwrap_or(ALGO_NONE),
        ALGO_ZSTD => pick_zstdd(peer_supported)
            .or_else(|| pick(ALGO_ZSTD))
            .unwrap_or(ALGO_NONE),
        #[cfg(feature = "zstd")]
        ALGO_ZSTDD => {
            // explicit dictionary request: honor it only on an exact match of
            // our registered name in the peer list; a foreign fingerprint (or
            // no dictionary here) downgrades to plain zstd, never to a
            // mismatched-dictionary stream (which would corrupt data).
            if let Some(name) = zstdd_name() {
                if requested == name && peer_supported.contains(&name) {
                    return name;
                }
            }
            pick(ALGO_ZSTD).unwrap_or(ALGO_NONE)
        }
        #[cfg(not(feature = "zstd"))]
        ALGO_ZSTDD => ALGO_NONE, // this build has no zstd, dictionary or not
        ALGO_BROTLI => pick(ALGO_BROTLI).unwrap_or(ALGO_NONE),
        ALGO_DEFLATE => pick(ALGO_DEFLATE).unwrap_or(ALGO_NONE),
        _ => ALGO_NONE,
    }
}

// Well-known magic prefixes: content that is already compressed. The sender's
// first chunk is sniffed; matches switch the stream to 'none' (saves CPU and
// the ~0.3% expansion). Receiver-side needs nothing: unflagged frames pass raw.
const MAGIC_PREFIXES: [&[u8]; 9] = [
    &[0x1f, 0x8b],             // gzip
    &[0x28, 0xb5, 0x2f, 0xfd], // zstd
    &[0x50, 0x4b, 0x03, 0x04], // zip
    &[0x89, 0x50, 0x4e, 0x47], // png
    &[0xff, 0xd8, 0xff],       // jpeg
    &[0x37, 0x7a, 0xbc, 0xaf], // 7z
    &[0x52, 0x61, 0x72, 0x21], // rar
    &[0x25, 0x50, 0x44, 0x46], // %PDF
    &[0x42, 0x5a, 0x68],       // bzip2
];

/// Heuristic: does this first chunk look pre-compressed?
pub fn looks_precompressed(chunk: &[u8]) -> bool {
    if chunk.len() < 4 {
        return false;
    }
    for magic in MAGIC_PREFIXES {
        if chunk.starts_with(magic) {
            return true;
        }
    }
    // ISO-BMFF (mp4/mov/heic): "ftyp" at offset 4
    chunk.len() >= 12 && &chunk[4..8] == b"ftyp"
}

enum CompInner {
    None,
    Deflate(flate2::write::DeflateEncoder<Vec<u8>>),
    Brotli(Box<brotli::CompressorWriter<Vec<u8>>>),
    #[cfg(feature = "zstd")]
    Zstd(
        Box<zstd::stream::write::Encoder<'static, Vec<u8>>>,
        &'static str,
    ),
}

/// Chunk-oriented compressor holding one continuous context per direction.
pub struct Compressor {
    inner: CompInner,
}

impl Compressor {
    /// Creates a compressor for `algo` at `level` (meaning varies per
    /// algorithm; clamped internally). A `zstdd:<fp>` algo uses the
    /// registered dictionary with that fingerprint.
    pub fn new(algo: &str, level: i32) -> Self {
        let inner = match algo {
            ALGO_DEFLATE => CompInner::Deflate(flate2::write::DeflateEncoder::new(
                Vec::new(),
                flate2::Compression::new(level.max(0) as u32),
            )),
            ALGO_BROTLI => CompInner::Brotli(Box::new(brotli::CompressorWriter::new(
                Vec::new(),
                64 * 1024,
                level.max(1) as u32,
                22,
            ))),
            #[cfg(feature = "zstd")]
            ALGO_ZSTD => CompInner::Zstd(
                Box::new(
                    zstd::stream::write::Encoder::new(Vec::new(), level.max(1))
                        .expect("zstd encoder"),
                ),
                ALGO_ZSTD,
            ),
            // dictionary-accelerated zstd: same default level as plain zstd
            #[cfg(feature = "zstd")]
            _ if is_zstdd(algo) => match zstdd_bytes_for(algo) {
                Some(dict) => CompInner::Zstd(
                    Box::new(
                        zstd::stream::write::Encoder::with_dictionary(
                            Vec::new(),
                            if level >= 1 { level } else { 3 },
                            &dict,
                        )
                        .expect("zstd encoder with dictionary"),
                    ),
                    zstdd_name().unwrap_or(ALGO_ZSTD),
                ),
                // unreachable via negotiate() (it never returns a zstdd name
                // we do not have the dictionary for); stay raw rather than
                // panic — the stream degrades to 'none' semantics.
                None => {
                    log::warn!("compress: no dictionary registered for {algo}; stream is raw");
                    CompInner::None
                }
            },
            _ => CompInner::None,
        };
        Compressor { inner }
    }

    /// Compress one chunk with a flush boundary; returns wire bytes (may be empty
    /// only for empty input).
    pub fn push(&mut self, data: &[u8]) -> std::io::Result<Vec<u8>> {
        if data.is_empty() {
            return Ok(Vec::new());
        }
        match &mut self.inner {
            CompInner::None => Ok(data.to_vec()),
            CompInner::Deflate(w) => {
                w.write_all(data)?;
                w.flush()?; // Z_SYNC_FLUSH equivalent
                Ok(std::mem::take(w.get_mut()))
            }
            CompInner::Brotli(w) => {
                w.write_all(data)?;
                w.flush()?; // BROTLI_OPERATION_FLUSH
                Ok(std::mem::take(w.get_mut()))
            }
            #[cfg(feature = "zstd")]
            CompInner::Zstd(w, _) => {
                w.write_all(data)?;
                w.flush()?; // ZSTD_e_flush
                Ok(std::mem::take(w.get_mut()))
            }
        }
    }

    /// Returns the algorithm actually in use.
    pub fn algo(&self) -> &'static str {
        match &self.inner {
            CompInner::None => ALGO_NONE,
            CompInner::Deflate(_) => ALGO_DEFLATE,
            CompInner::Brotli(_) => ALGO_BROTLI,
            #[cfg(feature = "zstd")]
            CompInner::Zstd(_, name) => name,
        }
    }
}

enum DecInner {
    None,
    Deflate(flate2::write::DeflateDecoder<Vec<u8>>),
    /// brotli via the low-level push API: DecompressorWriter buffers output
    /// internally and its flush() does not drive decoding (observed: first
    /// frame emits, later frames stall until the internal buffer fills).
    Brotli(Box<BrotliPushDecoder>),
    #[cfg(feature = "zstd")]
    Zstd(Box<zstd::stream::write::Decoder<'static, Vec<u8>>>),
    /// A `zstdd:<fp>` stream whose dictionary is not registered: every push
    /// errors — decoding with the wrong (or no) dictionary yields corrupt
    /// output, so failing loudly beats passing zstd bytes off as plaintext.
    #[cfg(feature = "zstd")]
    ZstdMissingDict,
}

type BrotliAlloc8 = brotli::HeapAlloc<u8>;
type BrotliAlloc32 = brotli::HeapAlloc<u32>;
type BrotliAllocHc = brotli::HeapAlloc<brotli::HuffmanCode>;

/// Brotli decoder built on the low-level `BrotliDecompressStream` push API:
/// unlike `DecompressorWriter`, it emits output eagerly per chunk, which the
/// per-chunk flush semantics of the wire protocol require.
pub struct BrotliPushDecoder {
    state: brotli::BrotliState<BrotliAlloc8, BrotliAlloc32, BrotliAllocHc>,
}

impl BrotliPushDecoder {
    fn new() -> Self {
        BrotliPushDecoder {
            state: brotli::BrotliState::new(
                BrotliAlloc8::default(),
                BrotliAlloc32::default(),
                BrotliAllocHc::default(),
            ),
        }
    }

    /// Feed one wire chunk, return whatever becomes decodable immediately.
    fn push(&mut self, wire: &[u8]) -> std::io::Result<Vec<u8>> {
        self.drive(wire)
    }

    /// Drain all pending output (brotli lazily emits; call at end-of-stream).
    fn finish(&mut self) -> std::io::Result<Vec<u8>> {
        self.drive(&[])
    }

    fn drive(&mut self, wire: &[u8]) -> std::io::Result<Vec<u8>> {
        let mut out = Vec::new();
        let mut outbuf = [0u8; 64 * 1024];
        let mut avail_in = wire.len();
        let mut input_offset = 0usize;
        let mut total_out: usize = 0;
        loop {
            let mut avail_out = outbuf.len();
            let mut output_offset = 0usize;
            let res = brotli::BrotliDecompressStream(
                &mut avail_in,
                &mut input_offset,
                wire,
                &mut avail_out,
                &mut output_offset,
                &mut outbuf,
                &mut total_out,
                &mut self.state,
            );
            if output_offset > 0 {
                out.extend_from_slice(&outbuf[..output_offset]);
            }
            match res {
                brotli::BrotliResult::NeedsMoreOutput => continue,
                brotli::BrotliResult::NeedsMoreInput => {
                    // make-progress API: keep going while input remains OR the
                    // last call still produced output (lazy emission)
                    if avail_in > 0 || output_offset > 0 {
                        continue;
                    }
                    break;
                }
                brotli::BrotliResult::ResultSuccess => break,
                brotli::BrotliResult::ResultFailure => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "brotli decode failure",
                    ));
                }
            }
        }
        Ok(out)
    }
}

/// Chunk-oriented decompressor holding one continuous context per direction.
pub struct Decompressor {
    inner: DecInner,
}

impl Decompressor {
    /// Creates a decompressor for `algo`. A `zstdd:<fp>` algo decodes with
    /// the registered dictionary of that fingerprint; decoding a
    /// dictionary-compressed stream without the dictionary fails at push
    /// time (zstd reports the corruption) rather than silently in `new`.
    pub fn new(algo: &str) -> Self {
        let inner = match algo {
            ALGO_DEFLATE => DecInner::Deflate(flate2::write::DeflateDecoder::new(Vec::new())),
            ALGO_BROTLI => DecInner::Brotli(Box::new(BrotliPushDecoder::new())),
            #[cfg(feature = "zstd")]
            ALGO_ZSTD => DecInner::Zstd(Box::new(
                zstd::stream::write::Decoder::new(Vec::new()).expect("zstd decoder"),
            )),
            #[cfg(feature = "zstd")]
            _ if is_zstdd(algo) => match zstdd_bytes_for(algo) {
                Some(dict) => DecInner::Zstd(Box::new(
                    zstd::stream::write::Decoder::with_dictionary(Vec::new(), &dict)
                        .expect("zstd decoder with dictionary"),
                )),
                None => {
                    // no matching dictionary: wire a decoder that fails on
                    // first input instead of silently passing raw zstd bytes
                    // through as if they were plaintext
                    log::warn!("decompress: no dictionary registered for {algo}; stream will fail");
                    DecInner::ZstdMissingDict
                }
            },
            _ => DecInner::None,
        };
        Decompressor { inner }
    }

    /// Decompress one wire chunk; returns logical bytes (may be empty when the
    /// algorithm emits nothing for this input).
    pub fn push(&mut self, data: &[u8]) -> std::io::Result<Vec<u8>> {
        if data.is_empty() {
            return Ok(Vec::new());
        }
        match &mut self.inner {
            DecInner::None => Ok(data.to_vec()),
            DecInner::Deflate(w) => {
                w.write_all(data)?;
                let _ = w.flush();
                Ok(std::mem::take(w.get_mut()))
            }
            DecInner::Brotli(w) => w.push(data),
            #[cfg(feature = "zstd")]
            DecInner::Zstd(w) => {
                w.write_all(data)?;
                let _ = w.flush();
                Ok(std::mem::take(w.get_mut()))
            }
            #[cfg(feature = "zstd")]
            DecInner::ZstdMissingDict => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "zstd dictionary not registered for this stream",
            )),
        }
    }

    /// End-of-stream: drain any lazily-held output.
    pub fn finish(&mut self) -> std::io::Result<Vec<u8>> {
        match &mut self.inner {
            DecInner::Brotli(w) => w.finish(),
            DecInner::Deflate(w) => {
                let _ = w.flush();
                Ok(std::mem::take(w.get_mut()))
            }
            #[cfg(feature = "zstd")]
            DecInner::Zstd(w) => {
                let _ = w.flush();
                Ok(std::mem::take(w.get_mut()))
            }
            _ => Ok(Vec::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_parsing_rejects_zstdd_fingerprints() {
        assert_eq!(parse_level("zstd:9"), Some(9));
        // a fingerprint suffix must never be read as a compression level —
        // not even the pathological all-digit one
        assert_eq!(parse_level("zstdd:0123abcd"), None);
        assert_eq!(parse_level("zstdd:00000012"), None);
        assert_eq!(base_algo("zstdd:0123abcd"), "zstdd");
        assert!(is_zstdd("zstdd:0123abcd"));
        assert!(!is_zstdd("zstdd:short"));
        assert!(!is_zstdd("zstdd:0123abcg"));
        assert!(!is_zstdd("zstd"));
    }

    #[cfg(feature = "zstd")]
    mod zstdd {
        use super::super::*;
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        /// A deterministic text-ish corpus that looks like the small,
        /// repetitive payloads dictionaries are for.
        fn sample_corpus() -> Vec<u8> {
            let mut out = String::new();
            for i in 0..400 {
                out.push_str(&format!(
                    "record-{i:04} status=ok service=krymux path=/var/lib/krymux/record-{i:04} checksum=sha256:{i:08x}\n"
                ));
            }
            out.into_bytes()
        }

        /// The registry is a process global and tests run in parallel: every
        /// registry-dependent assertion lives in this ONE (async, so it can
        /// also drive real sessions) test so the state transitions are
        /// sequential and deterministic.
        #[tokio::test]
        async fn dictionary_lifecycle_and_mux_negotiation() {
            // 1. an empty dictionary is refused
            assert_eq!(set_zstd_dictionary(&[]), "");

            // 2. registration yields a well-formed name and advertisement
            let corpus = sample_corpus();
            let name = set_zstd_dictionary(&corpus); // the sample file IS the raw dictionary
            assert_eq!(name.len(), "zstdd:".len() + 8);
            assert!(name.starts_with("zstdd:"));
            assert!(is_zstdd(&name));
            assert!(supported().contains(&name.as_str()));

            // 3. negotiation: exact fingerprint match upgrades, anything else
            //    falls back to plain zstd (Node peers never list zstdd)
            let node_peer = ["none", "deflate", "brotli", "zstd"];
            assert_eq!(negotiate("zstd", &node_peer), ALGO_ZSTD);
            assert_eq!(negotiate("auto", &node_peer), ALGO_ZSTD);
            let same_peer = ["none", "zstd", name.as_str()];
            assert_eq!(negotiate("zstd", &same_peer), name.as_str());
            assert_eq!(negotiate("auto", &same_peer), name.as_str());
            assert_eq!(negotiate(&name, &same_peer), name.as_str()); // explicit request
            let other_fp_peer = ["none", "zstd", "zstdd:deadbeef"];
            assert_eq!(negotiate("zstd", &other_fp_peer), ALGO_ZSTD);
            assert_eq!(negotiate("zstdd:deadbeef", &other_fp_peer), ALGO_ZSTD);
            assert_eq!(negotiate("zstd", &["none"]), ALGO_NONE);
            assert_eq!(parse_level(&name), None);

            // 4. round-trip fidelity through the chunk-oriented API (the same
            //    push/flush pattern the mux pumps use), plus real compression
            let mut comp = Compressor::new(&name, 3);
            assert_eq!(comp.algo(), name.as_str());
            let mut decomp = Decompressor::new(&name);
            let mut wire_total = 0usize;
            let mut roundtrip = Vec::new();
            for chunk in corpus.chunks(700) {
                let wire = comp.push(chunk).expect("compress chunk");
                wire_total += wire.len();
                let plain = decomp.push(&wire).expect("decompress chunk");
                roundtrip.extend_from_slice(&plain);
            }
            roundtrip.extend_from_slice(&decomp.finish().expect("finish"));
            assert_eq!(roundtrip, corpus, "dictionary round-trip must be lossless");
            assert!(
                wire_total < corpus.len() / 2,
                "dictionary compression should shrink the corpus: wire={wire_total} raw={}",
                corpus.len()
            );

            // 5. without the dictionary the stream fails: re-register a
            //    DIFFERENT dictionary, then try to decode a stream named
            //    after the old fingerprint
            let mut other = corpus.clone();
            other.extend_from_slice(b"a completely different dictionary");
            let other_name = set_zstd_dictionary(&other);
            assert_ne!(other_name, name);
            let mut orphan = Decompressor::new(&name);
            let first_wire = comp.push(b"one more chunk").expect("compress");
            let res = orphan.push(&first_wire);
            assert!(
                res.is_err(),
                "a zstdd stream must fail (not silently corrupt) without its dictionary"
            );
            // and negotiation no longer offers the stale name
            assert_eq!(negotiate("zstd", &same_peer), ALGO_ZSTD);

            // 6. plain zstd is untouched by all of this
            let mut pc = Compressor::new(ALGO_ZSTD, 3);
            let mut pd = Decompressor::new(ALGO_ZSTD);
            let w = pc.push(b"plain zstd still works").expect("plain compress");
            let p = pd.push(&w).expect("plain decompress");
            assert_eq!(p, b"plain zstd still works".to_vec());

            // 7. end-to-end through two real multiplexed sessions: HELLO
            //    advertisement, "auto" upgrade, OPEN/OPEN_ACK and the
            //    per-stream pumps all speaking zstdd
            let name = set_zstd_dictionary(&corpus); // restore the real dict
            let (a, b) = tokio::io::duplex(64 * 1024);
            let opts = |is_client: bool| crate::mux::SessionOpts {
                is_client,
                name: if is_client { "c" } else { "s" }.into(),
                rx_window: 262_144,
                rx_window_max: 4_194_304,
                max_streams: 8,
                keepalive_sec: 0,
            };
            // single-threaded test runtime: start the server side as a task
            // or both HELLO waits deadlock on each other
            let server_task = tokio::spawn(async move {
                crate::mux::MuxSession::start(
                    b,
                    opts(false),
                    Some(std::sync::Arc::new(
                        |stream: crate::mux::TunnelStream, _t: crate::mux::Target| {
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
                        },
                    )),
                )
                .await
            });
            let client = crate::mux::MuxSession::start(a, opts(true), None)
                .await
                .expect("client session");
            let server = server_task
                .await
                .expect("join server task")
                .expect("server session");

            let stream = client
                .open_stream(
                    crate::mux::Target {
                        host: Some("echo".into()),
                        port: 1,
                        unix: None,
                        hint: "raw".into(),
                    },
                    "auto",
                )
                .await
                .expect("open stream");
            assert_eq!(stream.compression(), name, "auto must upgrade to zstdd");
            let mut s = stream;
            s.write_all(&corpus).await.expect("send corpus");
            s.shutdown().await.expect("eof");
            let mut got = Vec::new();
            s.read_to_end(&mut got).await.expect("read echo back");
            assert_eq!(got, corpus, "echo through a zstdd stream must be lossless");
            client.close("done");
            server.close("done");
        }
    }
}
