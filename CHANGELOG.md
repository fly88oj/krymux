# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [0.2.0] - 2026-09-23

### Fixed (multi-language SDK review round)
- TypeScript: a synchronous throw from a user `'data'` handler now tears down only
  that stream (v0.2.0 escalated it to a whole-session GOAWAY); dead push()/flush()
  compression machinery removed.
- Python: `read(None)` regression (TypeError) restored to drain-all semantics;
  **credit grants now happen on app consumption** (was frame arrival) — receive
  memory is bounded for slow readers and the writer queue is capped (256 frames),
  closing the broken backpressure chain; benchmarks interleaved to match. With
  correct backpressure, 16 MiB none throughput doubled (171 → 341 MiB/s — the old
  write-all-then-read pattern hid an end-of-transfer stall).
- Go: a WINDOW credit grant that hits a full writer queue is restored to the
  pending tail instead of being silently dropped (could permanently stall a peer).

### Added
- `sdks/WRITER_CONTRACT.md`: the single normative writer contract (drain-only-queued,
  bounded per-write, flush-before-park, flush-on-teardown, credit-on-consumption)
  referenced by all three SDKs; TS stream-isolation regression test.

### Changed
- **TypeScript SDK**: the stream writer now coalesces queued DATA frames into
  single socket writes (up to 16 frames per write, mirroring the Rust writer
  task), with one backpressure round-trip per batch instead of per frame.
  Uncompressed inbound frames take a synchronous fast path instead of a
  per-frame promise chain, and each deflate chunk is compressed with a single
  transform round-trip. Bulk echo throughput improves ~1.7x (16 MiB) to ~6x
  (1 MiB) depending on payload; wire protocol unchanged.
- **Go SDK**: the session writer flushes coalesced frame bursts with
  `net.Buffers` (writev on TCP, no intermediate concat copy) and the reader
  reuses its payload buffer across frames instead of allocating per frame.
  Bulk echo throughput improves up to ~2.4x; wire protocol unchanged.
- **Python SDK**: the session writer coalesces the queued frames behind one
  transport write + drain per wakeup, the receive buffer consumes by offset
  with amortized compaction (no more O(n) memmove per read on large buffered
  streams), and several per-frame defensive copies were removed. Bulk echo
  throughput improves ~1.1-1.2x; wire protocol unchanged.

### Added
- Echo throughput benchmarks for the TypeScript, Go and Python SDKs
  (`sdks/<lang>/bench/echo.*`): 1 MiB and 16 MiB payloads, none and deflate,
  median of 3 runs, prints MiB/s. Measures the mux/stream data path over
  loopback TCP with both sessions in-process (no TLS, which is runtime-
  internal and unaffected by these changes).
## [0.1.0] - 2026-09-22

Initial public release (previously developed under an internal name).

- Multi-language SDK monorepo: Rust reference crate (`crates/krymux`), TypeScript,
  Go and Python SDKs (`sdks/`), each interop-tested against the Rust binaries;
  apps (`krymux-tunnel`, `krymux-sync`) build on the SDK in a Cargo workspace.
- CI integration workflow: coverage job (Rust line-coverage gate 55%, per-language
  numbers; lcov artifact), Linux integration (parameterized edge matrix, per-language
  interop, cross-language matrix), Windows full E2E; POSIX-runnable e2e/deletion suites.



### Fixed
- Intermittent data loss + stall (~10-30% of bulk transfers): stream deregistration
  on Drop dropped in-flight WINDOW credit grants, parking the sender's pump forever;
  killed-at-timeout sessions then surfaced as clean truncated EOFs. Streams now
  retire only after the app handle is gone AND the outbound pump finished; inbound
  pumps drain-and-credit when the app side vanishes; DATA to a dead stream no longer
  tears down the whole session. Regression test with 16 KiB fixed windows
  (old code 3/3 fail, new code 11/11 pass).

### Changed
- Repository restructured into a **Cargo workspace**: `crates/krymux` is the pure
  library SDK (no binary, no CLI dependencies) and every executable is an app on
  top of it — `apps/krymux-tunnel` (tunnel operations CLI: `keygen`,
  `fingerprint`, `probe`, `server`, `client`) and `apps/krymux-sync` (FileSync:
  `sync-server`, `sync-client`). Pure reorganization; wire behavior unchanged.
- Project renamed to **Krymux** (previously internal name ectun) ahead of the
  first public release: crate/binary `krymux`, log prefixes `krymux-server:` /
  `krymux-client:`, ALPN `krymux`, env vars `KRYMUX_LOG` / `KRYMUX_MUX_TRACE`.
  The `/sdk/ectun-browser.mjs` route, the vendored SDK file name, and the
  `ectun-ws-auth-v1` transcript label keep their historical spellings (the
  browser SDK is now vendored in-repo at `browser/ectun-browser.mjs`).

### Changed / Performance
- Persistent sync hash cache `.sync-cache.json` (size+mtime hit skips SHA-1):
  3000-file full pass 184-304 s -> 5.5-6.4 s; no-op pass 0.40 s -> 0.22 s.
- Writer batching (<=16 frames per syscall) + frame-allocation reduction in the
  outbound pump: 16 MiB echo none +13%, zstd +9% (none 415 -> 460 MB/s median).
- Sync scan parallelism cap 8 -> 16.

### Added
- Reproducible benchmark harness `bench/run-bench.sh` (+ `bench/BASELINE.md` with
  post-optimization numbers and the intermittent-degradation environment study:
  five host-level hypotheses tested and eliminated — see BASELINE.md).
- Stability soak `bench/soak.sh` (mixed load + reconnect storms + RSS timeline).

<details><summary>Development history before the rename</summary>

## [0.3.0] - 2026-09-22

### Added
- Deletion propagation (tombstones): deletions propagate across all clients with
  mtime last-writer protection, clock-skew correction, 30-day expiry, and readonly
  suppression on both sides (`deletion-semantics-probe.sh` verifies no resurrection).
- Typed sync protocol vocabulary in `sync/protocol.rs` (message consts + constructors;
  wire format unchanged) as the spec basis for future Go/Python SDKs.
- zstd dictionaries (`zstdDictionary` config): fingerprint-exact `zstdd` negotiation,
  automatic fallback to plain zstd against peers without the same dictionary.
- SOCKS5 UDP ASSOCIATE (RFC 1928) with a UDP relay on the server; FRAG != 0 refused.
- Browser SDK served built-in at `/sdk/ectun-browser.mjs` (embedded at build time
  from the Node reference repo).
- WS auth v2 transcript binding (domain-separated SHA-256 over both identities and
  nonces), dual-accept with v1; unauthenticated WS connection cap (256).

### Fixed
- Browsers could never complete WS auth against the Rust server: the advertised
  SPKI was a raw EC point, not DER (now byte-compatible with WebCrypto/Node).
- Pre-compressed payloads (magic-byte bypass) sent with FLAG_COMPRESSED set broke
  every compressed stream carrying already-compressed content.
- WS ping frames were never answered (and killed the connection during auth).

## [0.2.0-pre] - 2026-09-21 (pre-rename)

### Added

- Bidirectional file sync: uploads in addition to downloads. Client pushes
  stream through `put_start` / binary chunks / `put_done`, verified
  server-side by size and SHA-1, installed via tmp file plus atomic rename
  with mtime restoration.
- `--watch` daemon mode: local filesystem events (debounced by a quiet
  window) and server-pushed `rescan_hint` over a long-lived notify stream
  trigger immediate passes; the periodic reconcile interval remains the
  fallback; failed passes reconnect with exponential backoff (1 s to 60 s).
- Multi-client semantics: one sync server serves several clients
  concurrently; watcher events fired during a sync session coalesce into a
  single hint delivered to the other clients when the session ends.
- Concurrency hardening: exclusive root lock (`.sync.lock`, released
  automatically on exit or crash), startup lock checks, and cleanup of stale
  `*.sync-tmp` staging files.
- Cross-OS hardening: multi-address connect so a blackholed AAAA record
  cannot starve the connect budget, case-collision guard for
  case-insensitive filesystems (Windows/macOS), and a Windows-illegal-name
  guard (reserved device names, invalid characters, trailing dot/space).
- 1S2C (one server, two clients) scenarios in the end-to-end test matrix.

## [0.1.0-pre] - 2026-09-20 (pre-rename)

### Added

- Initial release: TLS 1.3 mutual authentication with an Ed25519
  fingerprint whitelist (fail closed on missing/unmatched certificates).
- CMPX multiplexing: credit-based per-stream flow control with dynamic
  window growth, per-stream compression negotiation, keepalive pings, and
  GOAWAY teardown.
- Compression: deflate, brotli, and zstd (feature-gated) with level presets
  (`algo:level`) and magic-prefix bypass for pre-compressed content.
- Local frontends: SOCKS5 CONNECT proxy and HTTP/1.1 proxy (CONNECT
  tunneling plus absolute-form forwarding).
- WebSocket browser branch: wss:// access with P-256 challenge-response
  authentication.
- `pq` feature switching the TLS crypto provider to aws-lc-rs.

</details>
