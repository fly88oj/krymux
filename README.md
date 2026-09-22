# Krymux
[![CI](https://github.com/fly88oj/krymux/actions/workflows/ci.yml/badge.svg)](https://github.com/fly88oj/krymux/actions/workflows/ci.yml) [![Integration](https://github.com/fly88oj/krymux/actions/workflows/integration.yml/badge.svg)](https://github.com/fly88oj/krymux/actions/workflows/integration.yml)

Secure service access over reverse tunnels.

**English** | [简体中文](README.zh-CN.md) | [日本語](README.ja.md) | [Deutsch](README.de.md) | [Français](README.fr.md) | [Español](README.es.md)

`krymux` exposes local services to the internet through a plaintext TCP relay such as frp — relays that provide no end-to-end encryption and no per-client access control. It runs a reverse proxy on the service machine and establishes a **TLS 1.3 mutually-authenticated encrypted tunnel** to the client (frp only ever sees ciphertext). Inside the tunnel is a **multiplexed set of logical streams** with **per-stream compression**, **credit-based flow control**, **half-close**, and **keepalive**. The trust model is WireGuard/SSH-shaped: the server holds a whitelist of client **Ed25519 public-key fingerprints** (`sha256(SPKI)`), and the client **pins the server's fingerprint** against man-in-the-middle attacks.

This repository is the **Rust implementation**: a Cargo workspace whose `crates/krymux` is a pure protocol **SDK** library, with two small applications on top of it — `krymux-tunnel` (tunnel operations CLI) and `krymux-sync` (file sync) — each a ~5 MB static binary with no runtime dependencies. It is **wire-protocol compatible with the TypeScript SDK** (`sdks/typescript`, ported from the Node reference) and the Go/Python SDKs under `sdks/` — same Ed25519 fingerprint identity system, same JSON config schema, all ends freely interchangeable and cross-benchmarked.

```
User program ── local SOCKS5/HTTP proxy or SDK ──> krymux client
     ═══ TLS 1.3 (mutual Ed25519 auth) + multiplexing + compression ═══   ← frp sees only ciphertext
              via frps (public) → frpc relay → machine-local preset port
                                          └──> krymux server (reverse proxy)
                                               ├─ host a.test  → 127.0.0.1:3000
                                               ├─ host *.test  → 127.0.0.1:8080
                                               └─ any port / Unix socket / client-chosen target (optional)

Browser (no client process needed)
     ═══ wss:// → TLS → WebSocket → P-256 signature auth + CMPX multiplexing ═══
              same port (HTTP GET detection branch), likewise relayed through frp
                                          └──> same krymux server
```

## Features

- **End-to-end encryption** — TLS 1.3 only (ALPN `krymux`), Ed25519 certificates, AES-GCM/ChaCha20-Poly1305; the frp link carries nothing but ciphertext.
- **Public-key whitelist** — `sha256(SPKI)` fingerprint *is* the identity; fail-closed admission after the handshake. The client pins the server fingerprint.
- **Multiplexing** — hundreds of full-duplex logical streams over one TLS connection (a browser opening 50 connections = 1 handshake).
- **Per-stream compression** — `deflate` / `brotli` / `zstd` with continuous contexts and streaming flush; `none` pass-through; `auto` negotiation. Level presets like `"zstd:9"`, `"brotli:11"`, `"deflate:9"`.
- **Magic-byte bypass** — first-chunk sniffing detects already-compressed content (gzip/zstd/zip/png/jpeg/7z/rar/pdf/bzip2/mp4) and automatically switches that stream to `none` (saves CPU, avoids expansion).
- **Credit-based flow control** — per-stream windows accounted on *decompressed* bytes; slow consumers cannot exhaust memory or starve other streams. Dynamic window auto-growth doubles the grant every 100 ms while a stream drains: 4 → 32.4 MB/s on a single stream at 50 ms RTT (from the old fixed 256 KB window up to the 4 MB cap).
- **Protocol transparency** — TCP byte-stream semantics with half-close preserved; HTTP/WebSocket/SSH/database protocols pass through verbatim.
- **vhost routing** — the client names a hostname; the server routes by host / port / fallback / client-chosen target to different upstreams.
- **Browser (WebSocket) access** — `wss://` with P-256 app-layer signature authentication sharing the same fingerprint whitelist; built-in launcher page; zero-dependency browser SDK.
- **Bidirectional file sync** — SHA-1 hash diff, mtime clock-offset alignment, atomic writes, lock detection, watch daemon with server-pushed change hints.
- **Post-quantum build** — `--features krymux/pq` (aws-lc-rs backend) negotiates the X25519MLKEM768 hybrid KEM.
- **Single binary, no runtime deps** — pure-Rust dependency chain in the base build.

## Architecture

**Krymux is an SDK; every executable is an app on top of it.**

- `crates/krymux` — the **SDK**: a pure library (no binary) implementing the whole wire protocol — TLS 1.3 mutual auth, Ed25519 identities, CMPX framing/multiplexing/flow control, compression, vhost routing, SOCKS5/HTTP frontends, and the browser (WebSocket) frontend.
- `apps/krymux-tunnel` — **tunnel operations CLI** (`keygen`, `fingerprint`, `probe`, `server`, `client` with `--socks5`/`--http-proxy`); install with `cargo install --path apps/krymux-tunnel`.
- `apps/krymux-sync` — **FileSync application** (`sync-server`, `sync-client --watch/--interval/--mode`); install with `cargo install --path apps/krymux-sync`.
- `browser/` — the vendored **browser JS SDK** (`ectun-browser.mjs`), embedded into server binaries at build time.
- `sdks/typescript`, `sdks/golang`, `sdks/python` — **additional language SDKs**: TypeScript (zero runtime deps), Go (stdlib only) and Python (cryptography only), each wire-compatible (ALPN `krymux`, Ed25519 fingerprint trust, credit flow control, half-close, none/deflate compression) and interop-tested against the Rust binaries in both directions.

Dependency edges run one way only: apps → SDK. Nothing in the SDK depends on clap or on any application code, so embedding the protocol in another binary is `krymux = { path = "crates/krymux" }` (or the published crate) away.

## Architecture positioning

**The protocol SDK stays multi-language; the applications are Rust-only.**

- The protocol SDK (frames / multiplexing / TLS / compression) keeps two implementations — Node (reference) and Rust — as mutual regression baselines; Go and Python are planned.
- Higher-level applications (file sync, WS frontend extensions, …) are implemented **only in Rust** to keep the maintenance surface small.
- The Node package is positioned as a **pure protocol reference** (no applications); production deployment uses this Rust binary.

### Implementation notes (Rust)

- **TLS**: rustls (ring backend), TLS 1.3 only, ALPN `krymux`. The server requires a client certificate from any issuer, then admits the connection against the `sha256(SPKI)` whitelist (fail-closed). The client pins the server fingerprint. Certificates are generated by rcgen (Ed25519).
- **Multiplexing**: the same frame format as the Node version (see [`../ectun/docs/PROTOCOL.md`](../ectun/docs/PROTOCOL.md)) — per-stream credit flow control (accounted on decompressed bytes), continuous compression contexts, half-close propagation.
- **Task model**: two tasks per connection (reader/writer) + per-stream inbound/outbound pumps + credit ticker + keepalive; data reaches the application via tokio duplexes. Tunnel sockets set `TCP_NODELAY`.
- **Compression**: `deflate` (flate2), `brotli` (brotli crate, low-level push API), `zstd` (optional feature). Brotli decompression uses the `BrotliDecompressStream` low-level API — `DecompressorWriter` parks output in an internal buffer and its flush does not drive decoding, which loses tail bytes on large cross-implementation transfers; the low-level path avoids this.
- **Fixed (postmortem archived)**: an EOF tail bug caused by a `Drop` double-lock self-deadlock (a non-reentrant std `Mutex` locked again inside an `if let` predicate — permanent hang, `JoinHandle` never returns). Also fixed: the tokio split write-half not sending EOF on drop (explicit `poll_shutdown` + server-side `stream.shutdown()`), and documented that "write everything, then read" backpressure deadlocks identically on raw TCP — the correct pattern is to write while reading, which browsers/curl do naturally.

## Build

```bash
cargo build --release                                # workspace: SDK + both apps, pure-Rust dependency chain
cargo build --release --features krymux/zstd         # + zstd (C compilation verified under MSVC/gcc) — recommended
cargo build --release --features krymux/pq           # + aws-lc-rs post-quantum KEM (~5.7 MB binaries)
cargo build --release --features "krymux/pq krymux/zstd"  # everything
# artifacts: target/release/krymux-tunnel and target/release/krymux-sync — no runtime dependencies
```

Cross-compiling for Linux (deploying to a server or LXD):

```bash
rustup target add x86_64-unknown-linux-gnu
# with a Linux-side linker: cargo build --release --target x86_64-unknown-linux-gnu
# or use cross / cargo-zigbuild
```

Note: the base build advertises `none`/`deflate`/`brotli` in HELLO negotiation; `zstd` requires the `zstd` feature.

## Quick start

CLI surface (same shape as the Node version; tunnel operations in `krymux-tunnel`, file sync in `krymux-sync`):

| Command | Purpose |
|---|---|
| `krymux-tunnel keygen --out <dir> --role server\|client [--name x] [--cn cn]` | Generate an Ed25519 identity (key + self-signed cert + fingerprint) |
| `krymux-tunnel fingerprint <key-or-cert.pem>` | Print the fingerprint of a PEM file |
| `krymux-tunnel probe <host:port>` | Show a server's key fingerprint (TOFU helper) |
| `krymux-tunnel server --config server.json` | Run the reverse-proxy server |
| `krymux-tunnel client --config client.json [--socks5 h:p] [--http-proxy h:p]` | Run the client (optionally with local proxy frontends) |
| `krymux-sync sync-server --path <dir> [--port 17890] [--mode bidir\|readonly]` | Run a file-sync server behind krymux |
| `krymux-sync sync-client --path <dir> --config client.json [--mode …] [--watch] [--interval 30]` | Run a file-sync client through the tunnel |

### 1. Generate identities on both ends

```bash
./target/release/krymux-tunnel keygen --out ./keys --role server
./target/release/krymux-tunnel keygen --out ./keys --role client --name alice
```

Each command prints the identity's `sha256:` fingerprint.

### 2. (TOFU) Check the server fingerprint

If you don't know the server fingerprint yet, verify it out-of-band once and write it into the config:

```bash
./target/release/krymux-tunnel probe frp.example.com:7000
```

### 3. Server config (on the service machine — this is the port frpc forwards to)

```jsonc
// server.json
{
  "listen": "127.0.0.1:7443",                       // ← frpc's localPort points here
  "identity": { "key": "keys/server.key.pem", "cert": "keys/server.crt.pem" },
  "auth": {
    "mode": "whitelist",
    "fingerprints": [ "sha256:<alice fingerprint, printed by keygen>" ]
  },
  "routes": [
    { "host": ["nas.example"], "upstream": ["127.0.0.1", 5000] },
    { "host": ["*.example"],   "upstream": ["127.0.0.1", 80] },
    { "host": ["db"], "port": 5432, "upstream": ["127.0.0.1", 5432] }
  ],
  "fallbackUpstream": ["127.0.0.1", 80],            // route for unmatched hosts
  "clientTargets": { "enabled": false }             // true = allow clients to pick arbitrary host:port
}
```

```bash
./target/release/krymux-tunnel server --config server.json
```

### 4. Client config (anywhere)

```jsonc
// client.json
{
  "endpoint": "frp.example.com:7000",               // ← the public port frps exposes
  "identity": { "key": "keys/alice.key.pem", "cert": "keys/alice.crt.pem" },
  "serverFingerprint": "sha256:<server fingerprint from probe>",
  "compression": "auto"
}
```

```bash
./target/release/krymux-tunnel client --config client.json --socks5 127.0.0.1:1080
```

### 5. Use it

Point a browser or curl at the local SOCKS5 proxy — **the hostname becomes the vhost routing key**:

```bash
curl --socks5-hostname 127.0.0.1:1080 http://nas.example/
```

`--http-proxy 127.0.0.1:8080` provides an HTTP/1.1 proxy frontend (CONNECT + absolute-form) instead. Config fields are identical to the Node version; see [`../ectun/examples/`](../ectun/examples/) for complete scenarios.

## File sync

```bash
# Host A (server side, behind krymux)
krymux-sync sync-server --path /data --port 17890 [--mode bidir|readonly]
# krymux server config: { "host": ["sync"], "upstream": ["127.0.0.1", 17890] }

# Host B (client side, through the tunnel)
krymux-sync sync-client --path /data --config client.json [--mode bidir|readonly]

# Daemon mode: keep running, push local changes immediately, pull remote changes,
# auto-reconnect on failure
krymux-sync sync-client --path /data --config client.json --watch --interval 30
```

### Sync engine

- **Bidirectional**: download server → client and upload client → server, driven by **SHA-1 hash comparison**, **mtime clock-offset alignment** between the two machines, **atomic writes** (tmp file → rename), and **lock detection**.
- **Read-only mode is negotiated** via `hello_ack`: when the server is read-only the client automatically suppresses uploads, and the server still rejects `put` regardless.
- **Conflict reporting** for concurrent edits (see multi-client semantics below).
- **Path-traversal protection**: `..` segments, absolute paths, and drive letters are always rejected.

### Watch daemon (`--watch`, `apps/krymux-sync/src/sync/daemon.rs`)

- **Local changes** → notify events with a **700 ms debounce quiet period**, skipping `*.sync-tmp` and read events (inotify reports our own scan's hash reads as changes; unfiltered, this self-triggers a loop on Linux).
- **Remote changes** → pushed proactively by the server (`rescan_hint`): sync-server watches its own tree (`apps/krymux-sync/src/sync/notify.rs`) and notifies connected daemons immediately on change — hint arrival is second-level. Hints are **suppressed while a sync session is active** (so the server doesn't echo back the uploads it is receiving); one coalesced hint fires at session end, which is also what propagates changes to other clients. Old servers without hint support degrade silently and the interval takes over.
- **`--interval`** (default 30 s) periodic reconciliation is now a **safety net** (lost hints / old servers) rather than the primary mechanism.
- **Reconnect**: on tunnel loss the next pass fails and rebuilds the tunnel with exponential backoff starting at 1 s, capped at 60 s.
- **Kill-safe at any moment**: all writes go through tmp+rename and scans skip debris.

### Multi-client semantics

N clients may sync the same server root simultaneously. One client's changes are broadcast to the others within seconds via the session-end hint (no waiting for the interval). Concurrent edits of the same file converge **last-writer-wins by mtime** — every endpoint eventually agrees, with no mixed content.

### Locks and startup conflicts (verified by the 8 phases of `edge-e2e.sh`)

- **Root mutual exclusion**: sync-server/sync-client take an exclusive OS file lock on `<root>/.sync.lock` at startup (std 1.89 native API: `LockFileEx` on Windows, `flock` on Unix). A second process on the same root is refused outright; a crashed process releases the lock automatically — no stale-lock recovery needed.
- **Startup lock check**: if any file in the root is held exclusively by another process, startup is refused and the offending files are listed.
- **Runtime locks**: files locked on the client side are skipped for the pass (untouched). Files locked or unreadable on the server side (including scan-time read failures = hash `None`) are treated as *undeterminable → skip this pass*, never misclassified as conflicts.
- **Crash debris**: `kill -9` at any moment is safe (tmp+rename atomicity; E2E-tested with 500 MB, no tearing). Stale `*.sync-tmp` files ≥ 1 h old are cleaned at startup.
- **Single-point failure isolation**: one un-installable file (e.g. a directory placeholder) is skipped without starving the rest of the pass; a failed download verification (size/hash) is retried once within the pass.
- **Verification boundary**: the file-lock end-to-end path is verified on Windows (real sharing violations); unprivileged Linux containers cannot simulate unwritable files (root ignores chmod; chattr needs `CAP_LINUX_IMMUTABLE`), so the Linux side is verified via two-process `flock` exclusion plus kill-and-revive.

### Cross-OS compatibility (Windows ↔ Linux, tested through an LXD-proxy-simulated relay)

- **Connect layer**: multi-address resolution with sequential attempts and an independent **5 s timeout per address** — mDNS/DNS names with several A/AAAA records no longer starve the connection budget when IPv6 is blackholed (observed with `myhost.local` returning 3×IPv6 + 2×IPv4, where blackholed IPv6 caused guaranteed timeouts).
- **Filenames**: UTF-8 (Chinese filenames + content) lossless in both directions; **Windows-illegal names** (`<>:"|?*`, reserved names like `CON`/`COM1`, trailing dots/spaces) are skipped with a warning; **case collisions** (Linux `Foo.txt` + `foo.txt`) warn on every platform, and case-insensitive platforms sync only the first-seen name (preventing perpetual download-overwrite flip-flop); long paths work (Windows `\\?\` prefix, tested at 212 characters).
- **Symlinks**: skipped per `lstat` semantics (not followed, not propagated, no cycle risk).
- **mtime across filesystems**: NTFS↔ext4 round-trips stay stable via hash short-circuiting (identical content = no-op).
- **Boundary**: macOS (FSEvents watcher) has never been built or run — unverified.

### Deletion propagation (tombstones)

Deletions propagate to every client (30-day tombstone store `.sync-tombstones.json`, a persistent hash cache `.sync-cache.json` (size+mtime hits skip re-hashing; full pass ~30-50x faster),
clock-skew-corrected mtime last-writer protection, readonly suppression on both
sides). Deleting a file and then editing it elsewhere: the newer content wins.
Verified bidirectionally with no resurrection by `deletion-semantics-probe.sh`.

## Browser (WebSocket) access

The server serves three connection kinds on the **same TLS port**, dual-mode by detection: native mTLS clients (Ed25519 cert + ALPN `krymux`) vs. everything without a client certificate, where an HTTP `GET` branches into the WebSocket/static path. frp just keeps forwarding TCP ciphertext — no extra configuration.

1. Start the server. It auto-generates a browser identity (`ws-p256.key.pem`, P-256) and logs its `wsFingerprint`.
2. Open `https://<frps-public-port>/` in a browser (accept the self-signed certificate exception once) — the built-in launcher page loads.
3. Add the identity fingerprint shown on the page to the server's `auth.fingerprints` — the **same whitelist** native clients use.
4. Refresh, enter a target `host:port`, connect — any routed service is reachable from the browser tab.

Authentication is equivalent in strength to mTLS: one `sha256(SPKI)` whitelist mixes Ed25519 (native) and P-256 (browser) entries; the client's app-layer signature proves whitelist identity, the server's signature proves the pinned identity (inside TLS). The Rust server enforces a 10 s auth timeout and a 256-connection concurrent WS cap. The SDK is a zero-dependency single-file ESM (`ectun-browser.mjs`, vendored in this repository at `browser/ectun-browser.mjs` — serve or import it; the wire protocol is identical):

```js
import { getIdentity, connect } from '/sdk/ectun-browser.mjs';
const id = await getIdentity();          // P-256 identity, persisted in IndexedDB
// id.fingerprint → add to the server whitelist
const c = await connect({
  endpoint: 'wss://frps.example:7000',
  serverFingerprint: 'sha256:…',         // pin the server's WS identity
  identity: id,
});
const s = await c.openStream({ host: 'a.test', port: 80 });
await s.write(new TextEncoder().encode('GET / HTTP/1.1\r\nHost: a.test\r\n…'));
await s.end();
s.onData((chunk) => …); s.onEnd(() => …);
```

SDK v1 advertises `none` compression (the CMPX negotiation is ready for future upgrades). Protocol details: [`../ectun/docs/PROTOCOL.md` §6A](../ectun/docs/PROTOCOL.md).

## Verification

```bash
bash e2e-sync-test.sh   # file sync: 9-phase main flow
bash edge-e2e.sh        # file sync: 8 edge phases (locks / crash / conflicts)
```

- **Interop 11/11** against the Node reference (`interop/test-interop.mjs`):
  - Node client → Rust server: none/deflate/brotli 1 MB echo byte-identical, dual-vhost routing, unrouted target rejected, non-whitelisted key rejected;
  - Rust client → Rust server: SOCKS5 + vhost (exercised with curl);
  - Rust client → Node server: none/deflate/brotli 1 MB echo byte-identical.
- **Fingerprint interop**: the Node `fingerprint` command computes the same value for Rust-keygen certificates and vice versa.
- **LXC deployment template**: two-container setup in [`deploy/lxc/`](deploy/lxc/) — `server.json` / `client.json` / systemd units for server, sync-server, and sync-client(s). Real-machine results there: 100 MB transferred md5-identical, cross-client propagation in ~2 s, rescan-hint delivery in ~1 s.

## Performance

Loopback benchmarks (Node numbers from the Node reference, Node 24.15, see [`../ectun/docs/BENCHMARKS.md`](../ectun/docs/BENCHMARKS.md); Rust numbers from `examples/bench`, 16 MB echo):

| Configuration | Throughput |
|---|---|
| Rust, 16 MB echo, no compression | ~405 MB/s |
| Rust, 16 MB echo, zstd (compressible text) | ~739 MB/s |
| Node reference, no compression (×1/×4 streams) | ~80 MB/s (single-core JS ceiling) |
| Node reference, zstd ×4 streams (text) | ~319 MB/s |
| Node reference, brotli ×4 streams (text) | ~285 MB/s |
| **Window auto-growth, single stream @ 50 ms RTT** | **4.0 → 32.4 MB/s** (fixed 256 KB → auto up to 4 MB) |
| Through a TCP relay (frp simulated) | no measurable penalty |
| Stream-open latency | p50 0.28 ms (within an established connection) |
| Full TLS handshake | ~6 ms (loopback) |

Compression often *raises* throughput (fewer bytes on the wire); the window bottleneck on real frp links is eliminated by auto-growth, leaving public bandwidth and compression CPU as the limits.

## Configuration reference

JSON with camelCase keys, identical schema in both implementations.

### server.json

| Field | Type | Default | Description |
|---|---|---|---|
| `listen` | string | *required* | `host:port` to listen on; frpc's `localPort` points here |
| `identity.key`, `identity.cert` | string | *required* | Ed25519 PEM paths from `keygen` |
| `auth.mode` | string | `"whitelist"` | admission mode |
| `auth.fingerprints` | string[] | `[]` | `sha256(SPKI)` client whitelist (`auth.clients` entries are merged in) |
| `routes[].host` (alias `hosts`) | string or string[] | — | vhost match keys; wildcards like `*.example` |
| `routes[].port` (alias `ports`) | number, `"n"`, `"a-b"`, `"*"`, or array | — | optional port pattern for the route |
| `routes[].upstream` | `[host, port]`, `"host:port"`, `"unix:/path"`, or `{host, port}` / `{unix}` | — | where matched traffic is delivered |
| `fallbackUpstream` (alias `defaultUpstream`) | upstream | — | route for hosts matching no route |
| `clientTargets.enabled` | bool | `false` | allow clients to specify arbitrary `host:port` targets |
| `clientTargets.allowHosts` | string[] | `["*"]` | host patterns a client may pick |
| `clientTargets.allowPorts` | pattern[] | — | port patterns a client may pick |
| `keepaliveSec` | integer | `30` | keepalive interval |
| `maxStreams` | integer | `1024` | max logical streams per connection |
| `rxWindow` | integer | `262144` (256 KB) | initial per-stream receive window |
| `rxWindowMax` | integer | `4194304` (4 MB) | auto-growth cap; set equal to `rxWindow` to disable growth |
| `log.level` | string | `"info"` | log level |
| `statsIntervalMs` | integer | — | periodic stats printing |

### client.json

| Field | Type | Default | Description |
|---|---|---|---|
| `endpoint` | string | *required* | public `host:port` exposed by frps |
| `identity.key`, `identity.cert` | string | *required* | client Ed25519 PEM paths |
| `serverFingerprint` | string | *required* | pinned server fingerprint `sha256:…` |
| `compression` | string | `"auto"` | `none` / `auto` / `deflate` / `brotli` / `zstd` (zstd build), or level presets like `"zstd:9"`, `"brotli:11"`, `"deflate:9"` (applies to the sending side) |
| `keepaliveSec` | integer | `30` | keepalive interval |
| `rxWindow` | integer | `262144` (256 KB) | initial per-stream receive window (settable on both ends) |
| `rxWindowMax` | integer | `4194304` (4 MB) | auto-growth cap |
| `socks5` | string | — | local SOCKS5 frontend address, e.g. `127.0.0.1:1080` |
| `httpProxy` | string | — | local HTTP/1.1 proxy frontend (CONNECT + absolute-form) |
| `log.level` | string | `"info"` | log level |

Window auto-growth: when a stream has consumed over half its window and drained it, the grant doubles every 100 ms; backpressured streams do not grow. Both ends may configure `rxWindow`/`rxWindowMax`; `rxWindowMax = rxWindow` disables growth.

## Troubleshooting

- `KRYMUX_LOG=debug` for debug logging.
- `KRYMUX_MUX_TRACE=1` for frame-level tracing on stderr (including flags).


## Testing & CI

Every commit runs three parallel integration jobs (`.github/workflows/integration.yml`):

- **coverage** — Rust line coverage via cargo-llvm-cov (subprocess-instrumented app
  binaries merged) with a **55% gate**, plus Go / Python / TypeScript coverage
  numbers in the job summary; lcov artifact attached. Current: Rust ≈61%
  (SDK crate ≈69%), Go 65%, Python 76%, TS 89%.
- **integration-linux** — workspace tests incl. `tests/integration.rs`
  (parameterized edge matrix: window × compression × payload-size, 54 combos in
  4 test functions), each language SDK's interop vs the Rust binaries, the
  6-direction cross-language matrix, and the POSIX e2e/deletion suites.
- **integration-windows** — the full bash E2E suites (14-phase sync matrix,
  8-phase edge/lock cases, deletion probe) incl. Windows-exclusive-handle paths.

`tests/integration.rs` is the fast cross-platform core (≈10 s): table-driven
parameterization instead of near-duplicate test functions — same coverage,
different parameters (window sizes, compression, 0/1/65535/65536/65537/1MiB
payloads, frame edges, sync lifecycle/conflicts).

## Roadmap

- **zstd dictionaries (`zstdd`)** — design finalized: offline `zstd --train`, both sides referencing the same dictionary, HELLO compression negotiation of `zstdd` with a dictionary-fingerprint suffix check; expected 2–4× smaller first packets on short streams (HTTP/API). The Node side needs a native binding or negotiated fallback to plain zstd.
- **PAD frame length bucketing** with fixed-rate cover traffic (reserved in protocol v1.1).
- **Cluster / multi-core** throughput.
- **UDP** support.
- **Go / Python SDKs**.
- **Noise-style key derivation** for WS auth.
- **macOS** build & verification (FSEvents watcher).

## License

MIT
