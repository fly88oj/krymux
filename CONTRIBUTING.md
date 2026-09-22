# Contributing to Krymux

Thanks for contributing! This repository is the Rust implementation of the
krymux tunnel; the Node implementation is the wire-compatibility reference.

## Building

This is a Cargo workspace: `crates/krymux` is the pure library SDK, and every
executable is an app on top of it (`apps/krymux-tunnel`, `apps/krymux-sync`).

Debug build:

```
cargo build
```

Recommended release build (enables zstd compression):

```
cargo build --release --features krymux/zstd
```

Feature flags live on the `krymux` SDK crate, so workspace commands select
them as `--features krymux/<flag>`:

- `zstd` — adds zstd to the negotiated compression algorithms (off by default).
- `pq` — switches the TLS crypto provider to aws-lc-rs.

## Verification

Before opening a PR, run the following and make sure they are clean:

```
cargo clippy --workspace --all-targets --features krymux/zstd
```

Must report zero warnings for every workspace member.

```
cargo check --workspace --features krymux/zstd
cargo doc --no-deps -p krymux --features krymux/zstd
```

End-to-end suites (bash, from the repository root; build the release binaries
first — they drive `target/release/krymux-tunnel.exe` and
`target/release/krymux-sync.exe`):

```
cargo build --release --features krymux/zstd
bash e2e-sync-test.sh
bash edge-e2e.sh
```

Interop against the Node reference implementation:

```
cd interop && node test-interop.mjs
```

## Conventions

- Comments, commit messages, and documentation are in English only.
- Documentation follows rustdoc conventions: `//!` module-level docs, `///`
  on public items, written in the third person, without trivial
  restatements of the item name.
- Keep changes wire-compatible with the Node reference implementation unless
  the change is explicitly versioned in the protocol.
- The SDK crate must stay a pure library: no `main.rs`, no CLI dependencies
  (clap/env_logger), no application code. New executables go under `apps/`
  and depend on the SDK by path.

## Pull requests

- No behavior changes without tests: bug fixes and features need a covering
  case in the end-to-end suites or a unit test.
- Keep PRs focused and describe the what and the why, not just the how.
- Documentation-only changes are welcome and do not require new tests.

## Project layout

```
crates/krymux/           the SDK — pure library crate (no binary)
  src/lib.rs             crate root and module list
  src/keys.rs            Ed25519 identities and fingerprints
  src/tls.rs             TLS 1.3 mutual-auth setup (rustls)
  src/frame.rs           CMPX wire framing
  src/mux.rs             CMPX multiplexing session and streams
  src/compress.rs        deflate/brotli/zstd chunk compression
  src/router.rs          target-to-upstream routing
  src/server.rs          server connection handling
  src/client.rs          client tunnel API
  src/socks5.rs          local SOCKS5 frontend
  src/httpproxy.rs       local HTTP/1.1 proxy frontend
  src/ws.rs              WebSocket (browser) frontend
  src/config.rs          JSON configuration loading
  examples/              small repro and benchmark programs (SDK APIs only)
  tests/                 SDK-level integration tests (mux regression, UDP relay)
apps/krymux-tunnel/      tunnel operations CLI (keygen, fingerprint, probe, server, client)
apps/krymux-sync/        FileSync application — sync engine + sync-server/sync-client CLI
browser/                 vendored browser JS SDK (embedded by build.rs)
interop/                 Node interop tests
bench/                   benchmark harness and soak script
deploy/                  deployment helpers
```

## Integration tests & coverage (local)

```bash
cargo test --workspace --features krymux/zstd     # incl. tests/integration.rs (≈10 s)
bash e2e-sync-test.sh && bash edge-e2e.sh && bash deletion-semantics-probe.sh
bash scripts/xlang-matrix.sh                        # 6 cross-language directions
cargo llvm-cov --workspace --features krymux/zstd   # coverage (CI gate: 55% lines)
```

Testing principles: prefer ONE table-driven parameterized test over copied
near-duplicate functions (see `crates/krymux/tests/integration.rs` — 54
window×compression×payload combinations in a single loop). Edge parameters
sharing code paths still need explicit rows: same coverage, different behavior.
