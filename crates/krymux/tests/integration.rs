//! Cross-platform integration suite (pure Rust — no bash, no cygpath, runs
//! on Linux and Windows CI alike).
//!
//! Three table-driven parameterized groups, deliberately folded into as few
//! test functions as possible (the "same coverage, different parameters"
//! mandate: one loop over a parameter matrix instead of near-duplicate fns):
//!
//! - `echo_matrix` — window x compression x payload-size matrix over two
//!   in-process `MuxSession`s joined by a duplex pair with an echo handler
//!   closure; asserts byte-exact echo for every combination.
//! - `sync_semantics_*` — bidirectional file-sync lifecycle against the real
//!   `krymux-sync`/`krymux-tunnel` binaries (located via `KRYMUX_*_BIN`, else
//!   the workspace target dir): initial sync, both-direction edits,
//!   deletions, readonly rejection, conflict resolution and
//!   delete-then-recreate — the phases of e2e-sync-test.sh /
//!   deletion-semantics-probe.sh merged into two sequential-phase functions.
//! - `frame_edge` — wire-frame edges: length-0 frames, max-length headers,
//!   unknown-type and truncated-header rejection, oversized-frame GOAWAY at
//!   session level (driving one session half with raw bytes).
//!
//! Readiness is always a 1 s poll with early exit; there are no blind sleeps.

use krymux::compress;
use krymux::frame::{
    encode_frame, frame_header, FrameHeader, DEFAULT_MAX_DATA, FLAG_COMPRESSED, FLAG_FIN, FT_DATA,
    FT_GOAWAY, FT_HELLO, FT_OPEN, FT_OPEN_ACK, FT_PING, FT_PONG, FT_WINDOW, HARD_MAX_FRAME,
    HEADER_SIZE,
};
use krymux::mux::{MuxSession, SessionOpts, Target, TunnelStream};
use serde_json::json;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ===========================================================================
// echo_matrix — window x compression x payload, one loop-driven test
// ===========================================================================

fn opts(is_client: bool, window: u32) -> SessionOpts {
    SessionOpts {
        is_client,
        name: if is_client { "c" } else { "s" }.into(),
        // FIXED window (rx == rx_max): flow control is exercised at exactly
        // the parameter under test, including the 16 KiB credit-starved case
        rx_window: window,
        rx_window_max: window,
        max_streams: 8,
        keepalive_sec: 0,
    }
}

/// In-loop echo handler: everything the stream receives is written back,
/// then the handler half-closes — the same closure shape the server uses
/// for raw upstreams.
fn echo_handler(stream: TunnelStream, _t: Target) {
    tokio::spawn(async move {
        stream.accept(Some("echo"));
        let mut s = stream;
        let mut buf = vec![0u8; 64 * 1024];
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
}

fn echo_target() -> Target {
    Target {
        host: Some("echo".into()),
        port: 9,
        unix: None,
        hint: "raw".into(),
    }
}

/// Deterministic payload: a 251-byte cycle (compressible, not all-zero).
fn payload(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i % 251) as u8).collect()
}

/// One byte-exact echo over a fresh stream; returns the echoed bytes.
async fn echo_once(client: &MuxSession, algo: &str, n: usize, label: &str) -> Vec<u8> {
    let s = tokio::time::timeout(
        Duration::from_secs(10),
        client.open_stream(echo_target(), algo),
    )
    .await
    .unwrap_or_else(|_| panic!("{label}: open_stream stalled"))
    .unwrap_or_else(|e| panic!("{label}: open_stream: {e:#}"));

    // the negotiated algorithm must match the request modulo feature support
    let expect = match (algo, cfg!(feature = "zstd")) {
        ("zstd", false) => "none", // negotiated down: peer lacks zstd
        (a, _) => a,
    };
    assert_eq!(s.compression(), expect, "{label}: negotiated algorithm");

    let data = payload(n);
    let want = data.clone();
    // Writer and reader run CONCURRENTLY (mux_regression's
    // writer-finishes-first shape): the peer's credit grants depend on the
    // app consuming echoed bytes, so a strictly sequential write-then-read
    // can deadlock once the payload exceeds the receive window.
    let (mut r, mut w) = tokio::io::split(s);
    let echoed = tokio::time::timeout(Duration::from_secs(60), async {
        let writer = async {
            if !data.is_empty() {
                w.write_all(&data).await?;
            }
            w.shutdown().await?;
            Ok::<(), anyhow::Error>(())
        };
        let reader = async {
            let mut got = Vec::new();
            r.read_to_end(&mut got).await?;
            Ok::<Vec<u8>, anyhow::Error>(got)
        };
        tokio::try_join!(writer, reader).map(|(_, got)| got)
    })
    .await
    .unwrap_or_else(|_| panic!("{label}: echo stalled"))
    .unwrap_or_else(|e| panic!("{label}: echo io: {e:#}"));
    assert_eq!(echoed, want, "{label}: byte-exact echo");
    echoed
}

/// Parameter matrix: rx-window x compression x payload size. 3 x 3 x 6 = 54
/// combinations in ONE test function — the same coverage the old per-algo /
/// per-size near-duplicate tests would have spread across dozens of fns.
/// One session pair per (window, algo); the six payload sizes run as six
/// consecutive streams on that pair.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn echo_matrix() {
    const WINDOWS: [u32; 3] = [16 * 1024, 256 * 1024, 4 * 1024 * 1024];
    const ALGOS: [&str; 3] = ["none", "deflate", "zstd"];
    const SIZES: [usize; 6] = [0, 1, 65535, 65536, 65537, 1024 * 1024];

    let mut combos = 0usize;
    let mut bytes = 0usize;
    for &window in &WINDOWS {
        for &algo in &ALGOS {
            let (a, b) = tokio::io::duplex(64 * 1024);
            let server_task = tokio::spawn(async move {
                MuxSession::start(b, opts(false, window), Some(Arc::new(echo_handler))).await
            });
            let client = MuxSession::start(a, opts(true, window), None)
                .await
                .unwrap_or_else(|e| panic!("window={window} algo={algo}: client session: {e:#}"));
            let server = server_task
                .await
                .unwrap()
                .unwrap_or_else(|e| panic!("window={window} algo={algo}: server session: {e:#}"));

            for &n in &SIZES {
                let label = format!("window={window} algo={algo} size={n}");
                let got = echo_once(&client, algo, n, &label).await;
                bytes += got.len();
                combos += 1;
            }
            drop(client);
            drop(server);
        }
    }
    eprintln!("echo_matrix: {combos} combinations, {bytes} echoed bytes, all byte-exact");
}

// ===========================================================================
// sync_semantics — the real binaries, phases merged into two test fns
// ===========================================================================

/// Locate a workspace binary: env override, else `<target>/{debug,release}`.
fn find_bin(env_var: &str, name: &str) -> Option<PathBuf> {
    if let Some(p) = std::env::var_os(env_var) {
        let p = PathBuf::from(p);
        assert!(p.is_file(), "{env_var}={p:?} does not exist");
        return Some(p);
    }
    let exe = if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_string()
    };
    let target = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target"));
    ["debug", "release"]
        .iter()
        .map(|prof| target.join(prof).join(&exe))
        .find(|p| p.is_file())
}

fn require_sync_bins() -> Option<(PathBuf, PathBuf)> {
    let pair = find_bin("KRYMUX_SYNC_BIN", "krymux-sync")
        .zip(find_bin("KRYMUX_TUNNEL_BIN", "krymux-tunnel"));
    if pair.is_none() {
        if std::env::var_os("KRYMUX_INTEGRATION_REQUIRE_BINS").is_some() {
            panic!(
                "sync binaries not found but required (KRYMUX_INTEGRATION_REQUIRE_BINS is set); \
                 build with: cargo build --workspace"
            );
        }
        eprintln!(
            "skipping sync_semantics: krymux-sync / krymux-tunnel binaries not found \
             (build with `cargo build --workspace`, or set KRYMUX_SYNC_BIN/KRYMUX_TUNNEL_BIN)"
        );
    }
    pair
}

/// A running `krymux-tunnel server` + `krymux-sync sync-server` pair over a
/// temp directory, plus the client config that reaches the sync root through
/// the tunnel. Dropping the stack kills both processes.
struct SyncStack {
    #[allow(dead_code)] // kept for debugging; killed on drop
    dir: PathBuf,
    tunnel: tokio::process::Child,
    sync: tokio::process::Child,
    client_cfg: PathBuf,
}

impl Drop for SyncStack {
    fn drop(&mut self) {
        let _ = self.tunnel.start_kill();
        let _ = self.sync.start_kill();
    }
}

fn unique_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "krymux-it-{}-{}-{tag}",
        std::process::id(),
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn spawn_logged(bin: &Path, args: &[&str], log: &Path) -> tokio::process::Child {
    let log_file = std::fs::File::create(log).unwrap();
    let out = log_file.try_clone().unwrap();
    tokio::process::Command::new(bin)
        .args(args)
        .stdout(log_file)
        .stderr(out)
        .kill_on_drop(true)
        .spawn()
        .unwrap_or_else(|e| panic!("spawn {} {:?}: {e}", bin.display(), args))
}

/// 1 s poll with early exit: wait until 127.0.0.1:port accepts TCP.
async fn wait_tcp(port: u16, what: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "{what} never listened on 127.0.0.1:{port}"
        );
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

/// 1 s poll with early exit: wait until `cond()` holds (no blind sleeps).
async fn wait_until(limit: Duration, what: &str, cond: impl Fn() -> bool) {
    let deadline = tokio::time::Instant::now() + limit;
    while !cond() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for {what}"
        );
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

/// A one-shot pass that retries while the root lock is still held by a
/// freshly killed daemon (Windows can hold `.sync.lock` for a moment after
/// TerminateProcess; edge-e2e.sh does the same dance).
async fn sync_pass_retry_lock(sb: &Path, stack: &SyncStack, label: &str, tries: u32) -> String {
    for attempt in 1..=tries {
        let out = tokio::time::timeout(
            Duration::from_secs(60),
            tokio::process::Command::new(sb)
                .args([
                    "sync-client",
                    "--path",
                    stack.dir.join("B").to_str().unwrap(),
                    "--config",
                    stack.client_cfg.to_str().unwrap(),
                ])
                .output(),
        )
        .await
        .expect("{label}: sync-client timed out")
        .expect("spawn sync-client");
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        if out.status.success() {
            return text;
        }
        assert!(
            text.contains("another sync process already holds") && attempt < tries,
            "{label}: sync-client failed:\n{text}"
        );
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    unreachable!("retry loop returns from the success branch")
}

fn fingerprint_of(identity_json: &Path) -> String {
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(identity_json).unwrap()).unwrap();
    v["fingerprint"]
        .as_str()
        .unwrap_or_else(|| panic!("no fingerprint in {}", identity_json.display()))
        .to_string()
}

fn write_json(path: &Path, v: serde_json::Value) {
    std::fs::write(path, serde_json::to_string(&v).unwrap()).unwrap();
}

impl SyncStack {
    /// Keys + configs + both servers, ready to serve. `route_to` is the
    /// sync-server port the tunnel's "sync" route points at.
    async fn start(
        dir: PathBuf,
        tb: &Path,
        sb: &Path,
        tag: &str,
        sync_port: u16,
        sync_mode: &str,
    ) -> SyncStack {
        let keys = dir.join("keys");
        std::fs::create_dir_all(&keys).unwrap();
        for (role, name) in [("server", "srv"), ("client", "cli")] {
            let st = tokio::process::Command::new(tb)
                .args([
                    "keygen",
                    "--out",
                    keys.to_str().unwrap(),
                    "--role",
                    role,
                    "--name",
                    name,
                ])
                .output()
                .await
                .unwrap();
            assert!(
                st.status.success(),
                "keygen {role} failed: {}",
                String::from_utf8_lossy(&st.stderr)
            );
        }
        let srv_fp = fingerprint_of(&keys.join("srv.identity.json"));
        let cli_fp = fingerprint_of(&keys.join("cli.identity.json"));

        let tunnel_port = free_port();
        let cfg = dir.join(format!("{tag}-server.json"));
        write_json(
            &cfg,
            json!({
                "listen": format!("127.0.0.1:{tunnel_port}"),
                "identity": {
                    "key": keys.join("srv.key.pem"),
                    "cert": keys.join("srv.crt.pem"),
                },
                "auth": { "mode": "whitelist", "fingerprints": [cli_fp] },
                "routes": [ { "host": ["sync"], "upstream": ["127.0.0.1", sync_port] } ],
            }),
        );
        let client_cfg = dir.join(format!("{tag}-client.json"));
        write_json(
            &client_cfg,
            json!({
                "endpoint": format!("127.0.0.1:{tunnel_port}"),
                "identity": {
                    "key": keys.join("cli.key.pem"),
                    "cert": keys.join("cli.crt.pem"),
                },
                "serverFingerprint": srv_fp,
            }),
        );

        let sync = spawn_logged(
            sb,
            &[
                "sync-server",
                "--path",
                dir.join("A").to_str().unwrap(),
                "--port",
                &sync_port.to_string(),
                "--mode",
                sync_mode,
            ],
            &dir.join(format!("{tag}-sync.log")),
        );
        let tunnel = spawn_logged(
            tb,
            &["server", "--config", cfg.to_str().unwrap()],
            &dir.join(format!("{tag}-tunnel.log")),
        );
        wait_tcp(sync_port, "{tag} sync-server").await;
        wait_tcp(tunnel_port, "{tag} tunnel server").await;
        SyncStack {
            dir,
            tunnel,
            sync,
            client_cfg,
        }
    }

    /// One one-shot sync-client pass over root B; returns the stdout+stderr
    /// (stats line: "Sync complete: downloaded=N, uploads=N, ...").
    async fn sync_pass(&self, sb: &Path, label: &str) -> String {
        let out = tokio::time::timeout(
            Duration::from_secs(60),
            tokio::process::Command::new(sb)
                .args([
                    "sync-client",
                    "--path",
                    self.dir.join("B").to_str().unwrap(),
                    "--config",
                    self.client_cfg.to_str().unwrap(),
                ])
                .output(),
        )
        .await
        .unwrap_or_else(|_| panic!("{label}: sync-client timed out"))
        .expect("spawn sync-client");
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(out.status.success(), "{label}: sync-client failed:\n{text}");
        text
    }
}

fn stats(text: &str, key: &str) -> usize {
    let line = text
        .lines()
        .find(|l| l.contains("Sync complete:"))
        .unwrap_or_else(|| panic!("no stats line in:\n{text}"));
    let pat = format!("{key}=");
    line.split(", ")
        .find(|f| f.contains(&pat))
        .and_then(|f| f.trim().split(&pat).nth(1).and_then(|v| v.parse().ok()))
        .unwrap_or_else(|| panic!("no {key} in stats line: {line}"))
}

fn write_file(root: &Path, rel: &str, content: &str) {
    let p = root.join(rel);
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(&p, content).unwrap();
}

fn read_file(root: &Path, rel: &str) -> String {
    String::from_utf8_lossy(&std::fs::read(root.join(rel)).unwrap()).into_owned()
}

/// Set a file's mtime to an explicit instant — deterministic last-writer
/// ordering without sleeps.
fn set_mtime(p: &Path, at: SystemTime) {
    let f = std::fs::File::options().write(true).open(p).unwrap();
    f.set_times(std::fs::FileTimes::new().set_accessed(at).set_modified(at))
        .unwrap();
}

fn assert_trees_equal(a: &Path, b: &Path) {
    let walk = |root: &Path| -> Vec<(String, usize)> {
        let mut out = Vec::new();
        fn rec(root: &Path, rel: &str, out: &mut Vec<(String, usize)>) {
            let dir = root.join(rel);
            for e in std::fs::read_dir(&dir).unwrap() {
                let e = e.unwrap();
                let name = e.file_name().to_string_lossy().into_owned();
                // engine-internal state is not part of the synced tree
                if name.starts_with(".sync") || name.ends_with(".sync-tmp") {
                    continue;
                }
                let child_rel = if rel.is_empty() {
                    name.clone()
                } else {
                    format!("{rel}/{name}")
                };
                if e.file_type().unwrap().is_dir() {
                    rec(root, &child_rel, out);
                } else {
                    out.push((
                        child_rel,
                        std::fs::metadata(e.path()).unwrap().len() as usize,
                    ));
                }
            }
        }
        rec(root, "", &mut out);
        out.sort();
        out
    };
    let (ta, tb) = (walk(a), walk(b));
    assert_eq!(ta, tb, "trees differ:\n  {a:?}: {ta:?}\n  {b:?}: {tb:?}");
    for (rel, _) in ta {
        assert_eq!(
            std::fs::read(a.join(&rel)).unwrap(),
            std::fs::read(b.join(&rel)).unwrap(),
            "content mismatch for {rel}"
        );
    }
}

/// Initial sync, bidirectional edits, both-direction deletions, readonly
/// rejection — the sequential phases of e2e-sync-test.sh (1-4, 10) and the
/// deletion probe folded into one function.
#[tokio::test]
async fn sync_semantics_lifecycle() {
    let Some((sb, tb)) = require_sync_bins() else {
        return;
    };
    tokio::time::timeout(Duration::from_secs(180), async {
        let dir = unique_dir("lifecycle");
        std::fs::create_dir_all(dir.join("A")).unwrap();
        std::fs::create_dir_all(dir.join("B")).unwrap();
        let stack = SyncStack::start(dir.clone(), &tb, &sb, "main", free_port(), "bidir").await;
        let a = dir.join("A");
        let b = dir.join("B");

        // ---- phase 1: initial download (server -> client) ----
        write_file(&a, "readme.txt", "hello tunnel\n");
        write_file(&a, "docs/notes.md", "line1\n");
        write_file(&a, "big.bin", &"x".repeat(100_000));
        let t = stack.sync_pass(&sb, "initial").await;
        assert_eq!(stats(&t, "downloaded"), 3, "initial download count");
        assert_eq!(stats(&t, "uploads"), 0);
        assert_trees_equal(&a, &b);

        // ---- phase 2: BOTH directions in one pass ----
        // client-side: new file + edit of an existing one, mtimes pushed
        // deterministically into the future (last-writer beats the server)
        let t0 = SystemTime::now();
        write_file(&b, "new-from-client.txt", "client created this\n");
        write_file(&b, "docs/notes.md", "line1\nEDITED-CLIENT\n");
        set_mtime(&b.join("new-from-client.txt"), t0 + Duration::from_secs(3));
        set_mtime(&b.join("docs/notes.md"), t0 + Duration::from_secs(3));
        // server-side: edit with a newer mtime too -> must come down
        write_file(&a, "readme.txt", "hello tunnel EDITED-SERVER\n");
        set_mtime(&a.join("readme.txt"), t0 + Duration::from_secs(4));
        let t = stack.sync_pass(&sb, "bidir").await;
        assert_eq!(stats(&t, "uploads"), 2, "client upload count (new+edited)");
        assert_eq!(stats(&t, "downloaded"), 1, "server edit must come down");
        assert_eq!(read_file(&a, "docs/notes.md"), "line1\nEDITED-CLIENT\n");
        assert_eq!(
            read_file(&a, "new-from-client.txt"),
            "client created this\n"
        );
        assert_eq!(read_file(&b, "readme.txt"), "hello tunnel EDITED-SERVER\n");
        assert_trees_equal(&a, &b);

        // ---- phase 3: converged re-sync is a no-op ----
        let t = stack.sync_pass(&sb, "noop").await;
        assert_eq!(stats(&t, "downloaded"), 0, "re-sync must converge");
        assert_eq!(stats(&t, "uploads"), 0);

        // ---- phase 4: deletions propagate in both directions ----
        // A one-shot pass cannot DETECT an external local deletion (no
        // watcher => no local tombstone), so this phase mirrors the deletion
        // probe: a watch daemon on B records the client-side delete and the
        // server hub pushes the server-side one.
        write_file(&a, "gone-a.txt", "doomed on A\n");
        write_file(&b, "gone-b.txt", "doomed on B\n");
        stack.sync_pass(&sb, "delete setup").await;
        assert!(a.join("gone-b.txt").is_file());
        assert!(b.join("gone-a.txt").is_file());
        let mut daemon = spawn_logged(
            &sb,
            &[
                "sync-client",
                "--path",
                b.to_str().unwrap(),
                "--config",
                stack.client_cfg.to_str().unwrap(),
                "--watch",
                "--interval",
                "2",
            ],
            &dir.join("daemon.log"),
        );
        // prove the daemon is up AND its watcher armed before deleting
        // (deletion-semantics-probe.sh waits the same way): a marker pushed
        // through the daemon must land on B first
        write_file(&a, "daemon-alive.txt", "marker\n");
        wait_until(Duration::from_secs(45), "daemon initial pass", || {
            b.join("daemon-alive.txt").exists()
        })
        .await;
        std::fs::remove_file(a.join("gone-a.txt")).unwrap();
        std::fs::remove_file(b.join("gone-b.txt")).unwrap();
        wait_until(Duration::from_secs(45), "deletions to propagate", || {
            !a.join("gone-b.txt").exists() && !b.join("gone-a.txt").exists()
        })
        .await;
        // kill the daemon, then prove no resurrection with a fresh one-shot
        let _ = daemon.start_kill();
        let _ = daemon.wait().await;
        let t = sync_pass_retry_lock(&sb, &stack, "delete no-resurrect", 10).await;
        assert_eq!(
            stats(&t, "downloaded"),
            0,
            "no re-download of deleted files"
        );
        assert_eq!(stats(&t, "uploads"), 0, "no resurrection upload");
        assert!(!b.join("gone-a.txt").exists());
        assert!(!a.join("gone-b.txt").exists());
        assert_trees_equal(&a, &b);

        // ---- phase 5: readonly sync-server rejects uploads ----
        let ro_dir = unique_dir("readonly");
        std::fs::create_dir_all(ro_dir.join("A")).unwrap();
        std::fs::create_dir_all(ro_dir.join("B")).unwrap();
        let ro_port = free_port();
        let ro_stack = SyncStack::start(ro_dir.clone(), &tb, &sb, "ro", ro_port, "readonly").await;
        write_file(&ro_dir.join("A"), "ro-seed.txt", "ro-seed\n");
        write_file(
            &ro_dir.join("B"),
            "readonly-test.txt",
            "should not be uploaded\n",
        );
        let t = ro_stack.sync_pass(&sb, "readonly").await;
        assert_eq!(stats(&t, "uploads"), 0, "readonly must suppress uploads");
        assert!(
            !ro_dir.join("A/readonly-test.txt").exists(),
            "readonly server accepted an upload"
        );
        assert_eq!(read_file(&ro_dir.join("B"), "ro-seed.txt"), "ro-seed\n");
        drop(ro_stack);

        drop(stack);
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&ro_dir);
    })
    .await
    .expect("sync_semantics_lifecycle timed out");
}

/// Conflict resolution: last-writer-wins both directions, same-mtime
/// conflicts detected (not blended), delete-then-recreate — the
/// deletion-semantics and conflict phases folded into one function.
#[tokio::test]
async fn sync_semantics_conflicts() {
    let Some((sb, tb)) = require_sync_bins() else {
        return;
    };
    tokio::time::timeout(Duration::from_secs(120), async {
        let dir = unique_dir("conflict");
        std::fs::create_dir_all(dir.join("A")).unwrap();
        std::fs::create_dir_all(dir.join("B")).unwrap();
        let stack = SyncStack::start(dir.clone(), &tb, &sb, "cf", free_port(), "bidir").await;
        let a = dir.join("A");
        let b = dir.join("B");

        // baseline
        write_file(&a, "lww.txt", "server-version\n");
        write_file(&a, "lww2.txt", "server-version\n");
        write_file(&a, "same-mtime.txt", "base\n");
        write_file(&a, "recreate.txt", "v1\n");
        stack.sync_pass(&sb, "baseline").await;
        assert_trees_equal(&a, &b);

        // ---- last-writer-wins, BOTH directions in one pass ----
        let t0 = SystemTime::now();
        // B's copy newer by 3 s -> client version wins everywhere
        write_file(&b, "lww.txt", "client-version\n");
        set_mtime(&b.join("lww.txt"), t0 + Duration::from_secs(3));
        // A's copy newer by 4 s -> server version wins everywhere
        write_file(&a, "lww2.txt", "server-version-NEW\n");
        set_mtime(&a.join("lww2.txt"), t0 + Duration::from_secs(4));
        stack.sync_pass(&sb, "lww").await;
        assert_eq!(read_file(&a, "lww.txt"), "client-version\n");
        assert_eq!(read_file(&b, "lww.txt"), "client-version\n");
        assert_eq!(read_file(&a, "lww2.txt"), "server-version-NEW\n");
        assert_eq!(read_file(&b, "lww2.txt"), "server-version-NEW\n");
        assert_trees_equal(&a, &b);

        // ---- same-mtime conflict: counted, skipped, NOT blended ----
        let same = t0 + Duration::from_secs(10);
        write_file(&a, "same-mtime.txt", "server-edit\n");
        set_mtime(&a.join("same-mtime.txt"), same);
        write_file(&b, "same-mtime.txt", "client-edit\n");
        set_mtime(&b.join("same-mtime.txt"), same);
        let t = stack.sync_pass(&sb, "conflict").await;
        assert_eq!(stats(&t, "conflicts"), 1, "same-mtime edit must be flagged");
        assert_eq!(read_file(&a, "same-mtime.txt"), "server-edit\n");
        assert_eq!(read_file(&b, "same-mtime.txt"), "client-edit\n");

        // ---- delete-then-recreate with a newer mtime: recreate wins ----
        // (phase 10c of e2e-sync-test.sh: last-writer beats the tombstone)
        std::fs::remove_file(a.join("recreate.txt")).unwrap();
        write_file(&b, "recreate.txt", "v2-recreated\n");
        set_mtime(
            &b.join("recreate.txt"),
            SystemTime::now() + Duration::from_secs(5),
        );
        stack.sync_pass(&sb, "recreate").await;
        assert_eq!(read_file(&a, "recreate.txt"), "v2-recreated\n");
        assert_eq!(read_file(&b, "recreate.txt"), "v2-recreated\n");

        drop(stack);
        let _ = std::fs::remove_dir_all(&dir);
    })
    .await
    .expect("sync_semantics_conflicts timed out");
}

// ===========================================================================
// frame_edge — wire-frame edges: 0-length, max-length, truncated/rejected
// ===========================================================================

fn client_hello() -> Vec<u8> {
    let hello = json!({
        "v": 1,
        "mode": "client",
        "name": "raw-edge",
        "maxDataFrame": DEFAULT_MAX_DATA,
        "rxWindow": 262_144,
        "maxStreams": 8,
        "compression": compress::supported(),
    });
    encode_frame(FT_HELLO, 0, 0, hello.to_string().as_bytes())
}

/// Read one raw frame (header + payload) from a session half.
async fn read_frame<S: AsyncReadExt + Unpin>(s: &mut S) -> anyhow::Result<(u8, Vec<u8>)> {
    let mut hdr = [0u8; HEADER_SIZE];
    s.read_exact(&mut hdr).await?;
    let fh = FrameHeader::parse(&hdr)?;
    let mut payload = vec![0u8; fh.length as usize];
    if !payload.is_empty() {
        s.read_exact(&mut payload).await?;
    }
    Ok((fh.frame_type, payload))
}

/// Drive one server session from a raw half: exchange HELLO, inject a frame,
/// and return the GOAWAY reason the server sends back (session-level
/// rejection of protocol violations).
async fn inject_frame_expect_goaway(ftype: u8, length: u32, label: &str) -> String {
    let (mut raw, b) = tokio::io::duplex(64 * 1024);
    let server_task = tokio::spawn(MuxSession::start(b, opts(false, 256 * 1024), None));
    raw.write_all(&client_hello()).await.unwrap();
    let (t, _) = read_frame(&mut raw).await.unwrap();
    assert_eq!(t, FT_HELLO, "{label}: expected server HELLO");
    let _ = server_task
        .await
        .unwrap()
        .expect("server session must come up");

    // the offending frame: header claims `length`, we then stop writing
    raw.write_all(&frame_header(ftype, 0, 1, length))
        .await
        .unwrap();
    let reason = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let (t, payload) = read_frame(&mut raw).await?;
            if t == FT_GOAWAY {
                return Ok::<String, anyhow::Error>(String::from_utf8_lossy(&payload).into_owned());
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{label}: no GOAWAY within 10s"))
    .unwrap_or_else(|e| panic!("{label}: {e:#}"));
    reason
}

/// All frame-edge cases in one function: a synchronous header table plus the
/// session-level rejection table (each case a fresh raw-driven session).
#[tokio::test]
async fn frame_edge() {
    // ---- (a) length-0 and max-length headers round-trip ----
    let types = [
        (FT_HELLO, "HELLO"),
        (FT_OPEN, "OPEN"),
        (FT_OPEN_ACK, "OPEN_ACK"),
        (FT_DATA, "DATA"),
        (FT_WINDOW, "WINDOW"),
        (FT_PING, "PING"),
        (FT_PONG, "PONG"),
        (FT_GOAWAY, "GOAWAY"),
    ];
    let sid = 0xA5A5_0F0Fu32;
    for (ftype, _name) in types {
        let hdr = frame_header(ftype, FLAG_COMPRESSED | FLAG_FIN, sid, 0);
        let fh = FrameHeader::parse(&hdr).unwrap();
        assert_eq!(
            (fh.frame_type, fh.flags, fh.stream_id, fh.length),
            (ftype, FLAG_COMPRESSED | FLAG_FIN, sid, 0)
        );
        let wire = encode_frame(ftype, FLAG_FIN, sid, b"");
        assert_eq!(wire.len(), HEADER_SIZE, "length-0 frame is header-only");
        assert_eq!(
            FrameHeader::parse(wire[..HEADER_SIZE].try_into().unwrap())
                .unwrap()
                .length,
            0
        );
    }
    for len in [DEFAULT_MAX_DATA, HARD_MAX_FRAME as u32] {
        let hdr = frame_header(FT_DATA, 0, sid, len);
        assert_eq!(FrameHeader::parse(&hdr).unwrap().length, len);
    }
    // a full max-size DATA frame encodes with the exact length field
    let wire = encode_frame(FT_DATA, FLAG_COMPRESSED, sid, &vec![0u8; HARD_MAX_FRAME]);
    assert_eq!(wire.len(), HEADER_SIZE + HARD_MAX_FRAME);
    assert_eq!(
        FrameHeader::parse(wire[..HEADER_SIZE].try_into().unwrap())
            .unwrap()
            .length as usize,
        HARD_MAX_FRAME
    );

    // ---- (b) unknown frame types are rejected by the parser ----
    for bad in [0u8, FT_GOAWAY + 1, u8::MAX] {
        let hdr = frame_header(bad, 0, sid, 0);
        let err = FrameHeader::parse(&hdr).unwrap_err().to_string();
        assert!(err.contains("unknown frame type"), "type {bad}: {err}");
    }

    // ---- (c) session-level rejection of protocol-violating frames ----
    let cases: [(u8, u32, &str); 3] = [
        (FT_WINDOW, 5, "WINDOW payload cap is 4"),
        (FT_DATA, HARD_MAX_FRAME as u32 + 1, "DATA over the hard cap"),
        (FT_PING, 65, "PING payload cap is 64"),
    ];
    for (ftype, len, label) in cases {
        let reason = inject_frame_expect_goaway(ftype, len, label).await;
        assert!(
            reason.contains("oversized frame"),
            "{label}: GOAWAY reason was {reason}"
        );
    }

    // ---- (d) a frame before HELLO kills the session (fail closed) ----
    {
        let (mut raw, b) = tokio::io::duplex(64 * 1024);
        let server_task = tokio::spawn(MuxSession::start(b, opts(false, 256 * 1024), None));
        // the server sends its own HELLO immediately, then waits for ours;
        // a PING instead is a protocol violation that must fail the session
        raw.write_all(&encode_frame(FT_PING, 0, 0, &[0u8; 16]))
            .await
            .unwrap();
        let err = match server_task.await.unwrap() {
            Err(e) => e.to_string(),
            Ok(_) => panic!("pre-HELLO frame must fail session start"),
        };
        assert!(
            err.contains("did not send HELLO"),
            "expected HELLO wait failure, got: {err}"
        );
        // our half sees the server HELLO, then EOF (fail closed, no hang)
        let mut buf = [0u8; 256];
        let mut saw_hello = false;
        let eof = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                match raw.read(&mut buf).await.unwrap() {
                    0 => break,
                    n => {
                        if buf[0] == FT_HELLO {
                            saw_hello = true;
                        }
                        let _ = n;
                    }
                }
            }
        })
        .await;
        assert!(eof.is_ok(), "peer must EOF after the violation");
        assert!(saw_hello, "server HELLO must precede the teardown");
    }

    // ---- (e) truncated header (EOF mid-header) tears down cleanly ----
    {
        let (mut raw, b) = tokio::io::duplex(64 * 1024);
        let server_task = tokio::spawn(MuxSession::start(b, opts(false, 256 * 1024), None));
        raw.write_all(&client_hello()).await.unwrap();
        let (t, _) = read_frame(&mut raw).await.unwrap();
        assert_eq!(t, FT_HELLO);
        let session = server_task.await.unwrap().expect("session up");
        // 6 bytes of a 10-byte header, then the link dies
        raw.write_all(&frame_header(FT_DATA, 0, 1, 8)[..6])
            .await
            .unwrap();
        drop(raw);
        tokio::time::timeout(Duration::from_secs(10), session.wait_closed())
            .await
            .expect("truncated header + EOF must close the session, not hang");
    }
}
