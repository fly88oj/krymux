// Metric-emitting benchmark for the krymux harness (bench/run-bench.sh).
// Same deployment shape as examples/bench.rs (echo origin + krymux-tunnel.exe server
// child + in-process Rust client) but prints machine-parsable METRIC lines
// and adds percentile latencies, small-message RTT, and RSS sampling.
//
// Usage:
//   cargo build --release --features krymux/zstd --bin krymux-tunnel --example bench2
//   KRYMUX_BENCH2_MB=16 KRYMUX_BENCH2_ALGOS=none,zstd KRYMUX_BENCH2_PHASES=throughput,open,rtt,mem \
//     ./target/release/examples/bench2.exe
//
// Output lines (stdout):
//   METRIC throughput_none_16mb_mb_s 405.3
//   METRIC stream_open_p50_ms 0.28     ... etc.
// Human-readable progress goes to stdout too; the harness greps ^METRIC.
use krymux::client::{ConnectParams, EctunClient};
use krymux::keys;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

const MB: usize = 1024 * 1024;
const CHUNK: usize = 256 * 1024;

fn envs(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

fn make_payload(total: usize) -> Vec<u8> {
    // Same compressible-text shape as examples/bench.rs ("text" kind).
    let unit = b"2026-09-21T12:00:00Z GET /api/v1/items?page=1&size=50 HTTP/1.1 200 3ms log line. "
        .repeat(64);
    let mut v = vec![0u8; total];
    for (i, b) in v.iter_mut().enumerate() {
        *b = unit[i % unit.len()];
    }
    v
}

fn percentile(mut v: Vec<f64>, p: f64) -> f64 {
    assert!(!v.is_empty());
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let idx = ((p * v.len() as f64).ceil() as usize).clamp(1, v.len()) - 1;
    v[idx]
}

/// RSS in KiB via Windows tasklist (CSV row: "name","pid","session","sess#","mem K").
fn rss_kb(pid: u32) -> Option<u64> {
    let out = std::process::Command::new("tasklist")
        .args(["/FI", &format!("PID eq {pid}"), "/FO", "CSV", "/NH"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        if !line.starts_with('"') {
            continue; // localized "INFO: no tasks..." lines
        }
        let fields: Vec<&str> = line.trim().split("\",\"").collect();
        let last = fields.last()?.trim_matches('"');
        let kb: String = last.chars().filter(|c| c.is_ascii_digit()).collect();
        return kb.parse::<u64>().ok();
    }
    None
}

async fn wait_port(addr: &str, ms: u64) -> bool {
    let deadline = std::time::Duration::from_millis(ms);
    let t0 = std::time::Instant::now();
    loop {
        let Ok(a): Result<std::net::SocketAddr, _> = addr.parse() else {
            return false;
        };
        if std::net::TcpStream::connect_timeout(&a, std::time::Duration::from_millis(200)).is_ok() {
            return true;
        }
        if t0.elapsed() > deadline {
            return false;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = env_logger::Builder::from_env(env_logger::Env::new().filter_or("KRYMUX_LOG", "warn"))
        .try_init();
    let total_mb: usize = envs("KRYMUX_BENCH2_MB", "16").parse()?;
    let total = total_mb * MB;
    let port: u16 = envs("KRYMUX_BENCH2_PORT", "38501").parse()?;
    let algos: Vec<String> = envs("KRYMUX_BENCH2_ALGOS", "none,deflate,brotli,zstd")
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let phases: Vec<String> = envs("KRYMUX_BENCH2_PHASES", "throughput,open,rtt,mem")
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    // ---- echo origin (in-process; a separate socket peer) ----
    let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let echo_port = echo.local_addr()?.port();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = echo.accept().await else {
                continue;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 128 * 1024];
                let (mut rin, mut wout) = (0u64, 0u64);
                let end: String = loop {
                    match s.read(&mut buf).await {
                        Ok(0) => break "eof".to_string(),
                        Err(e) => {
                            break format!("err {e}");
                        }
                        Ok(n) => {
                            rin += n as u64;
                            if let Err(e) = s.write_all(&buf[..n]).await {
                                wout += n as u64;
                                break format!("wr-err {e}");
                            }
                            wout += n as u64;
                        }
                    }
                };
                eprintln!("# echo-conn done: read={rin} written={wout} end={end}");
            });
        }
    });

    // ---- identities + server child (recipe from examples/bench.rs) ----
    let exe = std::env::current_exe()?;
    let bin = exe
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("krymux-tunnel.exe");
    let keydir = std::env::temp_dir().join(format!("krymux-bench2-{port}"));
    let _ = std::fs::remove_dir_all(&keydir);
    let out = std::process::Command::new(&bin)
        .args([
            "keygen",
            "--out",
            keydir.to_str().unwrap(),
            "--role",
            "server",
        ])
        .output()?;
    let server_fp = String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| l.strip_prefix("fingerprint: "))
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    anyhow::ensure!(!server_fp.is_empty(), "keygen failed");

    let cfg = keydir.join("server.json");
    std::fs::write(
        &cfg,
        serde_json::json!({
            "listen": format!("127.0.0.1:{port}"),
            "identity": {
                "key": keydir.join("server.key.pem").display().to_string(),
                "cert": keydir.join("server.crt.pem").display().to_string(),
            },
            "auth": { "mode": "open" },
            "routes": [{ "host": ["*"], "upstream": ["127.0.0.1", echo_port] }],
            "keepaliveSec": 0,
        })
        .to_string(),
    )?;
    let mut cmd = Command::new(&bin);
    cmd.args(["server", "--config", cfg.to_str().unwrap()])
        .stdout(std::process::Stdio::null());
    // KRYMUX_BENCH2_SERVER_LOG=path captures the server child's stderr (debug).
    if let Ok(path) = std::env::var("KRYMUX_BENCH2_SERVER_LOG") {
        cmd.stderr(std::fs::File::create(&path)?);
    } else {
        cmd.stderr(std::process::Stdio::null());
    }
    let mut child = cmd.spawn()?;
    let listen = format!("127.0.0.1:{port}");
    anyhow::ensure!(
        wait_port(&listen, 10_000).await,
        "server child did not open {listen}"
    );

    let res = run(
        &listen,
        &keydir,
        &bin,
        &server_fp,
        child.id(),
        &phases,
        &algos,
        total,
        total_mb,
    )
    .await;
    // diagnostic: did the server child die on its own mid-run?
    if let Ok(Some(status)) = child.try_wait() {
        println!("# SERVER CHILD EXITED EARLY: {status}");
    }
    let _ = child.kill().await;
    let _ = std::fs::remove_dir_all(&keydir);
    res
}

#[allow(clippy::too_many_arguments)]
async fn run(
    listen: &str,
    keydir: &std::path::Path,
    bin: &std::path::Path,
    server_fp: &str,
    server_pid: Option<u32>,
    phases: &[String],
    algos: &[String],
    total: usize,
    total_mb: usize,
) -> anyhow::Result<()> {
    std::process::Command::new(bin)
        .args([
            "keygen",
            "--out",
            keydir.to_str().unwrap(),
            "--role",
            "client",
            "--name",
            "bench",
        ])
        .output()?;
    let identity = Arc::new(keys::load_identity(
        &keydir.join("bench.key.pem"),
        &keydir.join("bench.crt.pem"),
    )?);
    let client = EctunClient::connect(
        listen,
        &identity,
        server_fp,
        &ConnectParams {
            compression: "none".into(),
            keepalive_sec: 0,
            ..Default::default()
        },
    )
    .await?;
    let c = Arc::new(client);
    println!(
        "# bench2: {total_mb} MiB echo, algos [{}], phases [{}]",
        algos.join(","),
        phases.join(",")
    );

    // ---- phase: throughput ----
    if phases.iter().any(|p| p == "throughput") {
        for algo in algos {
            if algo == "zstd" && !cfg!(feature = "zstd") {
                println!("# SKIP zstd (example built without the zstd feature)");
                continue;
            }
            let payload = make_payload(total); // moved into the transfer task
            let t0 = Instant::now();
            let c2 = c.clone();
            let algo_s = algo.to_string();
            let got = tokio::task::spawn(async move {
                let mut s = c2.open_stream("bench", 9, Some(&algo_s)).await?;
                let negotiated = s.compression().to_string();
                let (mut r, mut w) = tokio::io::split(&mut s);
                let reader = async {
                    let mut got = 0usize;
                    let mut buf = vec![0u8; 128 * 1024];
                    let progress = std::env::var("KRYMUX_BENCH2_PROGRESS").is_ok();
                    let t0 = Instant::now();
                    let mut next_mark = 512 * 1024;
                    loop {
                        let n = r.read(&mut buf).await?;
                        if n == 0 && progress {
                            println!(
                                "# reader EOF at {} B after {:.1} ms",
                                got,
                                t0.elapsed().as_secs_f64() * 1000.0
                            );
                        }
                        got += n;
                        if progress && got >= next_mark {
                            println!(
                                "# reader at {} B ({:.1} ms)",
                                next_mark / 1024,
                                t0.elapsed().as_secs_f64() * 1000.0
                            );
                            next_mark += 512 * 1024;
                        }
                        if n == 0 {
                            break;
                        }
                    }
                    Ok::<usize, anyhow::Error>(got)
                };
                let writer = async {
                    let mut sent = 0usize;
                    while sent < payload.len() {
                        let take = CHUNK.min(payload.len() - sent);
                        w.write_all(&payload[sent..sent + take]).await?;
                        sent += take;
                    }
                    w.shutdown().await?;
                    Ok::<(), anyhow::Error>(())
                };
                let ((), got) = tokio::try_join!(writer, reader)?;
                anyhow::Ok((got, negotiated))
            })
            .await??;
            let (got, negotiated) = got;
            let ms = t0.elapsed().as_secs_f64() * 1000.0;
            let mbps = (total as f64 / MB as f64) / (ms / 1000.0);
            anyhow::ensure!(got == total, "echo short read: {got} != {total}");
            if negotiated != *algo {
                println!("# WARNING: requested {algo} but negotiated '{negotiated}'");
            }
            println!(
                "# {algo:8} echoed {} MiB in {ms:7.0} ms (negotiated: {negotiated})",
                got / MB
            );
            println!("METRIC throughput_{algo}_{total_mb}mb_mb_s {mbps:.1}");
        }
    }

    // ---- phase: stream-open latency (200 sequential open+close) ----
    if phases.iter().any(|p| p == "open") {
        for _ in 0..20 {
            // warm-up, unrecorded
            let mut s = c.open_stream("bench", 9, Some("none")).await?;
            s.shutdown().await?;
        }
        const N: usize = 200;
        let mut durs = Vec::with_capacity(N);
        for _ in 0..N {
            let t0 = Instant::now();
            let mut s = c.open_stream("bench", 9, Some("none")).await?;
            s.shutdown().await?;
            durs.push(t0.elapsed().as_secs_f64() * 1000.0);
        }
        let p50 = percentile(durs.clone(), 0.50);
        let p99 = percentile(durs.clone(), 0.99);
        let mean = durs.iter().sum::<f64>() / durs.len() as f64;
        println!(
            "# stream open+close: n={N} mean={mean:.3} p50={p50:.3} p99={p99:.3} max={:.3} ms",
            durs.iter().cloned().fold(f64::MIN, f64::max)
        );
        println!("METRIC stream_open_p50_ms {p50:.3}");
        println!("METRIC stream_open_p99_ms {p99:.3}");
    }

    // ---- phase: small-message RTT (500 x 1 KiB request/echo on one stream) ----
    if phases.iter().any(|p| p == "rtt") {
        let mut s = c.open_stream("bench", 9, Some("none")).await?;
        let req = vec![0x5au8; 1024];
        let mut buf = vec![0u8; 1024];
        for _ in 0..20 {
            // warm-up, unrecorded
            s.write_all(&req).await?;
            s.read_exact(&mut buf).await?;
        }
        const N: usize = 500;
        let mut durs = Vec::with_capacity(N);
        for _ in 0..N {
            let t0 = Instant::now();
            s.write_all(&req).await?;
            s.read_exact(&mut buf).await?;
            durs.push(t0.elapsed().as_secs_f64() * 1000.0);
        }
        let p50 = percentile(durs.clone(), 0.50);
        let p99 = percentile(durs.clone(), 0.99);
        println!(
            "# 1-KiB echo RTT: n={N} p50={p50:.3} p99={p99:.3} max={:.3} ms",
            durs.iter().cloned().fold(f64::MIN, f64::max)
        );
        println!("METRIC msg_rtt_p50_ms {p50:.3}");
        println!("METRIC msg_rtt_p99_ms {p99:.3}");
        let _ = s.shutdown().await;
    }

    // ---- phase: memory (RSS of server child + this client process) ----
    if phases.iter().any(|p| p == "mem") {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await; // let allocators settle
        let srv = server_pid.and_then(rss_kb);
        let cli = rss_kb(std::process::id());
        println!(
            "# RSS after run: server={} KiB client={} KiB",
            srv.map(|v| v.to_string()).unwrap_or_else(|| "n/a".into()),
            cli.map(|v| v.to_string()).unwrap_or_else(|| "n/a".into())
        );
        if let Some(v) = srv {
            println!("METRIC rss_server_kb {v}");
        }
        if let Some(v) = cli {
            println!("METRIC rss_client_kb {v}");
        }
    }

    c.session.close("bench2 done");
    Ok(())
}
