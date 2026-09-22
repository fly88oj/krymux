// Rust throughput/latency benchmark, deployment-shaped:
// echo origin + server (child process) + client (in-process).
// Usage: cargo run --release --example bench --features zstd
//        KRYMUX_BENCH_MB=4 for a quick run.
use krymux::client::EctunClient;
use krymux::keys;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

const MB: usize = 1024 * 1024;

fn total_bytes() -> usize {
    std::env::var("KRYMUX_BENCH_MB")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(256)
        * MB
}
const CHUNK: usize = 256 * 1024;

fn make_payload(kind: &str) -> Vec<u8> {
    let total = total_bytes();
    let mut v = vec![0u8; total];
    match kind {
        "random" => {
            let mut s = 0x9e3779b97f4a7c15u64;
            for b in v.iter_mut() {
                s ^= s >> 12;
                s ^= s << 25;
                s ^= s >> 27;
                *b = (s.wrapping_mul(0x2545F4914F6CDD1D) >> 56) as u8;
            }
        }
        _ => {
            let unit =
                b"2026-09-21T12:00:00Z GET /api/v1/items?page=1&size=50 HTTP/1.1 200 3ms log line. "
                    .repeat(64);
            for (i, b) in v.iter_mut().enumerate() {
                *b = unit[i % unit.len()];
            }
        }
    }
    v
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // echo origin (in-process is fine: it is a separate socket peer)
    let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let echo_port = echo.local_addr()?.port();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = echo.accept().await else {
                continue;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 128 * 1024];
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
            });
        }
    });

    // identities via the CLI binary
    let exe = std::env::current_exe()?;
    let bin = exe
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("krymux-tunnel.exe");
    let keydir = std::env::temp_dir().join("krymux-bench");
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
    let server_fp = {
        let text = String::from_utf8_lossy(&out.stdout).to_string();
        let mut f = String::new();
        for line in text.lines() {
            if let Some(v) = line.strip_prefix("fingerprint: ") {
                f = v.trim().to_string();
            }
        }
        assert!(!f.is_empty(), "keygen failed");
        f
    };

    // server config + child process
    let cfg = keydir.join("server.json");
    std::fs::write(
        &cfg,
        serde_json::json!({
            "listen": "127.0.0.1:38443",
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
    let mut child = Command::new(&bin)
        .args(["server", "--config", cfg.to_str().unwrap()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    tokio::time::sleep(std::time::Duration::from_millis(800)).await;

    // bench client identity: a second keygen (open auth accepts it)
    std::process::Command::new(&bin)
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
        "127.0.0.1:38443",
        &identity,
        &server_fp,
        &krymux::client::ConnectParams {
            compression: "none".into(),
            keepalive_sec: 0,
            ..Default::default()
        },
    )
    .await?;
    let c = Arc::new(client);

    let total = total_bytes();
    println!(
        "rust bench (release, echo round-trip, {}MB payload)",
        total / MB
    );
    #[cfg(feature = "zstd")]
    let algos: Vec<&str> = vec!["none", "deflate", "brotli", "zstd"];
    #[cfg(not(feature = "zstd"))]
    let algos: Vec<&str> = vec!["none", "deflate", "brotli"];

    for algo in algos {
        for kind in ["text", "random"] {
            let payload = make_payload(kind);
            let t0 = std::time::Instant::now();
            let c2 = c.clone();
            let algo_s = algo.to_string();
            let got = tokio::task::spawn(async move {
                let mut s = c2.open_stream("bench", 9, Some(&algo_s)).await?;
                // drain echo concurrently while writing (like TCP): the standard
                // lock-based split is built for single-task concurrent IO
                let (mut r, mut w) = tokio::io::split(&mut s);
                let reader = async {
                    let mut got = 0usize;
                    let mut buf = vec![0u8; 128 * 1024];
                    loop {
                        let n = r.read(&mut buf).await?;
                        got += n;
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
                anyhow::Ok(got)
            })
            .await??;
            let ms = t0.elapsed().as_secs_f64() * 1000.0;
            println!(
                "{:8} {:7} {:7.1} MB/s  (echoed {} MB in {:.0} ms)",
                algo,
                kind,
                (total as f64 / MB as f64) / (ms / 1000.0),
                got / MB,
                ms
            );
        }
    }

    // latency
    let t0 = std::time::Instant::now();
    let n = 50;
    for _ in 0..n {
        let mut s = c.open_stream("bench", 9, Some("none")).await?;
        s.shutdown().await?;
    }
    println!(
        "stream open+ack avg: {:.2} ms",
        t0.elapsed().as_secs_f64() * 1000.0 / n as f64
    );
    if let Ok(d) = c.session.ping().await {
        println!("ping RTT: {:.2?}", d);
    }

    c.session.close("bench done");
    let _ = child.kill().await;
    Ok(())
}
