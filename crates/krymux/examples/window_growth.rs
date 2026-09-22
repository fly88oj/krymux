// Window auto-growth validation: two in-process MuxSessions over a duplex with
// a tiny initial window; a paced transfer must grow the grant to the cap.
// Usage: cargo run --example window_growth --features zstd
use krymux::mux::{MuxSession, SessionOpts, Target};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let (io_a, io_b) = tokio::io::duplex(64 * 1024);

    let server_fut = MuxSession::start(
        io_a,
        SessionOpts {
            is_client: false,
            name: "srv".into(),
            rx_window: 32 * 1024,
            rx_window_max: 1024 * 1024,
            max_streams: 16,
            keepalive_sec: 0,
        },
        Some(Arc::new(|stream: krymux::mux::TunnelStream, _t: Target| {
            tokio::spawn(async move {
                stream.accept(None);
                let (mut r, mut w) = tokio::io::split(stream);
                let mut buf = vec![0u8; 16 * 1024];
                loop {
                    match r.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if w.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
                let _ = w.shutdown().await;
            });
        })),
    );
    let client_fut = MuxSession::start(
        io_b,
        SessionOpts {
            is_client: true,
            name: "cli".into(),
            rx_window: 32 * 1024,
            rx_window_max: 1024 * 1024,
            max_streams: 16,
            keepalive_sec: 0,
        },
        None,
    );
    let (_server, client) = tokio::try_join!(server_fut, client_fut)?;

    // ---- healthy stream: paced 1MB echo across multiple 100ms intervals ----
    let s = client
        .open_stream(
            Target {
                host: Some("g".into()),
                port: 1,
                unix: None,
                hint: "raw".into(),
            },
            "none",
        )
        .await?;
    let s = Arc::new(s);
    let granted_probe = s.rx_granted_arc();
    let mut s = Arc::try_unwrap(s).ok().unwrap();
    let (mut r, mut w) = tokio::io::split(&mut s);

    let reader = async {
        let mut got = 0usize;
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n = r.read(&mut buf).await?;
            got += n;
            if n == 0 {
                break;
            }
        }
        anyhow::Ok(got)
    };
    let writer = async {
        let chunk = vec![1u8; 32 * 1024];
        let total = 1024 * 1024;
        let mut sent = 0usize;
        while sent < total {
            for _ in 0..4 {
                if sent >= total {
                    break;
                }
                w.write_all(&chunk).await?;
                sent += chunk.len();
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        w.shutdown().await?;
        anyhow::Ok(())
    };
    let ((), got) = tokio::try_join!(writer, reader)?;
    let granted = granted_probe();
    println!("healthy: echoed {got} bytes, client grant grew to {granted} bytes");
    assert_eq!(got, 1024 * 1024);
    assert!(
        granted > 32 * 1024,
        "window must grow on a healthy stream (got {granted})"
    );
    assert!(granted <= 1024 * 1024, "growth capped");

    client.close("done");
    println!("window_growth: PASS");
    // in-process duplex sessions keep reader tasks parked; exit explicitly
    std::process::exit(0);
}
