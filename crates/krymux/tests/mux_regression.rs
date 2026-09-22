//! Regression tests for the CMPX mux half-close / teardown races found via
//! bench2's echo throughput phase (intermittent short reads with a CLEAN EOF
//! and occasional full stalls).
//!
//! The shape under test: writer-finishes-first. The client app writes
//! everything and shuts down its write side while the echo tail is still in
//! flight; the stream must still deliver every buffered byte before EOF.

use krymux::mux::{MuxSession, SessionOpts, Target, TunnelStream};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MB: usize = 1024 * 1024;

fn opts(is_client: bool) -> SessionOpts {
    SessionOpts {
        is_client,
        name: if is_client { "c" } else { "s" }.into(),
        // tiny FIXED client receive window: the server's outbound pump is
        // perpetually credit-starved, which turns the unregister-vs-grant
        // race at stream teardown into a near-certain event instead of a
        // rare one (bench2 saw it at 10-30% with a 256 KiB growing window).
        rx_window: 16 * 1024,
        rx_window_max: 16 * 1024,
        max_streams: 8,
        keepalive_sec: 0,
    }
}

/// A real TCP echo origin, same shape as bench2's.
async fn echo_origin() -> anyhow::Result<std::net::SocketAddr> {
    let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = echo.local_addr()?;
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
    Ok(addr)
}

/// Server-side stream handler, mirroring server.rs::handle_stream:
/// copy_bidirectional against the echo upstream, then explicit shutdown.
fn handle_like_server(stream: TunnelStream, echo: std::net::SocketAddr) {
    tokio::spawn(async move {
        stream.accept(Some("echo"));
        let mut stream = stream;
        let mut upstream = tokio::net::TcpStream::connect(echo).await.unwrap();
        let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
        let _ = stream.shutdown().await;
    });
}

trait Link: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin> Link for T {}

/// One full session pair over an in-process link (`duplex` or real TCP);
/// runs `total` echo bytes with the writer finishing before the reader.
/// Returns bytes received.
async fn one_echo_transfer(total: usize, tcp_link: bool) -> anyhow::Result<usize> {
    let echo = echo_origin().await?;
    let (a, b): (Box<dyn Link>, Box<dyn Link>) = if tcp_link {
        let ln = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = ln.local_addr()?;
        let srv = tokio::spawn(async move {
            let (s, _) = ln.accept().await.unwrap();
            s
        });
        let c = tokio::net::TcpStream::connect(addr).await?;
        (Box::new(c), Box::new(srv.await.unwrap()))
    } else {
        let (a, b) = tokio::io::duplex(64 * 1024);
        (Box::new(a), Box::new(b))
    };
    let server_task = tokio::spawn(async move {
        MuxSession::start(
            b,
            opts(false),
            Some(Arc::new(move |stream: TunnelStream, _t: Target| {
                handle_like_server(stream, echo);
            })),
        )
        .await
    });
    let client = MuxSession::start(a, opts(true), None)
        .await
        .expect("client session");
    let server = server_task.await.unwrap().expect("server session");

    let mut s = client
        .open_stream(
            Target {
                host: Some("bench".into()),
                port: 9,
                unix: None,
                hint: "raw".into(),
            },
            "none",
        )
        .await
        .expect("open stream");

    let payload: Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();
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
            let take = (256 * 1024).min(payload.len() - sent);
            w.write_all(&payload[sent..sent + take]).await?;
            sent += take;
        }
        w.shutdown().await?;
        Ok::<(), anyhow::Error>(())
    };
    let got = tokio::time::timeout(std::time::Duration::from_secs(15), async {
        tokio::try_join!(writer, reader)
    })
    .await
    .expect("transfer timed out (stall)")?
    .1;

    client.close("done");
    server.close("done");
    Ok(got)
}

/// Intermittent truncation regression: repeat the bench2 echo shape (16 MiB,
/// algo=none, writer-finishes-first) until it fails. On old code this loses
/// 24-72 KiB and reports a clean EOF; on fixed code every round delivers all
/// bytes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn echo_no_truncation_writer_finishes_first() {
    let total = 4 * MB;
    for round in 0..60 {
        let got = one_echo_transfer(total, true)
            .await
            .unwrap_or_else(|e| panic!("round {round}: transfer error: {e:#}"));
        assert_eq!(
            got,
            total,
            "round {round}: truncated echo (lost {} B)",
            total - got
        );
    }
}

/// Abandonment regression: a client that drops the stream after reading only
/// a prefix must not kill the session or stall the server's pump. On old code
/// the client's inbound pump exited on the first write error, late peer DATA
/// then failed the reader task ("stream gone") and tore the session down; the
/// server's outbound pump also lost its credit routing and parked forever.
/// On fixed code the pump drains+discards while granting credits, the peer
/// finishes cleanly, and the session serves a follow-up stream.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn abandoned_reader_keeps_session_alive() {
    let echo = echo_origin().await.unwrap();
    let (a, b) = tokio::io::duplex(64 * 1024);
    let server_task = tokio::spawn(async move {
        MuxSession::start(
            b,
            opts(false),
            Some(Arc::new(move |stream: TunnelStream, _t: Target| {
                handle_like_server(stream, echo);
            })),
        )
        .await
    });
    let client = MuxSession::start(a, opts(true), None)
        .await
        .expect("client session");
    let server = server_task.await.unwrap().expect("server session");

    let total = 2 * MB;
    {
        let s = client
            .open_stream(
                Target {
                    host: Some("bench".into()),
                    port: 9,
                    unix: None,
                    hint: "raw".into(),
                },
                "none",
            )
            .await
            .expect("open stream");
        // owned split so the halves (and the stream) can be dropped
        // independently of each other
        let (mut r, w) = tokio::io::split(s);
        let writer = tokio::spawn(async move {
            let mut w = w;
            let payload: Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();
            let mut sent = 0usize;
            while sent < payload.len() {
                let take = (256 * 1024).min(payload.len() - sent);
                if w.write_all(&payload[sent..sent + take]).await.is_err() {
                    break;
                }
                sent += take;
            }
            let _ = w.shutdown().await;
        });
        let mut buf = vec![0u8; 16 * 1024];
        let mut got = 0usize;
        while got < 128 * 1024 {
            let n = tokio::time::timeout(std::time::Duration::from_secs(10), r.read(&mut buf))
                .await
                .expect("prefix read stalled")
                .expect("prefix io");
            assert!(n > 0, "premature EOF at {got}");
            got += n;
        }
        // abandon mid-echo: cancel the writer, drop the read half; with the
        // writer task aborted both halves are gone and the TunnelStream drops
        drop(r);
        writer.abort();
        let _ = writer.await;
    }

    // the peer must be able to finish and the session must stay usable
    let mut s2 = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        client.open_stream(
            Target {
                host: Some("bench".into()),
                port: 9,
                unix: None,
                hint: "raw".into(),
            },
            "none",
        ),
    )
    .await
    .expect("follow-up open stalled: session died or peer stalled")
    .expect("follow-up open");
    s2.write_all(b"still-alive").await.unwrap();
    s2.shutdown().await.unwrap();
    let mut buf = Vec::new();
    tokio::time::timeout(std::time::Duration::from_secs(10), s2.read_to_end(&mut buf))
        .await
        .expect("follow-up echo stalled")
        .unwrap();
    assert_eq!(buf, b"still-alive");

    client.close("done");
    server.close("done");
}
