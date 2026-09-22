// Minimal repro (corrected topology): the mux's outbound pump reads
// session_rd while the app holds a_wr. Does a_wr.shutdown() wake a pending
// read on session_rd?
// Usage: cargo run --example eof_repro
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() {
    let (app, session_side) = tokio::io::duplex(64 * 1024);
    let (mut s_rd, _s_wr) = tokio::io::split(session_side);
    let (_a_rd, mut a_wr) = tokio::io::split(app);

    let t0 = Instant::now();
    let reader = tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        let n = s_rd.read(&mut buf).await;
        (n, t0.elapsed())
    });

    tokio::time::sleep(Duration::from_millis(200)).await;
    println!("shutting down app write half at {:?}", t0.elapsed());
    a_wr.shutdown().await.expect("shutdown");
    println!("shutdown returned at {:?}", t0.elapsed());

    let res = tokio::time::timeout(Duration::from_secs(3), reader).await;
    match res {
        Err(_) => {
            println!(
                "FAIL: session_rd did not wake within 3s after a_wr.shutdown() — EOF signal lost"
            );
            std::process::exit(1);
        }
        Ok(Ok((n, elapsed))) => match n {
            Ok(0) => {
                println!("PASS: EOF reached session_rd at {:?} (prompt)", elapsed);
                std::process::exit(0);
            }
            other => {
                println!("UNEXPECTED read result: {:?}", other);
                std::process::exit(2);
            }
        },
        Ok(Err(e)) => {
            println!("reader task failed: {e}");
            std::process::exit(3);
        }
    }
}
