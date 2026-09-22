//! End-to-end SOCKS5 UDP ASSOCIATE test: a UDP echo server, a krymux server
//! (hint=udp streams handled natively by server::handle_stream), a krymux
//! client with the SOCKS5 frontend, and a hand-rolled SOCKS5 UDP client
//! (tokio sockets + raw RFC 1928 bytes). Everything binds to 127.0.0.1 on
//! ephemeral ports in-process — hermetic and race-free (listeners are bound
//! before anything connects).

use krymux::client::{ConnectParams, EctunClient};
use krymux::keys;
use krymux::server;
use krymux::socks5;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

/// A SOCKS5 UDP client datagram: [RSV RSV FRAG ATYP DST.ADDR DST.PORT payload]
/// addressed to 127.0.0.1:`port`.
fn socks_udp_packet(port: u16, payload: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(10 + payload.len());
    pkt.extend_from_slice(&[0, 0, 0, 0x01, 127, 0, 0, 1]);
    pkt.extend_from_slice(&port.to_be_bytes());
    pkt.extend_from_slice(payload);
    pkt
}

#[tokio::test]
async fn socks5_udp_associate_end_to_end() -> anyhow::Result<()> {
    // ---- UDP echo upstream ----
    let echo = UdpSocket::bind("127.0.0.1:0").await?;
    let echo_port = echo.local_addr()?.port();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        while let Ok((n, peer)) = echo.recv_from(&mut buf).await {
            let _ = echo.send_to(&buf[..n], peer).await;
        }
    });

    // ---- identities + server config (catch-all route on purpose: hint=udp
    // must be handled natively, never routed to a TCP upstream) ----
    let dir = std::env::temp_dir().join(format!(
        "krymux-udp-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis()
    ));
    let server_id = keys::generate_identity("krymux-udp-test-server")?;
    let (srv_key, srv_cert) = keys::save_identity(&dir, &server_id, "server")?;
    let client_id = keys::generate_identity("krymux-udp-test-client")?;
    let (cli_key, cli_cert) = keys::save_identity(&dir, &client_id, "client")?;

    let cfg = serde_json::json!({
        "listen": "127.0.0.1:0", // unused: the test passes its own listener
        "identity": {
            "key": srv_key.display().to_string(),
            "cert": srv_cert.display().to_string()
        },
        "auth": { "mode": "open" },
        "routes": [ { "host": ["*"], "port": "*", "upstream": ["127.0.0.1", 9] } ]
    });
    let cfg_path = dir.join("server.json");
    std::fs::write(&cfg_path, cfg.to_string())?;
    let compiled = Arc::new(krymux::config::load_server_cfg(&cfg_path)?);

    // ---- krymux server on a pre-bound listener (exact port, no bind race) ----
    let tls_listener = TcpListener::bind("127.0.0.1:0").await?;
    let server_port = tls_listener.local_addr()?.port();
    let identity = Arc::new(keys::load_identity(&srv_key, &srv_cert)?);
    tokio::spawn(server::serve_connections(
        compiled,
        identity,
        tls_listener,
        None,
    ));

    // ---- krymux client + SOCKS5 frontend ----
    let client_identity = Arc::new(keys::load_identity(&cli_key, &cli_cert)?);
    let c = EctunClient::connect(
        &format!("127.0.0.1:{server_port}"),
        &client_identity,
        &server_id.fingerprint,
        &ConnectParams::default(),
    )
    .await?;
    let c = Arc::new(c);
    let socks_listener = socks5::socks5_listener("127.0.0.1:0").await?;
    let socks_addr = socks_listener.local_addr()?;
    tokio::spawn(socks5::serve_socks5(c.clone(), socks_listener));

    // ---- SOCKS5 UDP client: greeting ----
    let mut ctrl = TcpStream::connect(socks_addr).await?;
    ctrl.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut gr = [0u8; 2];
    ctrl.read_exact(&mut gr).await?;
    assert_eq!(&gr, &[0x05, 0x00], "server must pick no-auth");

    // ---- UDP ASSOCIATE for the echo server ----
    ctrl.write_all(&[0x05, 0x03, 0x00, 0x01, 127, 0, 0, 1])
        .await?;
    ctrl.write_all(&echo_port.to_be_bytes()).await?;
    let mut rep = [0u8; 10];
    ctrl.read_exact(&mut rep).await?;
    assert_eq!(rep[0], 0x05);
    assert_eq!(
        rep[1], 0x00,
        "ASSOCIATE must succeed, got error code {}",
        rep[1]
    );
    assert_eq!(rep[3], 0x01, "BND.ADDR must be IPv4");
    let relay = std::net::SocketAddr::from((
        [rep[4], rep[5], rep[6], rep[7]],
        u16::from_be_bytes([rep[8], rep[9]]),
    ));
    assert_eq!(
        relay.ip(),
        std::net::IpAddr::from(std::net::Ipv4Addr::LOCALHOST)
    );

    let udp = UdpSocket::bind("127.0.0.1:0").await?;
    let mut rbuf = vec![0u8; 65536];

    // ---- datagram round-trips (small + near-jumbo) ----
    udp.send_to(&socks_udp_packet(echo_port, b"hello krymux udp"), relay)
        .await?;
    let (n, _) = tokio::time::timeout(Duration::from_secs(10), udp.recv_from(&mut rbuf))
        .await
        .expect("echo reply must arrive")?;
    assert_eq!(
        &rbuf[..n],
        &socks_udp_packet(echo_port, b"hello krymux udp")[..]
    );

    let big: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
    udp.send_to(&socks_udp_packet(echo_port, &big), relay)
        .await?;
    let (n, _) = tokio::time::timeout(Duration::from_secs(10), udp.recv_from(&mut rbuf))
        .await
        .expect("big echo reply must arrive")?;
    assert_eq!(&rbuf[..n], &socks_udp_packet(echo_port, &big)[..]);

    // ---- FRAG != 0 must be refused (no reply) ----
    let mut frag = socks_udp_packet(echo_port, b"fragmented");
    frag[2] = 0x01;
    udp.send_to(&frag, relay).await?;
    let got = tokio::time::timeout(Duration::from_millis(500), udp.recv_from(&mut rbuf)).await;
    if let Ok(Ok((n, _))) = got {
        anyhow::bail!("fragmented datagram must not be relayed, got {} bytes", n);
    }

    // ---- control-connection close tears the association down, session lives ----
    ctrl.shutdown().await?;
    c.session
        .ping()
        .await
        .expect("session must survive an association close");
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}
