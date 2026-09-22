// Minimal in-process handshake check: rustls server (AnyClientCert) <-> rustls client (NoServerVerify + pin)
use krymux::{keys, tls};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let sid = keys::generate_identity("srv")?;
    let cid = keys::generate_identity("cli")?;
    println!("server fp: {}", sid.fingerprint);
    println!("client fp: {}", cid.fingerprint);

    let server_id = Arc::new(keys::LoadedIdentity {
        cert_der: sid.cert_der,
        key_der: sid.key_der,
        fingerprint: sid.fingerprint.clone(),
    });
    let client_id = Arc::new(keys::LoadedIdentity {
        cert_der: cid.cert_der,
        key_der: cid.key_der,
        fingerprint: cid.fingerprint,
    });

    let acceptor = tls::server_acceptor(&server_id)?;
    let connector = tls::client_connector(&client_id)?;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await?;
        let mut s = acceptor.accept(tcp).await?;
        let mut buf = [0u8; 64];
        let n = s.read(&mut buf).await?;
        s.write_all(&buf[..n]).await?;
        let alpn = s
            .get_ref()
            .1
            .alpn_protocol()
            .map(|p| String::from_utf8_lossy(p).to_string());
        let certs = s.get_ref().1.peer_certificates().map(|c| c.len());
        println!("server: echo done alpn={alpn:?} certs={certs:?}");
        Ok::<(), anyhow::Error>(())
    });

    let tcp = tokio::net::TcpStream::connect(addr).await?;
    let mut c = connector
        .connect(
            rustls::pki_types::ServerName::try_from("127.0.0.1".to_string())?,
            tcp,
        )
        .await?;
    c.write_all(b"hello-handshake").await?;
    let mut buf = [0u8; 64];
    let n = c.read(&mut buf).await?;
    println!("client: echoed {}", String::from_utf8_lossy(&buf[..n]));
    let fp = tls::peer_fingerprint(c.get_ref().1.peer_certificates())?;
    println!("client: server pin = {:?}", fp.as_deref().map(|f| &f[..19]));
    server.await??;
    println!("HANDSHAKE EXAMPLE OK");
    Ok(())
}
