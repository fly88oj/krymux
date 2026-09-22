//! Local SOCKS5 frontend (CONNECT + UDP ASSOCIATE, no auth) — the hostname
//! from the SOCKS request is carried to the server as the routing key.
//!
//! UDP ASSOCIATE (command 3) maps one association to one multiplexed stream
//! with hint `"udp"`; datagrams travel inside a tiny framing defined below
//! (the same codec the server's udp relay speaks — defined once, here).

use crate::client::EctunClient;
use crate::mux::{Target, TunnelStream};
use anyhow::Result;
use std::sync::Arc;
/// Target hint marking a stream as the SOCKS5 UDP relay; written here,
/// dispatched by the server — one constant so the two ends cannot drift.
pub const HINT_UDP: &str = "udp";

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

/// Serves SOCKS5 CONNECT/UDP-ASSOCIATE on `listen`, forwarding every
/// connection through the tunnel as one stream.
pub async fn run_socks5(client: Arc<EctunClient>, listen: &str) -> Result<()> {
    let listener = socks5_listener(listen).await?;
    serve_socks5(client, listener).await
}

/// Binds the SOCKS5 listener (split out so embedders and tests can learn the
/// actual bound address when binding to port 0).
pub async fn socks5_listener(listen: &str) -> Result<TcpListener> {
    let (host, port) = crate::config::parse_listen(listen)?;
    let listener = TcpListener::bind((host.as_str(), port)).await?;
    let local = listener.local_addr()?;
    eprintln!(
        "krymux-client: socks5 frontend on {}:{}",
        local.ip(),
        local.port()
    );
    Ok(listener)
}

/// Accept loop over an already-bound listener.
pub async fn serve_socks5(client: Arc<EctunClient>, listener: TcpListener) -> Result<()> {
    loop {
        let (sock, _) = match listener.accept().await {
            Ok(x) => x,
            Err(_) => continue,
        };
        let client = client.clone();
        tokio::spawn(async move {
            let _ = serve_socks(client, sock).await;
        });
    }
}

async fn serve_socks(client: Arc<EctunClient>, mut sock: TcpStream) -> Result<()> {
    sock.set_nodelay(true).ok();
    // greeting: [VER NMETHODS METHODS...]
    let mut hdr = [0u8; 2];
    sock.read_exact(&mut hdr).await?;
    if hdr[0] != 0x05 {
        anyhow::bail!("not socks5");
    }
    let mut methods = vec![0u8; hdr[1] as usize];
    sock.read_exact(&mut methods).await?;
    if !methods.contains(&0x00) {
        sock.write_all(&[0x05, 0xff]).await?;
        return Ok(());
    }
    sock.write_all(&[0x05, 0x00]).await?;

    // request: [VER CMD RSV ATYP ...]
    let mut req = [0u8; 4];
    sock.read_exact(&mut req).await?;
    if req[0] != 0x05 {
        anyhow::bail!("not socks5");
    }
    let host = match req[3] {
        0x01 => {
            let mut b = [0u8; 4];
            sock.read_exact(&mut b).await?;
            b.iter()
                .map(|x| x.to_string())
                .collect::<Vec<_>>()
                .join(".")
        }
        0x04 => {
            let mut b = [0u8; 16];
            sock.read_exact(&mut b).await?;
            b.chunks(2)
                .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
                .collect::<Vec<_>>()
                .join(":")
        }
        0x03 => {
            let mut l = [0u8; 1];
            sock.read_exact(&mut l).await?;
            let mut name = vec![0u8; l[0] as usize];
            sock.read_exact(&mut name).await?;
            String::from_utf8_lossy(&name).to_string()
        }
        _ => {
            sock.write_all(&[0x05, 0x08, 0, 1, 0, 0, 0, 0, 0, 0])
                .await?;
            return Ok(());
        }
    };
    let mut pb = [0u8; 2];
    sock.read_exact(&mut pb).await?;
    let port = u16::from_be_bytes(pb);

    match req[1] {
        0x01 => serve_connect(client, sock, &host, port).await,
        0x03 => serve_udp_associate(client, sock, &host, port).await,
        // 0x07 = command not supported
        _ => {
            sock.write_all(&[0x05, 0x07, 0, 1, 0, 0, 0, 0, 0, 0])
                .await?;
            Ok(())
        }
    }
}

/// SOCKS5 error code for an open_stream failure (mirrors the CONNECT table).
fn socks_error_code(e: &anyhow::Error) -> u8 {
    if e.to_string().contains("unreachable") {
        0x04
    } else if e.to_string().contains("denied") {
        0x02
    } else {
        0x01
    }
}

async fn serve_connect(
    client: Arc<EctunClient>,
    mut sock: TcpStream,
    host: &str,
    port: u16,
) -> Result<()> {
    let mut stream = match client.open_stream(host, port, None).await {
        Ok(s) => s,
        Err(e) => {
            sock.write_all(&[0x05, socks_error_code(&e), 0, 1, 0, 0, 0, 0, 0, 0])
                .await?;
            return Ok(());
        }
    };
    sock.write_all(&[0x05, 0x00, 0, 1, 0, 0, 0, 0, 0, 0])
        .await?;
    // both directions run concurrently (a stalled write never blocks the
    // reverse read) with standard half-close propagation — the same
    // semantics as the Node implementation's upstream pipe pump
    let _ = tokio::io::copy_bidirectional(&mut sock, &mut stream).await;
    Ok(())
}

/// UDP ASSOCIATE: one tunnel stream (hint `"udp"`) carries every datagram of
/// the association; the per-datagram destination travels inside the framing,
/// so the request's DST.ADDR/DST.PORT are advisory. A local UDP socket is
/// bound and reported back as BND.ADDR; the association lives exactly as
/// long as the TCP control connection (RFC 1928).
async fn serve_udp_associate(
    client: Arc<EctunClient>,
    mut ctrl: TcpStream,
    host: &str,
    port: u16,
) -> Result<()> {
    let target = Target {
        host: if host.is_empty() {
            None
        } else {
            Some(host.to_string())
        },
        port,
        unix: None,
        hint: HINT_UDP.to_string(),
    };
    let stream = match client
        .session
        .open_stream(target, &client.compression)
        .await
    {
        Ok(s) => s,
        Err(e) => {
            ctrl.write_all(&[0x05, socks_error_code(&e), 0, 1, 0, 0, 0, 0, 0, 0])
                .await?;
            return Ok(());
        }
    };
    let udp = match UdpSocket::bind("127.0.0.1:0").await {
        Ok(s) => s,
        Err(_) => {
            // 0x01 = general SOCKS server failure
            ctrl.write_all(&[0x05, 0x01, 0, 1, 0, 0, 0, 0, 0, 0])
                .await?;
            return Ok(());
        }
    };
    let port = udp.local_addr()?.port();
    // NOTE: BND.ADDR is the relay socket's local address — we bound
    // 127.0.0.1:0, so it is always loopback: exact for a SOCKS5 client on the
    // same host, which is the deployment this frontend serves. A remote
    // SOCKS5 client cannot use a 127.0.0.1 relay at all; the reply is
    // inherently approximate and we do not attempt external-address
    // discovery.
    let mut reply = [0u8; 10];
    reply[0] = 0x05;
    reply[3] = 0x01; // ATYP: IPv4
    reply[4..8].copy_from_slice(&[127, 0, 0, 1]);
    reply[8..10].copy_from_slice(&port.to_be_bytes());
    ctrl.write_all(&reply).await?;

    relay_udp_association(ctrl, udp, stream).await
}

/// The UDP relay pump on the client side of the tunnel.
async fn relay_udp_association(
    mut ctrl: TcpStream,
    udp: UdpSocket,
    stream: TunnelStream,
) -> Result<()> {
    let udp = Arc::new(udp);
    // the ORIGINAL client source address: learned from the first datagram,
    // replies go only there (an association serves exactly one client)
    let client_addr: Arc<std::sync::Mutex<Option<std::net::SocketAddr>>> =
        Arc::new(std::sync::Mutex::new(None));

    let (mut srd, mut swr) = tokio::io::split(stream);

    // tunnel → local client: frame → RFC 1928 UDP reply header + payload
    let inbound_udp = udp.clone();
    let inbound_addr = client_addr.clone();
    let inbound = tokio::spawn(async move {
        loop {
            match read_udp_frame(&mut srd).await {
                Ok(Some(f)) => {
                    let dest = *inbound_addr.lock().unwrap();
                    let Some(dest) = dest else { continue };
                    let pkt = build_udp_reply(f.atyp, &f.addr, f.port, &f.payload);
                    if inbound_udp.send_to(&pkt, dest).await.is_err() {
                        break;
                    }
                }
                Ok(None) => break, // tunnel EOF: association over
                Err(_) => break,   // malformed frame: association over
            }
        }
    });

    // local client → tunnel: strip the SOCKS5 UDP header, refuse fragments,
    // forward the payload framed
    let mut tcpbuf = [0u8; 512];
    let mut udobuf = vec![0u8; 65536];
    loop {
        tokio::select! {
            r = ctrl.read(&mut tcpbuf) => {
                match r {
                    Ok(0) | Err(_) => break, // control connection closed
                    Ok(_) => {} // undefined data on the control conn: ignore
                }
            }
            r = udp.recv_from(&mut udobuf) => {
                let Ok((n, src)) = r else { break };
                {
                    let mut peer = client_addr.lock().unwrap();
                    if peer.is_none() {
                        *peer = Some(src);
                    }
                    if *peer != Some(src) {
                        continue; // not the association's client: drop
                    }
                }
                if let Some((atyp, addr, port, payload)) = parse_udp_header(&udobuf[..n]) {
                    let frame = encode_udp_frame(atyp, addr, port, payload);
                    if swr.write_all(&frame).await.is_err() {
                        break;
                    }
                }
                // unparsable or fragmented (FRAG != 0) datagrams are dropped
            }
        }
    }
    // tell the server we are done (FIN), then stop the inbound pump
    let _ = swr.shutdown().await;
    inbound.abort();
    Ok(())
}

// ---------------- UDP frame codec (shared with the server) ----------------
//
// One tunneled UDP datagram:
//
//   [u8 atyp][addr bytes][u16 be port][u32 be len][datagram]
//
// atyp/addr follow RFC 1928 addressing: 0x01 = 4 raw IPv4 bytes,
// 0x03 = [u8 len][domain bytes], 0x04 = 16 raw IPv6 bytes. `len` bounds the
// datagram (<= 65535). The server's udp relay (server.rs) decodes/encodes
// the very same frames — this module is the single definition of the codec.

/// Largest datagram the codec accepts (a UDP payload can never exceed this).
pub(crate) const MAX_UDP_PAYLOAD: usize = 65_535;

/// One decoded tunnel UDP frame.
pub(crate) struct UdpFrame {
    pub atyp: u8,
    pub addr: Vec<u8>,
    pub port: u16,
    pub payload: Vec<u8>,
}

/// Encodes one datagram into the tunnel framing. `addr` is the BARE address
/// (4 IPv4 bytes, a domain name, or 16 IPv6 bytes); the per-atyp length
/// prefix for domains is written here, mirroring `read_udp_frame`.
pub(crate) fn encode_udp_frame(atyp: u8, addr: &[u8], port: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + addr.len() + 6 + payload.len());
    out.push(atyp);
    if atyp == 0x03 {
        out.push(addr.len() as u8);
    }
    out.extend_from_slice(addr);
    out.extend_from_slice(&port.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// read_exact that maps a clean (or truncated) EOF to Ok(false) so callers
/// can treat end-of-input as end-of-association.
async fn read_exact_or_eof<R: AsyncRead + Unpin>(
    r: &mut R,
    buf: &mut [u8],
) -> std::io::Result<bool> {
    match r.read_exact(buf).await {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(false),
        Err(e) => Err(e),
    }
}

/// Reads exactly one frame. `Ok(None)` = end of input; `Err(InvalidData)` =
/// malformed frame (bad atyp, oversize length).
pub(crate) async fn read_udp_frame<R: AsyncRead + Unpin>(
    r: &mut R,
) -> std::io::Result<Option<UdpFrame>> {
    let mut b1 = [0u8; 1];
    if !read_exact_or_eof(r, &mut b1).await? {
        return Ok(None);
    }
    let atyp = b1[0];
    let addr: Vec<u8> = match atyp {
        0x01 => {
            let mut a = vec![0u8; 4];
            if !read_exact_or_eof(r, &mut a).await? {
                return Ok(None);
            }
            a
        }
        0x04 => {
            let mut a = vec![0u8; 16];
            if !read_exact_or_eof(r, &mut a).await? {
                return Ok(None);
            }
            a
        }
        0x03 => {
            let mut l = [0u8; 1];
            if !read_exact_or_eof(r, &mut l).await? {
                return Ok(None);
            }
            let mut a = vec![0u8; l[0] as usize];
            if !a.is_empty() && !read_exact_or_eof(r, &mut a).await? {
                return Ok(None);
            }
            a
        }
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "bad atyp in udp frame",
            ))
        }
    };
    let mut pb = [0u8; 2];
    if !read_exact_or_eof(r, &mut pb).await? {
        return Ok(None);
    }
    let mut lb = [0u8; 4];
    if !read_exact_or_eof(r, &mut lb).await? {
        return Ok(None);
    }
    let len = u32::from_be_bytes(lb) as usize;
    if len > MAX_UDP_PAYLOAD {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "udp frame payload too large",
        ));
    }
    let mut payload = vec![0u8; len];
    if !read_exact_or_eof(r, &mut payload).await? {
        return Ok(None);
    }
    Ok(Some(UdpFrame {
        atyp,
        addr,
        port: u16::from_be_bytes(pb),
        payload,
    }))
}

/// Frame address bytes → host string ("127.0.0.1", "2001:db8::1" style, or
/// the domain itself for ATYP 3).
pub(crate) fn addr_bytes_to_host(atyp: u8, addr: &[u8]) -> Option<String> {
    match atyp {
        0x01 if addr.len() == 4 => Some(
            addr.iter()
                .map(|b| b.to_string())
                .collect::<Vec<_>>()
                .join("."),
        ),
        0x04 if addr.len() == 16 => Some(
            addr.chunks(2)
                .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
                .collect::<Vec<_>>()
                .join(":"),
        ),
        0x03 => Some(String::from_utf8_lossy(addr).to_string()),
        _ => None,
    }
}

/// An IP address → (atyp, addr bytes) for framing replies.
pub(crate) fn ip_to_addr_bytes(ip: std::net::IpAddr) -> (u8, Vec<u8>) {
    match ip {
        std::net::IpAddr::V4(v4) => (0x01, v4.octets().to_vec()),
        std::net::IpAddr::V6(v6) => (0x04, v6.octets().to_vec()),
    }
}

/// Parses an RFC 1928 §7 UDP datagram header from a client datagram:
/// [RSV(2) FRAG(1) ATYP(1) DST.ADDR DST.PORT payload]. Returns None for
/// anything malformed and for FRAG != 0 (fragmentation is refused).
fn parse_udp_header(pkt: &[u8]) -> Option<(u8, &[u8], u16, &[u8])> {
    if pkt.len() < 4 {
        return None;
    }
    if pkt[2] != 0 {
        return None; // FRAG != 0: fragmented datagrams are refused
    }
    let atyp = pkt[3];
    let (addr, rest) = match atyp {
        0x01 => {
            if pkt.len() < 8 {
                return None;
            }
            (&pkt[4..8], &pkt[8..])
        }
        0x04 => {
            if pkt.len() < 20 {
                return None;
            }
            (&pkt[4..20], &pkt[20..])
        }
        0x03 => {
            let n = pkt[4] as usize;
            if pkt.len() < 5 + n + 2 {
                return None;
            }
            (&pkt[5..5 + n], &pkt[5 + n..])
        }
        _ => return None,
    };
    if rest.len() < 2 {
        return None;
    }
    let port = u16::from_be_bytes([rest[0], rest[1]]);
    Some((atyp, addr, port, &rest[2..]))
}

/// Builds an RFC 1928 §7 UDP reply datagram toward the SOCKS5 client.
/// `addr` is the BARE address (the domain length prefix is added here).
fn build_udp_reply(atyp: u8, addr: &[u8], port: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + addr.len() + 2 + payload.len());
    out.extend_from_slice(&[0, 0, 0, atyp]); // RSV RSV FRAG(0) ATYP
    if atyp == 0x03 {
        out.push(addr.len() as u8);
    }
    out.extend_from_slice(addr);
    out.extend_from_slice(&port.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_header_parse_and_frag_refusal() {
        // RSV RSV FRAG ATYP(4) 127.0.0.1 port 5353 payload
        let ok = [0, 0, 0, 0x01, 127, 0, 0, 1, 0x14, 0xe9, b'x', b'y'];
        let (atyp, addr, port, payload) = parse_udp_header(&ok).expect("parses");
        assert_eq!((atyp, port), (0x01, 5353));
        assert_eq!(addr, &[127, 0, 0, 1]);
        assert_eq!(payload, b"xy");

        let frag = [0, 0, 1, 0x01, 127, 0, 0, 1, 0x14, 0xe9, b'x'];
        assert!(
            parse_udp_header(&frag).is_none(),
            "FRAG != 0 must be refused"
        );

        let short = [0, 0, 0, 0x01, 127, 0];
        assert!(parse_udp_header(&short).is_none());
    }

    #[tokio::test]
    async fn udp_frame_codec_roundtrip() {
        let payload: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
        let frame = encode_udp_frame(0x03, b"krymux.dev", 443, &payload);
        let (mut client, mut server) = tokio::io::duplex(64);
        // the frame far exceeds the duplex buffer: write concurrently or
        // write_all parks forever waiting for a reader
        tokio::spawn(async move {
            client.write_all(&frame).await.unwrap();
            client.shutdown().await.unwrap();
        });
        let f = read_udp_frame(&mut server).await.unwrap().expect("frame");
        assert_eq!(
            (f.atyp, f.addr.as_slice(), f.port),
            (0x03, b"krymux.dev".as_slice(), 443)
        );
        assert_eq!(f.payload, payload);
        // stream exhausted afterwards
        assert!(read_udp_frame(&mut server).await.unwrap().is_none());

        // v4 addresses round-trip too, and the SOCKS5 reply header carries
        // the same per-atyp encoding
        let f4 = encode_udp_frame(0x01, &[127, 0, 0, 1], 53, b"q");
        assert_eq!(&f4[..7], &[0x01, 127, 0, 0, 1, 0, 0x35]);
        let reply = build_udp_reply(0x03, b"krymux.dev", 443, b"z");
        assert_eq!(&reply[..6], &[0, 0, 0, 0x03, 10, b'k']);
    }

    #[test]
    fn addr_bytes_conversion() {
        assert_eq!(
            addr_bytes_to_host(0x01, &[127, 0, 0, 1]).as_deref(),
            Some("127.0.0.1")
        );
        assert_eq!(
            addr_bytes_to_host(0x03, b"example.com").as_deref(),
            Some("example.com")
        );
        let (atyp, bytes) = ip_to_addr_bytes("2001:db8::1".parse().unwrap());
        assert_eq!((atyp, bytes.len()), (0x04, 16));
        assert_eq!(
            addr_bytes_to_host(atyp, &bytes).as_deref(),
            Some("2001:0db8:0000:0000:0000:0000:0000:0001")
        );
    }
}
