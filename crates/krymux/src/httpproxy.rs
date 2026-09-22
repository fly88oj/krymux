//! Local HTTP/1.1 proxy frontend: CONNECT tunneling plus absolute-form
//! request forwarding.

use crate::client::EctunClient;
use anyhow::Result;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Serves HTTP/1.1 proxying on `listen`, forwarding every request or CONNECT
/// through the tunnel as one stream.
pub async fn run_http_proxy(client: Arc<EctunClient>, listen: &str) -> Result<()> {
    let (host, port) = crate::config::parse_listen(listen)?;
    let listener = TcpListener::bind((host.as_str(), port)).await?;
    let local = listener.local_addr()?;
    eprintln!(
        "krymux-client: http proxy frontend on {}:{}",
        local.ip(),
        local.port()
    );
    loop {
        let (sock, _) = match listener.accept().await {
            Ok(x) => x,
            Err(_) => continue,
        };
        let client = client.clone();
        tokio::spawn(async move {
            let _ = serve_http(client, sock).await;
        });
    }
}

async fn serve_http(client: Arc<EctunClient>, mut sock: TcpStream) -> Result<()> {
    sock.set_nodelay(true).ok();
    let mut acc: Vec<u8> = Vec::with_capacity(4 * 1024);
    let mut buf = [0u8; 8 * 1024];
    let head_end;
    loop {
        let n = sock.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        acc.extend_from_slice(&buf[..n]);
        if let Some(idx) = find_head_end(&acc) {
            head_end = idx;
            break;
        }
        if acc.len() > 64 * 1024 {
            return Ok(());
        }
    }
    let head = String::from_utf8_lossy(&acc[..head_end]).to_string();
    let rest = acc[head_end + 4..].to_vec();
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or_default().to_string();
    let m = request_line.split_whitespace().collect::<Vec<_>>();
    if m.len() < 3 {
        return Ok(());
    }
    let method = m[0];
    let target_url = m[1];

    if method == "CONNECT" {
        let (host, port) = split_host_port(target_url, 443);
        match client.open_stream(&host, port, None).await {
            Ok(mut stream) => {
                sock.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await?;
                if !rest.is_empty() {
                    stream.write_all(&rest).await?;
                }
                let _ = tokio::io::copy_bidirectional(&mut sock, &mut stream).await;
            }
            Err(_) => {
                sock.write_all(
                    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await?;
            }
        }
        return Ok(());
    }

    // absolute-form request
    let Ok(url) = url::parse(target_url) else {
        sock.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            .await?;
        return Ok(());
    };
    let host = url.host_str().unwrap_or("").to_string();
    let port = url.port.unwrap_or(80);
    let path = if url.path().is_empty() {
        "/".to_string()
    } else {
        url.path().to_string()
    };
    let query = url.query().map(|q| format!("?{}", q)).unwrap_or_default();

    let mut out = format!("{} {}{} {}\r\n", method, path, query, m[2]);
    for l in lines {
        if l.is_empty() {
            continue;
        }
        let lower = l.to_ascii_lowercase();
        if lower.starts_with("proxy-") || lower.starts_with("connection:") {
            continue;
        }
        out.push_str(l);
        out.push_str("\r\n");
    }
    out.push_str("Connection: close\r\n\r\n");

    match client.open_stream(&host, port, None).await {
        Ok(mut stream) => {
            stream.write_all(out.as_bytes()).await?;
            if !rest.is_empty() {
                stream.write_all(&rest).await?;
            }
            let _ = tokio::io::copy_bidirectional(&mut sock, &mut stream).await;
        }
        Err(_) => {
            sock.write_all(
                b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .await?;
        }
    }
    Ok(())
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn split_host_port(s: &str, default_port: u16) -> (String, u16) {
    if let Some(rest) = s.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            let host = rest[..end].to_string();
            let port: Option<u16> = rest[end + 1..].trim_start_matches(':').parse().ok();
            return (host, port.unwrap_or(default_port));
        }
    }
    match s.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().unwrap_or(default_port)),
        None => (s.to_string(), default_port),
    }
}

// tiny URL parser to avoid pulling in the `url` crate
mod url {
    pub struct Url {
        pub host: String,
        pub port: Option<u16>,
        pub path: String,
        pub query: Option<String>,
    }
    impl Url {
        pub fn host_str(&self) -> Option<&str> {
            Some(&self.host)
        }
        pub fn path(&self) -> &str {
            &self.path
        }
        pub fn query(&self) -> Option<&str> {
            self.query.as_deref()
        }
    }
    pub fn parse(s: &str) -> Result<Url, ()> {
        let (scheme, rest) = s.split_once("://").ok_or(())?;
        let (authority, pathq) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, ""),
        };
        let authority = authority.split('@').next_back().unwrap_or(authority);
        let (host, port) = if let Some(r) = authority.strip_prefix('[') {
            let end = r.find(']').ok_or(())?;
            let host = r[..end].to_string();
            let port = r[end + 1..].trim_start_matches(':').parse().ok();
            (host, port)
        } else {
            match authority.rsplit_once(':') {
                Some((h, p)) => (h.to_string(), p.parse().ok()),
                None => (authority.to_string(), None),
            }
        };
        if host.is_empty() {
            return Err(());
        }
        let (path, query) = match pathq.split_once('?') {
            Some((p, q)) => (p.to_string(), Some(q.to_string())),
            None => (pathq.to_string(), None),
        };
        let _ = scheme;
        Ok(Url {
            host,
            port,
            path,
            query,
        })
    }
}
