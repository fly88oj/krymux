//! krymux-tunnel CLI — tunnel operations: `keygen | fingerprint | server |
//! client | probe`.
//!
//! Thin application layer over the `krymux` SDK crate; the file-sync
//! application lives in `krymux-sync`.
use krymux::{client, config, httpproxy, keys, server, socks5, tls};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser)]
#[command(
    name = "krymux-tunnel",
    version,
    about = "Krymux — secure service access over reverse tunnels (tunnel operations CLI)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate an Ed25519 identity (key + self-signed cert + fingerprint)
    Keygen {
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value = "server")]
        role: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        cn: Option<String>,
    },
    /// Print the fingerprint of a key/certificate PEM file
    Fingerprint { path: PathBuf },
    /// Run the reverse-proxy server
    Server {
        #[arg(long)]
        config: PathBuf,
    },
    /// Run the client (optionally with local SOCKS5 / HTTP proxy frontends)
    Client {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        socks5: Option<String>,
        #[arg(long = "http-proxy")]
        http_proxy: Option<String>,
    },
    /// Show a server's key fingerprint (TOFU helper)
    Probe { endpoint: String },
}

#[tokio::main]
async fn main() {
    let _ = env_logger::Builder::from_env(env_logger::Env::new().filter_or("KRYMUX_LOG", "warn"))
        .try_init();
    let cli = Cli::parse();
    if let Err(e) = run(cli).await {
        eprintln!("fatal: {e:#}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<()> {
    match cli.cmd {
        Cmd::Keygen {
            out,
            role,
            name,
            cn,
        } => {
            let name = name.unwrap_or_else(|| role.clone());
            let id = keys::generate_identity(cn.as_deref().unwrap_or(&format!("krymux-{}", name)))?;
            let (key_path, cert_path) = keys::save_identity(&out, &id, &name)?;
            println!("identity:    {} ({})", role, name);
            println!("key:         {}", key_path.display());
            println!("cert:        {}", cert_path.display());
            println!("fingerprint: {}", id.fingerprint);
            if role == "client" {
                println!("\nAdd this fingerprint to the server config's auth.fingerprints list:\n  \"{}\"", id.fingerprint);
            } else {
                println!(
                    "\nPin this in client configs (serverFingerprint):\n  \"{}\"",
                    id.fingerprint
                );
            }
            Ok(())
        }
        Cmd::Fingerprint { path } => {
            // try as certificate, then as public key
            let text =
                std::fs::read_to_string(&path).with_context(|| path.display().to_string())?;
            let fp = keys::normalize_fingerprint(&text)
                .or_else(|_| keys::normalize_fingerprint(&path.display().to_string()))?;
            println!("{}", fp);
            Ok(())
        }
        Cmd::Server { config } => {
            let compiled = Arc::new(config::load_server_cfg(&config)?);
            let identity = Arc::new(keys::load_identity(
                &PathBuf::from(&compiled.cfg.identity.key),
                &PathBuf::from(&compiled.cfg.identity.cert),
            )?);
            let ws_identity = match krymux::ws::WsIdentity::generate() {
                Ok(id) => {
                    eprintln!(
                        "krymux-server: browser (WS) access enabled, wsFingerprint={}",
                        id.fingerprint
                    );
                    Some(Arc::new(id))
                }
                Err(e) => {
                    eprintln!("krymux-server: WS identity generation failed: {e}");
                    None
                }
            };
            let listen = compiled.cfg.listen.clone();
            server::run_server(compiled, identity, &listen, ws_identity).await
        }
        Cmd::Client {
            config,
            socks5,
            http_proxy,
        } => {
            let cfg = config::load_client_cfg(&config)?;
            let identity = Arc::new(keys::load_identity(
                &PathBuf::from(&cfg.identity.key),
                &PathBuf::from(&cfg.identity.cert),
            )?);
            let server_fp = keys::normalize_fingerprint(&cfg.server_fingerprint)?;
            let c = client::EctunClient::connect(
                &cfg.endpoint,
                &identity,
                &server_fp,
                &client::ConnectParams {
                    compression: cfg.compression.clone(),
                    keepalive_sec: cfg.keepalive_sec,
                    rx_window: cfg.rx_window,
                    rx_window_max: cfg.rx_window_max,
                    ..Default::default()
                },
            )
            .await?;
            eprintln!(
                "krymux-client: tunnel up to {} (server {}…)",
                cfg.endpoint,
                &server_fp[7..19.min(server_fp.len())]
            );
            let c = Arc::new(c);
            let socks_addr = socks5.or_else(|| cfg.socks5.clone());
            if let Some(socks) = socks_addr {
                let c2 = c.clone();
                tokio::spawn(async move {
                    if let Err(e) = socks5::run_socks5(c2, &socks).await {
                        eprintln!("socks5 frontend error: {e}");
                    }
                });
            }
            let http_addr = http_proxy.or_else(|| cfg.http_proxy.clone());
            if let Some(hp) = http_addr {
                let c2 = c.clone();
                tokio::spawn(async move {
                    if let Err(e) = httpproxy::run_http_proxy(c2, &hp).await {
                        eprintln!("http proxy frontend error: {e}");
                    }
                });
            }
            let _ = std::future::pending::<()>().await;
            Ok(())
        }
        Cmd::Probe { endpoint } => {
            let id = keys::generate_identity("probe")?;
            let identity = Arc::new(keys::LoadedIdentity {
                cert_der: id.cert_der,
                key_der: id.key_der,
                fingerprint: id.fingerprint,
            });
            let (host, port) = config::parse_listen(&endpoint)?;
            let connector = tls::client_connector(&identity)?;
            let tcp = tokio::net::TcpStream::connect((host.as_str(), port))
                .await
                .with_context(|| format!("connect {endpoint}"))?;
            let stream = connector
                .connect(rustls::pki_types::ServerName::try_from(host.clone())?, tcp)
                .await
                .context("tls handshake")?;
            let alpn = stream
                .get_ref()
                .1
                .alpn_protocol()
                .map(|p| String::from_utf8_lossy(p).to_string())
                .unwrap_or_else(|| "none".into());
            let fp = tls::peer_fingerprint(stream.get_ref().1.peer_certificates())
                .ok()
                .flatten();
            println!("endpoint:    {}", endpoint);
            println!("alpn:        {}", alpn);
            match fp {
                Some(fp) => {
                    println!("fingerprint: {}", fp);
                    println!(
                        "\nIf this is your server, pin it: \"serverFingerprint\": \"{}\"",
                        fp
                    );
                }
                None => println!("fingerprint: (none presented)"),
            }
            Ok(())
        }
    }
}
