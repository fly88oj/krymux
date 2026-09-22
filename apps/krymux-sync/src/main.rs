//! krymux-sync CLI — FileSync application: `sync-server | sync-client`.
//!
//! The sync engine is local to this binary; tunnel connectivity comes from
//! the `krymux` SDK crate.
mod sync;

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::AsyncReadExt as _;

#[derive(Parser)]
#[command(
    name = "krymux-sync",
    version,
    about = "Krymux FileSync — bidirectional file sync over krymux tunnels"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run a file sync server on a local TCP port (behind krymux)
    SyncServer {
        #[arg(long)]
        path: PathBuf,
        #[arg(long, default_value = "17890")]
        port: u16,
        #[arg(long, default_value = "bidir")]
        mode: String,
    },
    /// Run a file sync client through the krymux tunnel
    SyncClient {
        #[arg(long)]
        path: PathBuf,
        #[arg(long)]
        config: PathBuf,
        #[arg(long, default_value = "bidir")]
        mode: String,
        /// daemon mode: keep running, watch local changes, reconnect on failure
        #[arg(long)]
        watch: bool,
        /// reconcile interval in seconds (watch mode)
        #[arg(long, default_value = "30")]
        interval: u64,
    },
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

async fn run(cli: Cli) -> anyhow::Result<()> {
    match cli.cmd {
        Cmd::SyncServer { path, port, mode } => {
            let root = std::fs::canonicalize(&path)?;
            let _root_lock = sync::scanner::acquire_root_lock(&root)?;
            log::info!("checking for locked files…");
            sync::scanner::check_startup_locks(&root, true)?;
            let cleaned = sync::scanner::clean_stale_tmp(&root)?;
            if cleaned > 0 {
                eprintln!("[sync-server] cleaned {cleaned} stale *.sync-tmp");
            }
            let hub = match sync::notify::NotifyHub::new(&root) {
                Ok(h) => Arc::new(h),
                Err(e) => {
                    eprintln!("[sync-server] FS watcher unavailable ({e}); clients fall back to interval reconcile");
                    Arc::new(sync::notify::NotifyHub::disabled())
                }
            };
            let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
            println!(
                "sync server listening on 127.0.0.1:{port} (path={}, mode={mode})",
                root.display()
            );
            println!("\nConfigure krymux server to route here:");
            println!("  {{ \"host\": [\"sync\"], \"upstream\": [\"127.0.0.1\", {port}] }}\n");
            loop {
                let (mut socket, _) = listener.accept().await?;
                let root = root.clone();
                let mode = mode.clone();
                let hub = hub.clone();
                tokio::spawn(async move {
                    let _ = socket.set_nodelay(true);
                    // first frame decides the session type:
                    // hello → sync pass, notify_listen → long-lived hint stream
                    let mut parser = sync::protocol::SyncParser::new();
                    let mut buf = [0u8; 64 * 1024];
                    // keep the WHOLE first batch: a pipelining client may send
                    // hello + request_scan in one TCP segment, and dropping the
                    // extra frames would deadlock the session
                    let first_batch = loop {
                        match socket.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => match parser.push(&buf[..n]) {
                                Ok(msgs) => {
                                    if !msgs.is_empty() {
                                        break msgs;
                                    }
                                }
                                Err(_) => return,
                            },
                        }
                    };
                    let notify_session = matches!(
                        first_batch.first(),
                        Some(sync::protocol::SyncMessage::Json(v))
                            if v["t"] == sync::protocol::T_NOTIFY_LISTEN
                    );
                    let res = if notify_session {
                        sync::handle_notify_session(&mut socket, &hub).await
                    } else {
                        sync::handle_sync_server(
                            &mut socket,
                            &root,
                            &mode,
                            &hub,
                            parser,
                            first_batch,
                        )
                        .await
                    };
                    if let Err(e) = res {
                        eprintln!("[sync-server] session error: {e}");
                    }
                });
            }
        }
        Cmd::SyncClient {
            path,
            config,
            mode,
            watch,
            interval,
        } => {
            let root = std::fs::canonicalize(&path)?;
            let _root_lock = sync::scanner::acquire_root_lock(&root)?;
            log::info!("checking for locked files…");
            sync::scanner::check_startup_locks(&root, true)?;
            let cleaned = sync::scanner::clean_stale_tmp(&root)?;
            if cleaned > 0 {
                eprintln!("[sync] cleaned {cleaned} stale *.sync-tmp");
            }

            if watch {
                sync::daemon::run(&root, &config, &mode, interval).await
            } else {
                let cfg = krymux::config::load_client_cfg(&config)?;
                let identity = Arc::new(krymux::keys::load_identity(
                    &PathBuf::from(&cfg.identity.key),
                    &PathBuf::from(&cfg.identity.cert),
                )?);
                let server_fp = krymux::keys::normalize_fingerprint(&cfg.server_fingerprint)?;
                let c = krymux::client::EctunClient::connect(
                    &cfg.endpoint,
                    &identity,
                    &server_fp,
                    &krymux::client::ConnectParams {
                        ..Default::default()
                    },
                )
                .await?;
                eprintln!("tunnel connected to {}", cfg.endpoint);

                let mut stream = c.open_stream("sync", 17890, Some("none")).await?;
                eprintln!("sync stream opened");

                let stats = sync::run_sync_client(&mut stream, &root, &mode).await?;
                println!(
                    "\nSync complete: downloaded={}, uploads={}, conflicts={}, locked-skip={}",
                    stats.downloaded, stats.uploads, stats.conflicts, stats.locked_skipped
                );
                if stats.conflicts > 0 {
                    println!("\n⚠ {} conflicts need manual resolution", stats.conflicts);
                }
                c.session.close("sync done");
                Ok(())
            }
        }
    }
}
