// Sync daemon: keep a directory in sync through the krymux tunnel, forever.
//
// One-shot passes are chained into a loop:
//   - a local FS change (notify, debounced by a quiet window) triggers a pass
//   - a rescan_hint pushed by the server triggers a pass (notify stream)
//   - a periodic reconcile timer triggers a pass so remote changes get pulled
//     even against servers that don't push hints
//   - a failed pass drops the tunnel; the next pass reconnects with
//     exponential backoff (1s → 60s cap)
//
// Interruption safety: every file lands via tmp + rename, and both scanners
// skip `*.sync-tmp`, so killing the daemon at any point never corrupts a tree.

use crate::sync::SyncStats;
use anyhow::{Context, Result};
use krymux::client::EctunClient;
use krymux::config::ClientCfg;
use krymux::keys::{self, LoadedIdentity};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt as _;
use tokio::sync::mpsc;

/// Runs the sync daemon forever: one-shot passes chained by local filesystem
/// events (debounced), server-pushed rescan hints, and the reconcile
/// interval, with exponential reconnect backoff on failure.
pub async fn run(root: &Path, cfg_path: &Path, mode: &str, interval_sec: u64) -> Result<()> {
    let cfg: ClientCfg = krymux::config::load_client_cfg(cfg_path)?;
    let identity = Arc::new(keys::load_identity(
        &PathBuf::from(&cfg.identity.key),
        &PathBuf::from(&cfg.identity.cert),
    )?);
    let server_fp = keys::normalize_fingerprint(&cfg.server_fingerprint)?;
    let params = krymux::client::ConnectParams {
        compression: cfg.compression.clone(),
        keepalive_sec: cfg.keepalive_sec,
        rx_window: cfg.rx_window,
        rx_window_max: cfg.rx_window_max,
        ..Default::default()
    };

    let (tx, mut rx) = mpsc::channel::<()>(256);
    let _watcher = spawn_watcher(root, tx)?;

    // server push channel: the notify stream task forwards rescan hints here
    let (hint_tx, mut hint_rx) = mpsc::channel::<()>(256);
    let mut notify_task: Option<tokio::task::JoinHandle<()>> = None;

    let mut client: Option<Arc<EctunClient>> = None;
    let mut backoff = 1u64;
    let mut pass: u64 = 0;
    eprintln!(
        "[syncd] watching {} (interval {interval_sec}s, mode {mode})",
        root.display()
    );
    loop {
        pass += 1;
        match one_pass(
            &cfg,
            &identity,
            &server_fp,
            &params,
            &mut client,
            root,
            mode,
        )
        .await
        {
            Ok(stats) => {
                backoff = 1;
                log::info!(
                    "pass #{pass}: {} downloaded, {} uploaded, {} conflicts, {} locked-skip",
                    stats.downloaded,
                    stats.uploads,
                    stats.conflicts,
                    stats.locked_skipped
                );
                if stats.downloaded + stats.uploads > 0 {
                    eprintln!(
                        "[syncd] pass #{pass}: {} downloaded, {} uploaded",
                        stats.downloaded, stats.uploads
                    );
                }
                // (re)attach the notify stream whenever it's missing or died;
                // old servers that don't speak notify_listen leave it silent
                // and we simply keep running on interval reconcile
                let notify_alive = notify_task.as_ref().is_some_and(|t| !t.is_finished());
                if !notify_alive {
                    if let Some(c) = client.as_ref() {
                        notify_task = open_notify(c, hint_tx.clone()).await;
                    }
                }
            }
            Err(e) => {
                client = None; // force a fresh tunnel next time
                notify_task = None;
                log::warn!("pass #{pass} failed: {e:#}");
                eprintln!("[syncd] pass #{pass} failed: {e:#}; retry in {backoff}s");
                tokio::time::sleep(Duration::from_secs(backoff)).await;
                backoff = (backoff * 2).min(60);
                continue;
            }
        }

        let hints_open = notify_task.as_ref().is_some_and(|t| !t.is_finished());
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(interval_sec)) => {}
            _ = rx.recv() => settle(&mut rx, &mut hint_rx).await,
            fired = hint_rx.recv(), if hints_open => {
                if fired.is_some() {
                    log::debug!("rescan hint from server");
                    settle(&mut rx, &mut hint_rx).await;
                }
            }
            // the notify stream ending is itself a signal: revalidate now
            // instead of waiting out the interval
            _ = async {
                match notify_task.as_mut() {
                    Some(t) => { let _ = t.await; }
                    None => std::future::pending::<()>().await,
                }
            } => {
                notify_task = None;
                log::info!("notify stream ended; revalidating connection");
            }
        }
    }
}

/// Debounce: wait for a quiet window before scanning, so writers (editors,
/// unzip, our own tmp+rename, hint bursts) can finish.
async fn settle(rx: &mut mpsc::Receiver<()>, hint_rx: &mut mpsc::Receiver<()>) {
    loop {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(700)) => break,
            _ = rx.recv() => {}
            _ = hint_rx.recv() => {}
        }
    }
}

/// Open a long-lived notify stream on the tunnel. Any rescan_hint frame the
/// server pushes is forwarded as a trigger; the task exits when the stream
/// dies so the main loop can reopen it after the next pass.
async fn open_notify(
    c: &Arc<EctunClient>,
    tx: mpsc::Sender<()>,
) -> Option<tokio::task::JoinHandle<()>> {
    let mut stream = c.open_stream("sync", 17890, Some("none")).await.ok()?;
    if crate::sync::protocol::write_json(&mut stream, &crate::sync::protocol::notify_listen())
        .await
        .is_err()
    {
        return None;
    }
    Some(tokio::spawn(async move {
        let mut parser = crate::sync::protocol::SyncParser::new();
        let mut buf = [0u8; 4096];
        loop {
            match stream.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let Ok(msgs) = parser.push(&buf[..n]) else {
                        break;
                    };
                    let hint = msgs.iter().any(|m| {
                        matches!(m, crate::sync::protocol::SyncMessage::Json(v)
                            if v["t"] == crate::sync::protocol::T_RESCAN_HINT)
                    });
                    if hint && tx.send(()).await.is_err() {
                        break;
                    }
                }
            }
        }
    }))
}

/// One full connect-or-reuse → open stream → sync pass.
/// Connection errors propagate; the caller reconnects on the next iteration.
async fn one_pass(
    cfg: &ClientCfg,
    identity: &Arc<LoadedIdentity>,
    server_fp: &str,
    params: &krymux::client::ConnectParams,
    client: &mut Option<Arc<EctunClient>>,
    root: &Path,
    mode: &str,
) -> Result<SyncStats> {
    if client.is_none() {
        let c = EctunClient::connect(&cfg.endpoint, identity, server_fp, params)
            .await
            .context("tunnel connect")?;
        log::info!("tunnel connected to {}", cfg.endpoint);
        *client = Some(Arc::new(c));
    }
    let c = client.as_ref().expect("just set").clone();
    do_sync(&c, root, mode).await
}

async fn do_sync(c: &EctunClient, root: &Path, mode: &str) -> Result<SyncStats> {
    let mut stream = c.open_stream("sync", 17890, Some("none")).await?;
    crate::sync::run_sync_client(&mut stream, root, mode).await
}

fn spawn_watcher(root: &Path, tx: mpsc::Sender<()>) -> Result<notify::RecommendedWatcher> {
    use notify::{EventKind, RecursiveMode, Watcher};
    use std::collections::HashSet;
    use std::sync::{Arc, Mutex};

    let watch_root = root.to_path_buf();
    // Paths we have observed to be directories while they existed. Windows FS
    // events cannot tell a file removal from a directory removal, so the set
    // is what lets us avoid tombstoning a removed directory (a dir path is
    // never a synced file — tombstoning it would delete a same-named server
    // file that the user never deleted).
    let known_dirs: Arc<Mutex<HashSet<PathBuf>>> = Arc::new(Mutex::new(HashSet::new()));
    let kd = known_dirs.clone();
    let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        let Ok(ev) = res else { return };
        // inotify reports reads too — our own scan/hash would self-trigger a
        // pass loop on Linux, so only real mutations count
        let mutated = matches!(
            ev.kind,
            EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
        );
        // our own staging files, the root lockfile, and the tombstone store
        // converge to no-op passes; skip them
        let sync_metadata = |p: &std::path::Path| {
            p.file_name()
                .map(|n| crate::sync::scanner::is_sync_metadata(&n.to_string_lossy()))
                .unwrap_or(true)
        };
        // remember directories while we can still see them
        if matches!(ev.kind, EventKind::Create(_) | EventKind::Modify(_)) {
            for p in &ev.paths {
                if p.is_dir() {
                    if let Ok(mut dirs) = kd.lock() {
                        // bound the set: a huge tree would otherwise grow it
                        // without limit. Clearing wholesale is safe — member-
                        // ship is only a heuristic guard against tombstoning
                        // removed DIRECTORIES; after a clear the worst case is
                        // one spurious tombstone when a dir removal is misread
                        // as a file removal, which the next pass re-uploads
                        // (self-correcting). Repopulation is lazy from later
                        // Create/Modify events.
                        if dirs.len() >= 4096 {
                            dirs.clear();
                        }
                        dirs.insert(p.clone());
                    }
                }
            }
        }
        // a removed FILE is a deletion the next pass must propagate to the
        // server instead of re-downloading: tombstone it now, while we still
        // know the path (record BEFORE the pass trigger below, so the pass
        // the trigger launches is guaranteed to see it). Removed directories
        // are not tombstoned: platforms that report RemoveKind::Folder are
        // filtered here, the others by the known_dirs set above.
        if matches!(
            ev.kind,
            EventKind::Remove(notify::event::RemoveKind::File)
                | EventKind::Remove(notify::event::RemoveKind::Any)
                | EventKind::Remove(notify::event::RemoveKind::Other)
        ) {
            for p in &ev.paths {
                if sync_metadata(p) {
                    continue;
                }
                let was_dir = match kd.lock() {
                    Ok(mut dirs) => dirs.remove(p),
                    Err(_) => false,
                };
                if was_dir {
                    continue;
                }
                if let Ok(rel) = p.strip_prefix(&watch_root) {
                    let rel = rel.to_string_lossy().replace('\\', "/");
                    if !rel.is_empty() {
                        // queue, don't write: bulk deletions would otherwise
                        // rewrite the whole store once per file; the pass this
                        // trigger launches flush()es the set in one write at
                        // its start (see tombstones::queue) — so it still sees
                        // the tombstone before its diff
                        crate::sync::tombstones::queue(&rel);
                    }
                }
            }
        }
        let relevant = mutated && ev.paths.iter().any(|p| !sync_metadata(p));
        if relevant {
            let _ = tx.blocking_send(());
        }
    })?;
    watcher.watch(root, RecursiveMode::Recursive)?;
    Ok(watcher)
}
