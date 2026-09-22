// Server-side change notification hub.
//
// sync-server watches its own root; when local files change (something other
// than an in-flight sync session), every client that opened a notify stream
// gets a rescan_hint and can pull immediately instead of waiting out its
// reconcile interval.
//
// Debounce is leading-edge (~400ms suppression) — a burst coalesces into one
// hint, and the client's own quiet window absorbs the tail before scanning.

use anyhow::Result;
use notify::Watcher as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::broadcast;

const SUPPRESS_WINDOW: Duration = Duration::from_millis(400);

/// Broadcast hub behind the server's `rescan_hint` push: watches the sync
/// root and fans change hints out to every subscribed notify stream.
pub struct NotifyHub {
    tx: broadcast::Sender<()>,
    /// number of active sync sessions; while > 0, watcher events are held as
    /// pending instead of firing, so the server's own upload writes echo back
    /// as exactly one hint when the session ends (other clients then pull the
    /// fresh files immediately instead of waiting out their interval)
    active: Arc<AtomicUsize>,
    pending: Arc<AtomicBool>,
}

impl NotifyHub {
    /// Watches `root` recursively and begins hubbing change events.
    pub fn new(root: &Path) -> Result<Self> {
        let (tx, _) = broadcast::channel(16);
        let active = Arc::new(AtomicUsize::new(0));
        let pending = Arc::new(AtomicBool::new(false));
        let last_fire: Arc<Mutex<Option<Instant>>> = Arc::new(Mutex::new(None));
        let watch_root = root.to_path_buf();
        // Paths we have observed to be directories while they existed; FS
        // removal events on Windows cannot tell files from directories, so a
        // removed directory is recognized by this set instead (a dir path is
        // never a synced file — tombstoning it would delete a same-named
        // synced file that was never deleted)
        let known_dirs: Arc<Mutex<std::collections::HashSet<PathBuf>>> =
            Arc::new(Mutex::new(std::collections::HashSet::new()));
        let kd = known_dirs.clone();
        let mut watcher = notify::recommended_watcher({
            let tx = tx.clone();
            let active = active.clone();
            let pending = pending.clone();
            let last_fire = last_fire.clone();
            move |res: notify::Result<notify::Event>| {
                let Ok(ev) = res else { return };
                let mutated = matches!(
                    ev.kind,
                    notify::EventKind::Create(_)
                        | notify::EventKind::Modify(_)
                        | notify::EventKind::Remove(_)
                );
                // our own staging files, the root lockfile, the tombstone
                // store, and reads are not changes
                let sync_metadata = |p: &std::path::Path| {
                    p.file_name()
                        .map(|n| crate::sync::scanner::is_sync_metadata(&n.to_string_lossy()))
                        .unwrap_or(true)
                };
                // remember directories while we can still see them
                if matches!(
                    ev.kind,
                    notify::EventKind::Create(_) | notify::EventKind::Modify(_)
                ) {
                    for p in &ev.paths {
                        if p.is_dir() {
                            if let Ok(mut dirs) = kd.lock() {
                                // bound the set: a huge tree would otherwise
                                // grow it without limit. Clearing wholesale is
                                // safe — membership is only a heuristic guard
                                // against tombstoning removed DIRECTORIES;
                                // after a clear the worst case is one spurious
                                // tombstone when a dir removal is misread as
                                // a file removal, which the next pass
                                // re-uploads (self-correcting). Repopulation
                                // is lazy from later Create/Modify events.
                                if dirs.len() >= 4096 {
                                    dirs.clear();
                                }
                                dirs.insert(p.clone());
                            }
                        }
                    }
                }
                // a removed FILE is a deletion every client must learn about:
                // record its tombstone now (even mid-session) so the very next
                // scan_ready carries it — the deletion hint itself may still be
                // deferred to session end by the pending logic below. Removed
                // directories are not tombstoned.
                if matches!(
                    ev.kind,
                    notify::EventKind::Remove(notify::event::RemoveKind::File)
                        | notify::EventKind::Remove(notify::event::RemoveKind::Any)
                        | notify::EventKind::Remove(notify::event::RemoveKind::Other)
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
                                // queue, don't write: bulk deletions would
                                // otherwise rewrite the whole store once per
                                // file; the next sync pass flush()es the set
                                // in one write (see tombstones::queue)
                                crate::sync::tombstones::queue(&rel);
                            }
                        }
                    }
                }
                let relevant = mutated && ev.paths.iter().any(|p| !sync_metadata(p));
                if !relevant {
                    return;
                }
                if active.load(Ordering::Relaxed) > 0 {
                    // a sync session is writing (or racing with us); defer to
                    // one coalesced hint when it finishes
                    pending.store(true, Ordering::Relaxed);
                    return;
                }
                // leading-edge debounce: fire on the first event of a burst,
                // suppress the rest for a short window
                let mut last = last_fire.lock().expect("notify hub lock");
                if let Some(t) = *last {
                    if t.elapsed() < SUPPRESS_WINDOW {
                        return;
                    }
                }
                *last = Some(Instant::now());
                drop(last);
                let _ = tx.send(());
            }
        })?;
        watcher.watch(root, notify::RecursiveMode::Recursive)?;
        // the watcher is the process-lifetime source of hints — it must
        // outlive this constructor, so intentionally leak it
        std::mem::forget(watcher);
        Ok(NotifyHub {
            tx,
            active,
            pending,
        })
    }

    /// A hub that never fires (used when the filesystem cannot be watched).
    pub fn disabled() -> Self {
        let (tx, _) = broadcast::channel(1);
        NotifyHub {
            tx,
            active: Arc::new(AtomicUsize::new(0)),
            pending: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Subscribes to change hints; every receiver sees every hint.
    pub fn subscribe(&self) -> broadcast::Receiver<()> {
        self.tx.subscribe()
    }

    /// RAII session marker: while alive, watcher events are held pending;
    /// when the last session ends, one coalesced hint fires.
    pub fn active_guard(self: &Arc<Self>) -> ActiveGuard {
        self.active.fetch_add(1, Ordering::Relaxed);
        ActiveGuard(Arc::clone(self))
    }

    fn session_ended(&self) {
        let prev = self.active.fetch_sub(1, Ordering::Relaxed);
        if prev == 1 && self.pending.swap(false, Ordering::Relaxed) {
            let _ = self.tx.send(());
        }
    }
}

/// RAII marker of an active sync session; see `NotifyHub::active_guard`.
pub struct ActiveGuard(Arc<NotifyHub>);

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.session_ended();
    }
}
