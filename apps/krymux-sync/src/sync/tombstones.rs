// Tombstone store: deletions remembered per root so they propagate to peers
// instead of resurrecting from the surviving copy.
//
// Layout on disk (one JSON file per root, skipped by the scanner):
//   { "v": 1, "entries": { "<relpath>": <unix_ms> } }
//
// A tombstone means "this path was deleted at <unix_ms>"; the diff rules in
// mod.rs compare it against the other side's file mtimes, so deletions and
// later re-creations resolve last-writer-wins. Entries older than MAX_AGE
// are pruned at pass start (a deletion older than that may safely re-sync).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Name of the per-root tombstone store; skipped by scanner and watchers
/// like `.sync.lock` and `*.sync-tmp`.
pub const STORE_FILE: &str = ".sync-tombstones.json";

/// Tombstones older than this (unix ms) are dropped by [`prune`].
pub const MAX_AGE: u64 = 30 * 24 * 60 * 60 * 1000;

/// Serializes load/modify/save cycles between the sync pass and the FS
/// watcher callback thread of one process (the root lock already ensures a
/// single sync process per root).
static STORE_LOCK: Mutex<()> = Mutex::new(());

/// Deletions seen by watchers but not yet merged into the store; see [`queue`].
// path -> deletion time captured WHEN THE EVENT IS SEEN. The process-wide
// single-root invariant is guaranteed upstream by the .sync.lock root mutex.
static PENDING: Mutex<BTreeMap<String, u64>> = Mutex::new(BTreeMap::new());

/// On-disk store shape (see the module comment); serde-derived so reading and
/// writing share one definition. Both fields default so a partially-written
/// or hand-trimmed file degrades to "no tombstones" instead of a parse panic.
#[derive(serde::Serialize, serde::Deserialize)]
struct Store {
    #[serde(default)]
    v: u32,
    #[serde(default)]
    entries: BTreeMap<String, u64>,
}

fn lock_store() -> std::sync::MutexGuard<'static, ()> {
    STORE_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// Path of the tombstone store inside a root.
pub fn store_path(root: &Path) -> PathBuf {
    root.join(STORE_FILE)
}

/// Current unix time in milliseconds.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Loads the store; a missing file simply means nothing was deleted yet, a
/// corrupt one yields an empty map with a warning (the store is advisory
/// state — losing it degrades to v1 mirror semantics, never breaks sync).
pub fn load(root: &Path) -> BTreeMap<String, u64> {
    let _g = lock_store();
    load_unlocked(root)
}

/// Records one path as deleted right now.
pub fn record(root: &Path, path: &str) {
    let mut entries = BTreeMap::new();
    entries.insert(path.to_string(), now_ms());
    record_with(root, &entries);
}

/// Queue one path as deleted, WITHOUT touching disk.
///
/// Watchers call this per removed file: writing the whole store per event
/// made bulk deletions O(N²) disk I/O. The queued set is merged into the
/// store by [`flush`] at the start of the next sync pass (both sides call
/// it), so the tombstone always lands before any scan/diff reads the store.
///
/// Crash-window tradeoff: a process that dies before the next flush loses
/// only the queued-not-yet-flushed tombstones — the worst case is one
/// spurious re-download of a just-deleted file on the following pass, never
/// corruption and never a wrong deletion.
pub fn queue(path: &str) {
    let mut q = PENDING.lock().unwrap_or_else(|e| e.into_inner());
    // stamp at event time: flushing later with now() would widen the
    // last-writer window by up to one sync interval and could delete a
    // peer's newer edit made between the deletion and the flush
    q.entry(path.to_string()).or_insert_with(now_ms);
}

/// Merges every queued tombstone into the store in ONE load+save cycle and
/// clears the queue. Called at the start of each sync pass on both sides
/// (client: before the local tombstone load/diff; server: at hello and
/// before streaming tombstones). A no-op when nothing is queued.
pub fn flush(root: &Path) {
    let mut q = PENDING.lock().unwrap_or_else(|e| e.into_inner());
    if q.is_empty() {
        return;
    }
    let entries: BTreeMap<String, u64> = q.iter().map(|(p, ts)| (p.clone(), *ts)).collect();
    q.clear();
    drop(q);
    record_with(root, &entries);
}

/// Merges `entries` (path → unix ms) into the store: fresh load + merge +
/// prune + save, so a concurrent watcher write between our load and save
/// can never be lost.
pub fn record_with(root: &Path, entries: &BTreeMap<String, u64>) {
    let _g = lock_store();
    let mut map = load_unlocked(root);
    for (p, ts) in entries {
        map.insert(p.clone(), *ts);
    }
    prune(&mut map);
    save_unlocked(root, &map);
}

/// Drops entries older than [`MAX_AGE`] (called at pass start on both sides).
pub fn prune(map: &mut BTreeMap<String, u64>) {
    let cutoff = now_ms().saturating_sub(MAX_AGE);
    map.retain(|_, ms| *ms > cutoff);
}

fn load_unlocked(root: &Path) -> BTreeMap<String, u64> {
    let path = store_path(root);
    let data = match std::fs::read(&path) {
        Ok(d) => d,
        Err(_) => return BTreeMap::new(),
    };
    match serde_json::from_slice::<Store>(&data) {
        Ok(s) => s.entries,
        Err(e) => {
            log::warn!(
                "sync tombstones: corrupt store {} — starting empty: {e}",
                path.display()
            );
            BTreeMap::new()
        }
    }
}

fn save_unlocked(root: &Path, map: &BTreeMap<String, u64>) {
    let obj = Store {
        v: 1,
        entries: map.clone(),
    };
    let dest = store_path(root);
    // unique per process (the root lock guarantees one sync process), and the
    // suffix keeps it invisible to the scanner and covered by stale cleanup
    let tmp = dest.with_file_name(format!(".sync-tombstones.{}.sync-tmp", std::process::id()));
    let res = serde_json::to_string(&obj)
        .map_err(|e| e.to_string())
        .and_then(|s| std::fs::write(&tmp, s).map_err(|e| e.to_string()))
        .and_then(|()| std::fs::rename(&tmp, &dest).map_err(|e| e.to_string()));
    if let Err(e) = res {
        let _ = std::fs::remove_file(&tmp);
        log::warn!("sync tombstones: cannot save {}: {e}", dest.display());
    }
}
