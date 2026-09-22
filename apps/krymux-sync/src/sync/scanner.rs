// Directory scanner + parallel SHA-1 hasher.

use anyhow::Result;
use sha1::{Digest, Sha1};
use std::collections::BTreeMap;
use std::path::Path;
use tokio::task;

/// One file in a scanned tree; `hash` is `None` while unhashed or when the
/// file could not be read (e.g. locked by another process).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FileEntry {
    pub path: String, // relative, forward-slash separated
    pub size: u64,
    pub mtime_ms: f64,
    pub hash: Option<String>,
}

/// True for the sync engine's own metadata files (`*.sync-tmp` staging,
/// `*.sync.lock`, the tombstone store, the persistent hash cache): never
/// scanned, never transferred, and never a watcher trigger.
pub fn is_sync_metadata(name: &str) -> bool {
    name.ends_with(".sync-tmp")
        || name.ends_with(".sync.lock")
        || name == crate::sync::tombstones::STORE_FILE
        || name == CACHE_FILE
}

// ---------------- persistent hash cache ----------------
//
// Layout on disk (one JSON file per root, skipped by the scanner):
//   { "v": 1, "entries": { "<relpath>": {"size":N,"mtimeMs":T,"hash":"…"} } }
//
// A scan consults the cache and skips SHA-1 when a file's size and mtime
// are unchanged since it was last hashed (rsync `--size-only`-style fast
// path, but keyed on stat data only). The cache is advisory: a missing or
// corrupt file simply falls back to hashing everything. Files that could
// not be read (locked) get no entry, so they are re-hashed next pass.

/// Name of the per-root persistent hash cache; skipped like `.sync.lock`.
pub const CACHE_FILE: &str = ".sync-cache.json";

/// Cached hash facts for one path.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
struct CacheEntry {
    size: u64,
    mtime_ms: f64,
    hash: String,
}

/// On-disk cache shape; both fields default so a partially-written file
/// degrades to "no entries" instead of a parse panic.
#[derive(serde::Serialize, serde::Deserialize)]
struct CacheStore {
    #[serde(default)]
    v: u32,
    #[serde(default)]
    entries: BTreeMap<String, CacheEntry>,
}

/// True when the cached stat facts still describe this file (an mtime of 0
/// means the FS could not report one — never trust a hit on that).
fn cache_hit(c: &CacheEntry, f: &FileEntry) -> bool {
    f.mtime_ms > 0.0 && c.size == f.size && c.mtime_ms == f.mtime_ms
}

fn load_cache(root: &Path) -> BTreeMap<String, CacheEntry> {
    let data = match std::fs::read(root.join(CACHE_FILE)) {
        Ok(d) => d,
        Err(_) => return BTreeMap::new(),
    };
    match serde_json::from_slice::<CacheStore>(&data) {
        Ok(s) => s.entries,
        Err(e) => {
            log::warn!("sync cache: corrupt {} — starting empty: {e}", CACHE_FILE);
            BTreeMap::new()
        }
    }
}

/// Atomic save: unique tmp (scanner-skipped, stale-cleaned) + rename. The
/// root lock guarantees a single sync process per root, so no writer races.
fn save_cache(root: &Path, entries: &BTreeMap<String, CacheEntry>) {
    let dest = root.join(CACHE_FILE);
    let tmp = dest.with_file_name(format!(".sync-cache.{}.sync-tmp", std::process::id()));
    let res = serde_json::to_vec(&CacheStore {
        v: 1,
        entries: entries.clone(),
    })
    .map_err(|e| e.to_string())
    .and_then(|d| std::fs::write(&tmp, d).map_err(|e| e.to_string()))
    .and_then(|()| std::fs::rename(&tmp, &dest).map_err(|e| e.to_string()));
    if let Err(e) = res {
        let _ = std::fs::remove_file(&tmp);
        log::warn!("sync cache: cannot save {}: {e}", dest.display());
    }
}

/// Recursively scan a directory, returning file entries (without hashes).
pub fn scan_directory(root: &Path) -> Result<Vec<FileEntry>> {
    let mut files = Vec::new();
    // one unreadable directory or a vanished entry must not fail the whole
    // scan (a failing pass on both sides would block sync forever); such
    // entries are skipped and revisited on the next pass
    fn walk(dir: &Path, root: &Path, files: &mut Vec<FileEntry>) -> Result<()> {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(e) => {
                log::warn!(
                    "sync scan: skipping unreadable directory {}: {e}",
                    dir.display()
                );
                return Ok(());
            }
        };
        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if is_sync_metadata(&name) {
                continue;
            }
            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            if meta.is_dir() {
                walk(&path, root, files)?;
            } else if meta.is_file() {
                let rel = path
                    .strip_prefix(root)
                    .map_err(|e| anyhow::anyhow!("strip_prefix: {e}"))?
                    .to_string_lossy()
                    .replace('\\', "/");
                files.push(FileEntry {
                    path: rel,
                    size: meta.len(),
                    mtime_ms: meta
                        .modified()
                        .ok()
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d| d.as_secs_f64() * 1000.0)
                        .unwrap_or(0.0),
                    hash: None,
                });
            }
        }
        Ok(())
    }
    walk(root, root, &mut files)?;
    files.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(files)
}

/// Hash a single file using streaming SHA-1.
pub fn hash_file(path: &Path) -> Result<String> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha1::new();
    let mut buf = [0u8; 512 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Scan + hash all files with parallel workers. A persistent per-root hash
/// cache (`CACHE_FILE`) short-circuits the SHA-1 of any file whose size and
/// mtime are unchanged since it was last hashed; the cache is refreshed
/// (changed entries updated, vanished paths pruned) after every scan.
pub async fn scan_and_hash(root: &Path, concurrency: usize) -> Result<Vec<FileEntry>> {
    // the walk and the cache load do real syscalls; keep them off the async workers
    let (files, cache) = task::spawn_blocking({
        let root = root.to_path_buf();
        move || -> Result<_> { Ok((scan_directory(&root)?, load_cache(&root))) }
    })
    .await
    .map_err(|e| anyhow::anyhow!("join scan: {e}"))??;
    let root = root.to_path_buf();

    let per = (files.len() + concurrency - 1) / concurrency.max(1);
    let chunks: Vec<Vec<FileEntry>> = if per == 0 {
        vec![files]
    } else {
        files.chunks(per).map(|c| c.to_vec()).collect()
    };

    let mut handles = Vec::new();
    for chunk in chunks {
        let root = root.clone();
        // only the cache lines relevant to this chunk cross the worker
        // boundary (a full-tree clone per worker would be O(files×workers))
        let mut subset = BTreeMap::new();
        for f in &chunk {
            if let Some(c) = cache.get(&f.path) {
                subset.insert(f.path.clone(), c.clone());
            }
        }
        handles.push(task::spawn_blocking(move || -> Result<Vec<FileEntry>> {
            let mut out = Vec::new();
            for mut f in chunk {
                if let Some(h) = subset
                    .get(&f.path)
                    .filter(|c| cache_hit(c, &f))
                    .map(|c| c.hash.clone())
                {
                    f.hash = Some(h); // stat-identical since the last hash
                } else {
                    let full = root.join(&f.path);
                    match hash_file(&full) {
                        Ok(h) => f.hash = Some(h),
                        Err(_) => f.hash = None,
                    }
                }
                out.push(f);
            }
            Ok(out)
        }));
    }

    let mut result = Vec::new();
    for h in handles {
        let mut chunk = h.await.map_err(|e| anyhow::anyhow!("join: {e}"))??;
        result.append(&mut chunk);
    }
    // scan_directory returns sorted input and chunks preserve that order

    // refresh the persistent cache from what this scan actually observed:
    // hashed files (cache hit or fresh hash) get an entry, everything else —
    // vanished paths and unreadable/locked files — is pruned, so a locked
    // file is simply re-hashed once it becomes readable again
    let mut fresh: BTreeMap<String, CacheEntry> = BTreeMap::new();
    for f in &result {
        if let Some(hash) = &f.hash {
            fresh.insert(
                f.path.clone(),
                CacheEntry {
                    size: f.size,
                    mtime_ms: f.mtime_ms,
                    hash: hash.clone(),
                },
            );
        }
    }
    if fresh != cache {
        let root = root.clone();
        let _ = task::spawn_blocking(move || save_cache(&root, &fresh)).await;
    }
    Ok(result)
}

/// Check if a file is exclusively locked by another process.
///
/// Only a Windows sharing violation (os error 32) counts as "locked": on Unix
/// there is no reliable exclusive-lock probe, and EACCES/EPERM usually means
/// a mode-0444 file that a rename-based install can still replace — treating
/// those as locked would skip such files forever.
pub fn is_file_locked(path: &Path) -> bool {
    if !cfg!(windows) {
        return false;
    }
    match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
    {
        Ok(_) => false,
        Err(e) => e.raw_os_error() == Some(32),
    }
}

/// Check all files for locks; strict mode errors out if any are locked.
pub fn check_startup_locks(root: &Path, strict: bool) -> Result<Vec<String>> {
    let files = scan_directory(root)?;
    let locked: Vec<String> = files
        .iter()
        .filter(|f| is_file_locked(&root.join(&f.path)))
        .map(|f| f.path.clone())
        .collect();
    if strict && !locked.is_empty() {
        return Err(anyhow::anyhow!(
            "files locked by other processes:\n  {}",
            locked.join("\n  ")
        ));
    }
    Ok(locked)
}

/// Take an exclusive OS lock on `<root>/.sync.lock` so two sync processes
/// cannot fight over one root. The lock is released automatically when the
/// process exits or crashes — no stale-lock recovery needed.
pub fn acquire_root_lock(root: &Path) -> Result<std::fs::File> {
    // std::fs::File::{try_lock,unlock} (stable 1.89): LockFileEx on Windows,
    // flock on Unix; released automatically on exit or crash — no recovery
    let lock_path = root.join(".sync.lock");
    let f = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)
        .map_err(|e| anyhow::anyhow!("open {}: {e}", lock_path.display()))?;
    f.try_lock().map_err(|_| {
        anyhow::anyhow!(
            "another sync process already holds {} — refusing to start",
            lock_path.display()
        )
    })?;
    Ok(f)
}

/// Remove crash-leftover staging files older than one hour. Safe once the
/// root lock is held: no other sync process is transferring into this tree.
pub fn clean_stale_tmp(root: &Path) -> Result<usize> {
    const STALE: std::time::Duration = std::time::Duration::from_secs(3600);
    let mut removed = 0;
    for entry in walkdir::WalkDir::new(root) {
        let Ok(entry) = entry else { continue };
        if !entry.file_type().is_file() {
            continue;
        }
        if !entry.file_name().to_string_lossy().ends_with(".sync-tmp") {
            continue;
        }
        let stale = entry
            .metadata()
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.elapsed().ok())
            .map(|age| age >= STALE)
            .unwrap_or(false);
        if stale && std::fs::remove_file(entry.path()).is_ok() {
            removed += 1;
        }
    }
    Ok(removed)
}
