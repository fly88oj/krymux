//! Build script: embed the browser SDK into this binary.
//!
//! Source of truth: the vendored copy in this repository at
//! `browser/ectun-browser.mjs` (originally from the Node reference
//! repository, the same file the Node server serves at runtime from
//! `GET /sdk/ectun-browser.mjs`). At build time we copy it into
//! `$OUT_DIR/ectun-browser.mjs`, where `src/ws.rs` picks it up with
//! `include_bytes!` — so the Rust binary always serves exactly the same SDK
//! the Node server would, and editing the file automatically rebuilds this
//! crate (cargo:rerun-if-changed).
//!
//! If the vendored file is missing (and the legacy fallback location, the
//! sibling Node repository at `../ectun/browser/ectun-browser.mjs`, is not
//! checked out either), we write a small self-describing placeholder instead
//! so the `include_bytes!` always compiles and the `/sdk/ectun-browser.mjs`
//! route stays well-defined; a `cargo:warning` tells the builder what
//! happened. The placeholder's first bytes are the marker `src/ws.rs` checks
//! to pick the launcher-page note.

use std::env;
use std::fs;
use std::path::PathBuf;

/// Written when the real SDK is absent; served as-is (it explains itself).
/// Keep in sync with `SDK_PLACEHOLDER_PREFIX` in `src/ws.rs`.
const PLACEHOLDER: &str = concat!(
    "// ectun-browser placeholder: the real SDK was not found at build time.\n",
    "// The vendored browser SDK should live at browser/ectun-browser.mjs in this\n",
    "// repository. Restore that file (it originates from the Node reference\n",
    "// repository's browser/ectun-browser.mjs) and rebuild to embed the real\n",
    "// module here.\n",
);

fn main() {
    let manifest =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR set by cargo"));
    // preferred: the vendored copy in this repository (repo root is two
    // levels up from this crate: <root>/crates/krymux)
    let vendored = manifest
        .join("../..")
        .join("browser")
        .join("ectun-browser.mjs");
    // legacy fallback: the sibling Node reference repository of the repo root
    let sibling = manifest
        .join("../../..")
        .join("ectun")
        .join("browser")
        .join("ectun-browser.mjs");
    let out =
        PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR set by cargo")).join("ectun-browser.mjs");

    let (src, is_vendored) = if vendored.is_file() {
        (vendored, true)
    } else if sibling.is_file() {
        println!(
            "cargo:warning=browser/ectun-browser.mjs missing from this repository: falling back to the sibling Node repo at ../ectun/browser/ectun-browser.mjs"
        );
        (sibling, false)
    } else {
        println!(
            "cargo:warning=browser/ectun-browser.mjs not found (in-repo or at ../ectun/browser/ectun-browser.mjs): embedding a placeholder SDK (/sdk/ectun-browser.mjs will serve it)"
        );
        fs::write(&out, PLACEHOLDER).unwrap_or_else(|e| panic!("write {}: {e}", out.display()));
        // watching the (nonexistent) file itself is a no-op; watch the parent
        // directory instead so the SDK appearing still triggers a rebuild
        if let Some(dir) = vendored.parent() {
            if dir.is_dir() {
                println!("cargo:rerun-if-changed={}", dir.display());
            }
        }
        return;
    };

    fs::copy(&src, &out)
        .unwrap_or_else(|e| panic!("copy {} -> {}: {e}", src.display(), out.display()));
    println!("cargo:rerun-if-changed={}", src.display());
    if is_vendored {
        // the sibling copy is no longer watched; if someone removes the
        // vendored file, the manifest change is enough to re-run this script
    }
}
