#!/usr/bin/env bash
# Deletion semantics probe (v2 tombstone propagation): deleting a file on
# either side must propagate to the other and must NOT resurrect from the
# surviving copy (the v1 mirror behavior). Pass/fail script.
# Cross-platform: POSIX-native on Linux, MSYS/Git-Bash on Windows.
set -u
cd "$(dirname "$0")"
EXE=""; case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) EXE=".exe";; esac
TBIN=./target/release/krymux-tunnel$EXE   # tunnel ops: keygen / fingerprint / probe / server / client
SBIN=./target/release/krymux-sync$EXE     # sync ops: sync-server / sync-client
npath() { if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s' "$1"; fi; }
D=$(mktemp -d /tmp/krymux-del-XXXX)
PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; done; [ -n "${KEEP:-}" ] || rm -rf "$D"; }
trap cleanup INT TERM; [ -n "${KEEP:-}" ] || trap cleanup EXIT

fail() { echo "❌ FAIL: $1"; exit 1; }
ok()   { echo "✅ $1"; }
wait_for() { local f=$1; for _ in $(seq 1 20); do [ -f "$f" ] && return 0; sleep 1; done; return 1; }
wait_gone() { local f=$1; for _ in $(seq 1 20); do [ ! -f "$f" ] && return 0; sleep 1; done; return 1; }

mkdir -p "$D/A" "$D/B"
"$TBIN" keygen --out "$D/k" --role server --name s >/dev/null || fail keygen-server
"$TBIN" keygen --out "$D/k" --role client --name c >/dev/null || fail keygen-client
SFP=$(sed -n 's/.*"fingerprint": *"\([^"]*\)".*/\1/p' "$D/k/s.identity.json")
CFP=$(sed -n 's/.*"fingerprint": *"\([^"]*\)".*/\1/p' "$D/k/c.identity.json")
W=$(npath "$D")
printf '{"listen":"127.0.0.1:39447","identity":{"key":"%s/k/s.key.pem","cert":"%s/k/s.crt.pem"},"auth":{"mode":"whitelist","fingerprints":["%s"]},"routes":[{"host":["sync"],"upstream":["127.0.0.1",17895]}]}' "$W" "$W" "$CFP" > "$D/srv.json"
printf '{"endpoint":"127.0.0.1:39447","identity":{"key":"%s/k/c.key.pem","cert":"%s/k/c.crt.pem"},"serverFingerprint":"%s"}' "$W" "$W" "$SFP" > "$D/cli.json"

"$SBIN" sync-server --path "$D/A" --port 17895 >"$D/srv.log" 2>&1 & PIDS+=($!)
"$TBIN" server --config "$D/srv.json" >"$D/tun.log" 2>&1 & PIDS+=($!)
sleep 1.5
printf 'to-be-deleted\n' > "$D/A/doomed.txt"
"$SBIN" sync-client --path "$D/B" --config "$D/cli.json" --watch --interval 2 >"$D/d.log" 2>&1 & PIDS+=($!)
wait_for "$D/B/doomed.txt" || { tail -8 "$D/d.log"; fail "setup: doomed.txt never reached B"; }

# ---- delete on the SERVER → client removes it, server copy stays gone ----
rm "$D/A/doomed.txt"
wait_gone "$D/B/doomed.txt" || { tail -8 "$D/d.log"; fail "client copy not removed after server-side delete (no propagation)"; }
sleep 3
[ -f "$D/A/doomed.txt" ] && fail "server copy resurrected from the client (v1 mirror behavior)"
ok "server-side delete propagated to the client; no resurrection"

# ---- delete on the CLIENT → server removes it, client copy stays gone ----
printf 'born-on-b\n' > "$D/B/born-on-b.txt"
wait_for "$D/A/born-on-b.txt" || { tail -8 "$D/d.log"; fail "setup: born-on-b.txt never reached A"; }
rm "$D/B/born-on-b.txt"
wait_gone "$D/A/born-on-b.txt" || { tail -8 "$D/d.log"; fail "server copy not removed after client-side delete (delete_file not honored)"; }
sleep 3
[ -f "$D/B/born-on-b.txt" ] && fail "client copy resurrected from the server"
ok "client-side delete propagated to the server; no resurrection"

echo ""
echo "🎉 deletion semantics: PASS (deletion propagates, no resurrection)"
KEEP=1
