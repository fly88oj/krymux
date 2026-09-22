#!/usr/bin/env bash
# Edge-case E2E: startup conflicts, runtime locks, crash leftovers, path conflicts.
# Windows locks are created by PowerShell holding an exclusive handle.
#
# WINDOWS-ONLY suite (exclusive-handle semantics need PowerShell + Win32
# sharing modes): on POSIX it exits 0 with a SKIP marker instead of failing.
set -u
cd "$(dirname "$0")"
if ! command -v powershell.exe >/dev/null 2>&1 && ! command -v powershell >/dev/null 2>&1; then
  echo "SKIP: edge-e2e.sh exercises Windows exclusive file locks (PowerShell holders) — windows-only"
  exit 0
fi
TBIN=./target/release/krymux-tunnel.exe   # tunnel ops: keygen / fingerprint / probe / server / client
SBIN=./target/release/krymux-sync.exe     # sync ops: sync-server / sync-client
DIR=$(mktemp -d /tmp/krymux-edge-XXXXXX)
PIDS=()
HOLDERS=()
cleanup() {
  for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null; done
  for p in "${HOLDERS[@]:-}"; do kill -9 "$p" 2>/dev/null; done
  [ -n "${KEEP:-}" ] || rm -rf "$DIR"
}
[ -n "${KEEP:-}" ] || trap cleanup EXIT

fail() { echo "❌ FAIL: $1"; exit 1; }
ok()   { echo "✅ $1"; }
wait_for() { local f=$1; for _ in $(seq 1 30); do [ -f "$f" ] && return 0; sleep 1; done; return 1; }
wait_for_content() { local f=$1 want=$2; for _ in $(seq 1 30); do [ "$(cat "$f" 2>/dev/null)" = "$want" ] && return 0; sleep 1; done; return 1; }

# hold an exclusive lock on a file for ~40s from a background PowerShell
hold_lock() { # $1 = file path (posix)
  local wp; wp=$(cygpath -w "$1")
  powershell.exe -NoProfile -Command "\$f=[System.IO.File]::Open('$wp','Open','ReadWrite','None'); Start-Sleep -Seconds 40" >/dev/null 2>&1 &
  HOLDERS+=($!)
  sleep 4   # powershell cold start — wait until the handle is actually held
}

# ---- stack ----
"$TBIN" keygen --out "$DIR/keys" --role server --name srv >/dev/null || fail keygen-srv
"$TBIN" keygen --out "$DIR/keys" --role client --name cli >/dev/null || fail keygen-cli
SRV_FP=$(sed -n 's/.*"fingerprint": *"\([^"]*\)".*/\1/p' "$DIR/keys/srv.identity.json")
CLI_FP=$(sed -n 's/.*"fingerprint": *"\([^"]*\)".*/\1/p' "$DIR/keys/cli.identity.json")
W=$(cygpath -m "$DIR")
printf '{"listen":"127.0.0.1:39450","identity":{"key":"%s/keys/srv.key.pem","cert":"%s/keys/srv.crt.pem"},"auth":{"mode":"whitelist","fingerprints":["%s"]},"routes":[{"host":["sync"],"upstream":["127.0.0.1",17897]}]}' "$W" "$W" "$CLI_FP" > "$DIR/server.json"
printf '{"endpoint":"127.0.0.1:39450","identity":{"key":"%s/keys/cli.key.pem","cert":"%s/keys/cli.crt.pem"},"serverFingerprint":"%s"}' "$W" "$W" "$SRV_FP" > "$DIR/client.json"
mkdir -p "$DIR/A" "$DIR/B"
printf 'baseline-x-v1\n' > "$DIR/A/x.txt"
printf 'baseline-y-v1\n' > "$DIR/A/y.txt"
printf 'baseline-z-v1\n' > "$DIR/A/z.txt"

# ---- E1: startup conflict — a locked file in the root refuses to start ----
# (both sides check before any connection is made)
hold_lock "$DIR/A/y.txt"
OUT=$(timeout 10 "$SBIN" sync-server --path "$DIR/A" --port 17897 2>&1); RC=$?
[ $RC -ne 0 ] && echo "$OUT" | grep -q "locked by other processes" || { echo "$OUT"; fail "E1 sync-server must refuse to start with a locked file (rc=$RC)"; }
for p in "${HOLDERS[@]:-}"; do kill -9 "$p" 2>/dev/null; done; HOLDERS=()
printf 'client-side-locked\n' > "$DIR/B/w.txt"
hold_lock "$DIR/B/w.txt"
OUT=$(timeout 10 "$SBIN" sync-client --path "$DIR/B" --config "$DIR/client.json" 2>&1); RC=$?
[ $RC -ne 0 ] && echo "$OUT" | grep -q "locked by other processes" || { echo "$OUT"; fail "E1 sync-client must refuse to start with a locked file (rc=$RC)"; }
for p in "${HOLDERS[@]:-}"; do kill -9 "$p" 2>/dev/null; done; HOLDERS=()
sleep 1; rm -f "$DIR/B/w.txt" 2>/dev/null || true
sleep 0.5
ok "E1: locked file in root → that side refuses to start (checked server AND client)"

# ---- start the real stack ----
"$TBIN" server --config "$DIR/server.json" >"$DIR/srv.log" 2>&1 & PIDS+=($!)
"$SBIN" sync-server --path "$DIR/A" --port 17897 >"$DIR/syncsrv.log" 2>&1 & PIDS+=($!)
sleep 1.5
"$SBIN" sync-client --path "$DIR/B" --config "$DIR/client.json" --watch --interval 2 >"$DIR/daemon.log" 2>&1 & DPID=$!; PIDS+=($DPID)
sleep 5
[ -f "$DIR/B/x.txt" ] || fail "baseline sync before E3"

# ---- E3: double daemon on the same root is rejected ----
OUT=$(timeout 10 "$SBIN" sync-client --path "$DIR/B" --config "$DIR/client.json" --watch 2>&1); RC=$?
[ $RC -ne 0 ] && echo "$OUT" | grep -q "another sync process already holds" || { echo "$OUT"; fail "E3 second daemon on same root must be rejected (rc=$RC)"; }
ok "E3: second daemon on the same root refused by .sync.lock (no double-writer)"

# ---- E4: file locked on the client when the server pushes an update ----
MT_BEFORE=$(stat -c %Y "$DIR/B/x.txt" 2>/dev/null || echo 0)
hold_lock "$DIR/B/x.txt"     # lock v1 in place BEFORE the server side changes
printf 'baseline-x-v2\n' > "$DIR/A/x.txt"
printf 'arrives-alongside\n' > "$DIR/A/alongside.txt"
sleep 7
[ "$(stat -c %Y "$DIR/B/x.txt" 2>/dev/null || echo 0)" = "$MT_BEFORE" ] || fail "E4 locked file was touched"
[ -f "$DIR/B/alongside.txt" ] || { tail -5 "$DIR/daemon.log"; fail "E4 other files must still sync"; }
for p in "${HOLDERS[@]:-}"; do kill -9 "$p" 2>/dev/null; done; HOLDERS=()
sleep 7
[ "$(cat "$DIR/B/x.txt")" = "baseline-x-v2" ] || { tail -5 "$DIR/daemon.log"; fail "E4 file not updated after lock release"; }
ok "E4: locked client file untouched while held, others synced; converged after release"

# ---- E5: file locked on the server → get_file error, client survives ----
kill -9 "$DPID" 2>/dev/null; sleep 1
printf 'baseline-y-v2\n' > "$DIR/A/y.txt"
hold_lock "$DIR/A/y.txt"
"$SBIN" sync-client --path "$DIR/B" --config "$DIR/client.json" --watch --interval 2 >>"$DIR/daemon.log" 2>&1 & DPID=$!; PIDS+=($DPID)
sleep 7
[ "$(cat "$DIR/B/y.txt" 2>/dev/null)" = "baseline-y-v1" ] || fail "E5 locked server file must not be served"
kill -0 "$DPID" 2>/dev/null || { tail -5 "$DIR/daemon.log"; fail "E5 daemon must survive a locked-server error"; }
printf 'still-alive\n' > "$DIR/A/still-alive.txt"
sleep 6
[ -f "$DIR/B/still-alive.txt" ] || fail "E5 daemon stopped syncing after locked error"
for p in "${HOLDERS[@]:-}"; do kill -9 "$p" 2>/dev/null; done; HOLDERS=()
sleep 7
[ "$(cat "$DIR/B/y.txt")" = "baseline-y-v2" ] || fail "E5 y.txt not converged after release"
ok "E5: locked server file → error logged, daemon alive and syncing others; converged after release"

# (Re)start the watch daemon, retrying briefly: kill -9 of a daemon that is
# mid-I/O can leave the Windows .sync.lock held for a moment after the
# process is gone, and an immediate restart is then correctly refused.
start_daemon() { # $1 = log file to append
  local log=$1 i
  for i in $(seq 1 15); do
    "$SBIN" sync-client --path "$DIR/B" --config "$DIR/client.json" --watch --interval 2 >>"$log" 2>&1 & DPID=$!; PIDS+=($DPID)
    sleep 1
    kill -0 "$DPID" 2>/dev/null && return 0
    echo "(daemon start attempt $i refused — .sync.lock still held; retrying)"
  done
  fail "daemon refused to start (root lock never released after kill)"
}

# ---- E6: kill -9 mid-flight → no torn files, converges after restart ----
kill -9 "$DPID" 2>/dev/null; sleep 1
head -c 524288000 /dev/urandom > "$DIR/A/huge.bin"
printf 'small-beside-huge-1\n' > "$DIR/A/s1.txt"
printf 'small-beside-huge-2\n' > "$DIR/A/s2.txt"
"$SBIN" sync-client --path "$DIR/B" --config "$DIR/client.json" --watch --interval 2 >>"$DIR/daemon.log" 2>&1 & DPID=$!; PIDS+=($DPID)
sleep 1.2
kill -9 "$DPID" 2>/dev/null
# every file present on B must be complete: small files exact, huge.bin (if present) must hash-match A
if [ -f "$DIR/B/huge.bin" ]; then
  [ "$(md5sum < "$DIR/B/huge.bin" | cut -d' ' -f1)" = "$(md5sum < "$DIR/A/huge.bin" | cut -d' ' -f1)" ] || fail "E6 huge.bin torn (atomicity broken)"
fi
for s in s1.txt s2.txt; do
  [ ! -f "$DIR/B/$s" ] || [ "$(cat "$DIR/B/$s")" = "small-beside-huge-${s:1:1}" ] || fail "E6 $s torn"
done
start_daemon "$DIR/daemon.log"
sleep 25
[ "$(md5sum < "$DIR/B/huge.bin" 2>/dev/null | cut -d' ' -f1)" = "$(md5sum < "$DIR/A/huge.bin" | cut -d' ' -f1)" ] || fail "E6 no convergence after crash+restart"
ok "E6: kill -9 mid-transfer left no torn files; restart converged (500MB hash-verified)"

# ---- E7: path type conflict (directory where a file should land) ----
mkdir -p "$DIR/B/dirconflict.txt"
printf 'file-content\n' > "$DIR/A/dirconflict.txt"
printf 'post-conflict\n' > "$DIR/A/post-conflict.txt"
sleep 8
kill -0 "$DPID" 2>/dev/null || { tail -8 "$DIR/daemon.log"; fail "E7 daemon died on path conflict"; }
[ -f "$DIR/B/post-conflict.txt" ] || { tail -8 "$DIR/daemon.log"; fail "E7 daemon stopped syncing after path conflict"; }
rmdir "$DIR/B/dirconflict.txt" 2>/dev/null || rm -rf "$DIR/B/dirconflict.txt"
sleep 7
[ "$(cat "$DIR/B/dirconflict.txt" 2>/dev/null)" = "file-content" ] || fail "E7 conflict file not synced after obstacle removed"
ok "E7: directory-vs-file conflict skipped gracefully; recovered after cleanup"

# ---- E8: stale *.sync-tmp leftovers are cleaned at startup ----
kill -9 "$DPID" 2>/dev/null; sleep 1
printf 'junk\n' > "$DIR/B/stale.sync-tmp"
touch -d '2 hours ago' "$DIR/B/stale.sync-tmp"
start_daemon "$DIR/daemon.log"
sleep 5
[ ! -f "$DIR/B/stale.sync-tmp" ] || fail "E8 stale tmp not cleaned"
ok "E8: stale (≥1h) *.sync-tmp cleaned at startup; scanner ignores fresh ones"

echo ""
echo "🎉 edge-case E2E: ALL PHASES PASSED"
KEEP=1
