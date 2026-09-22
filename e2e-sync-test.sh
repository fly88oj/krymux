#!/usr/bin/env bash
# E2E: bidirectional file sync through a real krymux (mTLS) tunnel, Rust-only.
# Cross-platform: POSIX-native on Linux, MSYS/Git-Bash on Windows (the only
# Windows-ism — cygpath for JSON config paths — degrades to a no-op wrapper).
set -u
cd "$(dirname "$0")"
EXE=""; case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) EXE=".exe";; esac
TBIN=./target/release/krymux-tunnel$EXE   # tunnel ops: keygen / fingerprint / probe / server / client
SBIN=./target/release/krymux-sync$EXE     # sync ops: sync-server / sync-client
# native path for JSON configs (mixed-style on Windows, verbatim on Linux)
npath() { if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s' "$1"; fi; }
DIR=$(mktemp -d /tmp/krymux-e2e-XXXXXX)
PIDS=()
cleanup() {
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; done
  [ -n "${KEEP:-}" ] || rm -rf "$DIR"
}
[ -n "${KEEP:-}" ] || trap cleanup EXIT

fail() { echo "❌ FAIL: $1"; exit 1; }
ok()   { echo "✅ $1"; }

# ---- keys ----
"$TBIN" keygen --out "$DIR/keys" --role server --name srv >/dev/null || fail keygen-server
"$TBIN" keygen --out "$DIR/keys" --role client --name cli >/dev/null || fail keygen-client
SRV_FP=$(sed -n 's/.*"fingerprint": *"\([^"]*\)".*/\1/p' "$DIR/keys/srv.identity.json")
CLI_FP=$(sed -n 's/.*"fingerprint": *"\([^"]*\)".*/\1/p' "$DIR/keys/cli.identity.json")
[ -n "$SRV_FP" ] && [ -n "$CLI_FP" ] || fail fingerprints

# ---- configs ----
cat > "$DIR/server.json" <<EOF
{
  "listen": "127.0.0.1:39443",
  "identity": {"key": "$(npath "$DIR")/keys/srv.key.pem", "cert": "$(npath "$DIR")/keys/srv.crt.pem"},
  "auth": {"mode": "whitelist", "fingerprints": ["$CLI_FP"]},
  "routes": [{"host": ["sync"], "upstream": ["127.0.0.1", 17890]}]
}
EOF
cat > "$DIR/client.json" <<EOF
{
  "endpoint": "127.0.0.1:39443",
  "identity": {"key": "$(npath "$DIR")/keys/cli.key.pem", "cert": "$(npath "$DIR")/keys/cli.crt.pem"},
  "serverFingerprint": "$SRV_FP"
}
EOF

# ---- roots + seed data (server side) ----
mkdir -p "$DIR/A/docs/sub" "$DIR/B"
printf 'hello tunnel\n' > "$DIR/A/readme.txt"
printf 'line1\nline2\nline3\n' > "$DIR/A/docs/notes.md"
printf 'nested\n' > "$DIR/A/docs/sub/deep.bin"
head -c 300000 /dev/urandom > "$DIR/A/big.bin"

# ---- start stack ----
"$TBIN" server --config "$DIR/server.json" >"$DIR/srv.log" 2>&1 & SRV_PID=$!; PIDS+=($SRV_PID)
"$SBIN" sync-server --path "$DIR/A" >"$DIR/syncsrv.log" 2>&1 & PIDS+=($!)
sleep 1.5

# ---- phase 1: download (server -> client) ----
"$SBIN" sync-client --path "$DIR/B" --config "$DIR/client.json" >"$DIR/c1.log" 2>&1
[ $? -eq 0 ] || { cat "$DIR/c1.log"; fail "phase1 sync-client"; }
grep -q "downloaded=4, uploads=0" "$DIR/c1.log" || { cat "$DIR/c1.log"; fail "phase1 stats"; }
diff -r --exclude=.sync.lock --exclude=.sync-cache.json "$DIR/A" "$DIR/B" >/dev/null || fail "phase1 tree mismatch"
ok "phase 1: 4 files downloaded through tunnel, trees identical"

# ---- phase 2: upload (client -> server) ----
printf 'client created this\n' > "$DIR/B/new-from-client.txt"
sleep 1.1  # ensure mtime strictly newer
printf 'line1\nline2\nline3\nEDITED-CLIENT\n' > "$DIR/B/docs/notes.md"
"$SBIN" sync-client --path "$DIR/B" --config "$DIR/client.json" >"$DIR/c2.log" 2>&1 || { cat "$DIR/c2.log"; fail "phase2 sync-client"; }
grep -q "uploads=2" "$DIR/c2.log" || { cat "$DIR/c2.log"; fail "phase2 upload count"; }
grep -q "EDITED-CLIENT" "$DIR/A/docs/notes.md" || fail "phase2 edited file not uploaded"
[ -f "$DIR/A/new-from-client.txt" ] || fail "phase2 new file not uploaded"
# re-sync should be a no-op
"$SBIN" sync-client --path "$DIR/B" --config "$DIR/client.json" >"$DIR/c3.log" 2>&1 || { cat "$DIR/c3.log"; fail "phase3 sync-client"; }
grep -q "downloaded=0, uploads=0" "$DIR/c3.log" || { cat "$DIR/c3.log"; fail "phase3 not converged"; }
ok "phase 2+3: 2 uploads (new+edited), re-sync converged to no-op"

# ---- phase 4: readonly server rejects uploads ----
# separate root: the root lock forbids a second sync-server on $DIR/A (by design)
mkdir -p "$DIR/A4"
printf 'ro-seed\n' > "$DIR/A4/ro-seed.txt"
"$SBIN" sync-server --path "$DIR/A4" --port 17891 --mode readonly >"$DIR/syncsrv2.log" 2>&1 & PIDS+=($!)
sleep 1
# point a second client config at a readonly sync server via a second route
cat > "$DIR/server2.json" <<EOF
{
  "listen": "127.0.0.1:39444",
  "identity": {"key": "$(npath "$DIR")/keys/srv.key.pem", "cert": "$(npath "$DIR")/keys/srv.crt.pem"},
  "auth": {"mode": "whitelist", "fingerprints": ["$CLI_FP"]},
  "routes": [{"host": ["sync"], "upstream": ["127.0.0.1", 17891]}]
}
EOF
"$TBIN" server --config "$DIR/server2.json" >"$DIR/srv2.log" 2>&1 & PIDS+=($!)
sleep 1
sed 's/39443/39444/' "$DIR/client.json" > "$DIR/client2.json"
printf 'should not be uploaded\n' > "$DIR/B/readonly-test.txt"
"$SBIN" sync-client --path "$DIR/B" --config "$DIR/client2.json" >"$DIR/c4.log" 2>&1 || { cat "$DIR/c4.log"; fail "phase4 sync-client"; }
[ ! -f "$DIR/A4/readonly-test.txt" ] || fail "phase4 readonly server accepted upload"
grep -q "uploads=0" "$DIR/c4.log" || { cat "$DIR/c4.log"; fail "phase4 upload attempted in readonly"; }
ok "phase 4: readonly mode honored end-to-end (negotiated, upload suppressed)"

# ---- phase 5: watch daemon (interval reconcile + local watch) ----
wait_for() { local f=$1; for _ in $(seq 1 30); do [ -f "$f" ] && return 0; sleep 1; done; return 1; }
wait_gone() { local f=$1; for _ in $(seq 1 30); do [ ! -f "$f" ] && return 0; sleep 1; done; return 1; }
wait_for_content() { local f=$1 want=$2; for _ in $(seq 1 30); do [ "$(cat "$f" 2>/dev/null)" = "$want" ] && return 0; sleep 1; done; return 1; }
rm -f "$DIR/B/readonly-test.txt"
"$SBIN" sync-client --path "$DIR/B" --config "$DIR/client.json" --watch --interval 2 >"$DIR/daemon.log" 2>&1 & PIDS+=($!)
sleep 4  # let the daemon do its first pass
printf 'remote change\n' > "$DIR/A/from-server-watched.txt"
wait_for "$DIR/B/from-server-watched.txt" || { tail -5 "$DIR/daemon.log"; fail "phase5 remote change not pulled by interval reconcile"; }
sleep 1.2
printf 'local change\n' > "$DIR/B/from-client-watched.txt"
wait_for "$DIR/A/from-client-watched.txt" || { tail -5 "$DIR/daemon.log"; fail "phase5 local change not pushed by watch trigger"; }
ok "phase 5: watch daemon — remote change pulled (interval), local change pushed (notify)"

# ---- phase 6: tunnel server restart → daemon auto-reconnects ----
kill "$SRV_PID" 2>/dev/null; sleep 1
"$TBIN" server --config "$DIR/server.json" >>"$DIR/srv.log" 2>&1 & PIDS+=($!)
sleep 1
printf 'after reconnect\n' > "$DIR/A/after-reconnect.txt"
wait_for "$DIR/B/after-reconnect.txt" || { tail -8 "$DIR/daemon.log"; fail "phase6 daemon did not reconnect after server restart"; }
ok "phase 6: daemon survived tunnel server restart (backoff reconnect) and synced"

# ---- phase 7: server push (rescan_hint) beats the interval ----
# a second daemon with a 60s interval: only a pushed hint can deliver the
# file within the observation window
mkdir -p "$DIR/B2" "$DIR/A7"
"$SBIN" sync-server --path "$DIR/A7" --port 17892 >"$DIR/syncsrv3.log" 2>&1 & PIDS+=($!)
cat > "$DIR/server3.json" <<EOF
{
  "listen": "127.0.0.1:39445",
  "identity": {"key": "$(npath "$DIR")/keys/srv.key.pem", "cert": "$(npath "$DIR")/keys/srv.crt.pem"},
  "auth": {"mode": "whitelist", "fingerprints": ["$CLI_FP"]},
  "routes": [{"host": ["sync"], "upstream": ["127.0.0.1", 17892]}]
}
EOF
"$TBIN" server --config "$DIR/server3.json" >"$DIR/srv3.log" 2>&1 & PIDS+=($!)
sed 's/39443/39445/' "$DIR/client.json" > "$DIR/client3.json"
"$SBIN" sync-client --path "$DIR/B2" --config "$DIR/client3.json" --watch --interval 60 >"$DIR/daemon2.log" 2>&1 & PIDS+=($!)
sleep 4   # initial pass attaches the notify stream
printf 'pushed by rescan_hint\n' > "$DIR/A7/hinted.txt"
wait_for "$DIR/B2/hinted.txt" || { tail -8 "$DIR/daemon2.log"; fail "phase7 file not delivered via rescan_hint within window"; }
ok "phase 7: server-side change pushed (rescan_hint) — arrived without waiting the 60s interval"

# ---- phase 8: 1 server + 2 clients ----
# B8 (interval 3) and C8 (interval 60) sync the same server root; C8's long
# interval means cross-client propagation must ride the deferred hint that
# fires when B8's upload session on the server ends
"$TBIN" keygen --out "$DIR/keys" --role client --name cli2 >/dev/null || fail keygen-cli2
CLI2_FP=$(sed -n 's/.*"fingerprint": *"\([^"]*\)".*/\1/p' "$DIR/keys/cli2.identity.json")
mkdir -p "$DIR/A8" "$DIR/B8" "$DIR/C8"
printf 'shared-one\n' > "$DIR/A8/shared.txt"
printf 'shared-two\n' > "$DIR/A8/another.txt"
cat > "$DIR/server4.json" <<EOF
{
  "listen": "127.0.0.1:39446",
  "identity": {"key": "$(npath "$DIR")/keys/srv.key.pem", "cert": "$(npath "$DIR")/keys/srv.crt.pem"},
  "auth": {"mode": "whitelist", "fingerprints": ["$CLI_FP", "$CLI2_FP"]},
  "routes": [{"host": ["sync"], "upstream": ["127.0.0.1", 17893]}]
}
EOF
"$SBIN" sync-server --path "$DIR/A8" --port 17893 >"$DIR/syncsrv4.log" 2>&1 & PIDS+=($!)
"$TBIN" server --config "$DIR/server4.json" >"$DIR/srv4.log" 2>&1 & SRV4_PID=$!; PIDS+=($SRV4_PID)
sed 's/39443/39446/' "$DIR/client.json" > "$DIR/client-b8.json"
sed -e 's/39443/39446/' -e 's/cli\./cli2./g' "$DIR/client.json" > "$DIR/client-c8.json"
"$SBIN" sync-client --path "$DIR/B8" --config "$DIR/client-b8.json" --watch --interval 3 >"$DIR/b8.log" 2>&1 & PIDS+=($!)
"$SBIN" sync-client --path "$DIR/C8" --config "$DIR/client-c8.json" --watch --interval 60 >"$DIR/c8.log" 2>&1 & C8_PID=$!; PIDS+=($C8_PID)
sleep 5
[ -f "$DIR/B8/shared.txt" ] && [ -f "$DIR/C8/shared.txt" ] || fail "phase8a both clients must sync initial tree"

printf 'born on B8\n' > "$DIR/B8/from-b8.txt"
wait_for "$DIR/A8/from-b8.txt" || { tail -5 "$DIR/b8.log"; fail "phase8b server did not receive B8 upload"; }
wait_for "$DIR/C8/from-b8.txt" || { tail -8 "$DIR/c8.log"; fail "phase8b C8 did not receive B8's file (deferred hint broken)"; }
ok "phase 8a+8b: 2-client initial sync + cross-client B→A→C via deferred session-end hint (C8 interval 60)"

# concurrent edit of the same file from both clients: content must converge
# everywhere to exactly one of the two writes (last-writer by mtime), no blend
sleep 1.2
printf 'VERSION-B8\n' > "$DIR/B8/race.txt"
sleep 1.6
printf 'VERSION-C8\n' > "$DIR/C8/race.txt"
sleep 10
B8V=$(cat "$DIR/B8/race.txt" 2>/dev/null); C8V=$(cat "$DIR/C8/race.txt" 2>/dev/null); A8V=$(cat "$DIR/A8/race.txt" 2>/dev/null)
[ -n "$B8V" ] && [ "$B8V" = "$C8V" ] && [ "$C8V" = "$A8V" ] || fail "phase8c concurrent edit did not converge (A='$A8V' B='$B8V' C='$C8V')"
ok "phase 8c: concurrent same-file edits converged to a single consistent version on all three"

# C8 goes down, A8 changes while it's away, C8 rejoins and catches up
kill "$C8_PID" 2>/dev/null; sleep 1
printf 'while C8 was down\n' > "$DIR/A8/catchup.txt"
"$SBIN" sync-client --path "$DIR/C8" --config "$DIR/client-c8.json" --watch --interval 60 >>"$DIR/c8.log" 2>&1 & PIDS+=($!)
sleep 6
[ -f "$DIR/C8/catchup.txt" ] || { tail -8 "$DIR/c8.log"; fail "phase8d rejoined client did not catch up"; }
ok "phase 8d: client downtime + rejoin → catch-up on first pass"

# tunnel restart with both clients attached: both reconnect, both converge
kill "$SRV4_PID" 2>/dev/null; sleep 1
"$TBIN" server --config "$DIR/server4.json" >>"$DIR/srv4.log" 2>&1 & PIDS+=($!)
sleep 1
printf 'after dual restart\n' > "$DIR/A8/dual-restart.txt"
sleep 12
[ -f "$DIR/B8/dual-restart.txt" ] || { tail -5 "$DIR/b8.log"; fail "phase8e B8 lost after tunnel restart"; }
[ -f "$DIR/C8/dual-restart.txt" ] || { tail -8 "$DIR/c8.log"; fail "phase8e C8 lost after tunnel restart"; }
ok "phase 8e: tunnel restart with 2 clients → both reconnected and synced"

# ---- phase 10: deletion matrix (tombstone propagation) ----
# The B daemon (phase 5) and the B8/C8 stack (phase 8) are still running.
# (a) delete on server A → client B removes it, A does NOT get it resurrected
printf 'doomed-on-a\n' > "$DIR/A/doom-a.txt"
wait_for "$DIR/B/doom-a.txt" || { tail -5 "$DIR/daemon.log"; fail "phase10a setup: doom-a.txt must reach B first"; }
rm "$DIR/A/doom-a.txt"
wait_gone "$DIR/B/doom-a.txt" || { tail -8 "$DIR/daemon.log"; fail "phase10a B did not remove the server-deleted file"; }
sleep 3
[ ! -f "$DIR/A/doom-a.txt" ] || fail "phase10a doomed file resurrected on A"
ok "phase 10a: server-side delete propagated to B, no resurrection"

# (b) delete on client B → removed from server A
printf 'doomed-on-b\n' > "$DIR/B/doom-b.txt"
wait_for "$DIR/A/doom-b.txt" || { tail -5 "$DIR/daemon.log"; fail "phase10b setup: doom-b.txt must reach A first"; }
rm "$DIR/B/doom-b.txt"
wait_gone "$DIR/A/doom-b.txt" || { tail -8 "$DIR/daemon.log"; fail "phase10b A did not remove the client-deleted file"; }
sleep 3
[ ! -f "$DIR/B/doom-b.txt" ] || fail "phase10b doom-b re-downloaded by B"
ok "phase 10b: client-side delete propagated to A"

# (c) delete on A, then recreate on B with new content AFTER the delete →
#     the new content wins on A (last-writer beats the tombstone)
printf 'v1\n' > "$DIR/A/last-writer.txt"
wait_for_content "$DIR/B/last-writer.txt" "v1" || { tail -5 "$DIR/daemon.log"; fail "phase10c setup: last-writer.txt must reach B"; }
rm "$DIR/A/last-writer.txt"
wait_gone "$DIR/B/last-writer.txt" || { tail -8 "$DIR/daemon.log"; fail "phase10c B did not apply the server delete"; }
sleep 1.2
printf 'v2-recreated\n' > "$DIR/B/last-writer.txt"
wait_for_content "$DIR/A/last-writer.txt" "v2-recreated" || { tail -8 "$DIR/daemon.log"; fail "phase10c recreated file did not win on A"; }
sleep 3
[ "$(cat "$DIR/B/last-writer.txt" 2>/dev/null)" = "v2-recreated" ] || fail "phase10c B lost its recreated copy"
ok "phase 10c: delete-then-recreate → new content wins on both sides (last-writer)"

# (d) two clients: delete on B8 → removed from A8 AND from C8
printf 'shared-doom\n' > "$DIR/A8/doom-multi.txt"
sleep 8   # B8 pulls on interval; C8 via the hub hint
[ -f "$DIR/B8/doom-multi.txt" ] && [ -f "$DIR/C8/doom-multi.txt" ] || fail "phase10d setup: doom-multi must reach B8 and C8 first"
rm "$DIR/B8/doom-multi.txt"
wait_gone "$DIR/A8/doom-multi.txt" || { tail -5 "$DIR/b8.log"; fail "phase10d A8 did not process delete_file from B8"; }
wait_gone "$DIR/C8/doom-multi.txt" || { tail -8 "$DIR/c8.log"; fail "phase10d C8 did not remove the multi-client deleted file"; }
sleep 3
[ ! -f "$DIR/A8/doom-multi.txt" ] || fail "phase10d resurrection on A8"
ok "phase 10d: multi-client — delete on B8 removed from A8 and C8 (tombstone via hub hint)"

echo ""
echo "🎉 E2E sync through krymux tunnel: ALL PHASES PASSED"
KEEP=1
