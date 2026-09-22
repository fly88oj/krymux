#!/usr/bin/env bash
# Stability soak: sustained mixed load + reconnect storms + RSS timeline.
# Uses the ALREADY-BUILT binary (no cargo) to avoid target-dir contention.
set -u
cd "$(dirname "$0")/.."
TBIN=./target/release/krymux-tunnel.exe   # tunnel ops: keygen / fingerprint / probe / server / client
SBIN=./target/release/krymux-sync.exe     # sync ops: sync-server / sync-client
[ -x "$TBIN" ] && [ -x "$SBIN" ] || { echo "build first"; exit 1; }
DUR_MIN=${SOAK_MIN:-10}
DIR=$(mktemp -d /tmp/krymux-soak-XXXXXX)
PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null; done; rm -rf "$DIR"; }
trap cleanup INT TERM
[ -n "${KEEP:-}" ] || trap cleanup EXIT

say() { echo "[$(date +%H:%M:%S)] $*"; }

"$TBIN" keygen --out "$DIR/k" --role server --name s >/dev/null
"$TBIN" keygen --out "$DIR/k" --role client --name c >/dev/null
SFP=$(sed -n 's/.*"fingerprint": *"\([^"]*\)".*/\1/p' "$DIR/k/s.identity.json")
CFP=$(sed -n 's/.*"fingerprint": *"\([^"]*\)".*/\1/p' "$DIR/k/c.identity.json")
W=$(cygpath -m "$DIR")
printf '{"listen":"127.0.0.1:39470","identity":{"key":"%s/k/s.key.pem","cert":"%s/k/s.crt.pem"},"auth":{"mode":"whitelist","fingerprints":["%s"]},"routes":[{"host":["sync"],"upstream":["127.0.0.1",17895]}]}' "$W" "$W" "$CFP" > "$DIR/srv.json"
printf '{"endpoint":"127.0.0.1:39470","identity":{"key":"%s/k/c.key.pem","cert":"%s/k/c.crt.pem"},"serverFingerprint":"%s"}' "$W" "$W" "$SFP" > "$DIR/cli.json"
mkdir -p "$DIR/A" "$DIR/B"
"$TBIN" server --config "$DIR/srv.json" >"$DIR/srv.log" 2>&1 & SRV=$!; PIDS+=($SRV)
"$SBIN" sync-server --path "$DIR/A" --port 17895 >"$DIR/ss.log" 2>&1 & PIDS+=($!)
for i in $(seq 1 60); do (echo > /dev/tcp/127.0.0.1/39470) 2>/dev/null && break; sleep 0.5; done
"$SBIN" sync-client --path "$DIR/B" --config "$DIR/cli.json" --watch --interval 3 >"$DIR/d.log" 2>&1 & PIDS+=($!)

rss_line() { powershell.exe -NoProfile -Command "\$p=Get-Process krymux-tunnel,krymux-sync -ErrorAction SilentlyContinue; if(\$p){ '{0} procs, {1:N0} KiB' -f \$p.Count, ((\$p | Measure-Object WorkingSet64 -Sum).Sum/1KB) } else { '0 procs' }" 2>/dev/null | tr -d '
'; }

say "soak start: ${DUR_MIN}min mixed load; RSS(t0): $(rss_line)"
END=$((SECONDS + DUR_MIN*60)); round=0; storms=0
while [ $SECONDS -lt $END ]; do
  round=$((round+1))
  # mixed churn on server side: small files + a medium blob + deletes
  for f in s1 s2 s3 s4 s5; do printf "round-$round-$f\n" > "$DIR/A/$f.txt"; done
  head -c 5242880 /dev/urandom > "$DIR/A/blob.bin"
  rm -f "$DIR/A/s5.txt"
  # reconnect storm twice during the soak
  if [ $round -eq 4 ] || [ $round -eq 12 ]; then
    storms=$((storms+1)); say "reconnect storm #$storms (server restart)"
    kill -9 $SRV 2>/dev/null; sleep 1
    "$TBIN" server --config "$DIR/srv.json" >>"$DIR/srv.log" 2>&1 & SRV=$!; PIDS+=($SRV)
    for i in $(seq 1 30); do (echo > /dev/tcp/127.0.0.1/39470) 2>/dev/null && break; sleep 0.5; done
  fi
  if [ $((round % 6)) -eq 0 ]; then say "round $round RSS: $(rss_line)"; fi
  # poll until blob round-$round content lands on B or 20s
  for i in $(seq 1 20); do grep -q "round-$round-s1" "$DIR/B/s1.txt" 2>/dev/null && break; sleep 1; done
done

say "final state check"
for i in $(seq 1 30); do [ ! -e "$DIR/A/s5.txt" ] && [ ! -e "$DIR/B/s5.txt" ] && break; sleep 1; done
[ ! -e "$DIR/B/s5.txt" ] && say "delete propagated: yes" || say "delete propagated: NO"
# wait for the LAST blob to converge before comparing: poll md5 stability on B
HA=$(md5sum < "$DIR/A/blob.bin" | cut -d' ' -f1)
for i in $(seq 1 30); do
  HB=$(md5sum < "$DIR/B/blob.bin" 2>/dev/null | cut -d' ' -f1)
  [ "$HA" = "$HB" ] && break
  sleep 1
done
[ "$HA" = "$HB" ] && say "blob integrity: OK ($HA)" || say "blob integrity: FAIL (A=$HA B=$HB)"
say "RSS(t-end): $(rss_line)"; say "daemon pass count: $(grep -c 'pass #' "$DIR/d.log")"
say "daemon failures: $(grep -c 'failed' "$DIR/d.log") | storms survived: $storms"
say "SOAK COMPLETE"
