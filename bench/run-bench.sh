#!/usr/bin/env bash
# =============================================================================
# krymux reproducible benchmark harness (Git-Bash / Windows compatible).
#
#   bash bench/run-bench.sh            run everything, write bench/BASELINE.md
#   KEEP=1   bash bench/run-bench.sh   keep the temp work dir (post-mortem)
#   SKIP_BUILD=1 ...                   skip `cargo build --release`
#
# What it measures (each throughput metric = median of 3 runs):
#   1. Throughput  — 16 MiB echo (Rust client -> krymux server -> echo origin)
#                    for none / zstd / brotli / deflate, via examples/bench2.rs
#                    (pre-existing metric-emitting bench; see its header).
#   2. One 64 MiB zstd run  +  RSS of server child & client right after it.
#   3. Stream-open latency — 200 sequential open_stream+close, p50/p99 ms.
#   4. Small-message RTT   — 500 x 1-KiB request/echo on one stream, p50/p99.
#   5. Sync pass time      — 3000-file tree (mixed 1..256 KiB, ~235 MiB):
#                    one-shot sync-client twice (full pass, then no-op
#                    convergence), reporting both wall times.
#   6. Daemon watch->push  — sync-client --watch, local file create until the
#                    file exists on the server side, 10 samples, median.
#
# Raw log:   bench/logs/baseline-<timestamp>.log
# Results:   bench/BASELINE.md
#
# Recipe for keys/configs follows e2e-sync-test.sh (keygen -> fingerprints ->
# whitelist auth -> route host "sync" to the sync-server port); benchmark
# topology for 1-4 follows examples/bench.rs / bench2.rs (echo origin spawned
# in-process by bench2, krymux-tunnel.exe server as a child, Rust client in-process).
# =============================================================================
set -u
set -o pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
TBIN=$ROOT/target/release/krymux-tunnel.exe
SBIN=$ROOT/target/release/krymux-sync.exe
BENCH2=$ROOT/target/release/examples/bench2.exe

STAMP=$(date '+%Y%m%d-%H%M%S')
LOGDIR=$ROOT/bench/logs
RAWLOG=$LOGDIR/baseline-$STAMP.log
BASELINE=$ROOT/bench/BASELINE.md
mkdir -p "$LOGDIR"

say() { printf '\n===== %s =====\n' "$*"; }

# --- timing helpers: EPOCHREALTIME (bash5) -> integer microseconds, no fork ---
now_us() { echo "${EPOCHREALTIME/./}"; }
elapsed_ms() { echo $(( ($2 - $1) / 1000 )); }   # us us -> ms

median() {  # median of a list of numbers
  printf '%s\n' "$@" | sort -n | awk '{a[NR]=$1} END {print (NR%2)?a[int(NR/2)+1]:(a[NR/2]+a[NR/2+1])/2}'
}
f1() { awk -v v="$1" 'BEGIN{printf "%.1f", v}'; }   # 1 decimal
f3() { awk -v v="$1" 'BEGIN{printf "%.3f", v}'; }   # 3 decimals
f2() { awk -v v="$1" 'BEGIN{printf "%.2f", v}'; }   # 2 decimals

kill_strays() {
  taskkill //IM krymux-tunnel.exe //F >/dev/null 2>&1 || true
  taskkill //IM krymux-sync.exe //F >/dev/null 2>&1 || true
}

PIDS=()
DIR=""
cleanup() {
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; done
  kill_strays
  if [ -n "${KEEP:-}" ] || [ -z "$DIR" ]; then :; else rm -rf "$DIR" 2>/dev/null; fi
}
trap cleanup EXIT

# everything below also lands in the raw log
exec > >(tee -a "$RAWLOG") 2>&1

# =============================================================================
say "krymux benchmark harness  $STAMP"
echo "host: $(uname -s -r -m)   cpus: ${NUMBER_OF_PROCESSORS:-n/a}"
CPU=$(powershell -NoProfile -Command '(Get-CimInstance Win32_Processor).Name' 2>/dev/null | head -1 | sed 's/^ *//;s/ *$//')
[ -n "$CPU" ] || CPU="n/a"
echo "cpu:  $CPU"

# ---- 0. build ---------------------------------------------------------------
if [ -z "${SKIP_BUILD:-}" ]; then
  say "cargo build --release --features krymux/zstd --bin krymux-tunnel --bin krymux-sync --example bench2"
  cargo build --release --features krymux/zstd --bin krymux-tunnel --bin krymux-sync --example bench2 || { echo "BUILD FAILED"; exit 1; }
fi
[ -x "$TBIN" ] || { echo "missing $TBIN (build first)"; exit 1; }
[ -x "$SBIN" ] || { echo "missing $SBIN (build first)"; exit 1; }
[ -x "$BENCH2" ] || { echo "missing $BENCH2 (build first)"; exit 1; }

# ---- metric plumbing --------------------------------------------------------
get_metric() { grep "^METRIC $2 " "$1" 2>/dev/null | tail -1 | awk '{print $3}'; }

# ---- clean stray processes from any earlier run ------------------------------
say "killing stray krymux-tunnel.exe / krymux-sync.exe"
kill_strays
tasklist //FI "IMAGENAME eq krymux-tunnel.exe" //FO CSV //NH 2>/dev/null | grep -c '^"krymux' | xargs -I{} echo "krymux-tunnel.exe processes after kill: {}"

# =============================================================================
say "phase 1-4: bench2 (echo throughput / open latency / 1-KiB RTT / RSS)"
# bench2_run <log> <timeout_s> <base_port> [ENV=val ...]
# Retries up to 5 attempts: bulk echo transfers on this machine/build are
# intermittently hit by a stall (~0.2 MB/s crawl) or a truncated tail with
# early EOF (see bench/BASELINE.md notes). Healthy runs finish in <5 s, so
# the timeout mainly kills stalled attempts fast. Each attempt gets its own
# port and stray cleanup.
RETRIES=0
bench2_run() {
  local log=$1 tmo=$2 port=$3; shift 3
  local attempt=1 rc
  while :; do
    env "$@" KRYMUX_BENCH2_PORT=$((port + attempt)) timeout "$tmo" "$BENCH2" >"$log" 2>&1
    rc=$?
    # success = metrics were emitted; a nonzero exit AFTER the metrics
    # (session-teardown noise like a late stray frame) must not fail the run
    if [ $rc -eq 0 ] || grep -q '^METRIC' "$log"; then
      [ $rc -ne 0 ] && echo "note: bench2 rc=$rc after metrics; treating as success"
      ATTEMPTS=$attempt; return 0
    fi
    if [ "$attempt" -ge 5 ]; then
      echo "bench2 FAILED after $attempt attempts (last rc=$rc); output tail:"
      tail -8 "$log"
      return 1
    fi
    echo "bench2 attempt $attempt failed (rc=$rc) — retrying"
    cp "$log" "$log.attempt$attempt" 2>/dev/null
    RETRIES=$((RETRIES + 1))
    kill_strays
    sleep 2
    attempt=$((attempt + 1))
  done
}

# ---- throughput: 3 runs per algo, algo-isolated (a zstd stall must not
# ---- force re-measuring the healthy algos) -----------------------------------
declare -A THR THR_RUNS
for ai in 1 2 3 4; do
  case $ai in
    1) algo=none;;    2) algo=zstd;;    3) algo=brotli;;    4) algo=deflate;;
  esac
  for i in 1 2 3; do
    echo "--- throughput run $i/3: algo=$algo (16 MiB) ---"
    L=$LOGDIR/bench2-${algo}-16mb-run$i.log
    bench2_run "$L" 60 $((38500 + ai * 10)) \
      KRYMUX_BENCH2_MB=16 KRYMUX_BENCH2_ALGOS=$algo KRYMUX_BENCH2_PHASES=throughput \
      || exit 1
    cat "$L"
    v=$(get_metric "$L" "throughput_${algo}_16mb_mb_s")
    [ -n "$v" ] || { echo "missing throughput_${algo}_16mb_mb_s in run $i"; exit 1; }
    THR_RUNS[$algo]="${THR_RUNS[$algo]:-} $v"
  done
  THR[$algo]=$(median ${THR_RUNS[$algo]})
done

# ---- stream-open latency + small-message RTT: 3 runs -------------------------
OPEN50_RUNS=(); OPEN99_RUNS=(); RTT50_RUNS=(); RTT99_RUNS=()
for i in 1 2 3; do
  echo "--- latency run $i/3 (200x open+close, 500x 1-KiB RTT) ---"
  L=$LOGDIR/bench2-latency-run$i.log
  bench2_run "$L" 60 38560 \
    KRYMUX_BENCH2_MB=1 KRYMUX_BENCH2_ALGOS=none KRYMUX_BENCH2_PHASES=open,rtt \
    || exit 1
  cat "$L"
  OPEN50_RUNS[$i]=$(get_metric "$L" stream_open_p50_ms)
  OPEN99_RUNS[$i]=$(get_metric "$L" stream_open_p99_ms)
  RTT50_RUNS[$i]=$(get_metric "$L" msg_rtt_p50_ms)
  RTT99_RUNS[$i]=$(get_metric "$L" msg_rtt_p99_ms)
  [ -n "${OPEN50_RUNS[$i]}" ] && [ -n "${RTT99_RUNS[$i]}" ] || { echo "missing latency metrics in run $i"; exit 1; }
done
OPEN_P50=$(median ${OPEN50_RUNS[1]} ${OPEN50_RUNS[2]} ${OPEN50_RUNS[3]})
OPEN_P99=$(median ${OPEN99_RUNS[1]} ${OPEN99_RUNS[2]} ${OPEN99_RUNS[3]})
RTT_P50=$(median ${RTT50_RUNS[1]} ${RTT50_RUNS[2]} ${RTT50_RUNS[3]})
RTT_P99=$(median ${RTT99_RUNS[1]} ${RTT99_RUNS[2]} ${RTT99_RUNS[3]})
echo "medians: none=$(f1 ${THR[none]}) zstd=$(f1 ${THR[zstd]}) brotli=$(f1 ${THR[brotli]}) deflate=$(f1 ${THR[deflate]}) MB/s | open p50/p99=$(f3 $OPEN_P50)/$(f3 $OPEN_P99) ms | rtt p50/p99=$(f3 $RTT_P50)/$(f3 $RTT_P99) ms | bench2 retries: $RETRIES"

# ---- one 64 MiB zstd run, RSS right after it --------------------------------
say "64 MiB zstd run + memory (RSS)"
L=$LOGDIR/bench2-64mb-zstd.log
bench2_run "$L" 180 38570 \
  KRYMUX_BENCH2_MB=64 KRYMUX_BENCH2_ALGOS=zstd KRYMUX_BENCH2_PHASES=throughput,mem \
  || exit 1
cat "$L"
Z64=$(get_metric "$L" throughput_zstd_64mb_mb_s)
RSS_SRV=$(get_metric "$L" rss_server_kb)
RSS_CLI=$(get_metric "$L" rss_client_kb)
[ -n "$Z64" ] && [ -n "$RSS_SRV" ] && [ -n "$RSS_CLI" ] || { echo "missing 64MiB/RSS metrics"; exit 1; }

# =============================================================================
if [ -n "${SKIP_SYNC:-}" ]; then say "phase 5 skipped (SKIP_SYNC=1)"; else
say "phase 5: sync benchmarks (3000-file tree)"
kill_strays   # bench2 kills its own children, but be safe before the sync stack

DIR=$(mktemp -d /tmp/krymux-bench-XXXXXX)
echo "work dir: $DIR"

# ---- keys + configs (recipe from e2e-sync-test.sh) ---------------------------
"$TBIN" keygen --out "$DIR/keys" --role server --name srv >/dev/null || { echo keygen-server FAILED; exit 1; }
"$TBIN" keygen --out "$DIR/keys" --role client --name cli >/dev/null || { echo keygen-client FAILED; exit 1; }
SRV_FP=$(sed -n 's/.*"fingerprint": *"\([^"]*\)".*/\1/p' "$DIR/keys/srv.identity.json")
CLI_FP=$(sed -n 's/.*"fingerprint": *"\([^"]*\)".*/\1/p' "$DIR/keys/cli.identity.json")
[ -n "$SRV_FP" ] && [ -n "$CLI_FP" ] || { echo fingerprints FAILED; exit 1; }
WKEYS=$(cygpath -m "$DIR")
cat > "$DIR/server.json" <<EOF
{
  "listen": "127.0.0.1:38601",
  "identity": {"key": "$WKEYS/keys/srv.key.pem", "cert": "$WKEYS/keys/srv.crt.pem"},
  "auth": {"mode": "whitelist", "fingerprints": ["$CLI_FP"]},
  "routes": [{"host": ["sync"], "upstream": ["127.0.0.1", 17890]}]
}
EOF
cat > "$DIR/client.json" <<EOF
{
  "endpoint": "127.0.0.1:38601",
  "identity": {"key": "$WKEYS/keys/cli.key.pem", "cert": "$WKEYS/keys/cli.crt.pem"},
  "serverFingerprint": "$SRV_FP"
}
EOF

# ---- 3000-file tree, mixed 1..256 KiB (~235 MiB) -----------------------------
say "generating 3000-file tree"
POOLD=$DIR/pool; mkdir -p "$POOLD"
NFILE=3000
TOTAL_BYTES=0
for sz in 1024 4096 16384 65536 131072 262144; do
  head -c $sz /dev/urandom > "$POOLD/p$sz.bin"
done
mkdir -p "$DIR/A"
for i in $(seq 0 $((NFILE - 1))); do
  case $((i % 6)) in
    0) sz=1024;;   1) sz=4096;;   2) sz=16384;;
    3) sz=65536;;  4) sz=131072;; 5) sz=262144;;
  esac
  d=$DIR/A/d$(printf '%02d' $((i / 100)))
  mkdir -p "$d"
  cp "$POOLD/p$sz.bin" "$d/f$i.bin" || { echo "tree gen FAILED at $i"; exit 1; }
  TOTAL_BYTES=$((TOTAL_BYTES + sz))
done
rm -rf "$POOLD"
echo "tree: $NFILE files, $((TOTAL_BYTES / 1024 / 1024)) MiB in $DIR/A"

# ---- start stack --------------------------------------------------------------
"$TBIN" server --config "$DIR/server.json" >"$DIR/srv.log" 2>&1 & PIDS+=($!)
"$SBIN" sync-server --path "$DIR/A" >"$DIR/syncsrv.log" 2>&1 & PIDS+=($!)
sleep 2
mkdir -p "$DIR/B"

# ---- one-shot full pass -------------------------------------------------------
say "sync full pass (3000 files)"
T0=$(now_us)
"$SBIN" sync-client --path "$DIR/B" --config "$DIR/client.json" >"$DIR/sync-full.log" 2>&1 \
  || { echo "full sync FAILED"; tail -10 "$DIR/sync-full.log"; exit 1; }
T1=$(now_us)
SYNC_FULL_MS=$(elapsed_ms $T0 $T1)
grep "Sync complete" "$DIR/sync-full.log"
grep -q "downloaded=$NFILE, uploads=0" "$DIR/sync-full.log" \
  || { echo "UNEXPECTED: full pass stats (wanted downloaded=$NFILE, uploads=0)"; }

# ---- one-shot no-op convergence ----------------------------------------------
say "sync no-op pass (convergence)"
T0=$(now_us)
"$SBIN" sync-client --path "$DIR/B" --config "$DIR/client.json" >"$DIR/sync-noop.log" 2>&1 \
  || { echo "no-op sync FAILED"; tail -10 "$DIR/sync-noop.log"; exit 1; }
T1=$(now_us)
SYNC_NOOP_MS=$(elapsed_ms $T0 $T1)
grep "Sync complete" "$DIR/sync-noop.log"
grep -q "downloaded=0, uploads=0" "$DIR/sync-noop.log" \
  || { echo "UNEXPECTED: no-op pass not converged"; }

# ---- daemon watch->push latency (10 samples) ----------------------------------
say "daemon watch->push latency (10 samples)"
"$SBIN" sync-client --path "$DIR/B" --config "$DIR/client.json" --watch --interval 60 >"$DIR/daemon.log" 2>&1 &
DPID=$!; PIDS+=($DPID)
sleep 6   # initial pass + notify attach
LAT=()
for k in $(seq 1 10); do
  printf 'watch-latency sample %d\n' "$k" > "$DIR/B/lat-$k.txt"
  T0=$(now_us)
  for _ in $(seq 1 600); do            # up to ~30 s (50 ms poll)
    [ -s "$DIR/A/lat-$k.txt" ] && break
    sleep 0.05
  done
  T1=$(now_us)
  if [ ! -s "$DIR/A/lat-$k.txt" ]; then
    echo "sample $k: file never arrived on the server side"; tail -5 "$DIR/daemon.log"; exit 1
  fi
  MS=$(elapsed_ms $T0 $T1)
  LAT+=("$MS")
  echo "sample $k: ${MS} ms"
  sleep 0.3   # let the watcher go quiet before the next create
done
LAT_MED=$(median "${LAT[@]}")
LAT_MIN=$(printf '%s\n' "${LAT[@]}" | sort -n | head -1)
LAT_MAX=$(printf '%s\n' "${LAT[@]}" | sort -n | tail -1)
echo "watch->push latency: median=${LAT_MED} ms  min=${LAT_MIN}  max=${LAT_MAX}"

# =============================================================================
say "writing $BASELINE"
kib2mib() { awk -v k="$1" 'BEGIN{printf "%.1f", k/1024}'; }
cat > "$BASELINE" <<EOF
# krymux BASELINE benchmarks

Generated by \`bench/run-bench.sh\` — raw log: \`bench/logs/baseline-$STAMP.log\`

- **Date**: $(date '+%Y-%m-%d %H:%M:%S')
- **Host**: $(uname -s -r -m), ${NUMBER_OF_PROCESSORS:-n/a} logical CPUs, CPU: $CPU
- **Build**: \`cargo build --release --features zstd\` (opt-level 3, thin LTO)
- **Topology** (throughput/latency/memory): echo origin (in-process) ← krymux-tunnel.exe server ← Rust client (in-process), loopback 127.0.0.1
- **Topology** (sync): sync-client (krymux-sync) → krymux-tunnel.exe server (mTLS whitelist) → sync-server (krymux-sync), one sync tree

## Throughput — 16 MiB echo round-trip (median of 3 runs)

| Compression | MB/s (median) | per-run MB/s |
|---|---:|---|
| none    | $(f1 ${THR[none]})    |${THR_RUNS[none]} |
| zstd    | $(f1 ${THR[zstd]})    |${THR_RUNS[zstd]} |
| brotli  | $(f1 ${THR[brotli]})  |${THR_RUNS[brotli]} |
| deflate | $(f1 ${THR[deflate]}) |${THR_RUNS[deflate]} |

Compressible text payload (repeating HTTP-log line), 256 KiB chunks, single stream, full echo round-trip.

## Throughput — 64 MiB echo, zstd (1 run)

| Compression | Payload | MB/s |
|---|---|---:|
| zstd | 64 MiB | $(f1 "$Z64") |

## Stream-open latency — 200 sequential open+close on one session

| Metric | Value |
|---|---:|
| p50 | $(f3 "$OPEN_P50") ms |
| p99 | $(f3 "$OPEN_P99") ms |

## Small-message RTT — 500 × 1-KiB request/echo on one stream

| Metric | Value |
|---|---:|
| p50 | $(f3 "$RTT_P50") ms |
| p99 | $(f3 "$RTT_P99") ms |

## File sync — 3000-file tree (mixed 1–256 KiB, $((TOTAL_BYTES / 1024 / 1024)) MiB total)

| Pass | Wall time | Result |
|---|---:|---|
| Full (cold client, 3000 downloads) | $(f2 "$(awk -v ms=$SYNC_FULL_MS 'BEGIN{print ms/1000}')") s | $(grep -o 'downloaded=[0-9]*, uploads=[0-9]*' "$DIR/sync-full.log" | head -1) |
| No-op convergence | $(f2 "$(awk -v ms=$SYNC_NOOP_MS 'BEGIN{print ms/1000}')") s | $(grep -o 'downloaded=[0-9]*, uploads=[0-9]*' "$DIR/sync-noop.log" | head -1) |

## Daemon watch→push latency — local file create until arrival on the server side

| Metric | Value |
|---|---:|
| Median (10 samples) | $(f2 "$(awk -v ms=$LAT_MED 'BEGIN{print ms/1000}')") s |
| Min / Max | $(f2 "$(awk -v ms=$LAT_MIN 'BEGIN{print ms/1000}')") s / $(f2 "$(awk -v ms=$LAT_MAX 'BEGIN{print ms/1000}')") s |

Samples (ms): ${LAT[*]}
Includes the daemon's 700 ms change-settle debounce plus a full 3000-file rescan before push. Poll granularity ≈ 50 ms.

## Memory — RSS after the 64 MiB zstd run

| Process | RSS |
|---|---:|
| krymux-tunnel.exe server | ${RSS_SRV} KiB ($(kib2mib "$RSS_SRV") MiB) |
| Rust client (bench2) | ${RSS_CLI} KiB ($(kib2mib "$RSS_CLI") MiB) |

## vs. README claims

| Metric | README claim | Measured | Delta |
|---|---:|---:|---:|
| 16 MiB echo, none | ~405 MB/s | $(f1 ${THR[none]}) MB/s | $(awk -v c=405 -v m=${THR[none]} 'BEGIN{printf "%+.0f%%", (m/c-1)*100}') |
| 16 MiB echo, zstd | ~739 MB/s | $(f1 ${THR[zstd]}) MB/s | $(awk -v c=739 -v m=${THR[zstd]} 'BEGIN{printf "%+.0f%%", (m/c-1)*100}') |
| Stream-open p50 | 0.28 ms | $(f3 "$OPEN_P50") ms | $(awk -v c=0.28 -v m=$OPEN_P50 'BEGIN{printf "%+.0f%%", (m/c-1)*100}') |

## Notes / anomalies

- **Bulk echo transfers are intermittently UNRELIABLE on this build/machine.**
  Observed failure modes across pre-baseline probes and this run:
  (a) a stall — throughput collapses to ~0.2 MB/s and the transfer crawls or
  never finishes (rc=timeout); (b) a truncated tail with an early EOF — the
  echo comes back 8-48 KiB short (`echo short read`). These hit **every**
  algorithm (first seen with zstd, then with plain none), occur in bursts
  (minutes where every attempt fails, then everything healthy again), and are
  not reproduced by an identical invocation minutes later. A healthy full
  bench2 pass takes ~2 s. The harness retries each bench2 invocation up to 5
  attempts (60 s timeout each) and keeps failed attempts as
  \`<run>.log.attemptN\`; bench2 retries needed for this baseline: **$RETRIES**.
- Successful zstd runs show high run-to-run variance (see per-run values in
  the throughput table).
- Each throughput algo is measured in its own bench2 process (3 runs each), so
  a retry never re-measures the healthy algos.
- Watch→push latency includes the daemon's fixed 700 ms change-settle debounce
  plus a full 3000-file rescan; poll granularity ≈ 50 ms.
EOF
cat "$BASELINE"

fi
say "DONE — baseline: $BASELINE   raw log: $RAWLOG"
