#!/usr/bin/env bash
# Cross-language interop matrix for the Krymux SDKs.
#
# Tests all 6 non-Rust language pairs DIRECTLY (the Rust-involving pairs are
# already covered by sdks/*/interop tests and are NOT re-run here):
#
#   ts→go  ts→py  go→ts  go→py  py→ts  py→go          (server→client)
#
# Per direction:
#   1. identities for BOTH peers are generated with the SERVER side's language
#      keygen (ts: sdks/typescript/scripts/xlang-tools.ts keygen, go:
#      examples/keygen, py: examples/keygen.py) into a shared dir using the
#      common <name>.key.pem / <name>.crt.pem / <name>.identity.json layout —
#      so the client side must cross-load the server language's PKCS#8 key and
#      certificate PEMs (that cross-load is itself part of the test);
#   2. the server starts with the client's fingerprint whitelisted (the Python
#      server additionally trusts the client certificate for the TLS
#      handshake; authorization stays fingerprint-whitelist-only);
#   3. the client pins the server's fingerprint, opens one stream, and echoes
#      >= 1 MiB (half random, half compressible), asserting a byte-exact
#      round-trip — once with compression "none" and once with "deflate";
#   4. processes are cleaned up with taskkill //F //T //PID on the exact PID
#      we spawned (no broad //IM kills).
#
# Readiness is a 250 ms TCP poll loop with early exit (no fixed sleeps).
# Output: one summary line per direction plus a final `matrix: N/6 passed`.
#
# Windows Git Bash:
#   ./scripts/xlang-matrix.sh

set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

BIN_DIR="target/xlang-matrix/bin"
RUN_BASE="target/xlang-matrix/runs"
TSX="sdks/typescript/node_modules/tsx/dist/cli.mjs"
NODE_BIN="${NODE_BIN:-node}"
PY_LAUNCHER="${XLANG_PY:-py}"
CLIENT_TIMEOUT_S=90
SERVER_READY_S=40

passed=0
failed=0
declare -a lines

log() { printf '%s\n' "$*"; }

# ---- process helpers ------------------------------------------------------

winpid_of() { # bash pid -> Windows pid (for taskkill)
  if [ -r "/proc/$1/winpid" ]; then cat "/proc/$1/winpid"; else echo "$1"; fi
}

kill_tree() { # kill_tree <bash pid> — kill exactly the tree we spawned
  [ -n "${1:-}" ] || return 0
  if kill -0 "$1" 2>/dev/null; then
    taskkill //F //T //PID "$(winpid_of "$1")" >/dev/null 2>&1 || kill -9 "$1" 2>/dev/null
    wait "$1" 2>/dev/null
  fi
}

run_timed() { # run_timed <timeout_s> <logfile> <cmd...>; rc 124 = timeout
  local tmo=$1 logf=$2
  shift 2
  "$@" >"$logf" 2>&1 &
  local pid=$!
  local deadline=$((SECONDS + tmo))
  while kill -0 "$pid" 2>/dev/null; do
    if [ "$SECONDS" -ge "$deadline" ]; then
      kill_tree "$pid"
      return 124
    fi
    sleep 0.2
  done
  wait "$pid"
}

wait_port() { # wait_port <host> <port> <timeout_s>: poll until TCP accepts
  "$NODE_BIN" -e '
    const net = require("net");
    const [host, port, tmo] = process.argv.slice(1);
    const deadline = Date.now() + Number(tmo) * 1000;
    (function attempt() {
      const s = net.connect({ host, port: Number(port) });
      s.once("connect", () => { s.destroy(); process.exit(0); });
      s.once("error", () => {
        s.destroy();
        if (Date.now() > deadline) { console.error("port never opened: " + host + ":" + port); process.exit(1); }
        else setTimeout(attempt, 250);
      });
    })();' "$1" "$2" "$3"
}

free_port() {
  "$NODE_BIN" -e 'const n=require("net");const s=n.createServer();s.listen(0,"127.0.0.1",()=>{console.log(s.address().port);s.close();});'
}

fp_of() { # fp_of <identity.json>: print the canonical fingerprint
  "$NODE_BIN" -e '
    const fs = require("fs");
    const o = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
    if (!/^sha256:[0-9a-f]{64}$/.test(o.fingerprint || "")) { console.error("bad identity json: " + process.argv[1]); process.exit(1); }
    console.log(o.fingerprint);' "$1"
}

tail_log() { # tail_log <file> <label> <n>
  if [ -f "$1" ]; then
    log "  --- $2 (last $3 lines of $1) ---"
    tail -n "$3" "$1" | sed 's/^/  | /'
  fi
}

# ---- per-language commands (all paths relative to repo root) ---------------

do_keygen() { # do_keygen <lang> <dir>
  case $1 in
    ts) "$NODE_BIN" "$TSX" sdks/typescript/scripts/xlang-tools.ts keygen --dir "$2" ;;
    go) "$BIN_DIR/keygen.exe" -dir "$2" ;;
    py) "$PY_LAUNCHER" sdks/python/examples/keygen.py --dir "$2" ;;
  esac
}

start_server() { # start_server <lang> <dir> <port> <client-fp> <logfile>; sets SRV_PID
  local lang=$1 dir=$2 port=$3 cfp=$4 logf=$5
  case $lang in
    ts)
      "$NODE_BIN" "$TSX" sdks/typescript/scripts/xlang-tools.ts server \
        --key "$dir/server.key.pem" --cert "$dir/server.crt.pem" \
        --allow "$cfp" --port "$port" >"$logf" 2>&1 &
      ;;
    go)
      "$BIN_DIR/echo-server.exe" -addr "127.0.0.1:$port" -identity "$dir" -allow "$cfp" >"$logf" 2>&1 &
      ;;
    py)
      "$PY_LAUNCHER" -u sdks/python/examples/echo_server.py \
        --listen "127.0.0.1:$port" \
        --key "$dir/server.key.pem" --cert "$dir/server.crt.pem" \
        --allow "$cfp" --trust-cert "$dir/client.crt.pem" >"$logf" 2>&1 &
      ;;
  esac
  SRV_PID=$!
}

run_client() { # run_client <lang> <dir> <port> <server-fp> <comp> <logfile>
  local lang=$1 dir=$2 port=$3 sfp=$4 comp=$5 logf=$6
  case $lang in
    ts)
      run_timed "$CLIENT_TIMEOUT_S" "$logf" \
        "$NODE_BIN" "$TSX" sdks/typescript/scripts/xlang-tools.ts client \
          --key "$dir/client.key.pem" --cert "$dir/client.crt.pem" \
          --fp "$sfp" --addr "127.0.0.1:$port" \
          --size 1048576 --compression "$comp"
      ;;
    go)
      run_timed "$CLIENT_TIMEOUT_S" "$logf" \
        "$BIN_DIR/echo-client.exe" -server "127.0.0.1:$port" -fp "$sfp" \
          -identity "$dir" -size 1048576 -compression "$comp" -pattern mix
      ;;
    py)
      run_timed "$CLIENT_TIMEOUT_S" "$logf" \
        "$PY_LAUNCHER" -u sdks/python/examples/echo_client.py \
          --addr "127.0.0.1:$port" \
          --key "$dir/client.key.pem" --cert "$dir/client.crt.pem" \
          --fp "$sfp" --size 1048576 --compression "$comp"
      ;;
  esac
}

client_ok() { # client_ok <lang> <logfile>: rc==0 already checked by caller
  case $1 in
    go) grep -q "byte-exact" "$2" ;;
    *)  grep -q "RESULT: OK" "$2" ;;
  esac
}

# ---- one matrix direction --------------------------------------------------

run_direction() { # run_direction <label> <server-lang> <client-lang>
  local label=$1 sl=$2 cl=$3
  local dir="$RUN_BASE/$label"
  rm -rf "$dir"
  mkdir -p "$dir"

  # 1. keygen with the SERVER side's language
  local kg_rc
  run_timed 60 "$dir/keygen.log" do_keygen "$sl" "$dir"
  kg_rc=$?
  if [ "$kg_rc" -ne 0 ]; then
    failed=$((failed + 1))
    lines+=("FAIL $label: $sl keygen failed rc=$kg_rc (see $dir/keygen.log)")
    tail_log "$dir/keygen.log" "$sl keygen" 15
    return
  fi
  local sfp cfp
  if ! sfp=$(fp_of "$dir/server.identity.json") || ! cfp=$(fp_of "$dir/client.identity.json"); then
    failed=$((failed + 1))
    lines+=("FAIL $label: cannot read fingerprints from $dir")
    return
  fi
  log "  [$label] keygen($sl): server ${sfp:0:19}... client ${cfp:0:19}..."

  # 2. start the server with the client's fingerprint whitelisted
  local port
  port=$(free_port)
  SRV_PID=""
  start_server "$sl" "$dir" "$port" "$cfp" "$dir/server.log"
  if ! wait_port 127.0.0.1 "$port" "$SERVER_READY_S"; then
    failed=$((failed + 1))
    lines+=("FAIL $label: $sl server never listened on 127.0.0.1:$port (see $dir/server.log)")
    tail_log "$dir/server.log" "$sl server" 15
    kill_tree "${SRV_PID:-}"
    return
  fi

  # 3. echo >= 1 MiB byte-exact with "none" and "deflate"
  local modes=()
  local comp rc
  for comp in none deflate; do
    if run_client "$cl" "$dir" "$port" "$sfp" "$comp" "$dir/client-$comp.log"; then
      if client_ok "$cl" "$dir/client-$comp.log"; then
        modes+=("$comp")
        continue
      fi
      rc=1 # verification marker missing
    else
      rc=$? # nonzero client exit (124 = watchdog timeout)
    fi
    failed=$((failed + 1))
    lines+=("FAIL $label ($comp): $cl client rc=$rc (see $dir/client-$comp.log, $dir/server.log)")
    tail_log "$dir/client-$comp.log" "$cl client ($comp)" 15
    tail_log "$dir/server.log" "$sl server" 15
    kill_tree "${SRV_PID:-}"
    return
  done

  # 4. clean up the tree we spawned
  kill_tree "${SRV_PID:-}"
  passed=$((passed + 1))
  lines+=("ok $label (${modes[0]}, ${modes[1]})")
  log "ok $label (${modes[0]}, ${modes[1]})"
}

# ---- build ------------------------------------------------------------------

log "xlang-matrix: building Go example binaries"
mkdir -p "$BIN_DIR" "$RUN_BASE"
if ! (cd sdks/golang && \
      go build -o ../../"$BIN_DIR"/echo-server.exe ./examples/echo-server && \
      go build -o ../../"$BIN_DIR"/echo-client.exe ./examples/echo-client && \
      go build -o ../../"$BIN_DIR"/keygen.exe ./examples/keygen); then
  log "matrix: 0/6 passed (go build failed)"
  exit 1
fi

# ---- the 6 non-Rust directions ----------------------------------------------

log "xlang-matrix: 6 directions, server→client, identities from the server language"

run_direction "ts→go" ts go
run_direction "ts→py" ts py
run_direction "go→ts" go ts
run_direction "go→py" go py
run_direction "py→ts" py ts
run_direction "py→go" py go

# ---- summary -----------------------------------------------------------------

log ""
for l in "${lines[@]}"; do log "$l"; done
log "matrix: $passed/6 passed"
[ "$passed" -eq 6 ] || exit 1
exit 0
