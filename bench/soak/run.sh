#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Busbar SOAK RIG — sustained load with leak/drift verdicts.
#
# Where bench/latency/ measures how FAST busbar is, this measures whether it STAYS that fast:
# drive continuous load (loadgen batches back-to-back) through busbar against the instant mock
# upstream for SOAK_MINUTES, sampling busbar's RSS between batches, then apply three verdicts:
#
#   1. ZERO ERRORS   — every batch completed with errors == 0 (no fd/socket/permit leak surfacing
#                      as late-run failures).
#   2. LATENCY DRIFT — the LAST batch's p99 must stay within DRIFT_FACTOR× the FIRST batch's p99
#                      (a leak that shows up as steadily-growing tail latency).
#   3. MEMORY DRIFT  — final RSS ≤ first-stable RSS × RSS_FACTOR + RSS_SLACK_MB (steady-state
#                      traffic must not grow the process without bound).
#
# Exit 0 = all verdicts pass. Non-zero = the failing verdict is printed.
#
# PRECONDITION: identical to bench/latency/run.sh — busbar's release binary only connects to the
# mock over publicly-trusted TLS on a non-loopback hostname (see bench/latency/README.md, "Serving
# the mock over trusted TLS"). The script probes the busbar->mock hop first and aborts with a clear
# message if it isn't serving 200s, rather than soaking a broken path.
#
# Usage:
#   bench/soak/run.sh                          # 10-minute soak, defaults below
#   SOAK_MINUTES=60 CONC=64 bench/soak/run.sh  # longer + heavier
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAT="$HERE/../latency"
REPO="$(cd "$HERE/../.." && pwd)"

SOAK_MINUTES="${SOAK_MINUTES:-10}"
BATCH_REQS="${BATCH_REQS:-5000}"
CONC="${CONC:-32}"
MOCK_PORT="${MOCK_PORT:-9001}"
BUSBAR_PORT="${BUSBAR_PORT:-8080}"
BENCH_TOKEN="bench-token"
DRIFT_FACTOR="${DRIFT_FACTOR:-3.0}"
RSS_FACTOR="${RSS_FACTOR:-1.25}"
RSS_SLACK_MB="${RSS_SLACK_MB:-50}"

PY="${PYTHON:-python3}"
RESULTS_DIR="$HERE/results"
mkdir -p "$RESULTS_DIR"
BATCHES="$RESULTS_DIR/batches.jsonl"
RSS_LOG="$RESULTS_DIR/rss.jsonl"
: > "$BATCHES"
: > "$RSS_LOG"

BIN="$REPO/target/release/busbar"
if [[ ! -x "$BIN" ]]; then
  echo ">> building busbar (release) ..."
  ( cd "$REPO" && cargo build --release )
fi

PIDS=()
cleanup() {
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
}
trap cleanup EXIT

wait_for_port() {  # host port
  for _ in $(seq 1 100); do
    if "$PY" - "$1" "$2" <<'EOF' 2>/dev/null
import socket,sys
s=socket.socket(); s.settimeout(0.2)
try:
    s.connect((sys.argv[1],int(sys.argv[2]))); sys.exit(0)
except Exception:
    sys.exit(1)
EOF
    then return 0; fi
    sleep 0.1
  done
  echo "!! timed out waiting for $1:$2" >&2; return 1
}

echo "== Busbar soak rig =="
echo "   binary  : $BIN"
echo "   duration: ${SOAK_MINUTES} min   batch: $BATCH_REQS reqs @ $CONC conc"
"$BIN" --version 2>/dev/null || true
uname -a
echo

# 1) instant mock upstream (delay=0 — soak stresses busbar, not the mock)
"$PY" "$LAT/mock_upstream.py" --port "$MOCK_PORT" --delay-ms 0 &
PIDS+=("$!")
wait_for_port 127.0.0.1 "$MOCK_PORT"

# 2) busbar over the latency bench's mock config (same provider/pool/token)
BUSBAR_PROVIDERS="$LAT/providers.mock.yaml" \
BUSBAR_CONFIG="$LAT/config.mock.yaml" \
BENCH_MOCK_KEY="x" \
  "$BIN" >"$RESULTS_DIR/busbar.log" 2>&1 &
BB_PID=$!
PIDS+=("$BB_PID")
if ! wait_for_port 127.0.0.1 "$BUSBAR_PORT"; then
  echo "!! Busbar did not open $BUSBAR_PORT. Its boot output:" >&2
  sed 's/^/!!   /' "$RESULTS_DIR/busbar.log" >&2 || true
  exit 1
fi

# 3) probe the busbar->mock hop before soaking (see PRECONDITION above)
PROBE=$(curl -s -o /dev/null -w '%{http_code}' \
  -H "Authorization: Bearer $BENCH_TOKEN" -H 'Content-Type: application/json' \
  -d '{"model":"mock-model","messages":[{"role":"user","content":"probe"}]}' \
  "http://127.0.0.1:$BUSBAR_PORT/v1/chat/completions" || echo 000)
if [[ "$PROBE" != "200" ]]; then
  echo "!! busbar->mock probe returned $PROBE (need 200). See bench/latency/README.md" >&2
  echo "!!   'Serving the mock over trusted TLS' — the release binary will not connect to a" >&2
  echo "!!   plain-http or self-signed loopback mock." >&2
  exit 1
fi

# 4) soak: back-to-back loadgen batches, RSS sample between each
END=$(( $(date +%s) + SOAK_MINUTES * 60 ))
BATCH=0
while (( $(date +%s) < END )); do
  BATCH=$((BATCH + 1))
  "$PY" "$LAT/loadgen.py" \
    --url "http://127.0.0.1:$BUSBAR_PORT" --mode full \
    --requests "$BATCH_REQS" --concurrency "$CONC" --warmup 0 \
    --token "$BENCH_TOKEN" --model mock-model \
    --label "batch-$BATCH" >> "$BATCHES"
  RSS_KB=$(ps -o rss= -p "$BB_PID" | tr -d ' ')
  echo "{\"batch\": $BATCH, \"ts\": $(date +%s), \"rss_kb\": ${RSS_KB:-0}}" >> "$RSS_LOG"
  echo "   batch $BATCH done (rss ${RSS_KB:-?} KB)"
done

# 5) verdicts
"$PY" "$HERE/verdict.py" \
  --batches "$BATCHES" --rss "$RSS_LOG" \
  --drift-factor "$DRIFT_FACTOR" --rss-factor "$RSS_FACTOR" --rss-slack-mb "$RSS_SLACK_MB"
