#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Matthew Jackson
#
# Reproducible Busbar added-latency benchmark — REAL-provider (Anthropic) mode.
#
# Measures the per-percentile DELTA between two paths that hit the SAME Anthropic model:
#   direct : loadgen ───────────────► api.anthropic.com      (baseline, x-api-key)
#   busbar : loadgen ──► busbar ─────► api.anthropic.com      (baseline + Busbar overhead)
# Anthropic's latency is in BOTH paths and cancels in the delta, so `busbar − direct` per percentile
# is Busbar's added overhead — measured against real provider jitter. Reported for:
#   full : non-streaming whole-response latency
#   ttft : streaming time-to-first-byte
#
# No local mock and no TLS gymnastics: the release binary already trusts api.anthropic.com's public
# cert, so the busbar->upstream hop just works.
#
# COST + RATE LIMITS: this calls a real API and spends real tokens. Load is intentionally MODEST
# (max_tokens=16 "ping"). Defaults: REQS=300 CONC=4. Tune up only if you accept the cost/limits.
#
# Requires: ANTHROPIC_API_KEY in the env, a busbar binary (release), python3, bash, curl.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"

: "${ANTHROPIC_API_KEY:?set ANTHROPIC_API_KEY (your Anthropic API key) before running}"

REQS="${REQS:-300}"
CONC="${CONC:-4}"
WARMUP="${WARMUP:-20}"
MODEL="${MODEL:-claude-haiku-4-5-20251001}"   # must match the model key in config.anthropic.yaml
BUSBAR_PORT="${BUSBAR_PORT:-8080}"
BENCH_TOKEN="bench-token"
PY="${PYTHON:-python3}"

# Locate a busbar binary: explicit override, ./busbar (install.sh drop), release build, or PATH.
if [[ -n "${BUSBAR_BIN:-}" && -x "${BUSBAR_BIN:-}" ]]; then BIN="$BUSBAR_BIN"
elif [[ -x "$REPO/busbar" ]]; then BIN="$REPO/busbar"
elif [[ -x "$REPO/target/release/busbar" ]]; then BIN="$REPO/target/release/busbar"
elif command -v busbar >/dev/null 2>&1; then BIN="$(command -v busbar)"
else echo "!! no busbar binary found (set BUSBAR_BIN, or 'curl -fsSL https://getbusbar.com/install.sh | sh')" >&2; exit 1
fi

RESULTS_DIR="$HERE/results"
mkdir -p "$RESULTS_DIR"
RESULTS="$RESULTS_DIR/results.anthropic.jsonl"
: > "$RESULTS"

echo "== Busbar added-latency benchmark — Anthropic (real provider) =="
echo "   binary : $BIN"
echo "   model  : $MODEL"
echo "   reqs   : $REQS   concurrency: $CONC   warmup: $WARMUP"
"$BIN" --version 2>/dev/null || true
uname -a
echo

PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

wait_for_port() {  # host port
  for _ in $(seq 1 100); do
    if "$PY" - "$1" "$2" <<'EOF' 2>/dev/null
import socket,sys
s=socket.socket(); s.settimeout(0.2)
try: s.connect((sys.argv[1],int(sys.argv[2]))); sys.exit(0)
except Exception: sys.exit(1)
EOF
    then return 0; fi
    sleep 0.1
  done
  echo "!! timed out waiting for $1:$2" >&2; return 1
}

# Start busbar pointed at Anthropic.
BUSBAR_PROVIDERS="$HERE/providers.anthropic.yaml" \
BUSBAR_CONFIG="$HERE/config.anthropic.yaml" \
ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY" \
  "$BIN" >"$RESULTS_DIR/busbar.anthropic.log" 2>&1 &
BB_PID=$!; PIDS+=("$BB_PID")
if ! wait_for_port 127.0.0.1 "$BUSBAR_PORT"; then
  echo "!! Busbar did not open $BUSBAR_PORT. Boot output:" >&2
  sed 's/^/!!   /' "$RESULTS_DIR/busbar.anthropic.log" >&2 || true
  exit 2
fi

# Reachability gate: one real busbar->Anthropic request must return 200 before we measure, so a bad
# key or upstream error surfaces clearly instead of as garbage numbers.
probe=$(curl -s -o /dev/null -w '%{http_code}' -m 30 \
  -H "Authorization: Bearer $BENCH_TOKEN" -H "Content-Type: application/json" \
  -H "anthropic-version: 2023-06-01" \
  -d "{\"model\":\"bench-pool\",\"max_tokens\":8,\"messages\":[{\"role\":\"user\",\"content\":\"ping\"}]}" \
  "http://127.0.0.1:$BUSBAR_PORT/v1/messages" || echo "000")
if [[ "$probe" != "200" ]]; then
  echo "!! busbar->Anthropic probe returned HTTP $probe (expected 200)." >&2
  echo "!! Check ANTHROPIC_API_KEY and that the model id is valid. busbar log:" >&2
  sed 's/^/!!   /' "$RESULTS_DIR/busbar.anthropic.log" >&2 || true
  exit 3
fi
echo ">> busbar->Anthropic reachable (200). Measuring…"
echo

for mode in full ttft; do
  # direct: loadgen -> api.anthropic.com  (x-api-key baseline)
  "$PY" "$HERE/loadgen.py" --url "https://api.anthropic.com" --path /v1/messages --api anthropic \
    --mode "$mode" --requests "$REQS" --concurrency "$CONC" --warmup "$WARMUP" \
    --header "x-api-key: $ANTHROPIC_API_KEY" --model "$MODEL" --label "direct/${mode}/real" | tee -a "$RESULTS"
  # busbar: loadgen -> busbar -> api.anthropic.com
  "$PY" "$HERE/loadgen.py" --url "http://127.0.0.1:$BUSBAR_PORT" --path /v1/messages --api anthropic \
    --mode "$mode" --requests "$REQS" --concurrency "$CONC" --warmup "$WARMUP" \
    --token "$BENCH_TOKEN" --model bench-pool --label "busbar/${mode}/real" | tee -a "$RESULTS"
done

echo
echo "== Computing deltas (busbar − direct) =="
"$PY" "$HERE/report.py" "$RESULTS"
echo
echo "Raw per-run JSON: $RESULTS"
