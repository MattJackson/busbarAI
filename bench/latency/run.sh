#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Matthew Jackson
#
# Reproducible Busbar added-latency benchmark — mock-upstream mode.
#
# Measures the DELTA between two paths against the SAME fixed-latency mock upstream:
#   * direct : loadgen -> mock_upstream            (baseline)
#   * busbar : loadgen -> busbar -> mock_upstream  (baseline + Busbar overhead)
# The difference per percentile = Busbar's added overhead. Reported for:
#   * full  : non-streaming whole-response latency
#   * ttft  : streaming time-to-first-byte
#
# Two upstream delays:
#   * delay=0   isolates pure Busbar overhead (mock contributes ~0 on both paths)
#   * delay=200 shows the same overhead against realistic provider latency (jitter context)
#
# Everything runs locally. No real provider, no real key, no network egress.
#
# ── PRECONDITION (read this) ───────────────────────────────────────────────────────────────────────
# Busbar's RELEASE binary trusts ONLY the compiled-in Mozilla (webpki) root set for UPSTREAM TLS
# (reqwest `rustls-tls`, webpki-roots; no OS store, no SSL_CERT_FILE, no insecure knob — a deliberate
# security stance, see Cargo.toml). It ALSO requires every provider `base_url` to be `https://` and
# rejects loopback/RFC-1918 hosts at startup (SSRF guard, config_validate.rs). Consequence: a plain
# local mock over http://127.0.0.1 cannot be reached, and a self-signed HTTPS mock is not trusted.
# So `mock-upstream mode` (this script) only completes its busbar->mock hop when the mock is served
# over TLS with a cert chained to a PUBLIC CA, on a non-loopback hostname Busbar's SSRF guard allows
# (e.g. `localtest.me`, which resolves to 127.0.0.1). See README.md "Serving the mock over trusted
# TLS". Without that, run `mode 2` (a real provider over HTTPS) — see README.md.
# The script detects when the busbar->mock hop fails and tells you, rather than emitting bad numbers.
#
# Usage:
#   bench/latency/run.sh                 # default: REQS=20000 CONC=50, delays 0 and 200
#   REQS=50000 CONC=100 bench/latency/run.sh
#   DELAYS="0" bench/latency/run.sh       # just the pure-overhead pass
#
# Requires: a release busbar binary (the script builds it if missing), python3, bash.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"

REQS="${REQS:-20000}"
CONC="${CONC:-50}"
WARMUP="${WARMUP:-2000}"
DELAYS="${DELAYS:-0 200}"
MOCK_PORT="${MOCK_PORT:-9001}"
BUSBAR_PORT="${BUSBAR_PORT:-8080}"
BENCH_TOKEN="bench-token"

PY="${PYTHON:-python3}"
RESULTS_DIR="$HERE/results"
mkdir -p "$RESULTS_DIR"
RESULTS="$RESULTS_DIR/results.jsonl"
: > "$RESULTS"

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

echo "== Busbar latency benchmark =="
echo "   binary : $BIN"
echo "   reqs   : $REQS   concurrency: $CONC   warmup: $WARMUP"
echo "   delays : $DELAYS ms"
"$BIN" --version 2>/dev/null || true
uname -a
echo

run_pass() {   # delay_ms
  local delay="$1"
  echo "---- upstream delay = ${delay}ms ----"

  # 1) start the mock upstream
  "$PY" "$HERE/mock_upstream.py" --port "$MOCK_PORT" --delay-ms "$delay" &
  local mock_pid=$!; PIDS+=("$mock_pid")
  wait_for_port 127.0.0.1 "$MOCK_PORT"

  # 2) start busbar pointed at the mock
  BUSBAR_PROVIDERS="$HERE/providers.mock.yaml" \
  BUSBAR_CONFIG="$HERE/config.mock.yaml" \
  BENCH_MOCK_KEY="x" \
    "$BIN" >"$RESULTS_DIR/busbar.${delay}ms.log" 2>&1 &
  local bb_pid=$!; PIDS+=("$bb_pid")
  if ! wait_for_port 127.0.0.1 "$BUSBAR_PORT"; then
    echo "!! Busbar did not open $BUSBAR_PORT. Its boot output:" >&2
    sed 's/^/!!   /' "$RESULTS_DIR/busbar.${delay}ms.log" >&2 || true
    echo "!! If this is a 'base_url must use https' / 'blocked internal host' error, that is the" >&2
    echo "!! PRECONDITION at the top of this script: the release binary will not talk to a plain" >&2
    echo "!! or self-signed local mock. See README.md 'Serving the mock over trusted TLS' or use" >&2
    echo "!! Mode 2 (a real provider). NOT emitting numbers." >&2
    kill "$mock_pid" 2>/dev/null || true
    return 2
  fi

  # Reachability gate: confirm the busbar->mock hop actually works before measuring. If Busbar
  # cannot reach the mock (the webpki-roots upstream-TLS constraint above), it returns a 5xx
  # "overloaded" instead of the canned 200 — measuring that would produce meaningless numbers.
  local probe
  probe=$(curl -s -o /dev/null -w '%{http_code}' -m 5 \
    -H "Authorization: Bearer $BENCH_TOKEN" -H "Content-Type: application/json" \
    -d '{"model":"bench-pool","messages":[{"role":"user","content":"ping"}],"max_tokens":8}' \
    "http://127.0.0.1:$BUSBAR_PORT/v1/chat/completions" || echo "000")
  if [[ "$probe" != "200" ]]; then
    echo "!! busbar->mock hop returned HTTP $probe (expected 200)." >&2
    echo "!! Busbar likely cannot reach the mock upstream over trusted TLS — see the PRECONDITION" >&2
    echo "!! block at the top of this script and README.md. NOT emitting numbers (would be invalid)." >&2
    echo "!! busbar log: $RESULTS_DIR/busbar.${delay}ms.log" >&2
    kill "$bb_pid" 2>/dev/null || true; kill "$mock_pid" 2>/dev/null || true
    return 3
  fi

  local m
  for mode in full ttft; do
    # direct: loadgen -> mock
    "$PY" "$HERE/loadgen.py" --url "http://127.0.0.1:$MOCK_PORT" \
      --mode "$mode" --requests "$REQS" --concurrency "$CONC" --warmup "$WARMUP" \
      --model bench-model --label "direct/${mode}/${delay}ms" | tee -a "$RESULTS"
    # busbar: loadgen -> busbar -> mock
    "$PY" "$HERE/loadgen.py" --url "http://127.0.0.1:$BUSBAR_PORT" \
      --mode "$mode" --requests "$REQS" --concurrency "$CONC" --warmup "$WARMUP" \
      --token "$BENCH_TOKEN" --model bench-pool --label "busbar/${mode}/${delay}ms" | tee -a "$RESULTS"
  done

  kill "$bb_pid" 2>/dev/null || true
  kill "$mock_pid" 2>/dev/null || true
  wait "$bb_pid" 2>/dev/null || true
  wait "$mock_pid" 2>/dev/null || true
  echo
}

passes_ok=0
for d in $DELAYS; do
  if run_pass "$d"; then
    passes_ok=$((passes_ok + 1))
  fi
done

if [[ "$passes_ok" -eq 0 ]]; then
  echo
  echo "== No pass produced busbar-path numbers (see messages above). ==" >&2
  echo "== The harness and mock are fine; the busbar->mock hop could not run here. ==" >&2
  echo "== Fill the docs table by running in an environment that satisfies the PRECONDITION. ==" >&2
  exit 4
fi

echo "== Computing deltas (busbar - direct) =="
"$PY" "$HERE/report.py" "$RESULTS"
echo
echo "Raw per-run JSON: $RESULTS"
