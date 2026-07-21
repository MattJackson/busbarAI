#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# LATENCY + THROUGHPUT — pluggable across gateways (same gateways/<name>/gateway.sh manifests as
# the memory suite). On ONE box against ONE instant mock, per gateway it measures:
#   * added latency (µs) at concurrency 1 = gateway p99 − direct-to-mock p99, small payloads
#   * RPS ceiling = the highest sustained requests/sec where p99 < 1000 ms AND zero errors
# and writes results/perf/<gateway>.json (+ a concurrency sweep for the latency-vs-load chart).
#
#   GATEWAY=busbar BUSBAR_BIN=~/busbar bench/perf/run.sh
#
# Knobs (env): C1_DUR (c1 latency run seconds, default 20), SWEEP ("1 8 16 32 64 128 256 512 1024"),
#   SWEEP_DUR (seconds per sweep point, default 10), PSIZE (payload bytes, default 256), CORES pin.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
MEM="$ROOT/memory"                              # reuse its mock.go + ugen.go
GATEWAY="${GATEWAY:-busbar}"
export GW_DIR="$ROOT/gateways/$GATEWAY"
[ -f "$GW_DIR/gateway.sh" ] || { echo "unknown gateway '$GATEWAY'"; exit 2; }

C1_DUR="${C1_DUR:-20}"; SWEEP_DUR="${SWEEP_DUR:-10}"; PSIZE="${PSIZE:-256}"
SWEEP="${SWEEP:-1 8 16 32 64 128 256 512 1024}"
P99_CEIL_MS="${P99_CEIL_MS:-1000}"
export CORES="${CORES:-0-3}"; LOADCORES="${LOADCORES:-0-3}"; MOCKCORES="${MOCKCORES:-0-3}"
export MOCK_PORT="${MOCK_PORT:-8000}"
RESULTS="$ROOT/results/perf"; mkdir -p "$RESULTS"
log(){ echo "[$(date +%H:%M:%S)] $*"; }
command -v taskset >/dev/null || taskset(){ shift 2; "$@"; }
command -v go >/dev/null || { echo "need Go"; exit 1; }

log "building mock + ugen"
go build -o "$MEM/mock" "$MEM/mock.go"; go build -o "$MEM/ugen" "$MEM/ugen.go"
MOCK="$MEM/mock"; UGEN="$MEM/ugen"

[ -f "$ROOT/gateways/versions.env" ] && source "$ROOT/gateways/versions.env"
gw_version(){ echo unknown; }; GW_HEADERS=()
# shellcheck source=/dev/null
source "$GW_DIR/gateway.sh"

log "starting mock :$MOCK_PORT (instant)"
pkill -f "$MOCK" 2>/dev/null; sleep 1
setsid taskset -c "$MOCKCORES" "$MOCK" -port "$MOCK_PORT" </dev/null >/dev/null 2>&1 &
sleep 1
cleanup(){ gw_stop 2>/dev/null; pkill -f "$MOCK" 2>/dev/null; }
trap cleanup EXIT

# run ugen, echo "rps fail p99us" parsed from its output line
probe(){ # url conc dur
  "$UGEN" -url "$1" -model "$GW_MODEL" -auth "$GW_AUTH" -c "$2" -d "$3" -psize "$PSIZE" "${UGEN_H[@]}" 2>/dev/null \
    | awk '{for(i=1;i<=NF;i++){split($i,a,"=");v[a[1]]=a[2]}; print v["rps"],v["fail"],v["p99us"],v["p50us"]}'
}

log "[$GATEWAY] build + launch"; gw_build || { echo "build failed"; exit 1; }; gw_launch
# Header arrays built AFTER launch so a manifest can mint a key in gw_launch (busbar vkey).
UGEN_H=(); CURL_H=()
for h in "${GW_HEADERS[@]:-}"; do [ -n "$h" ] && { UGEN_H+=(-H "$h"); CURL_H+=(-H "$h"); }; done
log "[$GATEWAY] wait 200 on $GW_PATH"; ok=0; c=000
for i in $(seq 1 60); do
  c=$(curl -s -m3 -o /dev/null -w "%{http_code}" "http://127.0.0.1:$GW_PORT$GW_PATH" -X POST \
      -H "content-type: application/json" -H "authorization: Bearer $GW_AUTH" "${CURL_H[@]}" \
      -d "{\"model\":\"$GW_MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"warm\"}],\"max_tokens\":16}")
  [ "$c" = 200 ] && { ok=1; break; }; sleep 1
done
[ "$ok" = 1 ] || log "[$GATEWAY] WARNING never got 200 (last=$c) — served=false"

# ── direct baseline (mock, same path/body) + gateway c1 → overhead µs ──────────────────────────────
DURL="http://127.0.0.1:$MOCK_PORT$GW_PATH"; GURL="http://127.0.0.1:$GW_PORT$GW_PATH"
log "[$GATEWAY] c1 baseline (direct→mock) ${C1_DUR}s"
read -r _drps _dfail DP99 DP50 < <(probe "$DURL" 1 "$C1_DUR")
log "[$GATEWAY] c1 gateway ${C1_DUR}s"
read -r _grps _gfail GP99 GP50 < <(probe "$GURL" 1 "$C1_DUR")
OVER_P99=$(( ${GP99:-0} - ${DP99:-0} )); OVER_P50=$(( ${GP50:-0} - ${DP50:-0} ))
log "[$GATEWAY] c1: gw p99=${GP99}µs direct p99=${DP99}µs → added p99=${OVER_P99}µs (p50 added=${OVER_P50}µs)"

# ── throughput ceiling: ramp concurrency, keep max sustained rps with p99<ceil AND 0 errors ────────
CEIL_RPS=0; CEIL_CONC=0; CEIL_P99=0; SWEEP_JSON=""
for conc in $SWEEP; do
  read -r rps fail p99 _p50 < <(probe "$GURL" "$conc" "$SWEEP_DUR")
  rps=${rps:-0}; fail=${fail:-1}; p99=${p99:-99999999}
  log "[$GATEWAY]   c=$conc → rps=$rps p99=$((p99/1000))ms fail=$fail"
  SWEEP_JSON="${SWEEP_JSON}${SWEEP_JSON:+,}{\"conc\":$conc,\"rps\":$rps,\"p99_us\":$p99,\"fail\":$fail}"
  if [ "$fail" -eq 0 ] && [ "$p99" -lt $((P99_CEIL_MS*1000)) ] && [ "$rps" -gt "$CEIL_RPS" ]; then
    CEIL_RPS=$rps; CEIL_CONC=$conc; CEIL_P99=$p99
  fi
done
log "[$GATEWAY] RPS ceiling = $CEIL_RPS rps @ c=$CEIL_CONC (p99 $((CEIL_P99/1000))ms, 0 errors)"

BUILD="$(gw_version 2>/dev/null | tr -d '\n' | sed 's/"/\\"/g')"
cat > "$RESULTS/$GATEWAY.json" <<JSON
{
  "gateway": "$GATEWAY",
  "build": "$BUILD",
  "served": $([ "$ok" = 1 ] && echo true || echo false),
  "added_latency_p50_us": $OVER_P50,
  "added_latency_p99_us": $OVER_P99,
  "gateway_c1_p99_us": ${GP99:-0},
  "direct_c1_p99_us": ${DP99:-0},
  "rps_ceiling": $CEIL_RPS,
  "rps_ceiling_concurrency": $CEIL_CONC,
  "rps_ceiling_p99_us": $CEIL_P99,
  "p99_ceiling_ms": $P99_CEIL_MS,
  "sweep": [$SWEEP_JSON],
  "payload_bytes": $PSIZE,
  "endpoint": "$GW_PATH",
  "model": "$GW_MODEL",
  "hardware": "$(uname -m) $(nproc 2>/dev/null || echo '?')vCPU",
  "measured_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
JSON
echo "================================================================"
echo " gateway=$GATEWAY   added latency p99=${OVER_P99}µs   RPS ceiling=${CEIL_RPS} @ c=${CEIL_CONC}"
echo " -> $RESULTS/$GATEWAY.json"
echo "================================================================"
