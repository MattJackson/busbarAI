#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# MEMORY under sustained load — pluggable across gateways. Adding a gateway = dropping a
# `gateways/<name>/gateway.sh` manifest (see gateways/README.md); this runner is gateway-agnostic.
#
# It records, on ONE box against ONE mock with ONE load profile:
#   * idle RSS      — resident memory right after the gateway answers 200, before any load
#   * peak RSS      — highest resident memory sampled during sustained load
#   * post-load RSS — resident memory ~15 s after load stops (does it release, or stay pinned?)
# and writes results/memory/<gateway>.json for the chart generator.
#
#   GATEWAY=busbar        BUSBAR_BIN=~/busbar   bench/memory/run.sh
#   GATEWAY=bifrost                             bench/memory/run.sh
#   GATEWAY=litellm-rust                        bench/memory/run.sh
#   GATEWAY=litellm-python                      bench/memory/run.sh
#
# Knobs (env): PSIZE (payload bytes, default 150000), CONC (default 1500), DUR (seconds, default 120),
#   CAP_MIB (watchdog ceiling — kills the load if RSS crosses it, default 40000), CORES (gateway pin).
# SAFETY: an unbounded gateway will OOM the box; the watchdog kills the load at CAP_MIB.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
GATEWAY="${GATEWAY:-busbar}"
export GW_DIR="$ROOT/gateways/$GATEWAY"
[ -f "$GW_DIR/gateway.sh" ] || { echo "unknown gateway '$GATEWAY' (no $GW_DIR/gateway.sh)"; exit 2; }

PSIZE="${PSIZE:-150000}"; CONC="${CONC:-1500}"; DUR="${DUR:-120}"; CAP_MIB="${CAP_MIB:-40000}"
export CORES="${CORES:-0-3}"; LOADCORES="${LOADCORES:-0-3}"; MOCKCORES="${MOCKCORES:-0-3}"
export MOCK_PORT="${MOCK_PORT:-8000}"
RESULTS="$ROOT/results/memory"; mkdir -p "$RESULTS"
log(){ echo "[$(date +%H:%M:%S)] $*"; }

# taskset may be absent (macOS); shim it to a no-op wrapper so the rig still runs locally.
command -v taskset >/dev/null || taskset(){ shift 2; "$@"; }

command -v go >/dev/null || { echo "need Go to build the mock + load gen"; exit 1; }
log "building mock + ugen"
go build -o "$HERE/mock" "$HERE/mock.go"
go build -o "$HERE/ugen" "$HERE/ugen.go"

# Source refs (branches/tags/versions) are pinned + overridable in ONE place, and recorded below.
# shellcheck source=/dev/null
[ -f "$ROOT/gateways/versions.env" ] && source "$ROOT/gateways/versions.env"
gw_version() { echo "unknown"; }  # default; the manifest below may override
GW_HEADERS=()  # a manifest may set extra request headers (e.g. Portkey routing, or a minted busbar vkey)
# shellcheck source=/dev/null
source "$GW_DIR/gateway.sh"

log "starting mock on :$MOCK_PORT"
pkill -f "$HERE/mock" 2>/dev/null; sleep 1
setsid taskset -c "$MOCKCORES" "$HERE/mock" -port "$MOCK_PORT" </dev/null >/dev/null 2>&1 &
sleep 1

cleanup(){ gw_stop 2>/dev/null; pkill -f "$HERE/mock" 2>/dev/null; }
trap cleanup EXIT

log "[$GATEWAY] build"; gw_build || { echo "build failed"; exit 1; }
log "[$GATEWAY] launch (pin $CORES, upstream mock :$MOCK_PORT)"; gw_launch
# Header arrays built AFTER launch so a manifest can mint a key in gw_launch (busbar vkey).
CURL_H=(); UGEN_H=()
for h in "${GW_HEADERS[@]:-}"; do [ -n "$h" ] && { CURL_H+=(-H "$h"); UGEN_H+=(-H "$h"); }; done

log "[$GATEWAY] waiting for 200 on $GW_PATH"
ok=0; c=000
for i in $(seq 1 60); do
  c=$(curl -s -m3 -o /dev/null -w "%{http_code}" "http://127.0.0.1:$GW_PORT$GW_PATH" \
      -X POST -H "content-type: application/json" -H "authorization: Bearer $GW_AUTH" "${CURL_H[@]}" \
      -d "{\"model\":\"$GW_MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"warm\"}],\"max_tokens\":16}")
  [ "$c" = "200" ] && { ok=1; break; }; sleep 1
done
[ "$ok" = 1 ] || log "[$GATEWAY] WARNING: never got 200 (last=$c) — recording anyway, served=false"
IDLE=$(gw_rss); log "[$GATEWAY] idle RSS: ${IDLE:-?} MiB (served=$([ "$ok" = 1 ] && echo true || echo false))"

# ── sampler + watchdog ──────────────────────────────────────────────────────────────────────────
PEAK=0; STOP=/tmp/mem.stop; rm -f "$STOP" /tmp/mem.peak; echo 0 >/tmp/mem.peak
( while [ ! -f "$STOP" ]; do
    v=$(gw_rss); [ -z "$v" ] && v=0
    awk -v v="$v" -v p="$PEAK" 'BEGIN{exit !(v+0>p+0)}' && { PEAK=$v; echo "$PEAK" >/tmp/mem.peak; }
    awk -v v="$v" -v c="$CAP_MIB" 'BEGIN{exit !(v+0>c+0)}' && { echo "[watchdog] $v MiB > cap $CAP_MIB — killing load"; pkill -x ugen; touch "$STOP"; }
    sleep 0.3
  done ) & SP=$!

log "[$GATEWAY] load: ${PSIZE}B payloads, c=$CONC, ${DUR}s (watchdog cap ${CAP_MIB} MiB)"
taskset -c "$LOADCORES" "$HERE/ugen" -url "http://127.0.0.1:$GW_PORT$GW_PATH" \
  -model "$GW_MODEL" -auth "$GW_AUTH" -c "$CONC" -d "$DUR" -psize "$PSIZE" "${UGEN_H[@]}" || true
touch "$STOP"; kill "$SP" 2>/dev/null
PEAK=$(cat /tmp/mem.peak)

log "[$GATEWAY] load stopped — waiting 15s to see if memory releases"
sleep 15
POST=$(gw_rss)

MEASURED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
HW="$(uname -m) $(nproc 2>/dev/null || echo '?')vCPU"
BUILD="$(gw_version 2>/dev/null | tr -d '\n' | sed 's/"/\\"/g')"
log "[$GATEWAY] built: $BUILD"
cat > "$RESULTS/$GATEWAY.json" <<JSON
{
  "gateway": "$GATEWAY",
  "build": "$BUILD",
  "served": $([ "$ok" = 1 ] && echo true || echo false),
  "idle_rss_mib": ${IDLE:-0},
  "peak_rss_mib": ${PEAK:-0},
  "post_load_rss_mib": ${POST:-0},
  "payload_bytes": $PSIZE,
  "concurrency": $CONC,
  "duration_s": $DUR,
  "endpoint": "$GW_PATH",
  "model": "$GW_MODEL",
  "hardware": "$HW",
  "measured_at": "$MEASURED_AT"
}
JSON

echo "================================================================"
echo " gateway=$GATEWAY  payload=${PSIZE}B  conc=$CONC  dur=${DUR}s"
echo "   idle RSS:      ${IDLE:-?} MiB"
echo "   PEAK RSS:      ${PEAK:-?} MiB   (under load)"
echo "   post-load RSS: ${POST:-?} MiB   (15s after load stops)"
echo " -> $RESULTS/$GATEWAY.json"
echo "================================================================"
