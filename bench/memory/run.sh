#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# MEMORY-under-sustained-big-payload benchmark — the honest reproduction of the "3.3 GB" story.
#
# Bifrost publishes a 3.34 GB peak-memory figure on its own benchmark. A SHORT, small-payload run
# (like a throughput sweep) never reproduces it — the pre-allocated pools don't fill, and a one-shot
# `docker stats` right after boot reports ~150 MB. That 150 MB is an artifact, not the peak.
#
# This rig fills the pools the way their own big-payload benchmark does: unique, LARGE request bodies
# (-psize bytes) at high concurrency, held for minutes, while sampling PEAK resident memory the whole
# time. Run it against Bifrost (its documented initial_pool_size 15000 / buffer_size 20000 config) and
# against Busbar, on the same box, same mock, same load.
#
# What we measured on a c7g.8xlarge (Graviton3, 16-core pin), Bifrost v1.6.4 / Busbar 1.4.0:
#   * Bifrost: memory grows WITHOUT BOUND. ~14.6 GB at 60 s with 150 KB payloads (still climbing),
#     ~44 GB with 300 KB payloads — well past its own published 3.34 GB — until we stopped it to keep
#     the 61 GB box from OOM-ing. The pooled buffers never release.
#   * Busbar: a BOUNDED plateau of ~1.1 GB under the identical 150 KB load (it's the in-flight working
#     set, not a leak) and it does not climb with time.
#
# SAFETY: a runaway gateway will OOM the box. This script runs a watchdog that KILLS the load the
# instant sampled memory crosses CAP_MIB, so an unbounded gateway can't take the machine down. Raise
# CAP_MIB to let it climb further; lower it to stay conservative.
#
# Usage:
#   GATEWAY=bifrost bench/memory/run.sh          # measure Bifrost (docker)
#   GATEWAY=busbar  BUSBAR_BIN=~/busbar bench/memory/run.sh
# Knobs (env): PSIZE (payload bytes, default 150000), CONC (default 1500), DUR (seconds, default 120),
#   CAP_MIB (watchdog ceiling, default 12000), CORES (gateway cpu pin, default 0-15).
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATEWAY="${GATEWAY:-bifrost}"
PSIZE="${PSIZE:-150000}"; CONC="${CONC:-1500}"; DUR="${DUR:-120}"; CAP_MIB="${CAP_MIB:-12000}"
CORES="${CORES:-0-15}"; LOADCORES="${LOADCORES:-16-27}"; MOCKCORES="${MOCKCORES:-28-31}"
MOCK_PORT=8000; GW_PORT=8080
log(){ echo "[$(date +%H:%M:%S)] $*"; }

command -v go >/dev/null || { echo "need Go to build the mock + load gen"; exit 1; }
log "building mock + ugen"
go build -o "$HERE/mock" "$HERE/mock.go"
go build -o "$HERE/ugen" "$HERE/ugen.go"

log "starting mock on cores $MOCKCORES"
pkill -f "$HERE/mock" 2>/dev/null; sleep 1
setsid taskset -c "$MOCKCORES" "$HERE/mock" -port "$MOCK_PORT" </dev/null >/dev/null 2>&1 &
sleep 1

# ── bring up the gateway under test ────────────────────────────────────────────────────────────────
if [ "$GATEWAY" = bifrost ]; then
  mkdir -p "$HERE/bfdata"; cp "$HERE/bf_config.json" "$HERE/bfdata/config.json"
  sudo docker rm -f bifrost >/dev/null 2>&1; sleep 1
  sudo docker run -d --name bifrost --network host --cpuset-cpus="$CORES" -e GOMAXPROCS="${CORES##*-}" \
    -v "$HERE/bfdata:/app/data" maximhq/bifrost:v1.6.4 >/dev/null 2>&1
  AUTH=sk-dummy
  rss(){ local m; m=$(sudo docker stats --no-stream --format '{{.MemUsage}}' bifrost 2>/dev/null | awk '{print $1}')
    case "$m" in *GiB) awk -v x="${m%GiB}" 'BEGIN{printf "%.1f",x*1024}';; *MiB) echo "${m%MiB}";; *) echo 0;; esac; }
else
  : "${BUSBAR_BIN:?set BUSBAR_BIN to the busbar binary}"
  pkill -x busbar 2>/dev/null; sleep 1
  setsid taskset -c "$CORES" env BUSBAR_WORKER_THREADS="$(( ${CORES##*-} + 1 ))" \
    BUSBAR_PROVIDERS="$HERE/bb.providers.yaml" BUSBAR_CONFIG="$HERE/bb.config.yaml" BENCH_MOCK_KEY=x \
    "$BUSBAR_BIN" </dev/null >/tmp/busbar.mem.log 2>&1 &
  AUTH=bench-token
  rss(){ awk '/VmRSS/{printf "%.1f", $2/1024}' "/proc/$(pgrep -x busbar)/status" 2>/dev/null; }
fi

log "waiting for $GATEWAY to answer 200"
for i in $(seq 1 40); do
  c=$(curl -s -m3 -o /dev/null -w "%{http_code}" http://127.0.0.1:$GW_PORT/v1/chat/completions \
      -X POST -H "content-type: application/json" -H "authorization: Bearer $AUTH" \
      -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"warm"}],"max_tokens":16}')
  [ "$c" = "200" ] && break; sleep 1
done
log "idle memory: $(rss) MiB"

# ── sampler + watchdog: track PEAK, and kill the load if it crosses CAP_MIB ──────────────────────────
PEAK=0; STOP=/tmp/mem.stop; rm -f "$STOP"
( while [ ! -f "$STOP" ]; do
    v=$(rss); [ -z "$v" ] && v=0
    awk -v v="$v" -v p="$PEAK" 'BEGIN{exit !(v+0>p+0)}' && PEAK=$v && echo "$PEAK" >/tmp/mem.peak
    awk -v v="$v" -v c="$CAP_MIB" 'BEGIN{exit !(v+0>c+0)}' && { echo "[watchdog] $v MiB > cap $CAP_MIB — killing load"; pkill -x ugen; touch "$STOP"; }
    sleep 0.3
  done ) & SP=$!

log "load: $GATEWAY, ${PSIZE}B payloads, c=$CONC, ${DUR}s (watchdog cap ${CAP_MIB} MiB)"
taskset -c "$LOADCORES" "$HERE/ugen" -url http://127.0.0.1:$GW_PORT/v1/chat/completions \
  -model gpt-4o-mini -auth "$AUTH" -c "$CONC" -d "$DUR" -psize "$PSIZE"
sleep 2; touch "$STOP"; kill "$SP" 2>/dev/null

echo "================================================================"
echo " gateway=$GATEWAY  payload=${PSIZE}B  conc=$CONC  dur=${DUR}s"
echo " PEAK RESIDENT MEMORY: $(cat /tmp/mem.peak) MiB"
echo "================================================================"
[ "$GATEWAY" = bifrost ] && sudo docker rm -f bifrost >/dev/null 2>&1
pkill -f "$HERE/mock" 2>/dev/null
