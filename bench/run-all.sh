#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# One command → answers. Runs the memory benchmark for every listed gateway on THIS box (same mock,
# same load, same pin), one at a time, then regenerates the chart from results/. Nothing to debug.
#
#   BUSBAR_BIN=~/busbar bench/run-all.sh                       # all gateways
#   BUSBAR_BIN=~/busbar bench/run-all.sh busbar litellm-rust   # a subset
#
# Each gateway is a drop-in dir under gateways/ (see gateways/README.md). Bifrost needs Docker;
# LiteLLM (Rust/Python) build from source/pip on first run.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATEWAYS=("$@")
[ ${#GATEWAYS[@]} -eq 0 ] && GATEWAYS=(busbar litellm-rust litellm-python bifrost portkey)
log(){ echo "[$(date +%H:%M:%S)] $*"; }

# Which suites to run (headline first): perf = latency + RPS ceiling; memory = idle/peak RSS.
SUITES="${SUITES:-perf memory}"
for gw in "${GATEWAYS[@]}"; do
  [ -f "$HERE/gateways/$gw/gateway.sh" ] || { log "skip unknown gateway '$gw'"; continue; }
  for suite in $SUITES; do
    log "══ $gw · $suite ══"
    GATEWAY="$gw" bash "$HERE/$suite/run.sh" || log "$gw $suite run failed (continuing)"
  done
done

log "regenerating charts"
if command -v python3 >/dev/null && python3 -c 'import matplotlib' 2>/dev/null; then
  python3 "$HERE/charts.py"
else
  log "matplotlib not present — results/memory/*.json written; run 'pip install matplotlib && python3 bench/charts.py' to draw"
fi
log "done — results/ + results/memory_rss.png"
