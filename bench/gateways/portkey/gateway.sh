#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Gateway manifest: Portkey OSS gateway (npx @portkey-ai/gateway).
#
# Routes to the mock via Portkey's own headers: x-portkey-provider + x-portkey-custom-host
# (the same way AIGatewayBench drives it). Anthropic Messages path.
GW_KIND=native
GW_PORT=8787
GW_PATH=/v1/messages
GW_MODEL=anthropic/mock
GW_AUTH=dummy
# PORTKEY_SPEC comes from gateways/versions.env.
GW_HEADERS=(
  "x-portkey-provider: anthropic"
  "x-portkey-custom-host: http://127.0.0.1:${MOCK_PORT:-8000}/v1"
)

gw_build() { command -v npx >/dev/null || { echo "need node/npx for portkey"; return 1; }; }

gw_launch() {
  pkill -f '@portkey-ai/gateway' 2>/dev/null; sleep 1
  setsid taskset -c "$CORES" npx -y "${PORTKEY_SPEC:-@portkey-ai/gateway}" \
    </dev/null >/tmp/portkey.mem.log 2>&1 &
}

_pk_pid() { ss -ltnpH "sport = :$GW_PORT" 2>/dev/null | grep -o 'pid=[0-9]*' | head -1 | cut -d= -f2; }
gw_rss() {
  local pid total=0 kb; pid="$(_pk_pid)"; [ -z "$pid" ] && { echo 0; return; }
  # node + any workers under the same process group
  for p in $pid $(pgrep -P "$pid" 2>/dev/null); do
    kb=$(awk '/VmRSS/{print $2}' "/proc/$p/status" 2>/dev/null); total=$((total + ${kb:-0}))
  done
  awk -v k="$total" 'BEGIN{printf "%.1f", k/1024}'
}
gw_version() { npm view "${PORTKEY_SPEC:-@portkey-ai/gateway}" version 2>/dev/null | sed 's/^/@portkey-ai\/gateway@/' || echo "@portkey-ai/gateway (npx latest)"; }
gw_stop() { pkill -f '@portkey-ai/gateway' 2>/dev/null; }
