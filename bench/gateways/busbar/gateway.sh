#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Gateway manifest: Busbar (native single binary), busbar 1.5.0.
#
# Governance is ALWAYS-ON in 1.5.0, so we run it the intended way: the in-memory store plus one
# minted virtual key (a single hashmap lookup on the hot path — no TLS, no hooks, pure proxy
# overhead). We mint the key via the admin API at launch and send it as x-api-key. Needs BUSBAR_BIN.
GW_KIND=native
GW_PORT=8080
GW_ADMIN_PORT=8081
GW_PATH=/bench-pool/v1/chat/completions   # pool name is the path prefix; body model is ignored
GW_MODEL=bench-model
GW_AUTH=x                                   # unused (auth is the minted x-api-key header below)

gw_build() { : "${BUSBAR_BIN:?set BUSBAR_BIN to the busbar binary}"; }
gw_version() { "$BUSBAR_BIN" --version 2>/dev/null | head -1 || echo "busbar (working-tree)"; }

gw_launch() {
  cat > "$GW_DIR/config.gen.yaml" <<YAML
listen: "127.0.0.1:$GW_PORT"
admin_listen: "127.0.0.1:$GW_ADMIN_PORT"
observability:
  emit_server_timing: true
governance:
  store: memory
  admin_token: bench-admin
providers:
  mock:
    api_key_env: BENCH_MOCK_KEY
models:
  bench-model:
    provider: mock
    max_concurrent: 8000
    max_requests: -1
pools:
  bench-pool:
    members:
      - target: bench-model
YAML
  cat > "$GW_DIR/providers.gen.yaml" <<YAML
mock:
  protocol: openai
  base_url: http://127.0.0.1:$MOCK_PORT
  error_map: {}
YAML
  pkill -x busbar 2>/dev/null; sleep 1
  setsid taskset -c "$CORES" env \
    BUSBAR_WORKER_THREADS="$(( ${CORES##*-} + 1 ))" \
    BUSBAR_PROVIDERS="$GW_DIR/providers.gen.yaml" \
    BUSBAR_CONFIG="$GW_DIR/config.gen.yaml" \
    BENCH_MOCK_KEY=x \
    "$BUSBAR_BIN" </dev/null >/tmp/busbar.bench.log 2>&1 &
  # wait for the admin listener, then mint one virtual key and route requests with it
  for _ in $(seq 1 40); do curl -fsS -o /dev/null "http://127.0.0.1:$GW_ADMIN_PORT/health" 2>/dev/null && break; sleep 0.5; done
  local resp; resp="$(curl -s -X POST -H "x-admin-token: bench-admin" -H 'content-type: application/json' \
    -d '{"name":"bench"}' "http://127.0.0.1:$GW_ADMIN_PORT/api/v1/admin/keys" 2>/dev/null)"
  local key; key="$(printf '%s' "$resp" | python3 -c 'import sys,json;
try: print(json.load(sys.stdin).get("secret",""))
except Exception: print("")' 2>/dev/null)"
  if [ -n "$key" ]; then GW_HEADERS=("x-api-key: $key"); else echo "[busbar] WARN: no vkey minted (resp: ${resp:0:80})"; fi
}

gw_rss() { awk '/VmRSS/{printf "%.1f", $2/1024}' "/proc/$(pgrep -x busbar)/status" 2>/dev/null; }
gw_stop() { pkill -x busbar 2>/dev/null; }
