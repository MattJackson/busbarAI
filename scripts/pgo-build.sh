#!/usr/bin/env bash
# PGO build creator: produce a profile-guided-optimized busbar binary in three phases.
#
#   1. build instrumented      (-Cprofile-generate)
#   2. train on a traffic MIX  (openai chat + anthropic-ingress translation + SSE streaming,
#                               against an embedded zero-dependency mock upstream)
#   3. build optimized         (-Cprofile-use)
#
# This is the release build: the layout of the shipped binary is deliberate (profile-guided),
# not the linker's dice roll, and the profile regenerates fresh from THIS source tree on every
# run - nothing is checked in, nothing goes stale. Usage:
#
#   scripts/pgo-build.sh                # binary at target/pgo/release/busbar
#   PGO_REQS=5000 scripts/pgo-build.sh  # more training requests per traffic shape
#
# Knobs: PGO_REQS (per-shape request count, default 2000), PGO_STREAMS (streamed requests,
# default 200), PGO_PORT / PGO_MOCK_PORT (defaults 18080/18000). Requires: cargo, rustup
# (llvm-tools is installed on demand), python3, curl. The training mix mirrors the benchmark
# suites (perf / xlate / stream); keep the shapes in sync when the product grows a new hot path.
set -euo pipefail
cd "$(dirname "$0")/.."

REQS="${PGO_REQS:-2000}"
STREAMS="${PGO_STREAMS:-200}"
PORT="${PGO_PORT:-18080}"
MOCK_PORT="${PGO_MOCK_PORT:-18000}"
PROF_DIR="$(pwd)/target/pgo-profiles"
WORK="$(mktemp -d)"
cleanup() {
  pkill -P $$ 2>/dev/null || true
  [ -n "${BUSBAR_PID:-}" ] && kill "$BUSBAR_PID" 2>/dev/null || true
  [ -n "${MOCK_PID:-}" ] && kill "$MOCK_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT
log() { echo "[pgo-build] $*"; }

# ---- phase 1: instrumented build ------------------------------------------------------------
log "phase 1/3: instrumented build"
rm -rf "$PROF_DIR"; mkdir -p "$PROF_DIR"
RUSTFLAGS="-Cprofile-generate=$PROF_DIR" \
  cargo build --release -p busbar --target-dir target/pgo-gen

# ---- embedded mock upstream (zero deps: python3 stdlib) --------------------------------------
# Speaks just enough OpenAI chat-completions for training: fixed JSON reply, and a paced SSE
# stream when the request body carries "stream": true. Not a test double for correctness - a
# traffic generator's counterparty. The benchmark repo's mock is the real one; this exists so
# the release build has no external checkout dependency.
cat > "$WORK/mock.py" <<'PY'
import http.server, json, time, sys
PORT = int(sys.argv[1])
BODY = json.dumps({
    "id": "chatcmpl-pgo", "object": "chat.completion", "created": 0, "model": "gpt-4o-mini",
    "choices": [{"index": 0, "message": {"role": "assistant", "content": "profile training reply"},
                  "finish_reason": "stop"}],
    "usage": {"prompt_tokens": 12, "completion_tokens": 5, "total_tokens": 17},
}).encode()
CHUNK = ('data: ' + json.dumps({"id": "chatcmpl-pgo", "object": "chat.completion.chunk",
         "created": 0, "model": "gpt-4o-mini",
         "choices": [{"index": 0, "delta": {"content": "tok "}, "finish_reason": None}]}) + '\n\n').encode()
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *a): pass
    def do_POST(self):
        n = int(self.headers.get("content-length", 0))
        body = self.rfile.read(n)
        if b'"stream": true' in body or b'"stream":true' in body:
            self.send_response(200)
            self.send_header("content-type", "text/event-stream")
            self.send_header("transfer-encoding", "chunked")
            self.end_headers()
            def w(b):
                self.wfile.write(f"{len(b):x}\r\n".encode() + b + b"\r\n")
            for _ in range(16):
                w(CHUNK); self.wfile.flush(); time.sleep(0.005)
            w(b"data: [DONE]\n\n"); w(b""); self.wfile.flush()
        else:
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(BODY)))
            self.end_headers()
            self.wfile.write(BODY)
class S(http.server.ThreadingHTTPServer):
    daemon_threads = True
S(("127.0.0.1", PORT), H).serve_forever()
PY

# ---- busbar training config (mirrors the benchmark manifest's shape) -------------------------
cat > "$WORK/config.yaml" <<YAML
listen: "127.0.0.1:$PORT"
admin_listen: "127.0.0.1:$((PORT + 1))"
observability:
  emit_server_timing: true
auth:
  chain: [tokens]
  upstream_credentials: own
  client_tokens:
    - "pgo-token"
providers:
  mock:
    api_key_env: PGO_MOCK_KEY
models:
  gpt-4o-mini:
    provider: mock
    max_concurrent: 512
    max_requests: -1
pools:
  bench-pool:
    members:
      - target: gpt-4o-mini
YAML
cat > "$WORK/providers.yaml" <<YAML
mock:
  protocol: openai
  base_url: http://127.0.0.1:$MOCK_PORT
  error_map: {}
YAML

# ---- phase 2: train --------------------------------------------------------------------------
log "phase 2/3: training ($REQS reqs x 3 shapes + $STREAMS streams)"
python3 "$WORK/mock.py" "$MOCK_PORT" & MOCK_PID=$!
BUSBAR_CONFIG="$WORK/config.yaml" BUSBAR_PROVIDERS="$WORK/providers.yaml" PGO_MOCK_KEY=x \
  ./target/pgo-gen/release/busbar & BUSBAR_PID=$!
for _ in $(seq 1 50); do
  curl -sf -o /dev/null "http://127.0.0.1:$PORT/healthz" && break; sleep 0.2
done

OPENAI_BODY='{"model":"gpt-4o-mini","messages":[{"role":"user","content":"profile training request with a moderately sized body to exercise the parser"}]}'
ANTH_BODY='{"model":"gpt-4o-mini","max_tokens":64,"messages":[{"role":"user","content":"profile training request for the translation path"}]}'
STREAM_BODY='{"model":"gpt-4o-mini","stream":true,"messages":[{"role":"user","content":"streaming profile training"}]}'

# shape 1: openai chat passthrough (the volume path)
seq 1 "$REQS" | xargs -P 8 -I{} curl -s -o /dev/null -X POST "http://127.0.0.1:$PORT/v1/chat/completions" \
  -H "content-type: application/json" -H "authorization: Bearer pgo-token" -d "$OPENAI_BODY"
log "  shape 1 (openai chat) done"
# shape 2: anthropic ingress -> openai upstream (the translation path)
seq 1 "$REQS" | xargs -P 8 -I{} curl -s -o /dev/null -X POST "http://127.0.0.1:$PORT/v1/messages" \
  -H "content-type: application/json" -H "anthropic-version: 2023-06-01" \
  -H "authorization: Bearer pgo-token" -d "$ANTH_BODY"
log "  shape 2 (anthropic translation) done"
# shape 3: SSE streaming relay
seq 1 "$STREAMS" | xargs -P 8 -I{} curl -s -o /dev/null -X POST "http://127.0.0.1:$PORT/v1/chat/completions" \
  -H "content-type: application/json" -H "authorization: Bearer pgo-token" -d "$STREAM_BODY"
log "  shape 3 (SSE streaming) done"

# graceful stop so the runtime flushes .profraw files
kill "$BUSBAR_PID"; wait "$BUSBAR_PID" 2>/dev/null || true; BUSBAR_PID=""
kill "$MOCK_PID" 2>/dev/null || true; MOCK_PID=""

# ---- phase 3: merge + optimized build --------------------------------------------------------
log "phase 3/3: merge profiles + optimized build"
rustup component add llvm-tools >/dev/null 2>&1 || true
PROFDATA="$(find "$(rustc --print sysroot)" -name llvm-profdata -type f | head -1)"
[ -n "$PROFDATA" ] || { echo "[pgo-build] llvm-profdata not found (rustup component add llvm-tools)"; exit 1; }
"$PROFDATA" merge -o "$PROF_DIR/merged.profdata" "$PROF_DIR"/*.profraw
RUSTFLAGS="-Cprofile-use=$PROF_DIR/merged.profdata" \
  cargo build --release -p busbar --target-dir target/pgo

log "done: target/pgo/release/busbar (profile: $PROF_DIR/merged.profdata)"
