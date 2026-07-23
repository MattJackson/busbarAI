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
#   PGO_TARGET=x86_64-unknown-linux-musl scripts/pgo-build.sh
#                                       # cargo --target build; binary at
#                                       # target/pgo/<target>/release/busbar. The instrumented
#                                       # binary must be host-executable (native-arch runners;
#                                       # musl-static runs fine on its build host) - if it
#                                       # isn't, PGO cannot train and the build FAILS (see below).
#
# FAIL-CLOSED RULE: PGO is MANDATORY for every release. If ANY pgo phase fails (instrumented
# build, training run producing no .profraw, profile merge, or the optimized build), the script
# logs LOUDLY why and exits NON-ZERO. It NEVER falls back to a plain `cargo build --release`:
# a release that cannot be PGO-built must fail, not silently ship a non-optimized binary.
#
# On success the binary lands at the SAME deterministic path, echoed on the last line:
#
#   target/pgo/release/busbar                 (no PGO_TARGET)
#   target/pgo/<PGO_TARGET>/release/busbar    (with PGO_TARGET)
#
# POSITIVE PGO PROOF: on success the script writes a marker file next to the binary,
#   target/pgo/<seg>release/busbar.pgo-verified
# recording the merged .profdata path, its byte size, and the .profraw count that fed it. The
# marker is written ONLY after the optimized (-Cprofile-use) build succeeds and only when the
# merged profile is non-empty, so its presence is proof the shipped binary was PGO-optimized.
# The workflow asserts this marker exists and is non-trivial before shipping, so it is impossible
# to ship a non-PGO binary and pass. Every fatal exit removes any stale marker first.
#
# Knobs: PGO_REQS (per-shape request count, default 2000), PGO_STREAMS (streamed requests,
# default 200), PGO_PORT / PGO_MOCK_PORT (defaults 18080/18000), PGO_TARGET (cargo --target).
# Requires: cargo, rustup (llvm-tools is installed on demand), python3, curl. The training mix
# mirrors the benchmark suites (perf / xlate / stream); keep the shapes in sync when the
# product grows a new hot path.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

REQS="${PGO_REQS:-2000}"
STREAMS="${PGO_STREAMS:-200}"
PORT="${PGO_PORT:-18080}"
MOCK_PORT="${PGO_MOCK_PORT:-18000}"
TARGET="${PGO_TARGET:-}"
# Unquoted on use (deliberate - a target triple has no spaces); empty = no --target flag,
# which keeps the historical no-target behavior byte-identical.
TARGET_FLAG="${TARGET:+--target $TARGET}"
# The target-triple path segment cargo inserts under --target-dir when --target is used.
TARGET_SEG="${TARGET:+$TARGET/}"
# THE deterministic output path (see fail-closed rule above).
OUT="target/pgo/${TARGET_SEG}release/busbar"
# Positive-proof marker: written only after a verified PGO build; the workflow gates on it.
MARKER="$OUT.pgo-verified"
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

# The fail-closed arm: log LOUDLY why PGO could not complete and exit NON-ZERO. NEVER fall back
# to a plain build - a release that cannot be PGO-built must fail rather than silently ship a
# non-optimized binary. Removes any stale proof marker so a prior run's marker can never be
# mistaken for this run's (the workflow gates on the marker).
pgo_fail() {
  echo "[pgo-build] ############################################################" >&2
  echo "[pgo-build] # PGO FAILED (FAIL-CLOSED): $*" >&2
  echo "[pgo-build] # PGO is MANDATORY for releases - refusing to ship a non-PGO binary." >&2
  echo "[pgo-build] # This build is BLOCKED. Fix the cause above and re-run; do NOT bypass" >&2
  echo "[pgo-build] # by disabling PGO. Common causes: instrumented binary not host-executable" >&2
  echo "[pgo-build] # (cross target), llvm-tools missing, or the trainer crashing/timing out." >&2
  echo "[pgo-build] ############################################################" >&2
  rm -f "$MARKER" 2>/dev/null || true
  # Stop any training processes a mid-phase failure left behind.
  [ -n "${BUSBAR_PID:-}" ] && kill "$BUSBAR_PID" 2>/dev/null || true
  [ -n "${MOCK_PID:-}" ] && kill "$MOCK_PID" 2>/dev/null || true
  BUSBAR_PID=""; MOCK_PID=""
  exit 1
}

# Any stale marker from a previous run must never survive into a fresh run: drop it up front so
# its presence at the end is proof of THIS run's success (belt-and-suspenders with pgo_fail).
rm -f "$MARKER" 2>/dev/null || true

# ---- phase 1: instrumented build ------------------------------------------------------------
log "phase 1/3: instrumented build"
rm -rf "$PROF_DIR"; mkdir -p "$PROF_DIR"
RUSTFLAGS="-Cprofile-generate=$PROF_DIR" \
  cargo build --release -p busbar $TARGET_FLAG --target-dir target/pgo-gen \
  || pgo_fail "instrumented build failed"
INSTRUMENTED="target/pgo-gen/${TARGET_SEG}release/busbar"
[ -x "$INSTRUMENTED" ] || pgo_fail "instrumented binary missing at $INSTRUMENTED"

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
# Training runs against a local mock with the open front door (empty chain): the static-token
# module was removed in 1.5.0 and signed-key minting is pointless for a throwaway trainer.
auth:
  chain: []
  upstream_credentials: own
providers:
  mock:
    api_key: { env: PGO_MOCK_KEY }
models:
  gpt-4o-mini:
    provider: mock
    max_concurrent: 512
    max_requests: -1
pools:
  bench-pool:
    members:
      - model: gpt-4o-mini
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
  "./$INSTRUMENTED" & BUSBAR_PID=$!
for _ in $(seq 1 50); do
  curl -sf -o /dev/null "http://127.0.0.1:$PORT/healthz" && break; sleep 0.2
done
# The instrumented binary must actually be serving (it may not even be host-executable under a
# cross PGO_TARGET) - a dead trainer means no profile, so fail open now rather than merge-fail.
curl -sf -o /dev/null "http://127.0.0.1:$PORT/healthz" \
  || pgo_fail "instrumented busbar never became healthy (not host-executable, or crashed)"

OPENAI_BODY='{"model":"gpt-4o-mini","messages":[{"role":"user","content":"profile training request with a moderately sized body to exercise the parser"}]}'
ANTH_BODY='{"model":"gpt-4o-mini","max_tokens":64,"messages":[{"role":"user","content":"profile training request for the translation path"}]}'
STREAM_BODY='{"model":"gpt-4o-mini","stream":true,"messages":[{"role":"user","content":"streaming profile training"}]}'

# shape 1: openai chat passthrough (the volume path)
seq 1 "$REQS" | xargs -P 8 -I{} curl -s -o /dev/null -X POST "http://127.0.0.1:$PORT/v1/chat/completions" \
  -H "content-type: application/json" -H "authorization: Bearer pgo-token" -d "$OPENAI_BODY" \
  || pgo_fail "training shape 1 (openai chat) failed"
log "  shape 1 (openai chat) done"
# shape 2: anthropic ingress -> openai upstream (the translation path)
seq 1 "$REQS" | xargs -P 8 -I{} curl -s -o /dev/null -X POST "http://127.0.0.1:$PORT/v1/messages" \
  -H "content-type: application/json" -H "anthropic-version: 2023-06-01" \
  -H "authorization: Bearer pgo-token" -d "$ANTH_BODY" \
  || pgo_fail "training shape 2 (anthropic translation) failed"
log "  shape 2 (anthropic translation) done"
# shape 3: SSE streaming relay
seq 1 "$STREAMS" | xargs -P 8 -I{} curl -s -o /dev/null -X POST "http://127.0.0.1:$PORT/v1/chat/completions" \
  -H "content-type: application/json" -H "authorization: Bearer pgo-token" -d "$STREAM_BODY" \
  || pgo_fail "training shape 3 (SSE streaming) failed"
log "  shape 3 (SSE streaming) done"

# graceful stop so the runtime flushes .profraw files
kill "$BUSBAR_PID"; wait "$BUSBAR_PID" 2>/dev/null || true; BUSBAR_PID=""
kill "$MOCK_PID" 2>/dev/null || true; MOCK_PID=""

# ---- phase 3: merge + optimized build --------------------------------------------------------
log "phase 3/3: merge profiles + optimized build"
rustup component add llvm-tools >/dev/null 2>&1 || true
PROFDATA="$(find "$(rustc --print sysroot)" -name llvm-profdata -type f | head -1)"
[ -n "$PROFDATA" ] || pgo_fail "llvm-profdata not found (rustup component add llvm-tools)"
ls "$PROF_DIR"/*.profraw >/dev/null 2>&1 \
  || pgo_fail "no .profraw files produced (instrumented run flushed nothing)"
MERGED="$PROF_DIR/merged.profdata"
"$PROFDATA" merge -o "$MERGED" "$PROF_DIR"/*.profraw \
  || pgo_fail "llvm-profdata merge failed"
# The merged profile is what -Cprofile-use consumes; an empty/absent one means the optimized
# build below would silently be a no-op PGO. Assert it is real BEFORE the build feeds it in.
[ -s "$MERGED" ] || pgo_fail "merged profile is empty/missing at $MERGED (training produced no usable coverage)"
RAW_COUNT="$(find "$PROF_DIR" -maxdepth 1 -name '*.profraw' -type f | wc -l | tr -d ' ')"
MERGED_SIZE="$(wc -c < "$MERGED" | tr -d ' ')"

RUSTFLAGS="-Cprofile-use=$MERGED" \
  cargo build --release -p busbar $TARGET_FLAG --target-dir target/pgo \
  || pgo_fail "optimized (-Cprofile-use) build failed"
[ -x "$OUT" ] || pgo_fail "optimized binary missing at $OUT"

# POSITIVE VERIFICATION: write the proof marker only now - after a non-empty merged profile was
# fed to a successful -Cprofile-use build. Its existence (checked by the workflow) is proof the
# shipped binary is PGO-optimized. Guard the merged profile is STILL non-empty at write time.
[ -s "$MERGED" ] || pgo_fail "merged profile vanished before marker write at $MERGED"
{
  echo "pgo-verified=1"
  echo "profile=$MERGED"
  echo "profile_bytes=$MERGED_SIZE"
  echo "profraw_count=$RAW_COUNT"
  echo "target=${TARGET:-<host>}"
  echo "reqs_per_shape=$REQS"
  echo "streams=$STREAMS"
  echo "built_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$MARKER" || pgo_fail "could not write proof marker at $MARKER"
[ -s "$MARKER" ] || pgo_fail "proof marker empty after write at $MARKER"

log "done: $OUT"
log "PGO VERIFIED: marker=$MARKER profile=$MERGED (${MERGED_SIZE} bytes from ${RAW_COUNT} .profraw)"
echo "$OUT"
