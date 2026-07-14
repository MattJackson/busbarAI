#!/usr/bin/env bash
# Pre-release gate. Mirrors .github/workflows/ci.yml EXACTLY so a tag can never ship red CI —
# in particular the config-specific dead-code that `-D warnings` rejects only under
# `--no-default-features` or on Windows (which a single default `cargo build` on a unix box
# silently passes). Run this before every `git tag vX.Y.Z`.
#
#   scripts/preflight.sh          # the CI mirror (fast)
#   scripts/preflight.sh --full   # + the acceptance harness (tests.json), the deeper release gate
#
# Exit 0 only if every mirrored job is green. Windows can't fully build on a mac (cross C
# toolchain), so it is a *type-check* best-effort here + a loud reminder to confirm the CI job.
set -uo pipefail
cd "$(dirname "$0")/.."
export RUSTFLAGS="-D warnings"   # same as CI env
fail=0
step() { echo; echo "━━━ $1"; shift; if "$@"; then echo "  ✓"; else echo "  ✗ FAILED: $*"; fail=1; fi; }

echo "▶ Pre-release gate — mirroring CI (RUSTFLAGS=$RUSTFLAGS)"

# ── Working tree must be COMMITTED ──
# CI checks the committed tree, not your working copy. A local `cargo fmt` that reformats a file
# but is never committed passes this gate yet fails CI. Fail loudly if anything is uncommitted.
if [ -n "$(git status --porcelain 2>/dev/null)" ]; then
  echo "  ✗ uncommitted changes — CI tests the COMMITTED tree, so commit first (a stray"
  echo "    'cargo fmt' edit that is never committed is exactly how red CI slips through):"
  git status --short | head; fail=1
fi

# ── Job 1: fmt · structure · clippy · build · test (default features) ──
step "fmt --all --check"                 cargo fmt --all -- --check
[ -x scripts/structure-lint.sh ] && step "structure-lint" ./scripts/structure-lint.sh
step "clippy (default, all-targets)"     cargo clippy --workspace --all-targets --locked -- -D warnings
step "build (default)"                   cargo build --workspace --locked
step "test (default)"                    cargo test --workspace --locked

# ── Job 2: no-default-features · clippy · build · test ──
# This is the job that catches feature-gated dead code (e.g. a getter only read by an
# optional auth link, a test helper behind a feature). --all-targets so TEST code is linted too.
step "clippy (no-default, all-targets)"  cargo clippy --no-default-features --all-targets --locked -- -D warnings
step "build (no-default)"                cargo build --no-default-features --locked
step "test (no-default)"                 cargo test --no-default-features --locked

# ── Security job: cargo-deny (advisories · licenses · sources · bans) ──
echo; echo "━━━ cargo-deny"
if command -v cargo-deny >/dev/null 2>&1; then
  if cargo deny check >/tmp/preflight-deny.log 2>&1; then echo "  ✓"; else
    echo "  ✗ cargo-deny failed:"; grep -iE "error|warning" /tmp/preflight-deny.log | head -6; fail=1
  fi
else
  echo "  ⚠ cargo-deny not installed (cargo install cargo-deny) — the Security CI job is NOT"
  echo "    covered locally; verify it green before tagging."
fi

# ── Job 3: windows build · test (best-effort locally) ──
# Catches cfg(unix)-only items left dead on Windows (e.g. a const used only inside #[cfg(unix)]).
echo; echo "━━━ windows check (x86_64-pc-windows-msvc)"
if rustup target list --installed 2>/dev/null | grep -q x86_64-pc-windows-msvc; then
  if cargo check --workspace --target x86_64-pc-windows-msvc >/tmp/preflight-win.log 2>&1; then
    echo "  ✓ windows type-check clean"
  # A REAL code error is a rustc diagnostic: `error[Ennnn]` or an unused/dead-code lint.
  # A cross C-toolchain gap (ring/libsqlite3 needing MSVC headers on a mac) is NOT our code.
  elif grep -qiE "error\[E[0-9]|is never (used|constructed|read)" /tmp/preflight-win.log; then
    echo "  ✗ windows has a REAL code error:"; grep -iE "error\[E[0-9]|is never (used|constructed|read)|-->" /tmp/preflight-win.log | grep -v check-cfg | head -6; fail=1
  else
    echo "  ⚠ could not complete locally (cross C-toolchain gap building ring/sqlite, not your Rust)."
    echo "    → VERIFY the 'windows build · test' CI job green before tagging."
  fi
else
  echo "  ⚠ windows target not installed (rustup target add x86_64-pc-windows-msvc)."
  echo "    The 'windows build · test' CI job is NOT covered locally — VERIFY it green before tagging."
fi

# ── Optional: deeper release gate (acceptance harness) ──
if [ "${1:-}" = "--full" ]; then
  H=../busbarAI-private/testing/harness
  if [ -x "$H/run.sh" ]; then
    step "acceptance harness (tests.json)" bash -c "cargo build --release --locked && env -u ANTHROPIC_API_KEY -u OPENAI_API_KEY -u GEMINI_API_KEY -u COHERE_API_KEY $H/run.sh target/release/busbar >/dev/null 2>&1 && python3 -c 'import json;d=json.load(open(\"/tmp/kat.json\"));s=d[\"summary\"];exit(0 if s[\"fail\"]==0 else 1)'"
  else
    echo; echo "  ⚠ acceptance harness not found at $H — skipping."
  fi
fi

echo
if [ $fail -eq 0 ]; then echo "✅ PREFLIGHT GREEN — safe to tag."; else echo "❌ PREFLIGHT FAILED — fix before tagging."; exit 1; fi
