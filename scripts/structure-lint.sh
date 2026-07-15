#!/usr/bin/env bash
# Structure lint — enforces the code-layout invariants in docs/code-layout.md so the tree stays
# navigable ("I'm looking for X, I know where it is") instead of drifting back to giant, inconsistent
# files. Three checks, all greppable, no external deps. Exit non-zero on any violation.
set -euo pipefail
cd "$(dirname "$0")/.."

# Impl files target ~1,500 lines; the hard ceiling forbids genuine MONSTER files (the thing that
# makes a codebase unnavigable) rather than micromanaging cohesive units. Test files are exempt from
# the size cap: they are located by name (foo/tests/<what>.rs), not read top-to-bottom, so the
# navigability the cap protects is already served by the tests/ folder convention + one-module-per-file.
MAX_LINES_IMPL=2500
fail=0

note() { printf '  %s\n' "$1"; }
hdr()  { printf '\n== %s ==\n' "$1"; }

# ── Invariant 1: no hybrids — a module is a file OR a folder, never both (`admin.rs` + `admin/`). ──
hdr "no hybrid modules (foo.rs beside foo/)"
while IFS= read -r d; do
  base="${d%/}"
  if [ -f "${base}.rs" ]; then
    note "HYBRID: ${base}.rs coexists with ${base}/ — fold ${base}.rs into ${base}/mod.rs"
    fail=1
  fi
done < <(find crates -type d)
[ "$fail" -eq 0 ] && note "ok"

# ── Invariant 2: no monster impl files — split by area. Test files (under a tests/ dir) are exempt. ─
hdr "no impl .rs file over ${MAX_LINES_IMPL} lines (test files exempt)"
big=0
while IFS= read -r f; do
  case "$f" in */tests/*) continue ;; esac   # test files are name-navigated → exempt from the cap
  n=$(wc -l < "$f")
  if [ "$n" -gt "$MAX_LINES_IMPL" ]; then note "OVERSIZED: $f ($n lines)"; fail=1; big=1; fi
done < <(find crates -name '*.rs')
[ "$big" -eq 0 ] && note "ok"

# ── Invariant 3: tests live in foo/tests/. The trigger is an inline test module BODY — a
#    `#[cfg(test)] mod X { ... }` (note the brace). A one-line `#[cfg(test)] #[path=...] mod X;`
#    DECLARATION is fine and expected: it keeps X a direct child so `use super::*` still resolves,
#    while the body lives in tests/X.rs. A folder-module hub (mod.rs) may carry those declarations
#    but no inline body; and no file may carry more than one inline body (the split trigger). A leaf
#    file (not a mod.rs) may keep a single inline body. ────────────────────────────────────────────
hdr "test locality (no inline test bodies in mod.rs; <=1 inline test body per file)"
loc=0
# Count inline test module BODIES: a `#[cfg(test)]` line whose next `mod X` line opens a brace.
inline_bodies() { awk '
  /^[[:space:]]*#\[cfg\(test\)\]/ { armed=1; next }
  armed && /^[[:space:]]*mod [A-Za-z0-9_]+[[:space:]]*\{/ { c++ }
  armed { armed=0 }
  END { print c+0 }' "$1"; }
while IFS= read -r f; do
  bodies=$(inline_bodies "$f")
  if [ "$(basename "$f")" = "mod.rs" ] && [ "$bodies" -ge 1 ]; then
    note "TESTS-IN-HUB: $f is a mod.rs with an inline test body — move it to tests/ (keep a #[path] decl)"
    fail=1; loc=1
  elif [ "$bodies" -ge 2 ]; then
    note "MULTI-TEST-MOD: $f has ${bodies} inline test bodies — give each its own tests/<name>.rs"
    fail=1; loc=1
  fi
done < <(find crates -name '*.rs')
[ "$loc" -eq 0 ] && note "ok"

hdr "result"
if [ "$fail" -ne 0 ]; then note "structure-lint FAILED — see docs/code-layout.md"; exit 1; fi
note "structure-lint passed"
