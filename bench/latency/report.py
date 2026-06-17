#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Matthew Jackson
#
# Reads the per-run JSON lines produced by loadgen.py (labels "direct/<mode>/<delay>ms" and
# "busbar/<mode>/<delay>ms") and prints, per (mode, delay):
#   * the direct and busbar p50/p99/p99.9 (microseconds)
#   * the DELTA (busbar - direct) at each percentile = Busbar's added overhead
# Also emits a Markdown table ready to paste into docs/benchmark.md.

import json
import sys
from collections import defaultdict


def load(path):
    rows = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                o = json.loads(line)
            except Exception:
                continue
            if "label" in o:
                rows[o["label"]] = o
    return rows


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "results/results.jsonl"
    rows = load(path)

    # group by (mode, delay)
    groups = defaultdict(dict)
    for label, o in rows.items():
        side, mode, delay = label.split("/")
        groups[(mode, delay)][side] = o

    print()
    md = []
    md.append("| Path | Upstream delay | p50 | p99 | p99.9 |")
    md.append("|------|---------------|-----|-----|-------|")

    for (mode, delay), sides in sorted(groups.items()):
        d = sides.get("direct")
        b = sides.get("busbar")
        title = "Non-streaming full response" if mode == "full" else "Streaming TTFT"
        print(f"### {title}  (upstream delay {delay})")
        if not d or not b:
            print("  (missing direct or busbar run)\n")
            continue
        for tag, o in (("direct", d), ("busbar", b)):
            print(
                f"  {tag:7s}  p50={o['p50_us']:>9} us  p99={o['p99_us']:>9} us  "
                f"p99.9={o['p999_us']:>9} us  (n={o['requests_ok']}, err={o['errors']}, rps={o['rps']})"
            )
        dp50 = round(b["p50_us"] - d["p50_us"], 1)
        dp99 = round(b["p99_us"] - d["p99_us"], 1)
        dp999 = round(b["p999_us"] - d["p999_us"], 1)
        print(f"  DELTA    p50={dp50:>9} us  p99={dp99:>9} us  p99.9={dp999:>9} us  <- Busbar overhead")
        print()
        md.append(
            f"| **Busbar added ({title.lower()})** | {delay} | "
            f"+{dp50} us | +{dp99} us | +{dp999} us |"
        )

    print("---- Markdown (paste into docs/benchmark.md) ----")
    print("\n".join(md))


if __name__ == "__main__":
    main()
