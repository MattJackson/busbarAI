# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Soak-rig verdicts (see run.sh): read the batch results + RSS samples and pass/fail the run on
# three checks — zero errors, bounded tail-latency drift, bounded memory drift. Stdlib only.

import argparse
import json
import sys


def load_jsonl(path):
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


def main():
    ap = argparse.ArgumentParser(description="Busbar soak-rig verdicts.")
    ap.add_argument("--batches", required=True)
    ap.add_argument("--rss", required=True)
    ap.add_argument("--drift-factor", type=float, default=3.0)
    ap.add_argument("--rss-factor", type=float, default=1.25)
    ap.add_argument("--rss-slack-mb", type=float, default=50.0)
    args = ap.parse_args()

    batches = load_jsonl(args.batches)
    rss = load_jsonl(args.rss)
    if len(batches) < 2:
        print(f"FAIL: only {len(batches)} batch(es) completed — soak too short to judge drift")
        return 1

    failures = []

    # 1. ZERO ERRORS across every batch.
    total_errors = sum(b.get("errors", 0) for b in batches)
    total_ok = sum(b.get("requests_ok", 0) for b in batches)
    if total_errors:
        bad = [(b["label"], b["errors"]) for b in batches if b.get("errors")]
        failures.append(f"errors: {total_errors} across batches {bad}")

    # 2. LATENCY DRIFT: last batch p99 within drift-factor of the first.
    first_p99, last_p99 = batches[0]["p99_us"], batches[-1]["p99_us"]
    if last_p99 > first_p99 * args.drift_factor:
        failures.append(
            f"latency drift: p99 {first_p99}us (first) -> {last_p99}us (last) "
            f"exceeds {args.drift_factor}x"
        )

    # 3. MEMORY DRIFT: final RSS within factor+slack of the FIRST-STABLE sample (the sample after
    #    the first batch — allocator warm-up and connection pools have settled by then).
    stable = rss[0]["rss_kb"] / 1024.0
    final = rss[-1]["rss_kb"] / 1024.0
    ceiling = stable * args.rss_factor + args.rss_slack_mb
    if final > ceiling:
        failures.append(
            f"memory drift: rss {stable:.1f}MB (first-stable) -> {final:.1f}MB (final) "
            f"exceeds ceiling {ceiling:.1f}MB"
        )

    print("== soak verdicts ==")
    print(f"   batches      : {len(batches)}   requests ok: {total_ok}   errors: {total_errors}")
    print(f"   p99 first/last: {first_p99}us / {last_p99}us (gate {args.drift_factor}x)")
    print(f"   rss first/last: {stable:.1f}MB / {final:.1f}MB (gate x{args.rss_factor}+{args.rss_slack_mb}MB)")
    if failures:
        for f in failures:
            print(f"FAIL: {f}")
        return 1
    print("PASS: zero errors, latency stable, memory stable")
    return 0


if __name__ == "__main__":
    sys.exit(main())
