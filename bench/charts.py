#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""Render benchmark charts from results/ — pretty, and pluggable.

Nothing is hard-coded: every number is read from results/<suite>/<gateway>.json (written by the
runners). Bars are colored by MEASUREMENT — green goes to whichever gateway measured best on the
metric, so if busbar loses, busbar isn't green.

Add a chart = append one `Chart(...)` to CHARTS below. Add a gateway = it shows up automatically
once it has a result file (label/order from GATEWAYS). Run after the benchmark:

    python3 bench/charts.py
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.font_manager as fm
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch  # noqa: F401  (kept for future annotations)

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"

# ── house style ──────────────────────────────────────────────────────────────────────────────────
BRAND = "#00b34a"   # busbar green — the "won this metric" color
BRAND_DK = "#059142"
SLATE = "#3a3f4b"   # everyone else's primary bar
MUTE = "#cdd0d7"    # secondary/idle bars
INK = "#1c2430"     # titles
GRAY = "#8a90a0"    # captions
GRID = "#eef0f3"
for _f in ("Inter", "Helvetica Neue", "Arial", "DejaVu Sans"):
    if any(_f.lower() in f.name.lower() for f in fm.fontManager.ttflist):
        plt.rcParams["font.family"] = _f
        break
plt.rcParams.update({"axes.edgecolor": "#d7dae0", "svg.fonttype": "none"})

# display order + labels. A gateway appears in a chart only if it has a result file this run.
GATEWAYS = {
    "busbar": "Busbar",
    "litellm-rust": "LiteLLM · Rust",
    "bifrost": "Bifrost",
    "portkey": "Portkey",
    "litellm-python": "LiteLLM · Python",
}


@dataclass(frozen=True)
class Series:
    field: str            # json key
    legend: str           # legend label
    kind: str = "rank"    # "rank" → green-to-winner/slate-to-rest; or a hex color for a fixed tint


@dataclass(frozen=True)
class Chart:
    name: str             # output png stem
    suite: str            # results/<suite>/*.json
    title: str
    subtitle: str
    unit: str
    series: list          # list[Series]; the FIRST series decides the winner + sort order
    log: bool = False
    higher_better: bool = False   # RPS: bigger wins (green to the max, sort desc)


CHARTS = [
    # ── the headline: what the system can DO ──────────────────────────────────────────────────────
    Chart(
        name="added_latency",
        suite="perf",
        title="Added latency — what the gateway costs you",
        subtitle="p99 the gateway adds on top of the upstream, concurrency 1 (lower is better)",
        unit="µs",
        series=[Series("added_latency_p99_us", "p99 added latency", "rank")],
        log=True,
    ),
    Chart(
        name="rps_ceiling",
        suite="perf",
        title="Throughput ceiling — how much the gateway can carry",
        subtitle="highest sustained requests/sec with p99 < 1s and zero errors (higher is better)",
        unit="requests / sec",
        series=[Series("rps_ceiling", "RPS ceiling", "rank")],
        higher_better=True,
    ),
    # ── supporting: memory (matters at scale) ─────────────────────────────────────────────────────
    Chart(
        name="memory_rss",
        suite="memory",
        title="Gateway memory under sustained load",
        subtitle="idle vs peak resident memory — same box, same mock, same load",
        unit="MiB",
        series=[
            Series("peak_rss_mib", "peak RSS (under load)", "rank"),
            Series("idle_rss_mib", "idle RSS (before load)", MUTE),
        ],
        log=True,
    ),
]


def _load(suite: str) -> list[dict]:
    d = RESULTS / suite
    rows = []
    for key, label in GATEWAYS.items():
        p = d / f"{key}.json"
        if not p.exists():
            continue
        obj = json.loads(p.read_text())
        obj["_key"], obj["_label"] = key, label
        rows.append(obj)
    return rows


def _fmt(v: float) -> str:
    if v >= 1000:
        return f"{v/1000:.1f}k" if v < 100000 else f"{v/1000:.0f}k"
    return f"{v:.0f}" if v >= 10 else f"{v:.1f}"


def render(chart: Chart) -> None:
    rows = _load(chart.suite)
    if not rows:
        print(f"skip {chart.name}: no results/{chart.suite}/*.json yet")
        return
    primary = chart.series[0].field
    vals_all = [float(r.get(primary, 0)) for r in rows]
    # winner = max if higher-is-better (RPS), else min; sort so the winner sits on top.
    best = max(vals_all) if chart.higher_better else min(vals_all)
    rows.sort(key=lambda r: float(r.get(primary, 0)), reverse=chart.higher_better)

    n = len(rows)
    ns = len(chart.series)
    fig, ax = plt.subplots(figsize=(11.5, 0.92 * n + 1.9))
    fig.patch.set_facecolor("white")
    ax.set_facecolor("white")
    group_h = 0.74
    bar_h = group_h / ns
    y0 = list(range(n))

    for si, s in enumerate(chart.series):
        offset = group_h / 2 - bar_h / 2 - si * bar_h
        vals = [float(r.get(s.field, 0)) for r in rows]
        if s.kind == "rank":
            colors = [BRAND if v == best else SLATE for v in vals]
        else:
            colors = [s.kind] * n
        bars = ax.barh([y + offset for y in y0], vals, height=bar_h * 0.92,
                       color=colors, zorder=3, label=s.legend)
        for r, bar, v in zip(rows, bars, vals):
            served = r.get("served", True)
            x = bar.get_width()
            ax.text(x * (1.06 if chart.log else 1.0) + (0 if chart.log else best * 0.02),
                    bar.get_y() + bar.get_height() / 2, _fmt(v),
                    va="center", ha="left", fontsize=9.5 if s.kind == "rank" else 8,
                    fontweight="bold" if s.kind == "rank" else "normal",
                    color=INK if s.kind == "rank" else GRAY, zorder=4)
            if s.kind == "rank" and not served:
                ax.text(x * 1.06, bar.get_y() + bar.get_height() / 2, "  ⚠ did not serve",
                        va="center", ha="left", fontsize=8, color="#c2410c", zorder=4)

    ax.set_yticks(y0)
    ax.set_yticklabels([r["_label"] for r in rows], fontsize=11.5, color=INK, fontweight="medium")
    ax.invert_yaxis()
    ax.tick_params(left=False)
    for sp in ("top", "right", "left"):
        ax.spines[sp].set_visible(False)
    ax.spines["bottom"].set_color("#d7dae0")
    if chart.log:
        ax.set_xscale("log")
    ax.xaxis.grid(True, color=GRID, zorder=0)
    ax.set_axisbelow(True)
    ax.set_xlabel(f"{chart.unit}   ·   lower is better" + ("   (log scale)" if chart.log else ""),
                  fontsize=9, color=GRAY)
    xmax = max(float(r.get(chart.series[0].field, 0)) for r in rows)
    ax.set_xlim(right=xmax * (2.6 if chart.log else 1.22))

    ax.set_title(chart.title, fontsize=15, fontweight="bold", color=INK, loc="left", pad=18)
    ax.text(0, 1.03, chart.subtitle, transform=ax.transAxes, fontsize=10.5, color=GRAY, va="bottom")

    # legend (only multi-series charts need it)
    if ns > 1:
        ax.legend(loc="lower right", fontsize=9, frameon=False, ncols=ns)

    meta = rows[0]
    bits = []
    if "hardware" in meta:
        bits.append(str(meta["hardware"]))
    if "concurrency" in meta and "payload_bytes" in meta:
        bits.append(f"{meta['concurrency']}× {int(meta['payload_bytes'])//1000}KB sustained")
    bits.append("green = measured best")
    fig.text(0.008, 0.012, "  ·  ".join(bits) + "     getbusbar.com/bench — every number regenerates from raw results",
             fontsize=7.3, color=GRAY)

    fig.tight_layout(rect=(0, 0.045, 1, 0.99))
    out = RESULTS / f"{chart.name}.png"
    fig.savefig(out, dpi=200, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"wrote {out}")


def main() -> None:
    RESULTS.mkdir(exist_ok=True)
    any_done = False
    for c in CHARTS:
        render(c)
        any_done = any_done or (RESULTS / f"{c.name}.png").exists()
    if not any_done:
        print("no charts drawn — run the benchmark first (bench/run-all.sh)")


if __name__ == "__main__":
    main()
