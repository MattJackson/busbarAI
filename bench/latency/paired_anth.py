#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Matthew Jackson
#
# PAIRED real-Anthropic wall-clock: direct vs through-Busbar, INTERLEAVED on alternating requests
# (direct, busbar, direct, busbar, …) in one time window. Because the two paths are fired back-to-back,
# Anthropic's minute-to-minute latency drift hits both equally and cancels in the delta — so the
# difference IS Busbar's true end-to-end cost (the extra hop + its ~tens-of-µs compute), measured by the
# CLIENT, not self-reported. Both paths use a persistent keep-alive connection (equal warmth). Stdlib
# only. The real key is read from the env (never argv).
import argparse
import http.client
import json
import os
import re
import socket
import ssl
import time
from urllib.parse import urlparse

DUR_RE = re.compile(r"busbar;dur=([0-9.]+)")


def pct(v, q):
    if not v:
        return float("nan")
    s = sorted(v)
    k = max(0, min(len(s) - 1, int(round(q * (len(s) - 1)))))
    return s[k]


def conn_for(url):
    p = urlparse(url)
    port = p.port or (443 if p.scheme == "https" else 80)
    if p.scheme == "https":
        c = http.client.HTTPSConnection(p.hostname, port, context=ssl._create_unverified_context(), timeout=30)
    else:
        c = http.client.HTTPConnection(p.hostname, port, timeout=30)
    c.connect()
    c.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return c, p.path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--busbar-url", required=True)   # http://127.0.0.1:8080/anth-pool/v1/messages
    ap.add_argument("--anth-url", default="https://api.anthropic.com/v1/messages")
    ap.add_argument("--model", required=True)
    ap.add_argument("--busbar-token", default="bench-token")
    ap.add_argument("--key-env", default="ANTHROPIC_API_KEY")
    ap.add_argument("--requests", type=int, default=400)   # per side (so 2N total)
    ap.add_argument("--warmup", type=int, default=20)
    ap.add_argument("--max-tokens", type=int, default=16)
    ap.add_argument("--max-seconds", type=float, default=300)
    a = ap.parse_args()

    real_key = os.environ.get(a.key_env, "")
    body = json.dumps({"model": a.model, "max_tokens": a.max_tokens,
                       "messages": [{"role": "user", "content": "ping"}]}).encode()
    h_common = {"Content-Type": "application/json", "anthropic-version": "2023-06-01",
                "Connection": "keep-alive"}
    h_direct = dict(h_common, **{"x-api-key": real_key})
    h_busbar = dict(h_common, **{"x-api-key": a.busbar_token})

    bc, bpath = conn_for(a.busbar_url)
    dc, dpath = conn_for(a.anth_url)

    def fire(conn, path, headers):
        t0 = time.perf_counter_ns()
        conn.request("POST", path, body=body, headers=headers)
        r = conn.getresponse()
        dur = r.getheader("server-timing")
        st = r.status
        r.read()
        wall = (time.perf_counter_ns() - t0) / 1000.0  # µs
        sd = None
        if dur:
            m = DUR_RE.search(dur)
            if m:
                sd = float(m.group(1)) * 1000.0
        return st, wall, sd

    # warmup both
    for _ in range(a.warmup):
        try:
            fire(dc, dpath, h_direct); fire(bc, bpath, h_busbar)
        except Exception:
            dc, _ = conn_for(a.anth_url); bc, _ = conn_for(a.busbar_url)

    dwall, bwall, bdur, derr, berr = [], [], [], 0, 0
    deadline = time.perf_counter() + a.max_seconds if a.max_seconds > 0 else 0
    for _ in range(a.requests):
        if deadline and time.perf_counter() >= deadline:
            break
        # DIRECT, then BUSBAR — alternating, back to back
        try:
            st, w, _ = fire(dc, dpath, h_direct)
            if st == 200:
                dwall.append(w)
            else:
                derr += 1
        except Exception:
            derr += 1; dc, _ = conn_for(a.anth_url)
        try:
            st, w, sd = fire(bc, bpath, h_busbar)
            if st == 200:
                bwall.append(w)
                if sd is not None:
                    bdur.append(sd)
            else:
                berr += 1
        except Exception:
            berr += 1; bc, _ = conn_for(a.busbar_url)

    def ms(x):
        return round(x / 1000.0, 1)

    out = {
        "n_direct": len(dwall), "n_busbar": len(bwall), "err_direct": derr, "err_busbar": berr,
        "direct_wall_ms": {"p50": ms(pct(dwall, .5)), "p99": ms(pct(dwall, .99)), "p999": ms(pct(dwall, .999))},
        "busbar_wall_ms": {"p50": ms(pct(bwall, .5)), "p99": ms(pct(bwall, .99)), "p999": ms(pct(bwall, .999))},
        "busbar_dur_us": {"p50": round(pct(bdur, .5), 1), "p99": round(pct(bdur, .99), 1)},
        # the honest paired deltas (Busbar end-to-end cost; drift cancels)
        "delta_p50_ms": round(ms(pct(bwall, .5)) - ms(pct(dwall, .5)), 1),
        "delta_p99_ms": round(ms(pct(bwall, .99)) - ms(pct(dwall, .99)), 1),
    }
    print(json.dumps(out))


if __name__ == "__main__":
    main()
