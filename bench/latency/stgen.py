#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Matthew Jackson
#
# Server-Timing load generator for the Busbar overhead benchmark.
#
# Fires N requests at a fixed concurrency and captures, per response, Busbar's OWN reported
# processing time from the `Server-Timing: busbar;dur=<ms>` header — its internal latency (total
# request minus the upstream round-trip). Reports p50/p99/p99.9 of THAT distribution (st_*), which
# is a true paired per-request measurement (Busbar's clock, not the client's) and therefore valid
# at the tail and independent of how fast the upstream is. Client wall-clock (wall_*) is reported
# alongside for context. Stdlib only.
#
# Because the headline number is Busbar's self-reported value, the client's own jitter does not
# pollute it — so the upstream can be an instant mock OR real Anthropic and st_* is comparable.
import argparse
import http.client
import json
import os
import re
import socket
import ssl
import sys
import threading
import time
from urllib.parse import urlparse

ST_RE = re.compile(r"dur=([0-9.]+)")
# Capture every `name;dur=X` metric in the Server-Timing header (busbar, pre, xreq, xresp, …) so the
# profiling split is visible, not just the headline `busbar` value.
ST_KV_RE = re.compile(r"([a-zA-Z][\w-]*)\s*;\s*dur=(-?[0-9.]+)")


def pct(sorted_vals, q):
    if not sorted_vals:
        return float("nan")
    k = max(0, min(len(sorted_vals) - 1, int(round(q * (len(sorted_vals) - 1)))))
    return sorted_vals[k]


def worker(args, body, n, headers, met_vals, wall_vals, errs, lock, ttft, deadline):
    parsed = urlparse(args.url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    def mk():
        if parsed.scheme == "https":
            ctx = ssl._create_unverified_context()
            c = http.client.HTTPSConnection(host, port, context=ctx, timeout=60)
        else:
            c = http.client.HTTPConnection(host, port, timeout=60)
        # Disable Nagle: without TCP_NODELAY a large response on a keep-alive loopback connection
        # collides with delayed-ACK and stalls ~40ms per request — a client artifact that has nothing
        # to do with Busbar but wrecks wall-clock (and run wall time) on big same-protocol bodies.
        c.connect()
        c.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return c

    conn = mk()
    mets, wl, e = {}, [], 0
    for _ in range(n):
        if deadline and time.perf_counter() >= deadline:
            break  # overall wall deadline hit (stalled upstream guard)
        t0 = time.perf_counter_ns()
        try:
            conn.request("POST", args.path, body=body, headers=headers)
            resp = conn.getresponse()
            sth = resp.getheader("server-timing")
            if resp.status != 200:
                e += 1
                resp.read()
                conn.close()
                conn = mk()
                continue
            if ttft:
                first = None
                while True:
                    line = resp.readline()
                    if not line:
                        break
                    if line.lstrip().startswith(b"data:"):
                        first = time.perf_counter_ns()
                        break
                resp.read()
                if first is None:
                    e += 1
                    conn.close()
                    conn = mk()
                    continue
                wl.append((first - t0) / 1000.0)
            else:
                resp.read()
                wl.append((time.perf_counter_ns() - t0) / 1000.0)
            if sth:
                for name, dur in ST_KV_RE.findall(sth):
                    val = float(dur)
                    if val < 0:
                        continue  # -1 sentinel: seam not exercised on this request
                    mets.setdefault(name, []).append(val * 1000.0)  # ms -> us
        except Exception:
            e += 1
            try:
                conn.close()
            except Exception:
                pass
            conn = mk()
    try:
        conn.close()
    except Exception:
        pass
    with lock:
        for name, vals in mets.items():
            met_vals.setdefault(name, []).extend(vals)
        wall_vals.extend(wl)
        errs[0] += e


def main():
    ap = argparse.ArgumentParser(description="Server-Timing load generator (Busbar internal latency).")
    ap.add_argument("--url", required=True)
    ap.add_argument("--path", default="/v1/chat/completions")
    ap.add_argument("--mode", choices=["full", "ttft"], default="full")
    ap.add_argument("--requests", type=int, default=20000)
    ap.add_argument("--concurrency", type=int, default=1)
    ap.add_argument("--warmup", type=int, default=1000)
    ap.add_argument("--token", default="")
    ap.add_argument("--api", choices=["openai", "anthropic"], default="openai")
    ap.add_argument("--protocol",
                    choices=["openai", "anthropic", "responses", "cohere", "gemini", "bedrock"],
                    help="when set, build the request (path + body + auth header) for this wire protocol "
                         "against pool --model; overrides --api/--path. The same-protocol passthrough.")
    ap.add_argument("--header", action="append", default=[],
                    help="extra header 'Key: Value'; value 'env:NAME' is read from the environment")
    ap.add_argument("--model", default="m")
    ap.add_argument("--prompt-tokens", type=int, default=1, help="approx prompt size for the payload sweep")
    ap.add_argument("--max-tokens", type=int, default=16)
    ap.add_argument("--label", default="")
    ap.add_argument("--max-seconds", type=float, default=0,
                    help="overall wall deadline; stop firing once exceeded (0 = no limit). Guards "
                         "against a stalled upstream wedging the run for hours.")
    a = ap.parse_args()

    prompt = ("ping " * max(1, a.prompt_tokens)).strip()
    pool = a.model
    headers = {"Content-Type": "application/json", "Connection": "keep-alive"}
    path = a.path

    if a.protocol:
        # Build the native request for the chosen wire protocol (same-protocol passthrough).
        bearer = lambda: headers.__setitem__("Authorization", f"Bearer {a.token}") if a.token else None
        if a.protocol == "openai":
            path = "/v1/chat/completions"
            body = {"model": pool, "max_tokens": a.max_tokens, "messages": [{"role": "user", "content": prompt}]}
            bearer()
        elif a.protocol == "anthropic":
            path = f"/{pool}/v1/messages"
            body = {"model": pool, "max_tokens": a.max_tokens, "messages": [{"role": "user", "content": prompt}]}
            headers["anthropic-version"] = "2023-06-01"
            if a.token:
                headers["x-api-key"] = a.token
        elif a.protocol == "responses":
            path = "/v1/responses"
            body = {"model": pool, "max_output_tokens": a.max_tokens, "input": prompt}
            bearer()
        elif a.protocol == "cohere":
            path = "/v2/chat"
            body = {"model": pool, "max_tokens": a.max_tokens, "messages": [{"role": "user", "content": prompt}]}
            bearer()
        elif a.protocol == "gemini":
            path = f"/v1beta/models/{pool}:generateContent"
            body = {"contents": [{"parts": [{"text": prompt}]}], "generationConfig": {"maxOutputTokens": a.max_tokens}}
            if a.token:
                headers["x-goog-api-key"] = a.token
        elif a.protocol == "bedrock":
            path = f"/model/{pool}/converse"
            body = {"messages": [{"role": "user", "content": [{"text": prompt}]}],
                    "inferenceConfig": {"maxTokens": a.max_tokens}}
            bearer()
        if a.mode == "ttft" and a.protocol in ("openai", "anthropic"):
            body["stream"] = True
    else:
        # Legacy path: openai/anthropic body shape, explicit --path.
        body = {"model": pool, "max_tokens": a.max_tokens, "messages": [{"role": "user", "content": prompt}]}
        if a.mode == "ttft":
            body["stream"] = True
        if a.api == "anthropic":
            headers["anthropic-version"] = "2023-06-01"
        if a.token:
            headers["Authorization"] = f"Bearer {a.token}"

    a.path = path
    bb = json.dumps(body).encode("utf-8")
    for h in a.header:
        k, _, v = h.partition(":")
        v = v.strip()
        if v.startswith("env:"):
            v = os.environ.get(v[4:], "")
        headers[k.strip()] = v

    ttft = a.mode == "ttft"

    def fire(total):
        mets, wl, er, lk = {}, [], [0], threading.Lock()
        per = max(1, total // a.concurrency)
        deadline = (time.perf_counter() + a.max_seconds) if a.max_seconds > 0 else 0
        ts = [threading.Thread(target=worker,
                               args=(a, bb, per, headers, mets, wl, er, lk, ttft, deadline))
              for _ in range(a.concurrency)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        return mets, wl, er[0]

    if a.warmup > 0:
        fire(a.warmup)
    t0 = time.perf_counter()
    mets, wl, errs = fire(a.requests)
    wall = time.perf_counter() - t0
    wl.sort()
    st = sorted(mets.get("busbar", []))
    out = {
        "label": a.label, "mode": a.mode, "ok": len(wl), "errors": errs, "conc": a.concurrency,
        "rps": round(len(wl) / wall, 1) if wall > 0 else 0,
        # Busbar's self-reported internal processing time (the headline metric).
        "st_p50_us": round(pct(st, 0.50), 1), "st_p99_us": round(pct(st, 0.99), 1),
        "st_p999_us": round(pct(st, 0.999), 1), "st_n": len(st),
        # Client wall-clock, for context.
        "wall_p50_us": round(pct(wl, 0.50), 1), "wall_p99_us": round(pct(wl, 0.99), 1),
        "wall_p999_us": round(pct(wl, 0.999), 1),
    }
    # Profiling sub-metrics (pre, xreq, xresp, …): p50 of each, so the internal split is visible.
    for name in sorted(mets):
        if name == "busbar":
            continue
        vals = sorted(mets[name])
        out[f"{name}_p50_us"] = round(pct(vals, 0.50), 1)
    print(json.dumps(out))
    if len(wl) == 0:
        print("ERROR: no successful requests", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
