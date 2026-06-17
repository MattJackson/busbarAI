#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Matthew Jackson
#
# Self-contained concurrent load generator for the Busbar latency benchmark.
#
# Why a custom client instead of only oha/hey: those tools report full-response percentiles well,
# but none of them measure streaming **TTFT** (time-to-first-SSE-byte), which is the number that
# matters for a streaming gateway. This client measures both, with the SAME high-resolution clock
# (time.perf_counter_ns), so the direct-vs-busbar delta is apples-to-apples.
#
# It drives ONE url with a fixed concurrency for a fixed number of requests, and reports
# p50 / p99 / p99.9 (plus min/mean/max) over the per-request latencies, in microseconds.
#
#   * mode=full   -> non-streaming; latency = whole response received.
#   * mode=ttft   -> streaming (sets "stream": true); latency = first SSE `data:` byte received.
#
# Stdlib only (http.client + threading). HTTP/1.1 keep-alive per worker connection.
#
# Usage:
#   python3 loadgen.py --url http://127.0.0.1:9001 --path /v1/chat/completions \
#       --mode full --requests 20000 --concurrency 50 --warmup 2000
#   python3 loadgen.py --url http://127.0.0.1:8080 --path /v1/chat/completions \
#       --mode ttft --token "$BUSBAR_CLIENT_TOKEN" --model bench-pool --stream

import argparse
import http.client
import json
import sys
import threading
import time
from urllib.parse import urlparse

PAYLOAD = {
    "model": "PLACEHOLDER",
    "messages": [{"role": "user", "content": "ping"}],
    "max_tokens": 16,
}


def percentile(sorted_us, q):
    if not sorted_us:
        return float("nan")
    # nearest-rank
    k = max(0, min(len(sorted_us) - 1, int(round(q * (len(sorted_us) - 1)))))
    return sorted_us[k]


def worker(args, body_bytes, n, headers, results, errors, lock, ttft):
    parsed = urlparse(args.url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if parsed.scheme == "https":
        import ssl

        ctx = ssl._create_unverified_context()
        conn = http.client.HTTPSConnection(host, port, context=ctx, timeout=30)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=30)

    local = []
    err = 0
    for _ in range(n):
        t0 = time.perf_counter_ns()
        try:
            conn.request("POST", args.path, body=body_bytes, headers=headers)
            resp = conn.getresponse()
            if resp.status != 200:
                err += 1
                resp.read()
                # reconnect on error to avoid a poisoned keep-alive
                conn.close()
                conn = (
                    http.client.HTTPSConnection(host, port, context=ssl._create_unverified_context(), timeout=30)
                    if parsed.scheme == "https"
                    else http.client.HTTPConnection(host, port, timeout=30)
                )
                continue
            if ttft:
                # Read until the first SSE data line arrives -> first-byte latency. `resp.readline()`
                # (the HTTPResponse, not the raw socket) honors the response framing (Content-Length,
                # chunked, or read-to-close), so it returns the decoded body lines.
                first = None
                while True:
                    line = resp.readline()
                    if not line:
                        break
                    if line.lstrip().startswith(b"data:"):
                        first = time.perf_counter_ns()
                        break
                # drain the rest so the connection frees cleanly
                resp.read()
                if first is not None:
                    local.append((first - t0) / 1000.0)  # ns -> us
                else:
                    err += 1
                # Streaming responses close the connection (EOF framing); reconnect for the next req.
                conn.close()
                conn = (
                    http.client.HTTPSConnection(host, port, context=__import__("ssl")._create_unverified_context(), timeout=30)
                    if parsed.scheme == "https"
                    else http.client.HTTPConnection(host, port, timeout=30)
                )
            else:
                resp.read()
                t1 = time.perf_counter_ns()
                local.append((t1 - t0) / 1000.0)
        except Exception:
            err += 1
            try:
                conn.close()
            except Exception:
                pass
            conn = (
                http.client.HTTPSConnection(host, port, context=__import__("ssl")._create_unverified_context(), timeout=30)
                if parsed.scheme == "https"
                else http.client.HTTPConnection(host, port, timeout=30)
            )
    try:
        conn.close()
    except Exception:
        pass
    with lock:
        results.extend(local)
        errors[0] += err


def run(args):
    if args.api == "anthropic":
        # Anthropic Messages API shape (max_tokens is required). Same single-token "ping" prompt as
        # the OpenAI path so both paths elicit equivalent upstream work and the delta is clean.
        body = {
            "model": args.model,
            "max_tokens": 16,
            "messages": [{"role": "user", "content": "ping"}],
        }
    else:
        body = dict(PAYLOAD)
        body["model"] = args.model
    if args.mode == "ttft":
        body["stream"] = True
    body_bytes = json.dumps(body).encode("utf-8")

    headers = {"Content-Type": "application/json", "Connection": "keep-alive"}
    if args.api == "anthropic":
        headers["anthropic-version"] = "2023-06-01"
    if args.token:
        headers["Authorization"] = f"Bearer {args.token}"
    # Arbitrary extra headers (e.g. `x-api-key: ...` for the direct-to-Anthropic baseline path).
    for h in args.header:
        k, _, v = h.partition(":")
        headers[k.strip()] = v.strip()

    ttft = args.mode == "ttft"

    # Warmup (not recorded): lets connections, the breaker, and TSC calibration settle.
    if args.warmup > 0:
        wresults, werrors, wlock = [], [0], threading.Lock()
        per = max(1, args.warmup // args.concurrency)
        threads = [
            threading.Thread(target=worker, args=(args, body_bytes, per, headers, wresults, werrors, wlock, ttft))
            for _ in range(args.concurrency)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    results, errors, lock = [], [0], threading.Lock()
    per = max(1, args.requests // args.concurrency)
    threads = [
        threading.Thread(target=worker, args=(args, body_bytes, per, headers, results, errors, lock, ttft))
        for _ in range(args.concurrency)
    ]
    t_start = time.perf_counter()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    wall = time.perf_counter() - t_start

    results.sort()
    out = {
        "label": args.label,
        "mode": args.mode,
        "url": args.url,
        "requests_ok": len(results),
        "errors": errors[0],
        "concurrency": args.concurrency,
        "wall_s": round(wall, 3),
        "rps": round(len(results) / wall, 1) if wall > 0 else 0,
        "p50_us": round(percentile(results, 0.50), 1),
        "p99_us": round(percentile(results, 0.99), 1),
        "p999_us": round(percentile(results, 0.999), 1),
        "min_us": round(results[0], 1) if results else None,
        "mean_us": round(sum(results) / len(results), 1) if results else None,
        "max_us": round(results[-1], 1) if results else None,
    }
    print(json.dumps(out))
    return out


def main():
    ap = argparse.ArgumentParser(description="Concurrent latency/TTFT load generator (stdlib).")
    ap.add_argument("--url", required=True, help="scheme://host:port (no path)")
    ap.add_argument("--path", default="/v1/chat/completions")
    ap.add_argument("--mode", choices=["full", "ttft"], default="full")
    ap.add_argument("--requests", type=int, default=20000)
    ap.add_argument("--concurrency", type=int, default=50)
    ap.add_argument("--warmup", type=int, default=2000)
    ap.add_argument("--token", default="")
    ap.add_argument("--api", choices=["openai", "anthropic"], default="openai",
                    help="request shape: openai (/v1/chat/completions) or anthropic (/v1/messages)")
    ap.add_argument("--header", action="append", default=[],
                    help="extra request header 'Key: Value' (repeatable; e.g. 'x-api-key: ...')")
    ap.add_argument("--model", default="mock-model")
    ap.add_argument("--label", default="")
    args = ap.parse_args()
    out = run(args)
    if out["requests_ok"] == 0:
        print("ERROR: no successful requests", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
