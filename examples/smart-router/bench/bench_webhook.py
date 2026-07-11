#!/usr/bin/env python3
"""Measure the decision latency of the webhook smart-router sidecar.

This times the exact work busbar's `route: webhook` transport does per request:
serialize a request+candidate projection, POST it to the sidecar, read back the
ranked order. It uses a KEPT-ALIVE connection because busbar reuses a reqwest
connection pool, so a cold-connect number would overstate the steady-state cost.

It measures the DECISION cost only (the work the hook adds), not a full LLM
request. End-to-end request latency = your upstream + this.

Run:  python3 bench_webhook.py            # boots the sidecar itself
      python3 bench_webhook.py 5000 3     # samples, candidate count

No dependencies beyond the Python standard library.
"""
import http.client
import json
import os
import statistics
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SERVER = os.path.join(HERE, "..", "policy_server.py")
PORT = 8791


def payload(n_candidates):
    tiers = ["large", "small", "small", "overflow"]
    return json.dumps(
        {
            "request": {
                "pool": "smart-router",
                "ingress_protocol": "openai",
                "message_count": 3,
                "has_tools": True,
                "total_chars": 1800,
                "max_tokens": 512,
                "stream": True,
            },
            "candidates": [
                {
                    "idx": i,
                    "model": f"model-{i}",
                    "tier": tiers[i % len(tiers)],
                    "cost_per_mtok": 0.10 + i,
                    "latency_ms": 250.0 + 60 * i,
                    "available_concurrency": 8 + i,
                    "budget_remaining": 1000,
                    "rate_headroom": 0.9,
                }
                for i in range(n_candidates)
            ],
        }
    ).encode()


def percentile(xs, q):
    return xs[min(int(q * len(xs)), len(xs) - 1)]


def main():
    samples = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    n_candidates = int(sys.argv[2]) if len(sys.argv) > 2 else 3
    body = payload(n_candidates)

    subprocess.run(f"lsof -ti :{PORT} 2>/dev/null | xargs kill -9 2>/dev/null; true", shell=True)
    srv = subprocess.Popen(
        [sys.executable, SERVER, str(PORT)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        # Wait for the sidecar to accept connections.
        conn = None
        for _ in range(50):
            try:
                conn = http.client.HTTPConnection("127.0.0.1", PORT)
                conn.request("POST", "/", body, {"Content-Type": "application/json"})
                conn.getresponse().read()
                break
            except OSError:
                time.sleep(0.05)
                conn = None
        if conn is None:
            print("sidecar did not start", file=sys.stderr)
            return 1

        def one():
            t = time.perf_counter_ns()
            conn.request("POST", "/", body, {"Content-Type": "application/json"})
            conn.getresponse().read()
            return (time.perf_counter_ns() - t) / 1e6  # ms

        for _ in range(min(500, samples // 4)):  # warm up
            one()
        xs = sorted(one() for _ in range(samples))

        print(f"webhook sidecar decision latency (localhost keep-alive, "
              f"{n_candidates} candidates, N={samples}):")
        print(f"  median {statistics.median(xs):.3f} ms   "
              f"p95 {percentile(xs, 0.95):.3f} ms   "
              f"p99 {percentile(xs, 0.99):.3f} ms   "
              f"min {xs[0]:.3f} ms")
    finally:
        srv.terminate()
    return 0


if __name__ == "__main__":
    sys.exit(main())
