#!/usr/bin/env python3
"""Smart-router policy sidecar for busbar (`route: webhook`).

Busbar POSTs a request projection + candidate list before each request's
failover loop; this sidecar classifies the request into a task bucket and
returns a ranked preference `{"order": [idx, ...]}`.

The payload contains ONLY the fields busbar actually sends (see
src/routing/webhook.rs, WebhookRequest): no prompt text ever leaves busbar,
so classification uses shape signals (size, message count, tools, streaming,
max_tokens), not content.

Fail-safe: if this process is slow, down, or wrong, busbar coerces the
decision to the pool's `on_error` (default: weighted SWRR) after
`policy.timeout_ms` (default 150 ms). A broken sidecar never blocks a request.

Run:  python3 policy_server.py [port]   (default 8787)
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

# ── Task buckets ─────────────────────────────────────────────────────────────
# Weights per bucket: how much each real signal matters, plus which operator
# tiers to boost. "Quality" here is the operator's judgment encoded as `tier`
# on the pool members; busbar enforces it, the sidecar just reads it.
BUCKETS = {
    #                cost  latency  headroom  boosted tiers
    "quick-answer": (0.30, 0.50, 0.20, ("small", "overflow")),
    "code":         (0.10, 0.20, 0.20, ("large", "primary")),
    "long-form":    (0.20, 0.10, 0.20, ("large", "primary")),
    "bulk":         (0.60, 0.10, 0.30, ("small", "overflow")),
}
TIER_BOOST = 0.5  # added when the candidate's tier is in the bucket's list


def classify(req):
    """Bucket the request from the projection busbar sends. No prompt text is
    available (by design), so this is shape-based, in priority order."""
    total_chars = req.get("total_chars") or 0
    max_tokens = req.get("max_tokens") or 0
    if req.get("has_tools"):
        return "code"            # tool/agent traffic wants the capable tier
    if max_tokens >= 4096 or total_chars > 24_000:
        return "long-form"       # ~4 chars/token: 24k chars is roughly 6k tokens
    if not req.get("stream") and req.get("message_count", 0) <= 1:
        return "bulk"            # single-shot, non-interactive: optimize cost
    return "quick-answer"        # interactive default: optimize latency


def score(cand, bucket, max_cost, max_latency, max_conc):
    """Weighted score from the fields busbar provides. Higher is better.
    Missing signals score neutral (0.5) so a cold lane is not punished."""
    w_cost, w_lat, w_conc, tiers = BUCKETS[bucket]
    cost = cand.get("cost_per_mtok")
    cost_s = 0.5 if cost is None else 1.0 - (cost / max_cost if max_cost else 0.0)
    lat = cand.get("latency_ms")  # EWMA; null until the lane has served a request
    lat_s = 0.5 if lat is None else 1.0 - (lat / max_latency if max_latency else 0.0)
    conc_s = (cand.get("available_concurrency", 0) / max_conc) if max_conc else 0.5
    s = w_cost * cost_s + w_lat * lat_s + w_conc * conc_s
    if cand.get("tier") in tiers:
        s += TIER_BOOST
    # Rate headroom, when governance provides it, scales the whole score down
    # as the key nears its RPM/TPM cap: prefer lanes least likely to 429.
    headroom = cand.get("rate_headroom")
    if headroom is not None:
        s *= 0.5 + 0.5 * headroom
    return s


def rank(payload):
    req = payload.get("request", {})
    cands = payload.get("candidates", [])
    if not cands:
        return {"abstain": True}
    bucket = classify(req)
    max_cost = max((c.get("cost_per_mtok") or 0.0) for c in cands) or 0.0
    max_latency = max((c.get("latency_ms") or 0.0) for c in cands) or 0.0
    max_conc = max(c.get("available_concurrency", 0) for c in cands) or 0
    scored = sorted(
        cands,
        key=lambda c: score(c, bucket, max_cost, max_latency, max_conc),
        reverse=True,
    )
    order = [c["idx"] for c in scored]
    print(f"[smart-router] bucket={bucket} order={order} "
          f"(chars={req.get('total_chars')} max_tokens={req.get('max_tokens')} "
          f"tools={req.get('has_tools')} stream={req.get('stream')})")
    return {"order": order}


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            payload = json.loads(self.rfile.read(length))
            body = rank(payload)
        except Exception as e:  # never 500 on bad input: abstain is the clean path
            print(f"[smart-router] error: {e}; abstaining", file=sys.stderr)
            body = {"abstain": True}
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):  # keep stdout for the ranking log line only
        pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8787
    print(f"[smart-router] listening on http://127.0.0.1:{port}/")
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()
