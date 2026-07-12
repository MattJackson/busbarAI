#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Fixed-latency mock upstream for the Busbar latency benchmark.
#
# Serves an OpenAI-shaped chat-completion at POST /v1/chat/completions (the exact path Busbar's
# OpenAI writer appends to base_url). Two roles in one server:
#
#   * Non-streaming  -> returns a canned chat.completion JSON body.
#   * Streaming (SSE)-> the request body has "stream": true, so we emit chat.completion.chunk
#                       SSE events ending with `data: [DONE]`, for TTFT measurement.
#
# A fixed, deterministic upstream delay (--delay-ms) is applied BEFORE the response begins. With
# --delay-ms 0 the upstream is effectively instant, which isolates Busbar's own added overhead:
# (A -> Busbar -> mock) minus (A -> mock) is pure Busbar cost, because the mock contributes the
# same fixed time on both paths. With --delay-ms 200 you get a realistic-provider-latency shape.
#
# Stdlib only (http.server + ThreadingHTTPServer). No third-party deps, no build step.
#
# Usage:
#   python3 mock_upstream.py --port 9001 --delay-ms 0
#   python3 mock_upstream.py --port 9001 --delay-ms 200
#   python3 mock_upstream.py --port 9443 --tls-cert cert.pem --tls-key key.pem   # HTTPS
#
# Then point a Busbar provider's base_url at the mock. NOTE: Busbar's release binary requires the
# provider base_url to be https:// and trusts ONLY public (webpki) CA roots for upstream TLS, so a
# plain-http mock works only as the *direct* baseline target — to put the mock on the *busbar* path
# you must serve it over TLS with a publicly-trusted cert (see README.md "Serving the mock over
# trusted TLS"). --tls-cert/--tls-key enable that here.

import argparse
import json
import ssl
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# A small, fixed canned completion. Token count is deliberately tiny so response *size* is not the
# thing being measured — we are measuring proxy overhead and TTFT, not bandwidth.
CANNED_TEXT = "Busbar adds only microseconds of overhead."

# Pre-serialized non-streaming body (computed once; identical every request for determinism).
_NONSTREAM_OBJ = {
    "id": "chatcmpl-bench-0001",
    "object": "chat.completion",
    "created": 1718000000,
    "model": "mock-model",
    "choices": [
        {
            "index": 0,
            "message": {"role": "assistant", "content": CANNED_TEXT},
            "finish_reason": "stop",
        }
    ],
    "usage": {"prompt_tokens": 8, "completion_tokens": 8, "total_tokens": 16},
}
_NONSTREAM_BODY = json.dumps(_NONSTREAM_OBJ).encode("utf-8")

# Streaming chunks: split CANNED_TEXT into a few word-chunks, each an OpenAI chat.completion.chunk.
_STREAM_WORDS = CANNED_TEXT.split(" ")


def _chunk(delta_content=None, finish=None):
    obj = {
        "id": "chatcmpl-bench-0001",
        "object": "chat.completion.chunk",
        "created": 1718000000,
        "model": "mock-model",
        "choices": [{"index": 0, "delta": {}, "finish_reason": finish}],
    }
    if delta_content is not None:
        obj["choices"][0]["delta"]["content"] = delta_content
    return ("data: " + json.dumps(obj) + "\n\n").encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    # Silence per-request logging (it would dominate wall-clock under load).
    def log_message(self, *args):
        pass

    protocol_version = "HTTP/1.1"  # keep-alive, required for realistic proxy throughput

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        return self.rfile.read(length) if length else b""

    def do_POST(self):
        raw = self._read_body()
        wants_stream = False
        try:
            wants_stream = bool(json.loads(raw).get("stream", False)) if raw else False
        except Exception:
            wants_stream = False

        delay = self.server.delay_ms / 1000.0

        if not self.path.startswith("/v1/chat/completions"):
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        if wants_stream:
            # Apply the fixed upstream delay BEFORE the first byte (this is what TTFT captures).
            if delay:
                time.sleep(delay)
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            # Close after the stream so the body is framed by EOF (unambiguous for any SSE client and
            # for the loadgen's read-to-first-`data:`); real provider streams behave similarly per-req.
            self.send_header("Connection", "close")
            self.close_connection = True
            self.end_headers()
            # role chunk first (matches real OpenAI streams), then word chunks, then DONE.
            self.wfile.write(_chunk(delta_content=""))
            for i, w in enumerate(_STREAM_WORDS):
                self.wfile.write(_chunk(delta_content=(w if i == 0 else " " + w)))
            self.wfile.write(_chunk(finish="stop"))
            self.wfile.write(b"data: [DONE]\n\n")
            self.wfile.flush()
        else:
            if delay:
                time.sleep(delay)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(_NONSTREAM_BODY)))
            self.end_headers()
            self.wfile.write(_NONSTREAM_BODY)


def main():
    ap = argparse.ArgumentParser(description="Fixed-latency OpenAI-shaped mock upstream.")
    ap.add_argument("--port", type=int, default=9001)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument(
        "--delay-ms",
        type=int,
        default=0,
        help="fixed upstream delay applied before the response (0 = instant; 200 = realistic).",
    )
    ap.add_argument("--tls-cert", default=None, help="PEM cert chain; enables HTTPS when set with --tls-key.")
    ap.add_argument("--tls-key", default=None, help="PEM private key for --tls-cert.")
    args = ap.parse_args()

    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    httpd.delay_ms = args.delay_ms
    httpd.daemon_threads = True

    scheme = "http"
    if args.tls_cert and args.tls_key:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(args.tls_cert, args.tls_key)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        scheme = "https"
    elif args.tls_cert or args.tls_key:
        ap.error("--tls-cert and --tls-key must be given together")

    print(
        f"mock_upstream listening on {scheme}://{args.host}:{args.port}  "
        f"(delay={args.delay_ms}ms, path=/v1/chat/completions)",
        flush=True,
    )
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
