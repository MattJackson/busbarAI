# Busbar latency benchmark

A reproducible measurement of the latency Busbar **adds** to a request. The method is a difference,
not an absolute: drive identical load against the same fixed-latency upstream over two paths and
subtract.

```
direct :  loadgen ───────────────► mock upstream      (baseline)
busbar :  loadgen ──► busbar ─────► mock upstream      (baseline + Busbar)
                       └── added overhead = busbar − direct, per percentile
```

Because the mock contributes the *same* fixed time on both paths, `busbar − direct` is Busbar's own
cost — nothing else. We report **p50 / p99 / p99.9** for two things that matter to a gateway:

- **Non-streaming full-response latency** — the whole response received.
- **Streaming TTFT** — time to the first SSE byte.

## Important precondition (read before running mock mode)

Busbar's **release binary** trusts **only the compiled-in Mozilla (webpki) root set** for *upstream*
TLS (reqwest `rustls-tls` + `webpki-roots`; no OS trust store, no `SSL_CERT_FILE`, no insecure flag —
a deliberate SSRF/credential-leak stance). It also requires every provider `base_url` to be
`https://` and **rejects loopback / RFC-1918 hosts at startup** (the SSRF guard in
`config_validate.rs`). Net effect:

- A plain `http://127.0.0.1` mock can be the **direct baseline** target (the load generator reaches
  it fine), but Busbar itself **will not connect to it** — so it can't be on the *busbar* path.
- A *self-signed* HTTPS mock is **not trusted** by the release binary either.

To put the mock on the **busbar** path you need an HTTPS mock whose cert chains to a **public CA**,
served on a hostname the SSRF guard allows (not an IP literal, not `*.localhost`). `localtest.me` and
`lvh.me` are public hostnames that resolve to `127.0.0.1`, so they satisfy both the SSRF guard *and*
loopback delivery — you just need a publicly-trusted cert for one of them. See **"Serving the mock
over trusted TLS"** below. If you can't obtain such a cert, use **Mode 2** (a real provider over
HTTPS, your own key) — that path always works because the provider already has a trusted cert.

`run.sh` probes the busbar→mock hop before measuring and **aborts with a clear message** if it
returns anything other than `200`, rather than emitting meaningless numbers.

Two upstream-delay settings:

- `delay=0` — an instant upstream, to **isolate pure Busbar overhead**.
- `delay=200` — a realistic ~200 ms provider, to show the overhead **against real provider jitter**.

## What's here

| File | Role |
|------|------|
| `mock_upstream.py` | Fixed-latency OpenAI-shaped upstream. Serves `POST /v1/chat/completions` non-streaming and SSE (`stream:true`). `--delay-ms` sets the upstream delay. Stdlib only. |
| `loadgen.py` | Concurrent client. Measures full-response latency **and** streaming TTFT on one high-res clock; reports p50/p99/p99.9 in µs. Stdlib only. |
| `providers.mock.yaml` | One provider, `mock`, with `base_url: http://127.0.0.1:9001`. |
| `config.mock.yaml` | One model, one single-member pool, token auth (`bench-token`), governance off. |
| `run.sh` | Orchestrator: build (if needed) → start mock → start busbar → drive both paths for `full` and `ttft` at each delay → compute deltas. |
| `report.py` | Reads the run JSON and prints the per-percentile delta table + Markdown. |

## Quick start (mock-upstream mode)

From the repo root (no real provider, no key, no network egress):

```bash
bench/latency/run.sh
```

Tune scale with env vars:

```bash
REQS=50000 CONC=100 bench/latency/run.sh    # more load
DELAYS="0" bench/latency/run.sh              # only the pure-overhead pass
WARMUP=5000 bench/latency/run.sh             # longer warmup
```

Outputs:

- Per-run JSON lines → `bench/latency/results/results.jsonl`
- Busbar process logs → `bench/latency/results/busbar.<delay>ms.log`
- A delta table + paste-ready Markdown printed at the end.

### Run a step manually

```bash
# 1. mock upstream (instant)
python3 bench/latency/mock_upstream.py --port 9001 --delay-ms 0 &

# 2. busbar pointed at it
BUSBAR_PROVIDERS=bench/latency/providers.mock.yaml \
BUSBAR_CONFIG=bench/latency/config.mock.yaml \
BENCH_MOCK_KEY=x \
  target/release/busbar &

# 3a. baseline: straight to the mock
python3 bench/latency/loadgen.py --url http://127.0.0.1:9001 \
  --mode full --requests 20000 --concurrency 50 --model bench-model --label direct/full/0ms

# 3b. through busbar
python3 bench/latency/loadgen.py --url http://127.0.0.1:8080 \
  --mode full --requests 20000 --concurrency 50 \
  --token bench-token --model bench-pool --label busbar/full/0ms

# 3c. streaming TTFT through busbar
python3 bench/latency/loadgen.py --url http://127.0.0.1:8080 \
  --mode ttft --requests 20000 --concurrency 50 \
  --token bench-token --model bench-pool --label busbar/ttft/0ms
```

## Serving the mock over trusted TLS (so the mock can sit on the busbar path)

The release binary trusts only public CA roots upstream (see the precondition above). To benchmark
pure overhead with the mock, terminate TLS in front of the mock with a **publicly-trusted** cert for
a hostname that resolves to loopback and passes the SSRF guard (`localtest.me` works for both):

1. Obtain a real cert+key for `localtest.me` (or your own loopback-resolving domain). For example,
   issue one with an ACME client against a DNS-01 challenge for a domain you control that you've
   pointed at `127.0.0.1`. (A self-signed cert will **not** work against the release binary.)
2. Serve the mock over HTTPS with it:

   ```bash
   python3 bench/latency/mock_upstream.py --port 9443 --delay-ms 0 \
     --tls-cert fullchain.pem --tls-key privkey.pem
   ```

3. Point the bench provider at it (edit `providers.mock.yaml`):

   ```yaml
   mock:
     protocol: openai
     base_url: https://localtest.me:9443
     error_map: {}
   ```

4. Run as normal: `bench/latency/run.sh` (set `MOCK_PORT=9443`). The busbar→mock hop now succeeds and
   the delta is pure Busbar overhead.

> If your environment ships a Busbar build with OS-trust-store upstream verification (e.g. an
> internal build using `rustls-native-certs`), you can instead trust a locally-generated CA and skip
> the public cert. The stock release does not.

## Optional: a faster non-streaming generator (oha / hey / bombardier / wrk)

`loadgen.py` is the reference because it is the only one that also measures **streaming TTFT**. For
non-streaming throughput you may prefer a Rust/Go generator if you have one installed. Example with
`oha` (`brew install oha`):

```bash
cat > /tmp/body.json <<'JSON'
{"model":"bench-pool","messages":[{"role":"user","content":"ping"}],"max_tokens":16}
JSON

# baseline
oha -n 20000 -c 50 -m POST -d @/tmp/body.json \
  -H 'content-type: application/json' \
  http://127.0.0.1:9001/v1/chat/completions

# through busbar (note the Authorization header)
oha -n 20000 -c 50 -m POST -d @/tmp/body.json \
  -H 'content-type: application/json' -H 'authorization: Bearer bench-token' \
  http://127.0.0.1:8080/v1/chat/completions
```

Subtract the percentiles oha prints for the two runs to get the added overhead. (oha/hey report
full-response percentiles only; use `loadgen.py --mode ttft` for first-byte numbers.)

## Mode 2 — point at a REAL provider (real-world delta with your own key)

Mock mode isolates Busbar's cost. To see the real-world delta against an actual provider, swap the
mock for a real one. You measure: `(client → busbar → provider) − (client → provider directly)`.

1. Use the **shipped** `providers.yaml` (it already has `openai`, `anthropic`, etc.) instead of the
   mock catalog, and a config that targets a real model. Minimal real config:

   ```yaml
   # config.real.yaml
   listen: "127.0.0.1:8080"
   auth: { mode: token, client_tokens: ["bench-token"] }
   providers:
     openai: { api_key_env: OPENAI_API_KEY }
   models:
     gpt-4o-mini: { provider: openai, max_concurrent: 64 }
   pools:
     bench-pool: { members: [ { target: gpt-4o-mini } ] }
   ```

2. Export your key and start busbar:

   ```bash
   export OPENAI_API_KEY=sk-...        # YOUR key — never committed
   BUSBAR_PROVIDERS=providers.yaml \
   BUSBAR_CONFIG=config.real.yaml \
     target/release/busbar &
   ```

3. Drive both paths. **Keep load modest** (you are paying per token, and the provider rate-limits):

   ```bash
   # direct to the provider (OpenAI key goes straight upstream)
   python3 bench/latency/loadgen.py --url https://api.openai.com \
     --mode full --requests 200 --concurrency 4 --warmup 20 \
     --token "$OPENAI_API_KEY" --model gpt-4o-mini --label direct/full/real

   # through busbar
   python3 bench/latency/loadgen.py --url http://127.0.0.1:8080 \
     --mode full --requests 200 --concurrency 4 --warmup 20 \
     --token bench-token --model bench-pool --label busbar/full/real

   python3 bench/latency/report.py /dev/stdin   # or append both lines to a file and pass it
   ```

   The real-provider delta will be **dominated by network jitter to the provider**, which is exactly
   the point: against hundreds of milliseconds of provider variance, Busbar's microseconds are below
   the noise floor. Mock mode is where you actually *see* the overhead.

## Status of the measured run (honesty)

This harness was built and exercised on an Apple Silicon macOS machine (`uname`: `Darwin … arm64`).
Validated end-to-end **except the busbar→mock hop**:

- `mock_upstream.py` serves the canned 200 and SSE correctly (checked with `curl` and `hey`).
- `loadgen.py` produces real p50/p99/p99.9 for both `full` and `ttft` against the mock directly.
- Busbar builds (`cargo build --release`) and boots against the bench config.
- **Blocked:** the release binary would not complete the busbar→mock hop, because its upstream TLS
  trusts only public webpki roots (precondition above) and a local self-signed mock isn't trusted; a
  public cert for `localtest.me` was not available in this offline environment, and Mode 2 needs a
  real provider key that wasn't available either.

Therefore the **measured added-overhead numbers were not captured here** — the docs table is left as
an explicit "run this to fill" placeholder rather than fabricated. Run this harness in an environment
with either (a) a publicly-trusted cert for a loopback domain, or (b) a real provider key, to fill it.

## Notes / honesty

- Numbers are **machine-specific**. Re-run on your hardware; report the shape, not someone else's
  absolute µs. The `uname -a` line in `run.sh`'s output records the machine.
- `loadgen.py` uses HTTP/1.1 keep-alive per worker so connection setup is not counted on every
  request (it is amortized; the warmup pass primes it).
- Mock and busbar are co-located on `127.0.0.1`, so loopback RTT is in *both* paths and cancels in
  the delta.
- Governance is OFF in the bench config — this measures the proxy hot path. Turning governance on
  adds a SQLite round-trip per request that is a separate, opt-in cost.
