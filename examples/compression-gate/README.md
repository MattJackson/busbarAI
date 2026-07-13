# Compression gate: rewrite the request body before it ships

A minimal **rewrite gate** — the hook arm that replaces a request's body before dispatch. The
compressor here just collapses whitespace runs (deliberately trivial, so the wire is the lesson);
swap one function for a real semantic compressor and everything around it stays the same.

## Register it

```yaml
hooks:
  compressor:
    kind: gate
    socket: /run/busbar/compress.sock
    prompt: rw                     # rewrite requires the read-write prompt grant
    global: true                   # fire on every request
    settings: { min_savings_pct: 10 }
```

Run the hook (you own its lifecycle; busbar lazy-connects and reconnects across restarts):

```sh
cd rust-hook && cargo run --release -- /run/busbar/compress.sock
```

## What rides the wire

Because the hook is registered `prompt: rw`, busbar projects the flattened prompt text
(`messages: [{role, text}]`) into each call; the hook replies with a replacement body in body form
(`{"rewrite": {"messages": [{role, content}]}}`) — or `{}` to abstain when the savings aren't worth
a body swap. The rewrite fires **before routing and before dispatch**, persists across failover,
and token accounting uses the provider-reported usage of the rewritten body: the savings are real
and measured.

It also speaks the two management messages:

- **configure** — busbar's first message on every connection, and the live push behind
  `PATCH /api/v1/admin/hooks/compressor/settings`. The hook applies `min_savings_pct` and acks by
  echoing the pushed `settings_version`; a bad value gets no ack, so busbar keeps the old settings
  and the operator's PATCH gets a 400.
- **describe** — answers with the settings JSON schema, served verbatim at
  `GET /api/v1/admin/hooks/compressor/schema`.

## Fail-safe

Everything degrades to the original body: a malformed reply, a timeout, a dead socket — with the
default `on_error: nothing` the gate simply drops out of the decision. A broken compressor never
corrupts (or blocks) a request.

Unix-domain sockets are macOS/Linux; on Windows register the same hook as a `webhook:` transport.
