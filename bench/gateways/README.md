# Gateways — drop-in benchmark targets

Every gateway the benchmark can measure is a directory here. **Adding a gateway = adding a
directory.** The runners (`memory/run.sh`, and friends) are gateway-agnostic: they `source`
`gateways/<name>/gateway.sh` and call a fixed contract. No runner edits, no branching.

## The contract

`gateways/<name>/gateway.sh` sets four variables and defines four functions:

```sh
GW_KIND=native|docker      # informational
GW_PORT=8080               # port the gateway listens on
GW_PATH=/v1/chat/completions   # request path used to probe + load it
GW_MODEL=gpt-4o-mini       # model string put in the request body
GW_AUTH=bench-token        # bearer token the gateway accepts

gw_build()  { :; }         # build/pull/install — idempotent; may be empty
gw_launch() { :; }         # start it, pinned to $CORES, upstream = mock at 127.0.0.1:$MOCK_PORT
gw_rss()    { :; }         # echo current resident memory in MiB
gw_stop()   { :; }         # stop + clean up
```

The runner exports for you: `$MOCK_PORT` (deterministic mock upstream), `$CORES` (cpu pin),
`$GW_DIR` (this gateway's directory, for config files).

The load body is `{"model","messages":[…],"max_tokens":16}` — valid for both OpenAI
`/v1/chat/completions` and Anthropic `/v1/messages`, so a gateway picks its `GW_PATH`/`GW_MODEL`
and it just works. The mock answers both shapes (OpenAI by default, Anthropic for `/messages`).

## Shipped gateways

| dir | what | notes |
|---|---|---|
| `busbar/` | Busbar single binary | needs `BUSBAR_BIN` |
| `bifrost/` | maximhq/bifrost (docker), documented pool config | needs Docker |
| `litellm-rust/` | BerriAI compiled AI-gateway beta | **only serves `/v1/messages` via `azure_ai` + the `python-config` reader** — see its `gateway.sh` header for why (verified against their source) |
| `litellm-python/` | LiteLLM `[proxy]` CLI | pip-installed on first run |

## Fairness

Same box, same mock, same load profile, same cpu pin for every gateway. Each is launched the only
way it actually serves the endpoint — no strawmen, no idle-only snapshots. If a gateway can't serve
the endpoint, that's recorded (`served:false`) rather than hidden.
