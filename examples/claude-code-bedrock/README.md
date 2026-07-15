# Claude Code → Amazon Nova on Bedrock, through Busbar

Point Claude Code (which speaks the Anthropic API) at Busbar with one environment variable, and
every turn is answered by **Amazon Nova on Bedrock** instead — Busbar translates Anthropic ⇄
Bedrock Converse on the fly. The agent never knows; you change one line of Busbar config, not one
line of Claude Code.

## Files

| File | What it is |
|------|------------|
| `config.yaml` | Busbar deployment: a `claude-code` pool with one member, `amazon-nova` → `amazon.nova-pro-v1:0`. |
| `run-busbar.sh` | Boots Busbar with this config, feeding it your AWS creds as `AWS_BEDROCK_CREDS`. |
| `env.sh` | Points Claude Code at Busbar (`ANTHROPIC_BASE_URL`, token, output cap). |
| `bedrock-usage.sh` | Reads AWS CloudWatch to prove Nova actually served the calls. |
| `workspace/` | A throwaway sample app for the agent to work on during a run. |

## Run it

```sh
# 0. Build Busbar and have AWS creds with Bedrock access in ~/.aws/credentials
cargo build --release

# 1. Start Busbar (reads ~/.aws, serves on 127.0.0.1:8080)
examples/claude-code-bedrock/run-busbar.sh

# 2. In another shell, point Claude Code at it and launch
source examples/claude-code-bedrock/env.sh
claude          # give it a normal task — Nova answers every turn

# 3. Confirm Bedrock served it
examples/claude-code-bedrock/bedrock-usage.sh
```

`env.sh` sets `ANTHROPIC_BASE_URL=http://127.0.0.1:8080/claude-code` — the `/claude-code` prefix
selects the pool in `config.yaml`. Swap the pool member for Gemini, Claude-behind-two-keys with
failover, etc., and Claude Code is unaffected.
