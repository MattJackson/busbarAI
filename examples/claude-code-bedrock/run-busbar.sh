#!/usr/bin/env bash
# Boot Busbar for the Claude-Code → Amazon Nova (Bedrock) example. Reads AWS creds from
# ~/.aws/credentials and hands them to Busbar as AWS_BEDROCK_CREDS (ACCESS:SECRET[:SESSION]).
# No secrets are printed. Build first: `cargo build --release`.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"

AKID=$(aws configure get aws_access_key_id)
SKEY=$(aws configure get aws_secret_access_key)
STOK=$(aws configure get aws_session_token || true)
if [ -n "${STOK:-}" ]; then
  export AWS_BEDROCK_CREDS="${AKID}:${SKEY}:${STOK}"
else
  export AWS_BEDROCK_CREDS="${AKID}:${SKEY}"
fi

# The admin token guards the admin API; mint the agent's signed key with:
#   curl -s -X POST http://127.0.0.1:8081/api/v1/admin/keys -H "authorization: Bearer $BUSBAR_ADMIN_TOKEN" -d '{"name":"claude-code"}'
export BUSBAR_ADMIN_TOKEN="${BUSBAR_ADMIN_TOKEN:-demo-admin-token}"
export BUSBAR_CONFIG="$HERE/config.yaml"
export BUSBAR_PROVIDERS="$ROOT/providers.yaml"
export BUSBAR_STATE_FILE=""
export RUST_LOG="${RUST_LOG:-warn}"

exec "$ROOT/target/release/busbar"
