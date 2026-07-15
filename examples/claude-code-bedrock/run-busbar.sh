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

export BUSBAR_CLIENT_TOKEN="${BUSBAR_CLIENT_TOKEN:-vk_demo_local}"
export BUSBAR_CONFIG="$HERE/config.yaml"
export BUSBAR_PROVIDERS="$ROOT/providers.yaml"
export BUSBAR_STATE_FILE=""
export RUST_LOG="${RUST_LOG:-warn}"

exec "$ROOT/target/release/busbar"
