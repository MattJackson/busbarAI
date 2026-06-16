#!/bin/sh
# Busbar installer — downloads the latest release binary for your platform plus the
# provider catalog, into the current directory (or $BUSBAR_INSTALL_DIR).
#
#   curl -fsSL https://ai-bus.bar/install.sh | sh
#
# No sudo, no global install: it drops `busbar` and `providers.yaml` where you run it,
# then prints the next steps. Override the target dir with BUSBAR_INSTALL_DIR=/usr/local/bin.
set -eu

REPO="MattJackson/busbarAI"
INSTALL_DIR="${BUSBAR_INSTALL_DIR:-$(pwd)}"

say() { printf '\033[1;36mbusbar\033[0m %s\n' "$1"; }
err() { printf '\033[1;31mbusbar: %s\033[0m\n' "$1" >&2; exit 1; }

# --- detect platform → Rust target triple --------------------------------------------
os="$(uname -s)"
arch="$(uname -m)"
case "$os" in
  Linux)  plat="unknown-linux-gnu" ;;
  Darwin) plat="apple-darwin" ;;
  *) err "unsupported OS '$os'. Windows: download the .zip from https://github.com/$REPO/releases/latest" ;;
esac
case "$arch" in
  x86_64|amd64)   cpu="x86_64" ;;
  arm64|aarch64)  cpu="aarch64" ;;
  *) err "unsupported architecture '$arch'" ;;
esac
target="${cpu}-${plat}"

# --- resolve the latest release tag --------------------------------------------------
say "finding the latest release…"
tag="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
  | grep -m1 '"tag_name"' | cut -d'"' -f4)"
[ -n "$tag" ] || err "could not determine the latest release tag"
say "latest is $tag for $target"

asset="busbar-${tag}-${target}.tar.gz"
url="https://github.com/$REPO/releases/download/$tag/$asset"

# --- download + extract the binary ---------------------------------------------------
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
say "downloading $asset…"
curl -fsSL "$url" -o "$tmp/busbar.tar.gz" || err "download failed: $url"
tar -xzf "$tmp/busbar.tar.gz" -C "$tmp"
bin="$(find "$tmp" -type f -name busbar | head -1)"
[ -n "$bin" ] || err "binary not found in archive"

mkdir -p "$INSTALL_DIR"
install -m 0755 "$bin" "$INSTALL_DIR/busbar" 2>/dev/null || { cp "$bin" "$INSTALL_DIR/busbar"; chmod 0755 "$INSTALL_DIR/busbar"; }

# --- fetch the provider catalog (needed at runtime) ----------------------------------
say "downloading providers.yaml…"
curl -fsSL "https://ai-bus.bar/providers.yaml" -o "$INSTALL_DIR/providers.yaml" \
  || say "warning: could not fetch providers.yaml — get it from https://ai-bus.bar/providers.yaml before running"

say "installed busbar $tag → $INSTALL_DIR/busbar"
cat <<EOF

Next steps:
  1. Write a config.yaml (see https://ai-bus.bar/getting-started/). Minimal:

       providers:
         anthropic:
           api_key_env: ANTHROPIC_KEY      # the NAME of the env var holding your key
       models:
         claude-sonnet: { provider: anthropic, max_concurrent: 10 }

  2. Export your provider key and run:

       export ANTHROPIC_KEY=sk-ant-...
       BUSBAR_PROVIDERS=$INSTALL_DIR/providers.yaml BUSBAR_CONFIG=./config.yaml $INSTALL_DIR/busbar

  3. Send a request (OpenAI-style):

       curl http://localhost:8080/v1/chat/completions \\
         -H 'content-type: application/json' \\
         -d '{"model":"claude-sonnet","messages":[{"role":"user","content":"Hello!"}]}'

Docs: https://ai-bus.bar  ·  Agent-readable: https://ai-bus.bar/llms.txt
EOF
