#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Gateway manifest: Bifrost (maximhq/bifrost, docker), its documented pool config.
GW_KIND=docker
GW_PORT=8080
GW_PATH=/v1/chat/completions
GW_MODEL=gpt-4o-mini
GW_AUTH=sk-dummy
# BIFROST_IMAGE comes from gateways/versions.env — override there.
BIFROST_IMAGE="${BIFROST_IMAGE:-maximhq/bifrost:v1.6.4}"

gw_version() { echo "$BIFROST_IMAGE"; }

gw_build() {
  mkdir -p "$GW_DIR/bfdata"; cp "$GW_DIR/config.json" "$GW_DIR/bfdata/config.json"
  sudo docker pull "$BIFROST_IMAGE" >/dev/null 2>&1 || true
}

gw_launch() {
  sudo docker rm -f bifrost >/dev/null 2>&1; sleep 1
  sudo docker run -d --name bifrost --network host --cpuset-cpus="$CORES" \
    -e GOMAXPROCS="${CORES##*-}" -v "$GW_DIR/bfdata:/app/data" "$BIFROST_IMAGE" >/dev/null 2>&1
}

gw_rss() {
  local m; m=$(sudo docker stats --no-stream --format '{{.MemUsage}}' bifrost 2>/dev/null | awk '{print $1}')
  case "$m" in
    *GiB) awk -v x="${m%GiB}" 'BEGIN{printf "%.1f", x*1024}' ;;
    *MiB) echo "${m%MiB}" ;;
    *) echo 0 ;;
  esac
}

gw_stop() { sudo docker rm -f bifrost >/dev/null 2>&1; }
