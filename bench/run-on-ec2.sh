#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# One-click: launch a fresh Graviton box, build busbar + the competitor gateways, run the memory
# head-to-head for every gateway, pull results/ (JSON + chart) back, TERMINATE the box. Nothing
# persists; the numbers reproduce from a cold machine.
#
#   BUSBAR_REPO=/path/to/busbarAI bench/run-on-ec2.sh                       # all gateways
#   BUSBAR_REPO=/path/to/busbarAI bench/run-on-ec2.sh busbar litellm-rust   # subset
#
# Requires awscli v2 (configured), ssh, rsync. Instance is m7g.4xlarge (16 vCPU / 64 GB Graviton3)
# so no gateway OOMs the box; the in-rig watchdog still caps the load.
set -euo pipefail
export AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-us-east-1}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="${BUSBAR_REPO:-$(cd "$HERE/.." && pwd)}"
GATEWAYS_ARG="$*"
ITYPE="${ITYPE:-m7g.4xlarge}"
SSM="/aws/service/canonical/ubuntu/server/24.04/stable/current/arm64/hvm/ebs-gp3/ami-id"
KEYNAME="busbar-bench-key"; KEYFILE="${TMPDIR:-/tmp}/${KEYNAME}.pem"; SGNAME="busbar-bench-sg"
SSHOPT="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=12 -i $KEYFILE"
log(){ echo "[$(date +%H:%M:%S)] $*"; }

if [[ ! -f "$KEYFILE" ]]; then
  aws ec2 delete-key-pair --key-name "$KEYNAME" >/dev/null 2>&1 || true
  aws ec2 create-key-pair --key-name "$KEYNAME" --query KeyMaterial --output text > "$KEYFILE"; chmod 600 "$KEYFILE"
fi
SG=$(aws ec2 describe-security-groups --group-names "$SGNAME" --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null || true)
[[ -z "$SG" || "$SG" == "None" ]] && SG=$(aws ec2 create-security-group --group-name "$SGNAME" --description "busbar bench SSH" --query GroupId --output text)
MYIP=$(curl -s https://checkip.amazonaws.com)
aws ec2 authorize-security-group-ingress --group-id "$SG" --protocol tcp --port 22 --cidr "${MYIP}/32" >/dev/null 2>&1 || true

AMI=$(aws ssm get-parameter --name "$SSM" --query Parameter.Value --output text)
log "launching $ITYPE ($AMI)"
IID=$(aws ec2 run-instances --image-id "$AMI" --instance-type "$ITYPE" --key-name "$KEYNAME" \
  --security-group-ids "$SG" \
  --block-device-mappings 'DeviceName=/dev/sda1,Ebs={VolumeSize=60,VolumeType=gp3}' \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=busbar-bench},{Key=purpose,Value=busbar-bench}]' \
  --query 'Instances[0].InstanceId' --output text)
trap 'log "TERMINATING $IID"; aws ec2 terminate-instances --instance-ids "$IID" >/dev/null 2>&1 || true' EXIT
aws ec2 wait instance-running --instance-ids "$IID"
IP=$(aws ec2 describe-instances --instance-ids "$IID" --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
log "ip=$IP — waiting for ssh"
for _ in $(seq 1 40); do ssh $SSHOPT ubuntu@"$IP" true 2>/dev/null && break || sleep 8; done

log "installing deps (go, rust, docker, python, build tools)"
ssh $SSHOPT ubuntu@"$IP" 'set -e
  sudo apt-get update -q
  sudo apt-get install -y -q build-essential pkg-config libssl-dev python3-venv python3-pip golang-go docker.io git nodejs npm
  sudo usermod -aG docker ubuntu || true
  command -v cargo >/dev/null || (curl -sSf https://sh.rustup.rs | sh -s -- -y)
  python3 -m pip install --user -q --break-system-packages matplotlib psutil 2>/dev/null || pip3 install -q matplotlib psutil || true' 2>&1 | sed 's/^/  [setup] /'

log "rsync busbar repo up (excluding target/.git/node_modules)"
rsync -az --delete -e "ssh $SSHOPT" \
  --exclude target --exclude .git --exclude node_modules --exclude '*/target' --exclude dist \
  "$REPO/" ubuntu@"$IP":~/busbarAI/

log "building busbar (release, jemalloc) on the box"
ssh $SSHOPT ubuntu@"$IP" 'source ~/.cargo/env; cd ~/busbarAI && cargo build --release -p busbar 2>&1 | tail -3' 2>&1 | sed 's/^/  [busbar] /'

log "running the memory head-to-head (all gateways) — takes a while (litellm builds from source)"
ssh $SSHOPT ubuntu@"$IP" "source ~/.cargo/env; cd ~/busbarAI
  export BUSBAR_BIN=~/busbarAI/target/release/busbar
  # Shared cpu pins only. Each suite uses its OWN payload/duration defaults (perf = small payloads
  # for latency; memory = 150KB sustained) — don't leak one suite's PSIZE into the other.
  export CORES=0-7 LOADCORES=8-13 MOCKCORES=14-15
  export SUITES=\"${SUITES:-perf memory}\"
  sudo -n true 2>/dev/null && sudo chmod 666 /var/run/docker.sock || true
  bash bench/run-all.sh $GATEWAYS_ARG" 2>&1 | sed 's/^/  [bench] /'

log "pulling results/ back"
rsync -az -e "ssh $SSHOPT" ubuntu@"$IP":~/busbarAI/bench/results/ "$HERE/results/" || true
log "done — bench/results/memory/*.json + bench/results/memory_rss.png"
