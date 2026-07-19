#!/usr/bin/env bash
set -uo pipefail
log(){ echo "[$(date +%H:%M:%S)] $*"; }
mkdir -p ~/results
pkill -f '/mocker' 2>/dev/null; sleep 1
cd ~/bifrost-benchmarking/mocker && setsid taskset -c 28-31 ./mocker -port 8000 </dev/null >/dev/null 2>&1 &
sleep 2
echo "cores,rps,failct,ugen_p50_ms,ugen_p99_ms,busbardur_p50_us,busbardur_p99_us,memMB" > ~/results/bb_grav.csv
for N in 2 4 6 8 10 12 14 16; do
  pkill -x busbar 2>/dev/null; sleep 1
  setsid taskset -c 0-$((N-1)) env BUSBAR_WORKER_THREADS=$N BUSBAR_PROVIDERS="$HOME/bb.providers.8000.yaml" BUSBAR_CONFIG="$HOME/bb.config.yaml" BENCH_MOCK_KEY=x "$HOME/busbar" </dev/null >~/busbar.$N.log 2>&1 &
  sleep 3
  ss -ltn | grep -q :8080 || { log "busbar DOWN N=$N"; continue; }
  PID=$(pgrep -x busbar)
  LAT=$(taskset -c 16 python3 ~/latency.py http://127.0.0.1:8080/v1/chat/completions 5000 2>/dev/null)
  D50=$(echo "$LAT" | python3 -c "import json,sys;print(json.load(sys.stdin).get('p50_us',0))" 2>/dev/null)
  D99=$(echo "$LAT" | python3 -c "import json,sys;print(json.load(sys.stdin).get('p99_us',0))" 2>/dev/null)
  ( for i in $(seq 1 40); do awk '/VmRSS/{printf "%.1f\n",$2/1024}' /proc/$PID/status 2>/dev/null; sleep 0.4; done | sort -n | tail -1 > ~/peak.txt ) &
  RSS=$!
  T=$(taskset -c 16-27 ~/ugen -url http://127.0.0.1:8080/v1/chat/completions -model bench-pool -c 500 -d 12)
  wait "$RSS"
  RPS=$(echo "$T"|grep -oE 'rps=[0-9]+'|cut -d= -f2); FC=$(echo "$T"|grep -oE 'fail=[0-9]+'|cut -d= -f2)
  P50=$(echo "$T"|grep -oE 'p50=[0-9.]+'|cut -d= -f2); P99=$(echo "$T"|grep -oE 'p99=[0-9.]+'|cut -d= -f2)
  echo "$N,$RPS,$FC,$P50,$P99,$D50,$D99,$(cat ~/peak.txt)" | tee -a ~/results/bb_grav.csv
done
pkill -x busbar 2>/dev/null; log "BB_GRAV_DONE"
