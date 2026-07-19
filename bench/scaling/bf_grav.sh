#!/usr/bin/env bash
set -uo pipefail
log(){ echo "[$(date +%H:%M:%S)] $*"; }
mkdir -p ~/results ~/bfdata
cat > ~/bfdata/config.json <<JSON
{ "providers": { "openai": { "keys":[{"value":"sk-dummy","models":["gpt-4o-mini"],"weight":1}],
  "network_config":{"base_url":"http://localhost:8000"},
  "concurrency_and_buffer_size":{"initial_pool_size":15000,"buffer_size":20000} } } }
JSON
pkill -f '/mocker' 2>/dev/null; sleep 1
cd ~/bifrost-benchmarking/mocker && setsid taskset -c 28-31 ./mocker -port 8000 </dev/null >/dev/null 2>&1 &
sleep 2
echo "cores,rps,failct,ugen_p50_ms,ugen_p99_ms,memMB" > ~/results/bf_grav.csv
for N in 2 4 6 8 10 12 14 16; do
  sudo docker rm -f bifrost >/dev/null 2>&1; sleep 1
  sudo docker run -d --name bifrost --network host --cpuset-cpus="0-$((N-1))" -e GOMAXPROCS=$N -v ~/bfdata:/app/data maximhq/bifrost:v1.6.4 >/dev/null 2>&1
  for i in $(seq 1 25); do c=$(curl -s -m3 -o /dev/null -w "%{http_code}" http://127.0.0.1:8080/v1/chat/completions -X POST -H "content-type: application/json" -d "{\"model\":\"gpt-4o-mini\",\"messages\":[{\"role\":\"user\",\"content\":\"w$i-$N\"}],\"max_tokens\":16}"); [ "$c" = "200" ] && break; sleep 1; done
  sleep 2
  MEM=$(sudo docker stats --no-stream --format "{{.MemUsage}}" bifrost 2>/dev/null | awk '{print $1}')
  T=$(taskset -c 16-27 ~/ugen -url http://127.0.0.1:8080/v1/chat/completions -model gpt-4o-mini -c 500 -d 12)
  RPS=$(echo "$T"|grep -oE 'rps=[0-9]+'|cut -d= -f2); FC=$(echo "$T"|grep -oE 'fail=[0-9]+'|cut -d= -f2)
  P50=$(echo "$T"|grep -oE 'p50=[0-9.]+'|cut -d= -f2); P99=$(echo "$T"|grep -oE 'p99=[0-9.]+'|cut -d= -f2)
  echo "$N,$RPS,$FC,$P50,$P99,$MEM" | tee -a ~/results/bf_grav.csv
done
sudo docker rm -f bifrost >/dev/null 2>&1; log "BF_GRAV_DONE"
