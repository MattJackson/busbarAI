#!/usr/bin/env bash
# Self-contained clean render: disable the long-name MCP plugin, render, restore it,
# then optimize + place the GIF. Runs in background so it can't hit a foreground timeout.
set -e
cd /Users/matthew/Developer/busbarAI/busbarAI
S="$HOME/.claude/settings.json"
python3 -c "import json;d=json.load(open('$S'));d['enabledPlugins']['hindsight-memory@hindsight']=False;json.dump(d,open('$S','w'),indent=2)"
curl -s -o /dev/null http://127.0.0.1:8080/v1/models -H "Authorization: Bearer vk_demo_local" || { BUSBAR_CLIENT_TOKEN=vk_demo_local nohup ./demo/run-busbar.sh >/tmp/busbar-demo.log 2>&1 & sleep 3; }
rm -f /tmp/busbar-demo-anchor
vhs demo/claude-nova.tape || true
# restore plugin no matter what
python3 -c "import json;d=json.load(open('$S'));d['enabledPlugins']['hindsight-memory@hindsight']=True;json.dump(d,open('$S','w'),indent=2)"
# optimize + place
if [ -f demo/claude-nova.gif ]; then
  gifsicle -O3 --lossy=60 --colors 192 demo/claude-nova.gif -o /tmp/cn-final.gif
  cp /tmp/cn-final.gif site/public/demo/claude-nova.gif
  cp /tmp/cn-final.gif demo/claude-nova.gif
  echo "RENDER_DONE size=$(stat -f%z /tmp/cn-final.gif) built=$(ls demo/workspace/ | tr '\n' ' ')"
else
  echo "RENDER_FAILED no gif produced"
fi
