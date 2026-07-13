#!/bin/bash
# One clean render of the Claude-Code→Nova demo. Disables the hindsight plugin for
# the run (long MCP tool names break Bedrock), renders, then restores it.
set +e
cd /Users/matthew/Developer/busbarAI/busbarAI || exit 2
S="$HOME/.claude/settings.json"
toggle(){ python3 -c "import json,sys;p='$S';d=json.load(open(p));d['enabledPlugins']['hindsight-memory@hindsight']=($1);json.dump(d,open(p,'w'),indent=2)"; }

toggle True >/dev/null 2>&1   # normalize first
toggle False                  # disable for render
curl -s -o /dev/null http://127.0.0.1:8080/v1/models -H "Authorization: Bearer vk_demo_local" \
  || { BUSBAR_CLIENT_TOKEN=vk_demo_local nohup ./demo/run-busbar.sh >/tmp/busbar-demo.log 2>&1 & sleep 3; }

rm -f demo/claude-nova.gif
vhs demo/claude-nova.tape > /tmp/vhs.out 2>&1
RC=$?

toggle True                   # restore plugin no matter what
SZ=$(stat -f%z demo/claude-nova.gif 2>/dev/null || echo MISSING)
FR=$(gifsicle --info demo/claude-nova.gif 2>/dev/null | grep -c 'image #')
echo "RENDER_DONE rc=$RC size=$SZ frames=$FR files=$(ls demo/workspace 2>/dev/null | tr '\n' ',')"
