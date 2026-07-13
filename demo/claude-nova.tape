# Claude Code, driven by Amazon Nova, through Busbar. Rendered with:  vhs demo/claude-nova.tape
Output demo/claude-nova.gif
Set Shell zsh
Set FontSize 13
Set Width 1300
Set Height 860
Set Padding 22
Set TypingSpeed 18ms
Set PlaybackSpeed 1.0

# --- setup (hidden): Busbar is already running; clean the scratch dir ----------
Hide
Type "mkdir -p /tmp/agentdemo && cd /tmp/agentdemo && rm -f *.txt 2>/dev/null; clear" Enter
Sleep 1s
Show

# --- 1. the reveal: the pool points at Amazon Nova on Bedrock ------------------
Type "# Busbar config: a 'claude-code' pool wired to Amazon Nova on AWS Bedrock" Sleep 500ms Enter
Type "sed -n '14,29p' ~/Developer/busbarAI/busbarAI/demo/config.yaml" Enter
Sleep 3s

# --- 2. point Claude Code at Busbar -------------------------------------------
Type "# Point Claude Code at Busbar. One base URL. It still thinks it's Anthropic." Sleep 500ms Enter
Type "source ~/Developer/busbarAI/busbarAI/demo/env.sh && echo $ANTHROPIC_BASE_URL" Enter
Sleep 2s

# --- 3. a real agentic task — but Nova is the brain ---------------------------
Type "# One agentic prompt -> many back-and-forth calls, every one answered by Nova" Sleep 500ms Enter
Type `claude -p "Do these one at a time with your tools: 1) create notes.txt with the line 'busbar demo'; 2) read it back; 3) create count.txt with the word count of notes.txt; 4) run ls. Then say DONE." --bare --dangerously-skip-permissions --max-turns 15` Enter
Sleep 48s

# --- 4. the receipts: Busbar's count, then AWS Bedrock's own usage ------------
Type "# Every call Busbar routed to the Bedrock backend:" Sleep 500ms Enter
Type `curl -s http://127.0.0.1:8080/metrics -H "Authorization: Bearer vk_demo_local" | grep 'requests_total.*claude-code.*ok'` Enter
Sleep 2500ms
Type "# And AWS Bedrock's own CloudWatch usage for nova-lite — not smoke and mirrors:" Sleep 500ms Enter
Type `aws cloudwatch get-metric-statistics --region us-east-1 --namespace AWS/Bedrock --metric-name Invocations --dimensions Name=ModelId,Value=amazon.nova-lite-v1:0 --start-time $(date -u -v-1H +%Y-%m-%dT%H:%M:%S) --end-time $(date -u +%Y-%m-%dT%H:%M:%S) --period 3600 --statistics Sum --query 'Datapoints[].Sum' --output text` Enter
Sleep 4s
