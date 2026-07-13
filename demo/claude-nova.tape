# Claude Code (real TUI) writing real code on Amazon Nova Pro via Busbar,
# with AWS Bedrock usage shown before and after.  Render:  vhs demo/claude-nova.tape
Output demo/claude-nova.gif
Set Shell zsh
Set FontSize 13
Set Width 1220
Set Height 780
Set Padding 20
Set TypingSpeed 15ms
Set Framerate 12

# --- setup (hidden): interactive comments, trusted workspace, point at Busbar --
Hide
Type "setopt interactive_comments" Enter
Type "source ~/Developer/busbarAI/busbarAI/demo/env.sh" Enter
Type "cd ~/Developer/busbarAI/busbarAI/demo/workspace && rm -f *.py *.html 2>/dev/null; rm -rf __pycache__ 2>/dev/null; clear" Enter
Sleep 1s
Show

# --- 1. the reveal + AWS usage BEFORE -----------------------------------------
Type "# Busbar: the claude-code pool is wired to Amazon Nova Pro on AWS Bedrock" Sleep 400ms Enter
Type "sed -n '18,29p' ~/Developer/busbarAI/busbarAI/demo/config.yaml" Enter
Sleep 2500ms
Type "# AWS Bedrock's own usage for nova-pro, BEFORE the run:" Sleep 400ms Enter
Type "~/Developer/busbarAI/busbarAI/demo/bedrock-usage.sh" Enter
Sleep 3500ms

# --- 2. launch the REAL Claude Code TUI and have it write real code -----------
Type "# Launch Claude Code -- it thinks it is talking to Anthropic. Watch it write code:" Sleep 400ms Enter
Type "claude --bare --dangerously-skip-permissions" Enter
Sleep 6s
Type "Write two Python files here: fizzbuzz.py that prints FizzBuzz for 1 to 20, and primes.py that prints every prime under 30. Do not run them. Then run ls -la, and tell me DONE."
Sleep 1s
Enter
Sleep 22s
Screenshot demo/verify-tui.png
Sleep 1s
Type "/exit" Enter
Sleep 1500ms

# --- 3. (hidden) let CloudWatch aggregate the run -----------------------------
Hide
Sleep 110s
Show

# --- 4. AWS usage AFTER -- every Claude Code turn hit Bedrock ------------------
Type "# AWS Bedrock's own usage for nova-pro, AFTER -- every turn hit Bedrock:" Sleep 400ms Enter
Type "~/Developer/busbarAI/busbarAI/demo/bedrock-usage.sh" Enter
Sleep 4s
