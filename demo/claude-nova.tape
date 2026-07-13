# Claude Code (real TUI) building a Sudoku web app on Amazon Nova Pro via Busbar,
# with AWS Bedrock usage shown before and after.  Render:  vhs demo/claude-nova.tape
Output demo/claude-nova.gif
Set Shell zsh
Set FontSize 13
Set Width 1220
Set Height 780
Set Padding 20
Set TypingSpeed 15ms
Set Framerate 12

# --- setup (hidden): interactive comments, FRESH trusted workspace, point at Busbar
Hide
Type "setopt interactive_comments" Enter
Type "source ~/Developer/busbarAI/busbarAI/demo/env.sh" Enter
Type "date -u +%Y-%m-%dT%H:%M:%S > /tmp/busbar_demo_start" Enter
Type "cd ~/Developer/busbarAI/busbarAI/demo/workspace && rm -f ./*.py(N) ./*.html(N) ./*.md(N); rm -rf __pycache__; clear" Enter
Sleep 1s
Show

# --- 1. the reveal + AWS usage BEFORE -----------------------------------------
Type "# Busbar: the claude-code pool is wired to Amazon Nova Pro on AWS Bedrock" Sleep 400ms Enter
Type "sed -n '18,29p' ~/Developer/busbarAI/busbarAI/demo/config.yaml" Enter
Sleep 2500ms
Type "# AWS Bedrock's own usage for Nova Pro, BEFORE the run:" Sleep 400ms Enter
Type "~/Developer/busbarAI/busbarAI/demo/bedrock-usage.sh" Enter
Sleep 3500ms

# --- 2. launch the REAL Claude Code TUI and give it real work -----------------
Type "# Launch Claude Code -- it thinks it is talking to Anthropic. Watch it build:" Sleep 400ms Enter
Type "claude --bare --dangerously-skip-permissions" Enter
Sleep 6s
Type "write a small sudoku web app across three files here: app.py (a stdlib http.server serving an interactive 9x9 grid), solver.py (a backtracking solver that prints a solved board), and README.md documenting both. Do not run them. Then run ls -la and tell me DONE."
Sleep 1s
Enter
Sleep 40s
Screenshot demo/verify-tui.png
Sleep 2s
Type "/exit"
Sleep 500ms
Enter
Sleep 1500ms

# --- 3. (hidden) let CloudWatch aggregate the run -----------------------------
Hide
Sleep 100s
Show

# --- 4. AWS usage AFTER -- every Claude Code turn hit Bedrock ------------------
Type "# AWS Bedrock's own usage for Nova Pro, AFTER -- every turn hit Bedrock:" Sleep 400ms Enter
Type "~/Developer/busbarAI/busbarAI/demo/bedrock-usage.sh" Enter
Sleep 4s
