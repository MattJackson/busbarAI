# Claude Code (real interactive TUI) driven by Amazon Nova through Busbar.
# Render:  vhs demo/claude-nova.tape
Output demo/claude-nova.gif
Set Shell zsh
Set FontSize 13
Set Width 1200
Set Height 740
Set Padding 20
Set TypingSpeed 16ms

# --- setup (hidden): interactive comments, trusted workspace, point at Busbar --
Hide
Type "setopt interactive_comments" Enter
Type "source ~/Developer/busbarAI/busbarAI/demo/env.sh" Enter
Type "cd ~/Developer/busbarAI/busbarAI/demo/workspace && rm -f *.txt 2>/dev/null; clear" Enter
Sleep 1s
Show

# --- 1. the reveal: the pool is wired to Amazon Nova on Bedrock ----------------
Type "# Busbar: the claude-code pool is wired to Amazon Nova on AWS Bedrock" Sleep 400ms Enter
Type "sed -n '18,29p' ~/Developer/busbarAI/busbarAI/demo/config.yaml" Enter
Sleep 3s
Type "# One variable points Claude Code at that Busbar pool:" Sleep 400ms Enter
Type "echo $ANTHROPIC_BASE_URL" Enter
Sleep 2s

# --- 2. launch the REAL Claude Code TUI ---------------------------------------
Type "# Launch Claude Code. It thinks it is talking to Anthropic -- watch:" Sleep 400ms Enter
Type "claude --bare --dangerously-skip-permissions" Enter
Sleep 5s
Down                  # bypass-permissions warning: move to "2. Yes, I accept"
Sleep 400ms
Enter
Sleep 4s
Screenshot demo/verify-ready.png

# --- 3. give it an agentic task; every turn is answered by Nova ----------------
Type "create notes.txt containing the words busbar demo, then read it back, then run ls, then tell me DONE"
Sleep 1s
Enter
Sleep 42s
Screenshot demo/verify-tui.png
Sleep 3s

# --- 4. exit the TUI ----------------------------------------------------------
Ctrl+C
Sleep 500ms
Ctrl+C
Sleep 1500ms
