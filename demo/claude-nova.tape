# Claude Code (real interactive window) driven by Amazon Nova through Busbar.
# Render:  vhs demo/claude-nova.tape
Output demo/claude-nova.gif
Set Shell zsh
Set FontSize 13
Set Width 1100
Set Height 680
Set Padding 20
Set TypingSpeed 15ms

# --- setup (hidden): point at Busbar, enter the trusted demo workspace ---------
Hide
Type "setopt interactive_comments" Enter
Type "source ~/Developer/busbarAI/busbarAI/demo/env.sh" Enter
Type "cd ~/Developer/busbarAI/busbarAI/demo/workspace && rm -f *.txt 2>/dev/null; clear" Enter
Sleep 1s
Show

# --- 1. reveal: the claude-code pool is wired to Amazon Nova on Bedrock --------
Type "# Busbar: the claude-code pool is wired to Amazon Nova on AWS Bedrock" Sleep 400ms Enter
Type "sed -n '18,29p' ~/Developer/busbarAI/busbarAI/demo/config.yaml" Enter
Sleep 3s
Type "# ANTHROPIC_BASE_URL points Claude Code at that pool. Now just run it:" Sleep 400ms Enter

# --- 2. launch the REAL Claude Code window ------------------------------------
Type "claude --dangerously-skip-permissions" Enter
Sleep 4s
Down                  # bypass-permissions warning: move to "2. Yes, I accept"
Sleep 400ms
Enter
Sleep 3s

# --- 3. an agentic task -- every turn is answered by Nova ----------------------
Type "create notes.txt containing the words busbar demo, then read it back, then run ls, then tell me DONE"
Sleep 800ms
Enter
Sleep 18s
Screenshot demo/verify-tui.png
Sleep 2s

# --- 4. exit ------------------------------------------------------------------
Ctrl+C
Sleep 400ms
Ctrl+C
Sleep 1200ms
