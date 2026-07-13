# Point Claude Code at Busbar. The only real "integration" — one base URL.
export ANTHROPIC_BASE_URL="http://127.0.0.1:8080/claude-code"
export ANTHROPIC_API_KEY="vk_demo_local"        # a Busbar-issued token
export ANTHROPIC_MODEL="claude-code"            # the Busbar pool name
export CLAUDE_CODE_MAX_OUTPUT_TOKENS=4096       # Nova Lite caps output at 10k
export DISABLE_PROMPT_CACHING=1                 # Nova Lite has no prompt cache
