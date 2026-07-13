Claude Code with an AWS Bedrock backend?!?

Claude Code only speaks Anthropic. Bedrock doesn't speak Anthropic. So this shouldn't work.

It does — because Busbar sits in the middle as an AI control plane and translates losslessly between wire protocols. I pointed Claude Code at a Busbar pool with one environment variable, wired that pool to Amazon Nova on Bedrock, and launched the real Claude Code TUI.

It loaded like always. It planned, wrote a file, read it back, ran ls, reported done — a normal little agentic loop. Every single one of those turns was answered by Amazon Nova, not Claude. The agent never knew.

And because "trust me" isn't a demo, I checked AWS Bedrock's own CloudWatch metrics: the invocations and the input tokens are right there under nova-lite.

Same agent you know. Different brain behind it. You change one line of Busbar config, not one line of Claude Code — and you also get failover, budgets, observability, and middleware on the path for free.

Write-up (with the recording and the receipts): https://getbusbar.com/blog/run-claude-code-through-busbar/

#ClaudeCode #AWSBedrock #LLM #AIInfrastructure #Rust
