Claude Code with an AWS Bedrock backend?!?

I pointed Claude Code at Busbar with one environment variable and gave it a normal agentic task. It planned, ran its tools, reported done. The usual.

Except the model answering every turn wasn't Claude. It was Amazon Nova, on Bedrock. Claude Code never knew.

That's the part I still think is wild. Claude Code speaks the Anthropic API, and Busbar translates that on the fly into a Bedrock call and back. So the coding agent you already use isn't locked to one provider. Point it at Nova, or Gemini, or Claude behind two keys with in-flight failover — you change one line of Busbar config, not one line of Claude Code.

And once it's on the path, everything else comes with it: every token and request in your own metrics, budgets you set, and middleware like on-path context compression.

I recorded the whole run, and AWS's own CloudWatch confirms Nova served every call. No smoke and mirrors.

Wrote up exactly how it works here 👇
https://getbusbar.com/blog/run-claude-code-through-busbar/

#ClaudeCode #AWSBedrock #LLM #AItooling
