package main

// Deterministic mock upstream for the memory/latency rigs. Answers any path with a 200 and a
// small JSON body — OpenAI chat-completion shape by default, Anthropic Messages shape for
// `/v1/messages` (so a gateway whose only working path is the Anthropic Messages API — e.g.
// LiteLLM-Rust's azure_ai route — gets a response it can actually parse). No real egress.
import (
	"flag"
	"io"
	"net/http"
	"strings"
)

func main() {
	port := flag.String("port", "8000", "")
	flag.Parse()
	openai := []byte(`{"id":"chatcmpl-x","object":"chat.completion","created":1,"model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":2,"total_tokens":12}}`)
	anthropic := []byte(`{"id":"msg_x","type":"message","role":"assistant","model":"claude","content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn","usage":{"input_tokens":10,"output_tokens":2}}`)
	h := func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		r.Body.Close()
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(200)
		if strings.Contains(r.URL.Path, "/messages") {
			w.Write(anthropic)
		} else {
			w.Write(openai)
		}
	}
	http.HandleFunc("/", h)
	srv := &http.Server{Addr: ":" + *port}
	srv.ListenAndServe()
}
