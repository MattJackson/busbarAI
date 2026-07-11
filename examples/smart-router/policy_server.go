// Smart-router policy sidecar for busbar (`route: webhook`), in Go.
//
// Busbar POSTs a projection of the request + the pool's candidates before each
// request's failover loop; this sidecar classifies the request into a task
// bucket and returns a ranked preference {"order":[idx,...]}. It uses ONLY the
// fields busbar actually sends (see src/routing/webhook.rs): no prompt text ever
// leaves busbar, so classification is on shape (size, counts, tools, streaming,
// max_tokens), not content.
//
// Fail-safe: if this process is slow, down, or wrong, busbar coerces the decision
// to the pool's on_error (default: weighted) after policy.timeout_ms (default
// 1ms by default; raise it for hooks that do I/O). A broken sidecar never blocks a request.
//
// Build/run:  go run policy_server.go [addr]   (default 127.0.0.1:8787)
// Stdlib only, no dependencies.
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"sort"
)

// What busbar sends. Absent numeric signals arrive as JSON null → nil pointer.
type request struct {
	Pool            string  `json:"pool"`
	IngressProtocol string  `json:"ingress_protocol"`
	MessageCount    int     `json:"message_count"`
	HasTools        bool    `json:"has_tools"`
	TotalChars      int     `json:"total_chars"`
	MaxTokens       *int    `json:"max_tokens"`
	Stream          bool    `json:"stream"`
}

type candidate struct {
	Idx                  int      `json:"idx"`
	Model                string   `json:"model"`
	Tier                 *string  `json:"tier"`
	CostPerMtok          *float64 `json:"cost_per_mtok"`
	LatencyMs            *float64 `json:"latency_ms"`
	AvailableConcurrency int      `json:"available_concurrency"`
	BudgetRemaining      *int64   `json:"budget_remaining"`
	RateHeadroom         *float64 `json:"rate_headroom"`
}

type payload struct {
	Request    request     `json:"request"`
	Candidates []candidate `json:"candidates"`
}

type reply struct {
	Order   []int `json:"order,omitempty"`
	Abstain bool  `json:"abstain,omitempty"`
}

// Per-bucket weights [cost, latency, concurrency] + the tiers to boost.
type weights struct {
	cost, lat, conc float64
	tiers           []string
}

const tierBoost = 0.5

func classify(r request) weights {
	switch {
	case r.HasTools: // agent / code traffic: send it to the frontier model
		return weights{0.20, 0.40, 0.40, []string{"fable"}}
	case (r.MaxTokens != nil && *r.MaxTokens >= 4096) || r.TotalChars > 24000: // long-form: opus territory
		return weights{0.40, 0.20, 0.40, []string{"opus"}}
	case !r.Stream && r.MessageCount <= 1: // single-shot batch: cheapest wins
		return weights{0.60, 0.10, 0.30, []string{"haiku"}}
	default: // a human waiting on an interactive answer: the everyday driver
		return weights{0.30, 0.50, 0.20, []string{"sonnet"}}
	}
}

func contains(xs []string, s *string) bool {
	if s == nil {
		return false
	}
	for _, x := range xs {
		if x == *s {
			return true
		}
	}
	return false
}

func rank(p payload) reply {
	if len(p.Candidates) == 0 {
		return reply{Abstain: true}
	}
	w := classify(p.Request)
	var maxCost, maxLat float64
	var maxConc int
	for _, c := range p.Candidates {
		if c.CostPerMtok != nil && *c.CostPerMtok > maxCost {
			maxCost = *c.CostPerMtok
		}
		if c.LatencyMs != nil && *c.LatencyMs > maxLat {
			maxLat = *c.LatencyMs
		}
		if c.AvailableConcurrency > maxConc {
			maxConc = c.AvailableConcurrency
		}
	}
	// Missing per-candidate signals score neutral (0.5): a cold lane is not punished.
	norm := func(v *float64, max float64) float64 {
		if v == nil || max <= 0 {
			return 0.5
		}
		return 1.0 - *v/max // lower cost/latency is better
	}
	score := func(c candidate) float64 {
		concS := 0.5
		if maxConc > 0 {
			concS = float64(c.AvailableConcurrency) / float64(maxConc)
		}
		s := w.cost*norm(c.CostPerMtok, maxCost) + w.lat*norm(c.LatencyMs, maxLat) + w.conc*concS
		if contains(w.tiers, c.Tier) {
			s += tierBoost // the operator's quality judgment
		}
		if c.RateHeadroom != nil {
			s *= 0.5 + 0.5**c.RateHeadroom // back off lanes near their rate cap
		}
		return s
	}
	cands := append([]candidate(nil), p.Candidates...)
	sort.SliceStable(cands, func(i, j int) bool {
		si, sj := score(cands[i]), score(cands[j])
		if si != sj {
			return si > sj // best first
		}
		return cands[i].Idx < cands[j].Idx // deterministic tie-break
	})
	order := make([]int, len(cands))
	for i, c := range cands {
		order[i] = c.Idx
	}
	log.Printf("[smart-router] bucket-weights=%.2f/%.2f/%.2f order=%v (chars=%d tools=%v stream=%v)",
		w.cost, w.lat, w.conc, order, p.Request.TotalChars, p.Request.HasTools, p.Request.Stream)
	return reply{Order: order}
}

func handler(w http.ResponseWriter, r *http.Request) {
	var p payload
	body := reply{Abstain: true} // never 500 on bad input: abstain is the clean path
	if err := json.NewDecoder(r.Body).Decode(&p); err == nil {
		body = rank(p)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}

func main() {
	addr := "127.0.0.1:8787"
	if len(os.Args) > 1 {
		addr = os.Args[1]
	}
	log.Printf("[smart-router] listening on http://%s/", addr)
	http.HandleFunc("/", handler)
	log.Fatal(http.ListenAndServe(addr, nil))
}
