package tools

import (
	"context"
	"encoding/json"
	"fmt"
)

const defaultSimilarLimit = 5
const maxSimilarLimit = 20

// Embedder turns text into a vector. Satisfied by pkg/ollama.Embedder.
type Embedder interface {
	Embed(ctx context.Context, text string) ([]float32, error)
}

// SearchHit is one vector-search result the tool can read.
type SearchHit struct {
	Score   float32
	Payload map[string]any
}

// VectorSearcher runs a similarity search. Satisfied by an adapter over the
// Qdrant store (kept as an interface so tests inject a mock, no import cycle).
type VectorSearcher interface {
	Search(ctx context.Context, vector []float32, topK uint64, severityFilter string) ([]SearchHit, error)
}

// SimilarEvents lets the agent recall historically similar incidents from the
// vector store to reason over precedent.
type SimilarEvents struct {
	embed  Embedder
	search VectorSearcher
}

// NewSimilarEvents builds the tool from an embedder and a searcher.
func NewSimilarEvents(embed Embedder, search VectorSearcher) *SimilarEvents {
	return &SimilarEvents{embed: embed, search: search}
}

func (s *SimilarEvents) Name() string { return "search_similar_events" }
func (s *SimilarEvents) Description() string {
	return "Find past security events similar to a natural-language incident description."
}
func (s *SimilarEvents) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"query":{"type":"string","description":"incident description"},"limit":{"type":"integer","description":"max results (default 5)"}},"required":["query"]}`)
}

// Execute embeds the query, searches the vector store, and returns the top
// matches as a compact JSON array for the LLM to reason over.
func (s *SimilarEvents) Execute(ctx context.Context, input json.RawMessage) (string, error) {
	var in struct {
		Query string `json:"query"`
		Limit int    `json:"limit"`
	}
	if err := json.Unmarshal(input, &in); err != nil {
		return "", fmt.Errorf("similar_events: bad input: %w", err)
	}
	if in.Query == "" {
		return "", fmt.Errorf("similar_events: query is required")
	}
	limit := in.Limit
	if limit <= 0 {
		limit = defaultSimilarLimit
	}
	if limit > maxSimilarLimit {
		limit = maxSimilarLimit
	}

	vec, err := s.embed.Embed(ctx, in.Query)
	if err != nil {
		return "", fmt.Errorf("similar_events: embed: %w", err)
	}
	hits, err := s.search.Search(ctx, vec, uint64(limit), "")
	if err != nil {
		return "", fmt.Errorf("similar_events: search: %w", err)
	}
	return formatHits(hits), nil
}

// formatHits projects the vector payloads into a stable, compact JSON array.
func formatHits(hits []SearchHit) string {
	out := make([]map[string]any, 0, len(hits))
	for _, h := range hits {
		out = append(out, map[string]any{
			"event_id":     str(h.Payload, "event_id"),
			"timestamp":    str(h.Payload, "timestamp"),
			"source":       str(h.Payload, "source"),
			"attack_type":  str(h.Payload, "attack_type"),
			"severity":     str(h.Payload, "severity"),
			"summary":      str(h.Payload, "summary"),
			"mitre_tactic": str(h.Payload, "mitre_tactic"),
			"score":        h.Score,
		})
	}
	b, _ := json.Marshal(out)
	return string(b)
}

// str safely reads a string field from a payload map.
func str(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}
