package tools

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

type mockEmbedder struct {
	vec []float32
	err error
}

func (m mockEmbedder) Embed(context.Context, string) ([]float32, error) {
	return m.vec, m.err
}

type mockSearcher struct {
	hits    []SearchHit
	gotTopK uint64
	err     error
}

func (m *mockSearcher) Search(_ context.Context, _ []float32, topK uint64, _ string) ([]SearchHit, error) {
	m.gotTopK = topK
	return m.hits, m.err
}

func simInput(query string, limit int) json.RawMessage {
	m := map[string]any{"query": query}
	if limit > 0 {
		m["limit"] = limit
	}
	b, _ := json.Marshal(m)
	return b
}

func TestSimilarEventsFormatsHits(t *testing.T) {
	search := &mockSearcher{hits: []SearchHit{{
		Score: 0.91,
		Payload: map[string]any{
			"event_id": "evt-1", "attack_type": "Brute Force",
			"severity": "P1", "summary": "ssh brute force", "mitre_tactic": "Credential Access",
		},
	}}}
	tool := NewSimilarEvents(mockEmbedder{vec: []float32{0.1, 0.2}}, search)

	out, err := tool.Execute(context.Background(), simInput("brute force on ssh", 0))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	for _, want := range []string{"evt-1", "Brute Force", "Credential Access", "0.91"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q: %s", want, out)
		}
	}
	if search.gotTopK != defaultSimilarLimit {
		t.Errorf("topK = %d, want default %d", search.gotTopK, defaultSimilarLimit)
	}
}

func TestSimilarEventsLimitCap(t *testing.T) {
	search := &mockSearcher{}
	tool := NewSimilarEvents(mockEmbedder{vec: []float32{0.1}}, search)
	if _, err := tool.Execute(context.Background(), simInput("x", 999)); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if search.gotTopK != maxSimilarLimit {
		t.Errorf("topK = %d, want capped %d", search.gotTopK, maxSimilarLimit)
	}
}

func TestSimilarEventsMissingQuery(t *testing.T) {
	tool := NewSimilarEvents(mockEmbedder{}, &mockSearcher{})
	if _, err := tool.Execute(context.Background(), simInput("", 0)); err == nil {
		t.Fatal("expected error on empty query")
	}
}

func TestSimilarEventsEmbedError(t *testing.T) {
	tool := NewSimilarEvents(mockEmbedder{err: errors.New("down")}, &mockSearcher{})
	if _, err := tool.Execute(context.Background(), simInput("q", 0)); err == nil {
		t.Fatal("expected embed error to propagate")
	}
}
