package ollama

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func mockOllamaServer(t *testing.T, dims int) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		vec := make([]float32, dims)
		for i := range vec {
			vec[i] = float32(i) * 0.001
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"embedding": vec})
	}))
	return srv, &calls
}

func TestEmbed_ReturnsCorrectLength(t *testing.T) {
	srv, _ := mockOllamaServer(t, 768)
	defer srv.Close()

	e := NewEmbedder(srv.URL)
	vec, err := e.Embed(context.Background(), "test text")
	if err != nil {
		t.Fatalf("Embed: %v", err)
	}
	if len(vec) != 768 {
		t.Errorf("embedding length: want 768, got %d", len(vec))
	}
}

func TestEmbed_NonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "model not found", http.StatusNotFound)
	}))
	defer srv.Close()

	e := NewEmbedder(srv.URL)
	_, err := e.Embed(context.Background(), "test")
	if err == nil {
		t.Fatal("expected error for HTTP 404, got nil")
	}
}

func TestEmbedBatch_CallsServerExactlyNTimes(t *testing.T) {
	srv, calls := mockOllamaServer(t, 768)
	defer srv.Close()

	e := NewEmbedder(srv.URL)
	texts := []string{"alpha", "beta", "gamma", "delta"}

	vecs, err := e.EmbedBatch(context.Background(), texts)
	if err != nil {
		t.Fatalf("EmbedBatch: %v", err)
	}
	if len(vecs) != len(texts) {
		t.Errorf("batch length: want %d, got %d", len(texts), len(vecs))
	}
	if got := calls.Load(); got != int64(len(texts)) {
		t.Errorf("server calls: want %d, got %d", len(texts), got)
	}
}

func TestEmbedBatch_EmptyInput(t *testing.T) {
	srv, calls := mockOllamaServer(t, 768)
	defer srv.Close()

	e := NewEmbedder(srv.URL)
	vecs, err := e.EmbedBatch(context.Background(), nil)
	if err != nil {
		t.Fatalf("EmbedBatch(nil): %v", err)
	}
	if len(vecs) != 0 {
		t.Errorf("expected empty result, got %d vectors", len(vecs))
	}
	if calls.Load() != 0 {
		t.Error("expected no server calls for empty input")
	}
}
