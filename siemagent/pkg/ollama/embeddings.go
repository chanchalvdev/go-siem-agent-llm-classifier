package ollama

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

type Embedder struct {
	baseURL string
	client  *http.Client
}

func NewEmbedder(baseURL string) *Embedder {
	if baseURL == "" {
		baseURL = "http://localhost:11434"
	}
	return &Embedder{
		baseURL: baseURL,
		client:  &http.Client{Timeout: 30 * time.Second},
	}
}

type embedRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
}

type embedResponse struct {
	Embedding []float32 `json:"embedding"`
}

// Embed returns a vector embedding for the given text using nomic-embed-text.
func (e *Embedder) Embed(ctx context.Context, text string) ([]float32, error) {
	body, err := json.Marshal(embedRequest{Model: "nomic-embed-text", Prompt: text})
	if err != nil {
		return nil, fmt.Errorf("marshal embed request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.baseURL+"/api/embeddings", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build embed request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := e.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("embed request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("embed request: HTTP %d", resp.StatusCode)
	}

	var result embedResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode embed response: %w", err)
	}
	if len(result.Embedding) == 0 {
		return nil, fmt.Errorf("embed response contained empty embedding")
	}
	return result.Embedding, nil
}

// EmbedBatch embeds multiple texts concurrently, limited to 5 parallel requests.
func (e *Embedder) EmbedBatch(ctx context.Context, texts []string) ([][]float32, error) {
	const maxParallel = 5
	sem := make(chan struct{}, maxParallel)

	results := make([][]float32, len(texts))
	errs := make([]error, len(texts))

	var wg sync.WaitGroup
	for i, text := range texts {
		wg.Add(1)
		go func(idx int, t string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			vec, err := e.Embed(ctx, t)
			results[idx] = vec
			errs[idx] = err
		}(i, text)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			return nil, fmt.Errorf("embed[%d]: %w", i, err)
		}
	}
	return results, nil
}
