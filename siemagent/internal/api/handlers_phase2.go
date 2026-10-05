package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/chverma/siemagent/internal/models"
	"github.com/chverma/siemagent/internal/pipeline"
)

// ── POST /api/ingest ─────────────────────────────────────────────────────────

func (s *Server) handleIngest(w http.ResponseWriter, r *http.Request) {
	var req models.IngestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if len(req.Logs) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "logs array is empty"})
		return
	}
	if len(req.Logs) > 500 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "maximum 500 log lines per request"})
		return
	}
	if req.Format == "" {
		req.Format = "auto"
	}

	// Parse all lines into events.
	var events []models.LogEvent
	for _, line := range req.Logs {
		if line == "" {
			continue
		}
		evs := s.parser.ParseLineWithFormat(line, req.Format)
		events = append(events, evs...)
	}
	accepted := len(events)

	// Classify using the worker pool, streaming chunked progress.
	flusher, canFlush := w.(http.Flusher)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Transfer-Encoding", "chunked")
	w.WriteHeader(http.StatusOK)

	pool := pipeline.NewWorkerPool(s.cfg.Workers, s.classifier)
	resultsCh := pool.Start(r.Context())

	var results []models.ClassifiedEvent
	var errCount int
	done := make(chan struct{})

	go func() {
		defer close(done)
		count := 0
		for ev := range resultsCh {
			results = append(results, s.record(ev))
			count++
			// Flush progress every 10 events.
			if count%10 == 0 && canFlush {
				progress, _ := json.Marshal(map[string]int{"progress": count, "accepted": accepted})
				_, _ = fmt.Fprintf(w, "%s\n", progress)
				flusher.Flush()
			}
		}
	}()

	for _, ev := range events {
		pool.Submit(ev)
	}
	pool.Close()
	<-done

	classified := len(results)
	errCount = accepted - classified

	// Sanitise log-derived content before returning it (log-injection defence).
	for i := range results {
		results[i] = sanitizeEvent(results[i])
	}

	resp := models.IngestResponse{
		Accepted:   accepted,
		Classified: classified,
		Errors:     errCount,
		Results:    results,
	}
	final, _ := json.Marshal(resp)
	_, _ = fmt.Fprintf(w, "%s\n", final)
	if canFlush {
		flusher.Flush()
	}
}

// ── GET /api/search ───────────────────────────────────────────────────────────

func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	if s.search == nil || s.embed == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "semantic search not configured (Qdrant/Ollama not available)",
		})
		return
	}

	q := r.URL.Query().Get("q")
	if q == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "q parameter is required"})
		return
	}

	limitStr := r.URL.Query().Get("limit")
	limit := uint64(20)
	if limitStr != "" {
		if n, err := strconv.ParseUint(limitStr, 10, 64); err == nil && n > 0 && n <= 100 {
			limit = n
		}
	}

	severityFilter := r.URL.Query().Get("severity")

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	vec, err := s.embed.Embed(ctx, q)
	if err != nil {
		slog.Error("embed failed", "component", "api", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "embedding failed"})
		return
	}

	hits, err := s.search.Search(ctx, vec, limit, severityFilter)
	if err != nil {
		slog.Error("search failed", "component", "api", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "search failed"})
		return
	}

	out := make([]models.SearchHit, 0, len(hits))
	for _, h := range hits {
		hit := models.SearchHit{
			Score: h.Score,
		}
		if v, ok := h.Payload["event_id"].(string); ok {
			hit.EventID = v
		}
		if v, ok := h.Payload["timestamp"].(string); ok {
			hit.Timestamp = v
		}
		if v, ok := h.Payload["source"].(string); ok {
			hit.Source = v
		}
		if v, ok := h.Payload["attack_type"].(string); ok {
			hit.AttackType = v
		}
		if v, ok := h.Payload["severity"].(string); ok {
			hit.Severity = models.Severity(v)
		}
		if v, ok := h.Payload["summary"].(string); ok {
			hit.Summary = v
		}
		if v, ok := h.Payload["mitre_tactic"].(string); ok {
			hit.MITRETactic = v
		}
		out = append(out, hit)
	}

	writeJSON(w, http.StatusOK, out)
}

// ── GET /api/analytics/summary ───────────────────────────────────────────────

func (s *Server) handleAnalyticsSummary(w http.ResponseWriter, r *http.Request) {
	summary, err := s.events.Summary(r.Context())
	if err != nil {
		slog.Error("analytics summary failed", "component", "api", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "analytics unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, summary)
}

// ── GET /api/events ──────────────────────────────────────────────────────────

const (
	defaultEventsLimit = 100
	maxEventsLimit     = 500
)

// handleEvents returns the most recent classified events, newest first, so the
// dashboard can show history that survives a page reload or server restart.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	limit := defaultEventsLimit
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > maxEventsLimit {
			writeJSON(w, http.StatusBadRequest, models.ValidationError{
				Error: fmt.Sprintf("limit must be between 1 and %d", maxEventsLimit), Field: "limit",
			})
			return
		}
		limit = n
	}

	events, err := s.events.Recent(r.Context(), limit)
	if err != nil {
		slog.Error("list events failed", "component", "api", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "events unavailable"})
		return
	}
	for i := range events {
		events[i] = sanitizeEvent(events[i])
	}
	writeJSON(w, http.StatusOK, events)
}
