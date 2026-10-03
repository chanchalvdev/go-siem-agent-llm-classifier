package api

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/chverma/siemagent/internal/store"
)

type healthCache struct {
	mu        sync.Mutex
	checks    map[string]string
	status    int
	expiresAt time.Time
}

var hc = &healthCache{}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	hc.mu.Lock()
	if time.Now().Before(hc.expiresAt) {
		checks, status := hc.checks, hc.status
		hc.mu.Unlock()
		writeJSON(w, status, map[string]interface{}{
			"status": readyStatusText(status),
			"checks": checks,
		})
		return
	}
	hc.mu.Unlock()

	checks := make(map[string]string)
	allOK := true

	// Check LLM reachability. Reasoning models (e.g. Gemini 3.x) take ~4s
	// even for a 1-token reply, so allow headroom.
	llmCtx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	if err := s.classifier.Ping(llmCtx); err != nil {
		checks["llm"] = "error: " + err.Error()
		allOK = false
	} else {
		checks["llm"] = "ok"
	}

	// Check the event database when one is configured.
	if p, ok := s.events.(store.Pinger); ok {
		dbCtx, dbCancel := context.WithTimeout(r.Context(), 2*time.Second)
		if err := p.Ping(dbCtx); err != nil {
			checks["postgres"] = "error: " + err.Error()
			allOK = false
		} else {
			checks["postgres"] = "ok"
		}
		dbCancel()
	}

	// Check Qdrant gRPC port
	if s.cfg.QdrantAddr != "" {
		conn, err := net.DialTimeout("tcp", s.cfg.QdrantAddr, 2*time.Second)
		if err != nil {
			checks["qdrant"] = "error: " + err.Error()
			allOK = false
		} else {
			_ = conn.Close()
			checks["qdrant"] = "ok"
		}
	}

	status := http.StatusOK
	if !allOK {
		status = http.StatusServiceUnavailable
	}

	hc.mu.Lock()
	hc.checks = checks
	hc.status = status
	hc.expiresAt = time.Now().Add(10 * time.Second)
	hc.mu.Unlock()

	writeJSON(w, status, map[string]interface{}{
		"status": readyStatusText(status),
		"checks": checks,
	})
}

func readyStatusText(code int) string {
	if code == http.StatusOK {
		return "ready"
	}
	return "not ready"
}
