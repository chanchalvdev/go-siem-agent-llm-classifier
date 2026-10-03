package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/chverma/siemagent/internal/detection"
	"github.com/chverma/siemagent/internal/logsafe"
	"github.com/chverma/siemagent/internal/store"
)

// detectionRule is the API view of a loaded detection rule.
type detectionRule struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description,omitempty"`
	Level       string   `json:"level"`
	Status      string   `json:"status,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Source      string   `json:"source"`
	Hits        int64    `json:"hits"`
	Enabled     bool     `json:"enabled"`
	// Type is "single" (one event) or "threshold" (count over a timeframe).
	Type      string `json:"type"`
	Threshold string `json:"threshold,omitempty"`
}

func toDetectionRule(r *detection.Rule) detectionRule {
	out := detectionRule{
		ID: r.ID, Title: r.Title, Description: r.Description, Level: r.Level,
		Status: r.Status, Tags: r.Tags, Source: r.Source, Hits: r.Hits(),
		Enabled: r.Enabled(), Type: "single",
	}
	if r.IsThreshold() {
		out.Type, out.Threshold = "threshold", r.Threshold()
	}
	return out
}

// handleDetectionRules lists loaded rules with their match counts since start.
func (s *Server) handleDetectionRules(w http.ResponseWriter, _ *http.Request) {
	out := []detectionRule{}
	if s.detections != nil {
		for _, r := range s.detections.Rules() {
			out = append(out, toDetectionRule(r))
		}
	}
	writeJSON(w, http.StatusOK, out)
}

type ruleUpdate struct {
	Enabled *bool `json:"enabled"`
}

// handleUpdateDetectionRule enables or disables a rule. The change applies
// immediately and is persisted when the store supports it.
func (s *Server) handleUpdateDetectionRule(w http.ResponseWriter, r *http.Request) {
	if s.detections == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "detection rules are disabled"})
		return
	}
	id := chi.URLParam(r, "id")
	rule, ok := s.detections.Rule(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "rule not found"})
		return
	}
	var req ruleUpdate
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil || req.Enabled == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": `body must be {"enabled": true|false}`})
		return
	}
	if rs, ok := s.events.(store.RuleStates); ok {
		if err := rs.SetRuleEnabled(r.Context(), id, *req.Enabled); err != nil {
			slog.Error("save rule state failed", "component", "api", "rule", rule.ID, "error", logsafe.Err(err))
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not save rule state"})
			return
		}
	}
	s.detections.SetEnabled(id, *req.Enabled)
	slog.Info("detection rule updated", "component", "api", "rule", logsafe.String(rule.ID), "enabled", rule.Enabled())
	writeJSON(w, http.StatusOK, toDetectionRule(rule))
}

// applyRuleStates restores saved enable/disable overrides at start.
func (s *Server) applyRuleStates() {
	rs, ok := s.events.(store.RuleStates)
	if s.detections == nil || !ok {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	states, err := rs.RuleStates(ctx)
	if err != nil {
		slog.Warn("could not load rule states; all rules enabled", "component", "api", "error", err)
		return
	}
	disabled := 0
	for id, enabled := range states {
		if s.detections.SetEnabled(id, enabled) && !enabled {
			disabled++
		}
	}
	if disabled > 0 {
		slog.Info("detection rules disabled by saved settings", "component", "api", "count", disabled)
	}
}
