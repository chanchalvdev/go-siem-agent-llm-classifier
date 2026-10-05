package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/chverma/siemagent/internal/incident"
	"github.com/chverma/siemagent/internal/logsafe"
	"github.com/chverma/siemagent/internal/suppression"
)

// WithSuppressions lets analysts snooze noisy alerts.
func WithSuppressions(svc *suppression.Service) ServerOption {
	return func(srv *Server) { srv.suppressions = svc }
}

type createSuppressionRequest struct {
	suppression.New
	// IncidentID, when set, records the snooze on that incident's timeline.
	IncidentID string `json:"incident_id"`
}

func (s *Server) requireSuppressions(w http.ResponseWriter) bool {
	if s.suppressions == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "suppressions are not enabled"})
		return false
	}
	return true
}

func (s *Server) handleListSuppressions(w http.ResponseWriter, _ *http.Request) {
	if !s.requireSuppressions(w) {
		return
	}
	writeJSON(w, http.StatusOK, s.suppressions.List())
}

func (s *Server) handleCreateSuppression(w http.ResponseWriter, r *http.Request) {
	if !s.requireSuppressions(w) {
		return
	}
	var req createSuppressionRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	who := actor(r)
	sup, err := s.suppressions.Create(r.Context(), who, req.New)
	if s.suppressionError(w, err) {
		return
	}
	if id := strings.TrimSpace(req.IncidentID); id != "" && s.incidents != nil {
		if _, err := s.incidents.Note(r.Context(), id, who, incident.ActivitySuppression, describeSuppression(sup)); err != nil {
			// The suppression exists; a missing incident only loses the note.
			slog.Warn("could not note suppression on incident", "component", "api", "incident", logsafe.String(id), "error", logsafe.Err(err))
		}
	}
	writeJSON(w, http.StatusCreated, sup)
}

func (s *Server) handleLiftSuppression(w http.ResponseWriter, r *http.Request) {
	if !s.requireSuppressions(w) {
		return
	}
	if s.suppressionError(w, s.suppressions.Lift(r.Context(), chi.URLParam(r, "id"))) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) suppressionError(w http.ResponseWriter, err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, suppression.ErrNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "suppression not found"})
	case errors.Is(err, suppression.ErrInvalid):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": strings.TrimPrefix(err.Error(), suppression.ErrInvalid.Error()+": ")})
	default:
		slog.Error("suppression operation failed", "component", "api", "error", logsafe.Err(err))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "the suppression store is unavailable"})
	}
	return true
}

// describeSuppression is the incident-timeline line for a new snooze.
func describeSuppression(sup suppression.Suppression) string {
	var what []string
	if sup.Entity != nil {
		what = append(what, sup.Entity.String())
	}
	if sup.RuleID != "" {
		what = append(what, "rule "+sup.RuleID)
	}
	if sup.AttackType != "" {
		what = append(what, "attack type "+sup.AttackType)
	}
	until := "until lifted"
	if sup.ExpiresAt != nil {
		until = "until " + sup.ExpiresAt.UTC().Format("2006-01-02 15:04 MST")
	}
	return "Suppressed " + strings.Join(what, ", ") + " " + until + " (" + sup.ID + "): " + sup.Reason
}
