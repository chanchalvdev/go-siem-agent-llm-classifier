package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/chverma/siemagent/internal/incident"
	"github.com/chverma/siemagent/internal/logsafe"
	"github.com/chverma/siemagent/internal/models"
	"github.com/chverma/siemagent/internal/response"
)

// WithResponse enables response playbooks. Requires incidents.
func WithResponse(e *response.Engine) ServerOption {
	return func(srv *Server) { srv.response = e }
}

// respond runs playbooks for the incident an alert just joined or opened.
func (s *Server) respond(inc incident.Incident, ev models.ClassifiedEvent) {
	if s.response == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if acts := s.response.OnAlert(ctx, inc, ev); len(acts) > 0 {
		slog.Info("response actions proposed", "component", "api", "incident", inc.ID, "count", len(acts))
	}
}

func (s *Server) requireResponse(w http.ResponseWriter) bool {
	if s.response == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "response playbooks are not enabled"})
		return false
	}
	return true
}

func (s *Server) handleListPlaybooks(w http.ResponseWriter, _ *http.Request) {
	if !s.requireResponse(w) {
		return
	}
	type view struct {
		*response.Playbook
		Enabled bool `json:"enabled"`
	}
	out := []view{}
	for _, p := range s.response.Playbooks() {
		out = append(out, view{p, p.IsEnabled()})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleListActions(w http.ResponseWriter, r *http.Request) {
	if !s.requireResponse(w) {
		return
	}
	q := r.URL.Query()
	f := response.Filter{Status: response.Status(q.Get("status")), IncidentID: q.Get("incident"), Limit: 200}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 500 {
			writeJSON(w, http.StatusBadRequest, models.ValidationError{Error: "limit must be 1–500", Field: "limit"})
			return
		}
		f.Limit = n
	}
	list, err := s.response.List(r.Context(), f)
	if err != nil {
		slog.Error("list actions failed", "component", "api", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not list actions"})
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleApproveAction(w http.ResponseWriter, r *http.Request) {
	if !s.requireResponse(w) {
		return
	}
	// Execution calls external systems; give it its own deadline.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	a, err := s.response.Approve(ctx, chi.URLParam(r, "id"), actor(r))
	if s.responseError(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, a)
}

type rejectRequest struct {
	Reason string `json:"reason"`
}

func (s *Server) handleRejectAction(w http.ResponseWriter, r *http.Request) {
	if !s.requireResponse(w) {
		return
	}
	var req rejectRequest
	if r.ContentLength != 0 {
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}
	}
	a, err := s.response.Reject(r.Context(), chi.URLParam(r, "id"), actor(r), req.Reason)
	if s.responseError(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, a)
}

func (s *Server) handleRunPlaybook(w http.ResponseWriter, r *http.Request) {
	if !s.requireResponse(w) {
		return
	}
	acts, err := s.response.RunPlaybook(r.Context(), chi.URLParam(r, "playbook"), chi.URLParam(r, "id"), actor(r))
	if errors.Is(err, incident.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "incident not found"})
		return
	}
	if s.responseError(w, err) {
		return
	}
	if acts == nil {
		acts = []response.Action{}
	}
	writeJSON(w, http.StatusOK, acts)
}

func (s *Server) responseError(w http.ResponseWriter, err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, response.ErrNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "action not found"})
	case errors.Is(err, response.ErrInvalid):
		writeJSON(w, http.StatusConflict, map[string]string{"error": strings.TrimPrefix(err.Error(), response.ErrInvalid.Error()+": ")})
	default:
		slog.Error("response action failed", "component", "api", "error", logsafe.Err(err))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not process the action"})
	}
	return true
}
