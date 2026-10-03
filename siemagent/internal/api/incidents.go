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
	"github.com/chverma/siemagent/internal/metrics"
	"github.com/chverma/siemagent/internal/models"
)

// WithIncidents enables alert correlation and case management.
func WithIncidents(svc *incident.Service) ServerOption {
	return func(srv *Server) { srv.incidents = svc }
}

// correlate attaches a stored event to an incident. It returns the result
// and whether the event joined or opened one.
func (s *Server) correlate(ev models.ClassifiedEvent) (incident.Result, bool) {
	if s.incidents == nil {
		return incident.Result{}, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, ok, err := s.incidents.Observe(ctx, ev)
	if err != nil {
		metrics.StoreErrorsTotal.Inc()
		slog.Error("incident correlation failed", "component", "api", "error", err)
		return incident.Result{}, false
	}
	return res, ok
}

func (s *Server) requireIncidents(w http.ResponseWriter) bool {
	if s.incidents == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "incidents are not enabled"})
		return false
	}
	return true
}

func (s *Server) handleListIncidents(w http.ResponseWriter, r *http.Request) {
	if !s.requireIncidents(w) {
		return
	}
	q := r.URL.Query()
	f := incident.Filter{
		Status:   incident.Status(q.Get("status")),
		Severity: models.Severity(strings.ToUpper(q.Get("severity"))),
		Assignee: q.Get("assignee"),
		Limit:    100,
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 500 {
			writeJSON(w, http.StatusBadRequest, models.ValidationError{Error: "limit must be 1–500", Field: "limit"})
			return
		}
		f.Limit = n
	}
	if v := q.Get("entity"); v != "" {
		e, err := incident.ParseEntity(v)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, models.ValidationError{
				Error: strings.TrimPrefix(err.Error(), incident.ErrInvalid.Error()+": "), Field: "entity"})
			return
		}
		f.Entity = &e
	}
	list, err := s.incidents.List(r.Context(), f)
	if err != nil {
		slog.Error("list incidents failed", "component", "api", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not list incidents"})
		return
	}
	for i := range list {
		list[i].Title = stripControl(list[i].Title)
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleIncidentStats(w http.ResponseWriter, r *http.Request) {
	if !s.requireIncidents(w) {
		return
	}
	st, err := s.incidents.Stats(r.Context())
	if err != nil {
		slog.Error("incident stats failed", "component", "api", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not compute stats"})
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleGetIncident(w http.ResponseWriter, r *http.Request) {
	if !s.requireIncidents(w) {
		return
	}
	d, err := s.incidents.Get(r.Context(), chi.URLParam(r, "id"))
	if s.incidentError(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, sanitizeDetail(d))
}

func (s *Server) handleUpdateIncident(w http.ResponseWriter, r *http.Request) {
	if !s.requireIncidents(w) {
		return
	}
	var u incident.Update
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&u); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	inc, err := s.incidents.Update(r.Context(), chi.URLParam(r, "id"), u, actor(r))
	if s.incidentError(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, inc)
}

type commentRequest struct {
	Body string `json:"body"`
}

func (s *Server) handleAddComment(w http.ResponseWriter, r *http.Request) {
	if !s.requireIncidents(w) {
		return
	}
	var req commentRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	act, err := s.incidents.Comment(r.Context(), chi.URLParam(r, "id"), actor(r), req.Body)
	if s.incidentError(w, err) {
		return
	}
	writeJSON(w, http.StatusCreated, act)
}

// incidentError writes the response for a service error and reports whether
// there was one: 404 for unknown incidents, 400 for bad input, 500 otherwise.
func (s *Server) incidentError(w http.ResponseWriter, err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, incident.ErrNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "incident not found"})
	case errors.Is(err, incident.ErrInvalid):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": strings.TrimPrefix(err.Error(), incident.ErrInvalid.Error()+": ")})
	default:
		slog.Error("incident store failed", "component", "api", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not save the incident"})
	}
	return true
}

// sanitizeDetail strips control characters from every log-derived string:
// titles, alert snapshots and history entries can all echo raw log text.
func sanitizeDetail(d incident.Detail) incident.Detail {
	d.Title = stripControl(d.Title)
	for i := range d.Alerts {
		a := &d.Alerts[i]
		a.Raw, a.Summary, a.AttackType, a.Hostname = stripControl(a.Raw), stripControl(a.Summary), stripControl(a.AttackType), stripControl(a.Hostname)
	}
	for i := range d.Activity {
		d.Activity[i].Body = stripControl(d.Activity[i].Body)
	}
	return d
}
