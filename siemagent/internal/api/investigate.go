package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/chverma/siemagent/internal/agent"
	"github.com/chverma/siemagent/internal/incident"
	"github.com/chverma/siemagent/internal/logsafe"
	"github.com/chverma/siemagent/internal/metrics"
	"github.com/chverma/siemagent/internal/models"
)

// investigationTimeout bounds one agent run, tool calls included.
const investigationTimeout = 2 * time.Minute

// AIActor is recorded as the author of AI investigations.
const AIActor = "ai-agent"

var (
	errAgentUnavailable = errors.New("the investigation agent is not configured")
	errAgentBusy        = errors.New("too many investigations in flight")
	errAlreadyRunning   = errors.New("an investigation is already running for this incident")
)

// startInvestigation runs fn in the background under the concurrency cap,
// broadcasting every agent event on the hub tagged with incidentID. The
// write-up is saved to the incident history when incidents are enabled.
func (s *Server) startInvestigation(incidentID, eventID string,
	fn func(ctx context.Context, send func(agent.AgentEvent)) error) error {

	if s.agent == nil || s.hub == nil {
		return errAgentUnavailable
	}
	s.agent.mu.Lock()
	if s.agent.running[incidentID] {
		s.agent.mu.Unlock()
		return errAlreadyRunning
	}
	select {
	case s.agent.slots <- struct{}{}:
	default:
		s.agent.mu.Unlock()
		metrics.InvestigationsSkippedTotal.Inc()
		return errAgentBusy
	}
	s.agent.running[incidentID] = true
	s.agent.mu.Unlock()

	go func() {
		defer func() {
			s.agent.mu.Lock()
			delete(s.agent.running, incidentID)
			s.agent.mu.Unlock()
			<-s.agent.slots
		}()
		ctx, cancel := context.WithTimeout(context.Background(), investigationTimeout)
		defer cancel()
		var writeUp strings.Builder
		err := fn(ctx, func(e agent.AgentEvent) {
			if e.Type == "chunk" {
				writeUp.WriteString(e.Data)
			}
			msg, _ := json.Marshal(map[string]string{
				"incident_id": incidentID, "event_id": eventID, "type": e.Type, "data": e.Data,
			})
			s.hub.Broadcast(msg)
		})
		if err != nil {
			slog.Error("investigation failed", "component", "api", "incident", logsafe.String(incidentID), "error", logsafe.Err(err))
			return
		}
		if s.incidents == nil || strings.TrimSpace(writeUp.String()) == "" {
			return
		}
		saveCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := s.incidents.Note(saveCtx, incidentID, AIActor, incident.ActivityInvestigation, writeUp.String()); err != nil {
			slog.Error("save investigation failed", "component", "api", "incident", logsafe.String(incidentID), "error", logsafe.Err(err))
		}
	}()
	return nil
}

// maybeInvestigate auto-launches an investigation for a P1/P2 event. With
// incidents enabled the agent receives the whole incident; otherwise just
// the event. No-op when the agent isn't wired.
func (s *Server) maybeInvestigate(ev models.ClassifiedEvent, incidentID string) {
	if ev.Severity != models.SeverityP1 && ev.Severity != models.SeverityP2 {
		return
	}
	eventID := ev.ProcessedAt.Format(time.RFC3339Nano)
	var err error
	if s.incidents != nil {
		err = s.investigateIncident(incidentID, eventID)
	} else {
		err = s.startInvestigation(incidentID, eventID, func(ctx context.Context, send func(agent.AgentEvent)) error {
			return agent.RunIncidentStream(ctx, s.agent.client, s.agent.model, s.agent.registry, ev, send)
		})
	}
	switch {
	case err == nil, errors.Is(err, errAgentUnavailable):
	case errors.Is(err, errAgentBusy):
		slog.Warn("investigation skipped: too many in flight", "component", "api",
			"limit", maxConcurrentInvestigations, "attack_type", ev.AttackType)
	default:
		slog.Warn("investigation not started", "component", "api", "incident", incidentID, "error", err)
	}
}

// investigateIncident runs the agent over the incident's current state.
func (s *Server) investigateIncident(incidentID, eventID string) error {
	return s.startInvestigation(incidentID, eventID, func(ctx context.Context, send func(agent.AgentEvent)) error {
		d, err := s.incidents.Get(ctx, incidentID)
		if err != nil {
			return err
		}
		brief, err := incident.Brief(d)
		if err != nil {
			return err
		}
		return agent.RunBriefStream(ctx, s.agent.client, s.agent.model, s.agent.registry,
			incident.InvestigationPrompt, brief, send)
	})
}

// handleInvestigateIncident starts an AI investigation on demand, e.g. after
// more alerts arrived or an analyst added context in comments.
func (s *Server) handleInvestigateIncident(w http.ResponseWriter, r *http.Request) {
	if !s.requireIncidents(w) {
		return
	}
	id := chi.URLParam(r, "id")
	if _, err := s.incidents.Get(r.Context(), id); s.incidentError(w, err) {
		return
	}
	err := s.investigateIncident(id, "")
	switch {
	case err == nil:
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "started", "incident_id": id})
	case errors.Is(err, errAgentUnavailable):
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
	case errors.Is(err, errAlreadyRunning):
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
	case errors.Is(err, errAgentBusy):
		w.Header().Set("Retry-After", "30")
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": err.Error() + "; try again shortly"})
	default:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not start the investigation"})
	}
}

// handleIncidentReport returns the incident report as Markdown. With
// ?download=1 it is served as a file attachment.
func (s *Server) handleIncidentReport(w http.ResponseWriter, r *http.Request) {
	if !s.requireIncidents(w) {
		return
	}
	d, err := s.incidents.Get(r.Context(), chi.URLParam(r, "id"))
	if s.incidentError(w, err) {
		return
	}
	report := incident.Report(sanitizeDetail(d), time.Now())
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	if r.URL.Query().Get("download") != "" {
		// d.ID comes from the store (INC-XXXXXXXX), never from the request path as-is.
		w.Header().Set("Content-Disposition", `attachment; filename="`+d.ID+`-report.md"`)
	}
	_, _ = w.Write([]byte(report))
}

type feedbackRequest struct {
	Helpful *bool  `json:"helpful"`
	Note    string `json:"note"`
}

func (s *Server) handleIncidentFeedback(w http.ResponseWriter, r *http.Request) {
	if !s.requireIncidents(w) {
		return
	}
	var req feedbackRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10)).Decode(&req); err != nil || req.Helpful == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": `body must be {"helpful": true|false, "note": "..."}`})
		return
	}
	act, err := s.incidents.Feedback(r.Context(), chi.URLParam(r, "id"), actor(r), *req.Helpful, req.Note)
	if s.incidentError(w, err) {
		return
	}
	writeJSON(w, http.StatusCreated, act)
}
