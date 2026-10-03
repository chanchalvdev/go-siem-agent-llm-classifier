package api

import (
	"net/http"
	"time"

	"github.com/chverma/siemagent/internal/retention"
)

// WithRetention exposes the data retention policy and its last run.
func WithRetention(r *retention.Runner) ServerOption {
	return func(srv *Server) { srv.retention = r }
}

type retentionStatus struct {
	// Active is false without Postgres: there is nothing durable to purge.
	Active          bool           `json:"active"`
	EventsDays      int            `json:"events_days"`
	IncidentsDays   int            `json:"incidents_days"`
	AuditDays       int            `json:"audit_days"`
	IntervalSeconds int            `json:"interval_seconds,omitempty"`
	LastRun         *retention.Run `json:"last_run"`
}

func days(d time.Duration) int { return int(d / (24 * time.Hour)) }

func (s *Server) handleRetention(w http.ResponseWriter, _ *http.Request) {
	if s.retention == nil {
		writeJSON(w, http.StatusOK, retentionStatus{})
		return
	}
	p := s.retention.Policy()
	writeJSON(w, http.StatusOK, retentionStatus{
		Active:          true,
		EventsDays:      days(p.Events),
		IncidentsDays:   days(p.Incidents),
		AuditDays:       days(p.Audit),
		IntervalSeconds: int(s.retention.Interval() / time.Second),
		LastRun:         s.retention.Last(),
	})
}
