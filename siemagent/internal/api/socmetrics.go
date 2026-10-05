package api

import (
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/chverma/siemagent/internal/incident"
	"github.com/chverma/siemagent/internal/socmetrics"
	"github.com/chverma/siemagent/internal/store"
)

// maxMetricIncidents bounds how many incidents one report reads.
const maxMetricIncidents = 50_000

// handleSOCMetrics reports MTTD, MTTA, MTTR, volume, false-positive rate and
// workload for the last ?days= (default 30, at most 365).
func (s *Server) handleSOCMetrics(w http.ResponseWriter, r *http.Request) {
	if !s.requireIncidents(w) {
		return
	}
	days := 30
	if v := r.URL.Query().Get("days"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || !socmetrics.ValidDays(n) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "days must be 1–365"})
			return
		}
		days = n
	}
	now := time.Now().UTC()
	since := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC).AddDate(0, 0, -(days - 1))

	incidents, err := s.incidents.List(r.Context(), incident.Filter{ActiveSince: since, Limit: maxMetricIncidents})
	if err != nil {
		slog.Error("soc metrics: list incidents", "component", "api", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "the incident store is unavailable"})
		return
	}
	var volume []store.DayVolume
	if v, ok := s.events.(store.Volumer); ok {
		if volume, err = v.DailyVolume(r.Context(), since); err != nil {
			slog.Error("soc metrics: event volume", "component", "api", "error", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "the event store is unavailable"})
			return
		}
	}
	writeJSON(w, http.StatusOK, socmetrics.Compute(now, days, incidents, volume))
}
