package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	EventsClassifiedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "events_classified_total",
			Help: "Total number of classified events by severity and attack type.",
		},
		[]string{"severity", "attack_type"},
	)

	ClassificationDurationSeconds = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "classification_duration_seconds",
			Help:    "Duration of log event classification in seconds.",
			Buckets: []float64{0.1, 0.5, 1, 2, 5, 10},
		},
	)

	LLMStreamErrorsTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "llm_stream_errors_total",
			Help: "Total number of errors from the LLM streaming API.",
		},
	)

	DetectionMatchesTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "detection_matches_total",
			Help: "Detection rule matches, by rule ID and level.",
		},
		[]string{"rule", "level"},
	)

	LLMCallsSavedTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "llm_calls_saved_total",
			Help: "Events classified by detection rules alone, without an LLM call.",
		},
	)

	StoreErrorsTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "store_errors_total",
			Help: "Total number of classified events that failed to persist.",
		},
	)

	AuthFailuresTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "auth_failures_total",
			Help: "Total number of requests rejected for a missing or invalid API key.",
		},
	)

	IngestReceivedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ingest_received_total",
			Help: "Log lines received by the streaming listeners, by transport.",
		},
		[]string{"transport"},
	)

	InvestigationsSkippedTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "investigations_skipped_total",
			Help: "P1/P2 events not investigated because the concurrent investigation limit was reached.",
		},
	)

	IngestDroppedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ingest_dropped_total",
			Help: "Log lines dropped because the classification queue was full, by transport.",
		},
		[]string{"transport"},
	)
)
