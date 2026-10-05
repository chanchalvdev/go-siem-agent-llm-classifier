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

	IOCMatchesTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ioc_matches_total",
			Help: "Watchlist matches on events, by indicator type (ip, cidr, domain, hash).",
		},
		[]string{"type"},
	)

	IOCFeedErrorsTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "ioc_feed_errors_total",
			Help: "Failed watchlist feed downloads.",
		},
	)

	EventsSuppressedTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "events_suppressed_total",
			Help: "Events matched by a suppression: stored, but kept out of incidents, playbooks and investigations.",
		},
	)

	RetentionDeletedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "retention_deleted_total",
			Help: "Rows deleted by the retention policy, by kind (events, incidents, audit, sessions).",
		},
		[]string{"kind"},
	)

	RetentionErrorsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "retention_errors_total",
			Help: "Failed retention purges, by kind.",
		},
		[]string{"kind"},
	)

	AuthLoginsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "auth_logins_total",
			Help: "Dashboard login attempts, by result (success, failed, locked).",
		},
		[]string{"result"},
	)

	ResponseActionsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "response_actions_total",
			Help: "Response action state changes, by action type and resulting status.",
		},
		[]string{"type", "status"},
	)

	AIFeedbackTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ai_investigation_feedback_total",
			Help: "Analyst ratings of AI investigations, by rating (helpful, unhelpful).",
		},
		[]string{"rating"},
	)

	IncidentsCreatedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "incidents_created_total",
			Help: "Incidents opened by correlation, by initial severity.",
		},
		[]string{"severity"},
	)

	IncidentAlertsCorrelatedTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "incident_alerts_correlated_total",
			Help: "Alerts that joined an existing open incident instead of opening a new one.",
		},
	)

	IncidentsResolvedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "incidents_resolved_total",
			Help: "Incidents resolved by analysts, by resolution.",
		},
		[]string{"resolution"},
	)

	DetectionGroupsDroppedTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "detection_aggregation_groups_dropped_total",
			Help: "Events a threshold rule could not track because its group table was full.",
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
