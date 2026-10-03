package models

import "time"

type Severity string

const (
	SeverityP1 Severity = "P1"
	SeverityP2 Severity = "P2"
	SeverityP3 Severity = "P3"
	SeverityP4 Severity = "P4"
	SeverityP5 Severity = "P5"
)

type LogEvent struct {
	Raw       string    `json:"raw"`
	Timestamp time.Time `json:"timestamp"`
	Hostname  string    `json:"hostname,omitempty"`
	AppName   string    `json:"app_name,omitempty"`
	ProcID    string    `json:"proc_id,omitempty"`
	Message   string    `json:"message"`
	Source    string    `json:"source"` // "syslog" | "json" | "raw"
}

type MITREInfo struct {
	Tactic      string `json:"tactic"`
	TechniqueID string `json:"technique_id"`
	Technique   string `json:"technique"`
}

type ClassifiedEvent struct {
	Event       LogEvent  `json:"event"`
	AttackType  string    `json:"attack_type"`
	MITRE       MITREInfo `json:"mitre"`
	Severity    Severity  `json:"severity"`
	Confidence  float64   `json:"confidence"`
	IOCs        []string  `json:"iocs"`
	Remediation string    `json:"remediation"`
	Summary     string    `json:"summary"`
	ProcessedAt time.Time `json:"processed_at"`
	// Detections lists the detection rules that matched the event.
	Detections []Detection `json:"detections,omitempty"`
	// ClassifiedBy records what produced the verdict: ClassifiedByRules,
	// ClassifiedByLLM, or ClassifiedByBoth. Empty on events stored before
	// detection rules existed.
	ClassifiedBy string `json:"classified_by,omitempty"`
	// SuppressedBy is the ID of the suppression that matched the event. A
	// suppressed event is stored but opens no incident and runs no playbook.
	SuppressedBy string `json:"suppressed_by,omitempty"`
}

const (
	ClassifiedByRules = "rules"
	ClassifiedByLLM   = "llm"
	ClassifiedByBoth  = "llm+rules"
)

// Detection is one rule match on an event.
type Detection struct {
	RuleID string   `json:"rule_id"`
	Title  string   `json:"title"`
	Level  string   `json:"level"` // informational | low | medium | high | critical
	Tags   []string `json:"tags,omitempty"`
	// Threshold rules only: how many events crossed the threshold, the
	// group they share (e.g. "src_ip=203.0.113.7") and the threshold itself.
	Count     int    `json:"count,omitempty"`
	Group     string `json:"group,omitempty"`
	Threshold string `json:"threshold,omitempty"`
}

// ClassifyRequest is the HTTP request body for POST /classify.
type ClassifyRequest struct {
	Log    string `json:"log"`
	Format string `json:"format"` // "syslog" | "json" | "auto"
}

// ValidationError is the HTTP response body for 400 errors.
type ValidationError struct {
	Error string `json:"error"`
	Field string `json:"field"`
}

// IngestRequest is the HTTP request body for POST /ingest.
type IngestRequest struct {
	Logs   []string `json:"logs"`
	Format string   `json:"format"` // "syslog" | "json" | "auto"
}

// IngestResponse is the HTTP response body for POST /ingest.
type IngestResponse struct {
	Accepted   int               `json:"accepted"`
	Classified int               `json:"classified"`
	Errors     int               `json:"errors"`
	Results    []ClassifiedEvent `json:"results"`
}

// SearchHit is a single result from the semantic search endpoint.
type SearchHit struct {
	EventID     string   `json:"event_id"`
	Timestamp   string   `json:"timestamp"`
	Source      string   `json:"source"`
	AttackType  string   `json:"attack_type"`
	Severity    Severity `json:"severity"`
	Summary     string   `json:"summary"`
	MITRETactic string   `json:"mitre_tactic"`
	Score       float32  `json:"score"`
}

// LLMAnalysis is the JSON shape the LLM must return.
type LLMAnalysis struct {
	AttackType  string   `json:"attack_type"`
	Tactic      string   `json:"tactic"`
	TechniqueID string   `json:"technique_id"`
	Technique   string   `json:"technique"`
	Severity    string   `json:"severity"`
	Confidence  float64  `json:"confidence"`
	IOCs        []string `json:"iocs"`
	Remediation string   `json:"remediation"`
	Summary     string   `json:"summary"`
}
