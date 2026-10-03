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
