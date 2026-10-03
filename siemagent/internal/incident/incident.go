// Package incident groups related alerts into incidents and tracks the
// analyst's work on them: status, assignment, comments and history.
//
// Analysts work incidents, not log lines. Alerts that share an entity (source
// IP, user or host) within a time window are correlated into one incident, so
// a brute force, the login that follows and a privilege escalation on the
// same host read as one story instead of three unrelated rows.
package incident

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/chverma/siemagent/internal/mitre"
	"github.com/chverma/siemagent/internal/models"
)

// Status is where an incident is in the analyst workflow.
type Status string

const (
	StatusNew           Status = "new"
	StatusInvestigating Status = "investigating"
	StatusResolved      Status = "resolved"
)

// Resolution records why a resolved incident was closed.
type Resolution string

const (
	ResolutionNone          Resolution = ""
	ResolutionTruePositive  Resolution = "true_positive"
	ResolutionFalsePositive Resolution = "false_positive"
	ResolutionBenign        Resolution = "benign"
	ResolutionDuplicate     Resolution = "duplicate"
)

// Entity kinds used for correlation.
const (
	EntityIP   = "ip"
	EntityUser = "user"
	EntityHost = "host"
)

// Entity is something alerts can share: an IP, a user or a host.
type Entity struct {
	Kind  string `json:"kind"` // ip | user | host
	Value string `json:"value"`
}

func (e Entity) String() string { return e.Kind + ":" + e.Value }

// ParseEntity reads "ip:1.2.3.4" style filters.
func ParseEntity(s string) (Entity, error) {
	kind, value, ok := strings.Cut(s, ":")
	if !ok || value == "" {
		return Entity{}, invalid("entity must look like ip:1.2.3.4, user:alice or host:web01")
	}
	switch kind {
	case EntityIP, EntityUser, EntityHost:
		return Entity{Kind: kind, Value: value}, nil
	}
	return Entity{}, invalid("entity kind must be ip, user or host")
}

// Incident is a correlated group of alerts and the case built on it.
type Incident struct {
	ID         string          `json:"id"`
	Title      string          `json:"title"`
	Severity   models.Severity `json:"severity"`
	Status     Status          `json:"status"`
	Resolution Resolution      `json:"resolution,omitempty"`
	Assignee   string          `json:"assignee,omitempty"`
	Entities   []Entity        `json:"entities"`
	// Tactics reached so far, in kill-chain order.
	Tactics    []string   `json:"tactics"`
	Techniques []string   `json:"techniques"`
	AlertCount int        `json:"alert_count"`
	FirstSeen  time.Time  `json:"first_seen"`
	LastSeen   time.Time  `json:"last_seen"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
	ResolvedAt *time.Time `json:"resolved_at,omitempty"`
}

// Open reports whether new alerts may still join the incident.
func (i *Incident) Open() bool { return i.Status != StatusResolved }

// Alert is a snapshot of one classified event inside an incident.
type Alert struct {
	ID          int64           `json:"id"`
	IncidentID  string          `json:"incident_id"`
	At          time.Time       `json:"at"`
	Severity    models.Severity `json:"severity"`
	AttackType  string          `json:"attack_type"`
	Summary     string          `json:"summary"`
	Tactic      string          `json:"tactic,omitempty"`
	TechniqueID string          `json:"technique_id,omitempty"`
	Rules       []string        `json:"rules,omitempty"`
	Hostname    string          `json:"hostname,omitempty"`
	Raw         string          `json:"raw"`
	Entities    []Entity        `json:"entities"`
}

// Activity kinds recorded in an incident's history.
const (
	ActivityCreated    = "created"
	ActivityStatus     = "status"
	ActivityAssignee   = "assignee"
	ActivitySeverity   = "severity"
	ActivityComment    = "comment"
	ActivityEscalated  = "escalated"
	ActivityResolution = "resolution"
	// ActivityInvestigation holds an AI agent's investigation write-up.
	ActivityInvestigation = "investigation"
	// ActivityFeedback is an analyst's rating of an AI investigation.
	ActivityFeedback = "feedback"
	// ActivityResponse records response actions: proposed, approved, run.
	ActivityResponse = "response"
)

// Activity is one entry in an incident's audit history.
type Activity struct {
	ID         int64     `json:"id,omitempty"` // zero in the response that creates it
	IncidentID string    `json:"incident_id"`
	At         time.Time `json:"at"`
	Actor      string    `json:"actor"`
	Kind       string    `json:"kind"`
	Body       string    `json:"body"`
}

// Detail is an incident with its alerts and history.
type Detail struct {
	Incident
	Alerts   []Alert    `json:"alerts"`
	Activity []Activity `json:"activity"`
}

// Update is an analyst change to an incident. Nil fields are left as they are.
type Update struct {
	Status     *Status          `json:"status,omitempty"`
	Resolution *Resolution      `json:"resolution,omitempty"`
	Assignee   *string          `json:"assignee,omitempty"`
	Severity   *models.Severity `json:"severity,omitempty"`
}

// ErrInvalid wraps every error caused by bad input (as opposed to storage
// failures), so callers can report it to the user.
var ErrInvalid = errors.New("invalid input")

func invalid(msg string) error { return fmt.Errorf("%w: %s", ErrInvalid, msg) }

// Validate rejects unknown values before anything is stored.
func (u Update) Validate() error {
	if u.Status == nil && u.Resolution == nil && u.Assignee == nil && u.Severity == nil {
		return invalid("nothing to update")
	}
	if u.Status != nil {
		switch *u.Status {
		case StatusNew, StatusInvestigating, StatusResolved:
		default:
			return invalid("status must be new, investigating or resolved")
		}
	}
	if u.Resolution != nil {
		switch *u.Resolution {
		case ResolutionNone, ResolutionTruePositive, ResolutionFalsePositive, ResolutionBenign, ResolutionDuplicate:
		default:
			return invalid("resolution must be true_positive, false_positive, benign or duplicate")
		}
	}
	if u.Severity != nil && severityRank(*u.Severity) > 5 {
		return invalid("severity must be P1–P5")
	}
	if u.Assignee != nil && len(*u.Assignee) > 100 {
		return invalid("assignee is too long")
	}
	return nil
}

// Filter narrows an incident list. Zero values match everything.
type Filter struct {
	Status   Status
	Severity models.Severity
	Assignee string
	Entity   *Entity
	Limit    int
}

// Stats summarises the incident queue for SOC metrics.
type Stats struct {
	Open          int            `json:"open"`
	ByStatus      map[Status]int `json:"by_status"`
	OpenBySev     map[string]int `json:"open_by_severity"`
	Resolved      int            `json:"resolved"`
	FalsePositive int            `json:"false_positive"`
	// MTTRSeconds is the mean time from creation to resolution.
	MTTRSeconds float64 `json:"mttr_seconds"`
}

// newID returns an incident identifier such as "INC-3F9A1C2B".
func newID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return "INC-" + strings.ToUpper(hex.EncodeToString(b))
}

func severityRank(s models.Severity) int {
	switch s {
	case models.SeverityP1:
		return 1
	case models.SeverityP2:
		return 2
	case models.SeverityP3:
		return 3
	case models.SeverityP4:
		return 4
	case models.SeverityP5:
		return 5
	}
	return 6
}

// higher reports whether a is more severe than b.
func higher(a, b models.Severity) bool { return severityRank(a) < severityRank(b) }

// mergeTactics adds a tactic and keeps the list in kill-chain order.
func mergeTactics(have []string, tactic string) []string {
	if mitre.TacticStage(tactic) < 0 {
		return have
	}
	for _, t := range have {
		if strings.EqualFold(t, tactic) {
			return have
		}
	}
	out := append(append([]string{}, have...), tactic)
	sort.SliceStable(out, func(i, j int) bool { return mitre.TacticStage(out[i]) < mitre.TacticStage(out[j]) })
	return out
}

func mergeStrings(have []string, v string) []string {
	if v == "" || v == "N/A" {
		return have
	}
	for _, x := range have {
		if x == v {
			return have
		}
	}
	return append(append([]string{}, have...), v)
}

func mergeEntities(have []Entity, add []Entity) []Entity {
	out := append([]Entity{}, have...)
	for _, e := range add {
		found := false
		for _, x := range out {
			if x == e {
				found = true
				break
			}
		}
		if !found {
			out = append(out, e)
		}
	}
	return out
}
