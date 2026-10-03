package response

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"
)

// Status is where an action is in its lifecycle.
type Status string

const (
	StatusPending   Status = "pending"   // waiting for an analyst
	StatusDryRun    Status = "dry_run"   // recorded only; never runs
	StatusRunning   Status = "running"   // approved (or auto), executing
	StatusSucceeded Status = "succeeded" // executed successfully
	StatusFailed    Status = "failed"    // executed with an error
	StatusRejected  Status = "rejected"  // an analyst declined it
)

// Action is one proposed or executed response step.
type Action struct {
	ID           string `json:"id"`
	IncidentID   string `json:"incident_id"`
	PlaybookID   string `json:"playbook_id"`
	PlaybookName string `json:"playbook_name"`
	Type         string `json:"type"`
	Target       string `json:"target,omitempty"` // IP, user or host; empty for incident-level actions
	Message      string `json:"message,omitempty"`
	// Step is the index of the action in its playbook. Webhook URLs (which
	// may embed tokens) are read from the playbook at run time, never stored.
	Step       int        `json:"step"`
	Status     Status     `json:"status"`
	Reason     string     `json:"reason"`
	Result     string     `json:"result,omitempty"`
	ProposedAt time.Time  `json:"proposed_at"`
	DecidedBy  string     `json:"decided_by,omitempty"`
	DecidedAt  *time.Time `json:"decided_at,omitempty"`
	ExecutedAt *time.Time `json:"executed_at,omitempty"`
	// DedupKey makes proposals idempotent: one per playbook step, incident
	// and target.
	DedupKey string `json:"-"`
}

// Describe renders the action for history entries, e.g. "block_ip 1.2.3.4".
func (a Action) Describe() string {
	if a.Target == "" {
		return a.Type
	}
	return a.Type + " " + a.Target
}

func newActionID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return "ACT-" + strings.ToUpper(hex.EncodeToString(b))
}

// ErrNotFound is returned for unknown action IDs.
var ErrNotFound = errors.New("action not found")

// ErrInvalid wraps errors caused by the request (wrong state, bad input).
var ErrInvalid = errors.New("invalid request")

// Filter narrows an action list. Zero values match everything.
type Filter struct {
	Status     Status
	IncidentID string
	Limit      int
}

// Store persists actions.
type Store interface {
	// Create stores a new action. created is false (and nothing is stored)
	// when an action with the same DedupKey already exists.
	Create(ctx context.Context, a Action) (created bool, err error)
	Get(ctx context.Context, id string) (Action, error)
	Update(ctx context.Context, a Action) error
	// List returns actions, newest first.
	List(ctx context.Context, f Filter) ([]Action, error)
}

// Memory is the in-memory Store used without a database.
type Memory struct {
	mu      sync.RWMutex
	actions map[string]Action
	keys    map[string]bool
}

func NewMemory() *Memory { return &Memory{actions: map[string]Action{}, keys: map[string]bool{}} }

func (m *Memory) Create(_ context.Context, a Action) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.keys[a.DedupKey] {
		return false, nil
	}
	m.keys[a.DedupKey] = true
	m.actions[a.ID] = a
	return true, nil
}

func (m *Memory) Get(_ context.Context, id string) (Action, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	a, ok := m.actions[id]
	if !ok {
		return Action{}, ErrNotFound
	}
	return a, nil
}

func (m *Memory) Update(_ context.Context, a Action) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.actions[a.ID]; !ok {
		return ErrNotFound
	}
	m.actions[a.ID] = a
	return nil
}

func (m *Memory) List(_ context.Context, f Filter) ([]Action, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := []Action{}
	for _, a := range m.actions {
		if (f.Status == "" || a.Status == f.Status) && (f.IncidentID == "" || a.IncidentID == f.IncidentID) {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ProposedAt.Equal(out[j].ProposedAt) {
			return out[i].ID > out[j].ID
		}
		return out[i].ProposedAt.After(out[j].ProposedAt)
	})
	if f.Limit > 0 && len(out) > f.Limit {
		out = out[:f.Limit]
	}
	return out, nil
}
