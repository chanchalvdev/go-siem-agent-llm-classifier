package incident

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"
)

// ErrNotFound is returned for unknown incident IDs.
var ErrNotFound = errors.New("incident not found")

// maxStoredAlerts caps the alert snapshots kept per incident. A long-running
// attack keeps counting (AlertCount) without growing storage without bound.
const maxStoredAlerts = 500

// Store persists incidents. Writes go through Service, which serialises them.
type Store interface {
	// FindOpen returns the open incident sharing any of the entities that
	// was most recently active after since, or nil.
	FindOpen(ctx context.Context, entities []Entity, since time.Time) (*Incident, error)
	// Save upserts the incident, records an alert snapshot (when non-nil)
	// and appends the activities.
	Save(ctx context.Context, inc Incident, alert *Alert, acts ...Activity) error
	Get(ctx context.Context, id string) (Detail, error)
	// List returns incidents, most recently active first.
	List(ctx context.Context, f Filter) ([]Incident, error)
	Stats(ctx context.Context) (Stats, error)
}

// Memory is the in-memory Store used without a database.
type Memory struct {
	mu        sync.RWMutex
	incidents map[string]*Detail
	nextID    int64
}

func NewMemory() *Memory { return &Memory{incidents: map[string]*Detail{}} }

func shares(have []Entity, want []Entity) bool {
	for _, a := range have {
		for _, b := range want {
			if a == b {
				return true
			}
		}
	}
	return false
}

func (m *Memory) FindOpen(_ context.Context, entities []Entity, since time.Time) (*Incident, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var best *Incident
	for _, d := range m.incidents {
		if !d.Open() || !d.LastSeen.After(since) || !shares(d.Entities, entities) {
			continue
		}
		if best == nil || d.LastSeen.After(best.LastSeen) {
			inc := d.Incident
			best = &inc
		}
	}
	return best, nil
}

func (m *Memory) Save(_ context.Context, inc Incident, alert *Alert, acts ...Activity) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.incidents[inc.ID]
	if !ok {
		d = &Detail{Alerts: []Alert{}, Activity: []Activity{}}
		m.incidents[inc.ID] = d
	}
	d.Incident = inc
	if alert != nil && len(d.Alerts) < maxStoredAlerts {
		m.nextID++
		a := *alert
		a.ID, a.IncidentID = m.nextID, inc.ID
		d.Alerts = append(d.Alerts, a)
	}
	for _, act := range acts {
		m.nextID++
		act.ID, act.IncidentID = m.nextID, inc.ID
		d.Activity = append(d.Activity, act)
	}
	return nil
}

func (m *Memory) Get(_ context.Context, id string) (Detail, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	d, ok := m.incidents[id]
	if !ok {
		return Detail{}, ErrNotFound
	}
	out := *d
	out.Alerts = append([]Alert{}, d.Alerts...)
	out.Activity = append([]Activity{}, d.Activity...)
	return out, nil
}

func (m *Memory) List(_ context.Context, f Filter) ([]Incident, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := []Incident{}
	for _, d := range m.incidents {
		if matchFilter(d.Incident, f) {
			out = append(out, d.Incident)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	if f.Limit > 0 && len(out) > f.Limit {
		out = out[:f.Limit]
	}
	return out, nil
}

func matchFilter(inc Incident, f Filter) bool {
	if f.Status != "" && inc.Status != f.Status {
		return false
	}
	if f.Severity != "" && inc.Severity != f.Severity {
		return false
	}
	if f.Assignee != "" && inc.Assignee != f.Assignee {
		return false
	}
	if f.Entity != nil && !shares(inc.Entities, []Entity{*f.Entity}) {
		return false
	}
	if !f.ActiveSince.IsZero() && inc.CreatedAt.Before(f.ActiveSince) && !inc.Open() &&
		(inc.ResolvedAt == nil || inc.ResolvedAt.Before(f.ActiveSince)) {
		return false
	}
	return true
}

func (m *Memory) Stats(_ context.Context) (Stats, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	b := newStatsBuilder()
	for _, d := range m.incidents {
		b.add(d.Incident)
	}
	return b.stats(), nil
}

// statsBuilder computes Stats from incidents (memory store, and tests).
type statsBuilder struct {
	s         Stats
	totalMTTR time.Duration
	mttrN     int
}

func newStatsBuilder() *statsBuilder {
	return &statsBuilder{s: Stats{ByStatus: map[Status]int{}, OpenBySev: map[string]int{}}}
}

func (b *statsBuilder) add(inc Incident) {
	b.s.ByStatus[inc.Status]++
	if inc.Open() {
		b.s.Open++
		b.s.OpenBySev[string(inc.Severity)]++
		return
	}
	b.s.Resolved++
	if inc.Resolution == ResolutionFalsePositive {
		b.s.FalsePositive++
	}
	if inc.ResolvedAt != nil {
		b.totalMTTR += inc.ResolvedAt.Sub(inc.CreatedAt)
		b.mttrN++
	}
}

func (b *statsBuilder) stats() Stats {
	if b.mttrN > 0 {
		b.s.MTTRSeconds = b.totalMTTR.Seconds() / float64(b.mttrN)
	}
	return b.s
}
