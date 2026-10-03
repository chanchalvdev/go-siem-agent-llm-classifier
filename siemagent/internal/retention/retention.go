// Package retention deletes data older than the configured policy, so a
// long-running deployment does not grow its database without bound.
//
// Only Postgres is purged: without a database, events live in a fixed-size
// ring buffer and everything is lost on restart anyway.
package retention

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/chverma/siemagent/internal/metrics"
)

// Kind names one class of data the purger deletes.
type Kind string

const (
	// Events are classified log events.
	Events Kind = "events"
	// Incidents are resolved incidents (with their alerts, entities and
	// history) and the response actions proposed for them.
	Incidents Kind = "incidents"
	// Audit is the audit log.
	Audit Kind = "audit"
	// Sessions are expired login sessions; always purged.
	Sessions Kind = "sessions"
)

// Policy is how long each kind of data is kept. Zero keeps it forever.
type Policy struct {
	Events    time.Duration
	Incidents time.Duration
	Audit     time.Duration
}

// Enabled reports whether the policy deletes anything besides expired sessions.
func (p Policy) Enabled() bool { return p.Events > 0 || p.Incidents > 0 || p.Audit > 0 }

// Purger deletes data of one kind older than cutoff and returns how many rows
// went.
type Purger interface {
	Purge(ctx context.Context, kind Kind, cutoff time.Time) (int64, error)
}

// Run is the outcome of one purge pass.
type Run struct {
	At      time.Time       `json:"at"`
	Deleted map[Kind]int64  `json:"deleted"`
	Errors  map[Kind]string `json:"errors,omitempty"`
}

// Runner applies a Policy periodically.
type Runner struct {
	policy   Policy
	purger   Purger
	interval time.Duration
	now      func() time.Time

	mu   sync.RWMutex
	last *Run
}

// New returns a Runner that purges every interval (default 1h).
func New(policy Policy, purger Purger, interval time.Duration) *Runner {
	if interval <= 0 {
		interval = time.Hour
	}
	return &Runner{policy: policy, purger: purger, interval: interval, now: time.Now}
}

// Policy returns the configured policy.
func (r *Runner) Policy() Policy { return r.policy }

// Interval returns how often the runner purges.
func (r *Runner) Interval() time.Duration { return r.interval }

// Last returns the most recent pass, or nil before the first one.
func (r *Runner) Last() *Run {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.last
}

// Start purges once immediately and then every interval until ctx ends.
func (r *Runner) Start(ctx context.Context) {
	r.Once(ctx)
	t := time.NewTicker(r.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.Once(ctx)
		}
	}
}

// Once runs one purge pass. A failing kind is logged and the others still run.
func (r *Runner) Once(ctx context.Context) Run {
	now := r.now().UTC()
	run := Run{At: now, Deleted: map[Kind]int64{}}
	for _, step := range []struct {
		kind Kind
		keep time.Duration
	}{
		{Sessions, 0},
		{Events, r.policy.Events},
		{Incidents, r.policy.Incidents},
		{Audit, r.policy.Audit},
	} {
		if step.kind != Sessions && step.keep <= 0 {
			continue
		}
		if ctx.Err() != nil {
			break
		}
		n, err := r.purger.Purge(ctx, step.kind, now.Add(-step.keep))
		run.Deleted[step.kind] = n
		metrics.RetentionDeletedTotal.WithLabelValues(string(step.kind)).Add(float64(n))
		if err != nil {
			if run.Errors == nil {
				run.Errors = map[Kind]string{}
			}
			run.Errors[step.kind] = err.Error()
			metrics.RetentionErrorsTotal.WithLabelValues(string(step.kind)).Inc()
			slog.Error("retention purge failed", "component", "retention", "kind", step.kind, "error", err)
		}
	}
	total := int64(0)
	for _, n := range run.Deleted {
		total += n
	}
	if total > 0 {
		slog.Info("retention purge", "component", "retention", "events", run.Deleted[Events],
			"incidents", run.Deleted[Incidents], "audit", run.Deleted[Audit], "sessions", run.Deleted[Sessions])
	}
	r.mu.Lock()
	r.last = &run
	r.mu.Unlock()
	return run
}
