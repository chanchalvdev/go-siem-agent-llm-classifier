// Package store persists classified events. Postgres is the durable backend;
// the in-memory ring buffer keeps the agent usable without a database.
package store

import (
	"context"
	"time"

	"github.com/chverma/siemagent/internal/models"
)

// Store is implemented by the in-memory EventStore and by Postgres.
type Store interface {
	Add(ctx context.Context, ev models.ClassifiedEvent) error
	// Recent returns up to limit events, newest first.
	Recent(ctx context.Context, limit int) ([]models.ClassifiedEvent, error)
	Summary(ctx context.Context) (AnalyticsSummary, error)
}

// Pinger is implemented by stores whose backend can become unreachable.
type Pinger interface {
	Ping(ctx context.Context) error
}

// ─── Analytics ────────────────────────────────────────────────────────────────

type AttackCount struct {
	Count    int    `json:"count"`
	Severity string `json:"severity"` // highest severity seen for this type
}

type TimelineBucket struct {
	Time   string         `json:"time"`
	Counts map[string]int `json:"counts"` // severity -> count
}

type AnalyticsSummary struct {
	TotalEvents      int                     `json:"total_events"`
	AttackTypeCounts map[string]*AttackCount `json:"attack_type_counts"`
	Timeline         []TimelineBucket        `json:"timeline"` // 10-min buckets, last 6h
	MITRETactics     map[string]int          `json:"mitre_tactics"`
}

const (
	timelineBuckets = 36
	bucketWidth     = 10 * time.Minute
	timelineWindow  = timelineBuckets * bucketWidth
)

var severityOrder = map[models.Severity]int{
	models.SeverityP1: 1,
	models.SeverityP2: 2,
	models.SeverityP3: 3,
	models.SeverityP4: 4,
	models.SeverityP5: 5,
}

func higherSeverity(a, b string) string {
	if severityOrder[models.Severity(a)] < severityOrder[models.Severity(b)] {
		return a
	}
	return b
}

// timelineSeverity reports whether a severity is charted on the timeline.
func timelineSeverity(sev string) bool {
	return sev == "P1" || sev == "P2" || sev == "P3"
}

// summaryBuilder accumulates analytics so both stores share one output shape.
type summaryBuilder struct {
	cutoff time.Time
	sum    AnalyticsSummary
}

func newSummaryBuilder(now time.Time) *summaryBuilder {
	cutoff := now.UTC().Add(-timelineWindow)
	buckets := make([]TimelineBucket, timelineBuckets)
	for i := range buckets {
		buckets[i] = TimelineBucket{
			Time:   cutoff.Add(time.Duration(i) * bucketWidth).Format("15:04"),
			Counts: make(map[string]int),
		}
	}
	return &summaryBuilder{
		cutoff: cutoff,
		sum: AnalyticsSummary{
			AttackTypeCounts: make(map[string]*AttackCount),
			Timeline:         buckets,
			MITRETactics:     make(map[string]int),
		},
	}
}

func (b *summaryBuilder) addAttack(attackType, severity string, n int) {
	ac, ok := b.sum.AttackTypeCounts[attackType]
	if !ok {
		ac = &AttackCount{Severity: severity}
		b.sum.AttackTypeCounts[attackType] = ac
	}
	ac.Count += n
	ac.Severity = higherSeverity(ac.Severity, severity)
}

func (b *summaryBuilder) addTactic(tactic string, n int) {
	if tactic != "" && tactic != "N/A" {
		b.sum.MITRETactics[tactic] += n
	}
}

func (b *summaryBuilder) addTimelineBucket(idx int, severity string, n int) {
	if idx >= 0 && idx < timelineBuckets && timelineSeverity(severity) {
		b.sum.Timeline[idx].Counts[severity] += n
	}
}

func (b *summaryBuilder) addTimeline(at time.Time, severity string) {
	if at.After(b.cutoff) {
		b.addTimelineBucket(int(at.Sub(b.cutoff)/bucketWidth), severity, 1)
	}
}
