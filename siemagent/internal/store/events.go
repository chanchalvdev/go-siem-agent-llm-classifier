package store

import (
	"context"
	"sync"
	"time"

	"github.com/chverma/siemagent/internal/models"
)

const maxEvents = 1000

// EventStore is a thread-safe ring buffer of the last N classified events.
// It is the fallback when no database is configured; events are lost on restart.
type EventStore struct {
	mu     sync.RWMutex
	events [maxEvents]models.ClassifiedEvent
	head   int // next write position
	count  int // total stored (capped at maxEvents)
}

func New() *EventStore { return &EventStore{} }

// Add appends a classified event to the ring buffer.
func (s *EventStore) Add(_ context.Context, ev models.ClassifiedEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events[s.head] = ev
	s.head = (s.head + 1) % maxEvents
	if s.count < maxEvents {
		s.count++
	}
	return nil
}

// Recent returns the most recent n events (newest first).
func (s *EventStore) Recent(_ context.Context, n int) ([]models.ClassifiedEvent, error) {
	return s.recent(n), nil
}

func (s *EventStore) recent(n int) []models.ClassifiedEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	n = max(0, min(n, s.count))
	out := make([]models.ClassifiedEvent, n)
	for i := range n {
		idx := (s.head - 1 - i + maxEvents) % maxEvents
		out[i] = s.events[idx]
	}
	return out
}

// Summary computes analytics over the buffered events.
func (s *EventStore) Summary(_ context.Context) (AnalyticsSummary, error) {
	events := s.recent(maxEvents)
	b := newSummaryBuilder(time.Now())
	for _, ev := range events {
		b.addAttack(ev.AttackType, string(ev.Severity), 1)
		b.addTactic(ev.MITRE.Tactic, 1)
		b.addTimeline(ev.ProcessedAt, string(ev.Severity))
	}
	b.sum.TotalEvents = len(events)
	return b.sum, nil
}
