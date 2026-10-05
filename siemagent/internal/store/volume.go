package store

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/chverma/siemagent/internal/models"
)

// DayVolume counts the events of one UTC day.
type DayVolume struct {
	Day time.Time `json:"day"` // midnight UTC
	// Events is every classified event; Alerts are the P1–P3 ones.
	Events     int `json:"events"`
	Alerts     int `json:"alerts"`
	Suppressed int `json:"suppressed"`
}

// Volumer reports daily event volume for SOC metrics.
type Volumer interface {
	DailyVolume(ctx context.Context, since time.Time) ([]DayVolume, error)
}

func isAlert(s models.Severity) bool {
	return s == models.SeverityP1 || s == models.SeverityP2 || s == models.SeverityP3
}

func day(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
}

// DailyVolume counts the buffered events (the memory store keeps only the
// last 1,000), oldest day first.
func (s *EventStore) DailyVolume(_ context.Context, since time.Time) ([]DayVolume, error) {
	byDay := map[time.Time]*DayVolume{}
	var order []time.Time
	events := s.recent(maxEvents)
	for i := len(events) - 1; i >= 0; i-- {
		ev := events[i]
		if ev.ProcessedAt.Before(since) {
			continue
		}
		d := day(ev.ProcessedAt)
		v := byDay[d]
		if v == nil {
			v = &DayVolume{Day: d}
			byDay[d] = v
			order = append(order, d)
		}
		v.Events++
		if isAlert(ev.Severity) {
			v.Alerts++
		}
		if ev.SuppressedBy != "" {
			v.Suppressed++
		}
	}
	out := make([]DayVolume, 0, len(order))
	for _, d := range order {
		out = append(out, *byDay[d])
	}
	slices.SortFunc(out, func(a, b DayVolume) int { return a.Day.Compare(b.Day) })
	return out, nil
}

// DailyVolume counts stored events per UTC day since the given time.
func (p *Postgres) DailyVolume(ctx context.Context, since time.Time) ([]DayVolume, error) {
	rows, err := p.pool.Query(ctx, `
		SELECT date_trunc('day', processed_at AT TIME ZONE 'UTC') AS d,
		       count(*),
		       count(*) FILTER (WHERE severity IN ('P1', 'P2', 'P3')),
		       count(*) FILTER (WHERE data ? 'suppressed_by')
		FROM events WHERE processed_at >= $1
		GROUP BY d ORDER BY d`, since)
	if err != nil {
		return nil, fmt.Errorf("daily volume: %w", err)
	}
	defer rows.Close()
	out := []DayVolume{}
	for rows.Next() {
		var v DayVolume
		if err := rows.Scan(&v.Day, &v.Events, &v.Alerts, &v.Suppressed); err != nil {
			return nil, fmt.Errorf("scan volume: %w", err)
		}
		v.Day = time.Date(v.Day.Year(), v.Day.Month(), v.Day.Day(), 0, 0, 0, 0, time.UTC)
		out = append(out, v)
	}
	return out, rows.Err()
}
