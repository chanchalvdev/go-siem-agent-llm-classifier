package store

import (
	"context"
	"testing"
	"time"

	"github.com/chverma/siemagent/internal/models"
)

func event(attack string, sev models.Severity, tactic string, at time.Time) models.ClassifiedEvent {
	return models.ClassifiedEvent{
		Event:       models.LogEvent{Raw: attack, Message: attack, Source: "syslog", Hostname: "host1"},
		AttackType:  attack,
		Severity:    sev,
		MITRE:       models.MITREInfo{Tactic: tactic, TechniqueID: "T0000"},
		Confidence:  0.9,
		IOCs:        []string{"10.0.0.1"},
		ProcessedAt: at,
	}
}

// testStoreContract checks behaviour every Store implementation must share.
// s must start empty.
func testStoreContract(t *testing.T, s Store) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)

	// Added in time order, as events arrive in practice.
	evs := []models.ClassifiedEvent{
		event("Old Attack", models.SeverityP2, "Impact", now.Add(-48*time.Hour)),
		event("Brute Force", models.SeverityP3, "Credential Access", now.Add(-50*time.Minute)),
		event("Brute Force", models.SeverityP1, "Credential Access", now.Add(-40*time.Minute)),
		event("Port Scan", models.SeverityP4, "Discovery", now.Add(-30*time.Minute)),
		event("Benign", models.SeverityP5, "N/A", now.Add(-20*time.Minute)),
	}
	for _, ev := range evs {
		if err := s.Add(ctx, ev); err != nil {
			t.Fatalf("Add: %v", err)
		}
	}

	t.Run("recent is newest first and limited", func(t *testing.T) {
		got, err := s.Recent(ctx, 2)
		if err != nil {
			t.Fatalf("Recent: %v", err)
		}
		if len(got) != 2 || got[0].AttackType != "Benign" || got[1].AttackType != "Port Scan" {
			t.Fatalf("unexpected recent events: %+v", got)
		}
		if got[0].Event.Hostname != "host1" || len(got[0].IOCs) != 1 {
			t.Fatalf("event fields not round-tripped: %+v", got[0])
		}
	})

	t.Run("recent handles bad limits", func(t *testing.T) {
		if got, err := s.Recent(ctx, 0); err != nil || len(got) != 0 {
			t.Fatalf("limit 0: %v %v", got, err)
		}
		if got, err := s.Recent(ctx, 100); err != nil || len(got) != len(evs) {
			t.Fatalf("limit 100: got %d events, err %v", len(got), err)
		}
	})

	t.Run("summary", func(t *testing.T) {
		sum, err := s.Summary(ctx)
		if err != nil {
			t.Fatalf("Summary: %v", err)
		}
		if sum.TotalEvents != len(evs) {
			t.Fatalf("total: want %d, got %d", len(evs), sum.TotalEvents)
		}
		bf := sum.AttackTypeCounts["Brute Force"]
		if bf == nil || bf.Count != 2 || bf.Severity != "P1" {
			t.Fatalf("brute force counts: %+v", bf)
		}
		if sum.MITRETactics["Credential Access"] != 2 || sum.MITRETactics["N/A"] != 0 {
			t.Fatalf("tactics: %+v", sum.MITRETactics)
		}
		if len(sum.Timeline) != timelineBuckets {
			t.Fatalf("timeline buckets: %d", len(sum.Timeline))
		}
		// Only P1–P3 inside the 6h window are charted: the P3 and P1 brute force.
		charted := 0
		for _, b := range sum.Timeline {
			for _, n := range b.Counts {
				charted += n
			}
		}
		if charted != 2 {
			t.Fatalf("timeline should chart 2 events, got %d", charted)
		}
	})
}

func TestEventStoreContract(t *testing.T) {
	testStoreContract(t, New())
}

func TestEventStoreRingBufferWraps(t *testing.T) {
	ctx := context.Background()
	s := New()
	for i := range maxEvents + 5 {
		_ = s.Add(ctx, event("e", models.SeverityP5, "", time.Unix(int64(i), 0)))
	}
	got, _ := s.Recent(ctx, maxEvents+100)
	if len(got) != maxEvents {
		t.Fatalf("want %d events, got %d", maxEvents, len(got))
	}
	if got[0].ProcessedAt.Unix() != int64(maxEvents+4) {
		t.Fatalf("newest event wrong: %v", got[0].ProcessedAt)
	}
}
