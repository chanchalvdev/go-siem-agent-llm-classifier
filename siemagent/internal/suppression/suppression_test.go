package suppression

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chverma/siemagent/internal/models"
)

func event(msg, host, attack string, rules ...string) models.ClassifiedEvent {
	ev := models.ClassifiedEvent{
		Event:      models.LogEvent{Hostname: host, Message: msg, Source: "syslog"},
		AttackType: attack,
		Severity:   models.SeverityP2,
	}
	for _, r := range rules {
		ev.Detections = append(ev.Detections, models.Detection{RuleID: r})
	}
	return ev
}

var bruteForce = event("Failed password for root from 203.0.113.9 port 22 ssh2", "web01", "Brute Force", "ssh-brute")

func newService(t *testing.T) (*Service, *time.Time) {
	t.Helper()
	svc, err := NewService(context.Background(), NewMemory())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	svc.now = func() time.Time { return now }
	return svc, &now
}

func TestValidation(t *testing.T) {
	svc, _ := newService(t)
	for name, n := range map[string]New{
		"no matcher":      {Reason: "noisy"},
		"no reason":       {Entity: "ip:203.0.113.9"},
		"bad entity":      {Entity: "mac:aa:bb", Reason: "x"},
		"entity no value": {Entity: "ip:", Reason: "x"},
		"long reason":     {Entity: "ip:1.2.3.4", Reason: strings.Repeat("x", 501)},
		"short duration":  {Entity: "ip:1.2.3.4", Reason: "x", Duration: "30s"},
		"long duration":   {Entity: "ip:1.2.3.4", Reason: "x", Duration: "2161h"},
		"bad duration":    {Entity: "ip:1.2.3.4", Reason: "x", Duration: "1 day"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := svc.Create(context.Background(), "ana", n); !errors.Is(err, ErrInvalid) {
				t.Fatalf("want ErrInvalid, got %v", err)
			}
		})
	}
}

func TestMatching(t *testing.T) {
	cases := []struct {
		name string
		n    New
		ev   models.ClassifiedEvent
		want bool
	}{
		{"ip", New{Entity: "ip:203.0.113.9"}, bruteForce, true},
		{"other ip", New{Entity: "ip:198.51.100.1"}, bruteForce, false},
		{"host is case-insensitive", New{Entity: "host:WEB01"}, bruteForce, true},
		{"user", New{Entity: "user:root"}, bruteForce, true},
		{"rule", New{RuleID: "ssh-brute"}, bruteForce, true},
		{"other rule", New{RuleID: "port-scan"}, bruteForce, false},
		{"attack type ignores case", New{AttackType: "brute force"}, bruteForce, true},
		{"all matchers must match", New{Entity: "ip:203.0.113.9", RuleID: "port-scan"}, bruteForce, false},
		{"entity and rule", New{Entity: "host:web01", RuleID: "ssh-brute"}, bruteForce, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, _ := newService(t)
			tc.n.Reason = "test"
			if _, err := svc.Create(context.Background(), "ana", tc.n); err != nil {
				t.Fatal(err)
			}
			if _, got := svc.Match(tc.ev); got != tc.want {
				t.Fatalf("match = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestExpiryHitsAndLift(t *testing.T) {
	ctx := context.Background()
	svc, now := newService(t)
	if _, ok := svc.Match(bruteForce); ok {
		t.Fatal("nothing suppressed yet")
	}
	sup, err := svc.Create(ctx, "ana", New{Entity: "ip:203.0.113.9", Reason: "pentest", Duration: "1h"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(sup.ID, "SUP-") || sup.CreatedBy != "ana" || !sup.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("created %+v", sup)
	}
	for range 3 {
		if got, ok := svc.Match(bruteForce); !ok || got.ID != sup.ID {
			t.Fatal("should be suppressed")
		}
	}
	if l := svc.List(); len(l) != 1 || l[0].Hits != 3 || l[0].LastHit == nil {
		t.Fatalf("hits not counted: %+v", l)
	}

	*now = now.Add(time.Hour) // expires exactly now
	if _, ok := svc.Match(bruteForce); ok {
		t.Fatal("expired suppression still matches")
	}
	if len(svc.List()) != 1 {
		t.Fatal("expired suppressions stay listed")
	}

	forever, _ := svc.Create(ctx, "ana", New{RuleID: "ssh-brute", Reason: "tuning"})
	if forever.ExpiresAt != nil {
		t.Fatal("no duration means until lifted")
	}
	if _, ok := svc.Match(bruteForce); !ok {
		t.Fatal("should be suppressed by the rule")
	}
	if err := svc.Lift(ctx, forever.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := svc.Match(bruteForce); ok {
		t.Fatal("lifted suppression still matches")
	}
	if err := svc.Lift(ctx, forever.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("lift twice: %v", err)
	}
}

func TestActiveLimit(t *testing.T) {
	ctx := context.Background()
	svc, now := newService(t)
	for i := range MaxActive {
		if _, err := svc.Create(ctx, "ana", New{AttackType: "type-" + string(rune('a'+i%26)), Reason: "x", Duration: "1h"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := svc.Create(ctx, "ana", New{AttackType: "one more", Reason: "x"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("limit not enforced: %v", err)
	}
	*now = now.Add(2 * time.Hour) // all expired: room again
	if _, err := svc.Create(ctx, "ana", New{AttackType: "one more", Reason: "x"}); err != nil {
		t.Fatalf("expired ones must not count: %v", err)
	}
}

func TestReloadFromStore(t *testing.T) {
	ctx := context.Background()
	st := NewMemory()
	svc, err := NewService(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	sup, _ := svc.Create(ctx, "ana", New{Entity: "ip:203.0.113.9", Reason: "pentest"})
	again, err := NewService(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := again.Match(bruteForce); !ok || got.ID != sup.ID {
		t.Fatal("suppression not reloaded")
	}
}

func TestConcurrentMatchAndCreate(t *testing.T) {
	ctx := context.Background()
	svc, _ := newService(t)
	_, _ = svc.Create(ctx, "ana", New{Entity: "ip:203.0.113.9", Reason: "x"})
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				svc.Match(bruteForce)
				if i == 0 {
					_, _ = svc.Create(ctx, "ana", New{AttackType: "noise", Reason: "x", Duration: "1h"})
				}
			}
		}()
	}
	wg.Wait()
	var hits int64
	for _, s := range svc.List() {
		hits += s.Hits
	}
	if hits != 400 {
		t.Fatalf("hits = %d, want 400", hits)
	}
}
