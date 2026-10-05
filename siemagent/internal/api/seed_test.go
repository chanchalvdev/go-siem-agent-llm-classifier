package api

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chverma/siemagent/internal/config"
	"github.com/chverma/siemagent/internal/detection"
	"github.com/chverma/siemagent/internal/incident"
	"github.com/chverma/siemagent/internal/models"
)

// rulesOnlyServer is the demo configuration: built-in rules, no LLM.
func rulesOnlyServer(t *testing.T) (*Server, *incident.Service) {
	t.Helper()
	rules, errs := detection.LoadBuiltin()
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	engine, errs := detection.NewEngine(rules)
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	inc := incident.NewService(incident.NewMemory(), incident.DefaultConfig())
	srv := New(config.Config{Port: "0", Provider: config.ProviderNone},
		detection.NewClassifier(nil, engine, detection.ModeRulesFirst, nil), WithIncidents(inc), WithDetections(engine))
	return srv, inc
}

// The demo scenario must produce its documented incidents with no LLM.
func TestSeedDemoScenarioRulesOnly(t *testing.T) {
	srv, inc := rulesOnlyServer(t)
	ctx := context.Background()
	n, err := srv.Seed(ctx, filepath.Join("..", "..", "demo", "attack-scenario.log"))
	if err != nil || n != 25 {
		t.Fatalf("seed: n=%d err=%v", n, err)
	}

	list, err := inc.List(ctx, incident.Filter{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	titles := map[string]incident.Incident{}
	for _, i := range list {
		titles[i.Title] = i
	}
	brute, ok := titles["SSH Brute Force from 185.220.101.77"]
	if !ok {
		t.Fatalf("brute-force incident missing; got %v", keys(titles))
	}
	if brute.Severity != models.SeverityP2 {
		t.Errorf("brute force severity %s", brute.Severity)
	}
	shadow := false
	for title, i := range titles {
		if strings.HasPrefix(title, "Shadow Copies Deleted") && i.Severity == models.SeverityP1 {
			shadow = true
		}
	}
	if !shadow {
		t.Errorf("P1 shadow-copy incident missing; got %v", keys(titles))
	}

	// Unmatched lines are kept as Unclassified, never dropped.
	events, _ := srv.events.Recent(ctx, 100)
	unclassified := 0
	for _, ev := range events {
		if ev.AttackType == detection.UnclassifiedType {
			unclassified++
		}
	}
	if len(events) != 25 || unclassified == 0 {
		t.Fatalf("stored %d events, %d unclassified", len(events), unclassified)
	}

	// A second start finds data and leaves it alone.
	if n, err := srv.Seed(ctx, filepath.Join("..", "..", "demo", "attack-scenario.log")); err != nil || n != 0 {
		t.Fatalf("reseed: n=%d err=%v", n, err)
	}
}

func TestSeedErrors(t *testing.T) {
	srv, _ := rulesOnlyServer(t)
	if _, err := srv.Seed(context.Background(), filepath.Join(t.TempDir(), "missing.log")); err == nil {
		t.Error("missing file must fail")
	}
	big := filepath.Join(t.TempDir(), "big.log")
	if err := os.WriteFile(big, []byte(strings.Repeat("cron[1]: job ran\n", maxSeedLines+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.Seed(context.Background(), big); err == nil || !strings.Contains(err.Error(), "more than") {
		t.Errorf("oversized file: %v", err)
	}
}

func keys(m map[string]incident.Incident) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
