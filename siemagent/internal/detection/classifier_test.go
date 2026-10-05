package detection

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"

	"github.com/chverma/siemagent/internal/models"
)

type fakeLLM struct {
	mu       sync.Mutex
	calls    int
	severity models.Severity
	err      error
}

func (f *fakeLLM) Classify(ctx context.Context, ev models.LogEvent) (models.ClassifiedEvent, error) {
	return f.ClassifyStream(ctx, ev, nil)
}

func (f *fakeLLM) ClassifyStream(_ context.Context, ev models.LogEvent, _ func(string)) (models.ClassifiedEvent, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return models.ClassifiedEvent{}, f.err
	}
	return models.ClassifiedEvent{Event: ev, AttackType: "LLM verdict", Severity: f.severity, ClassifiedBy: models.ClassifiedByLLM}, nil
}

func (f *fakeLLM) Ping(context.Context) error { return nil }

const (
	shadowDelete = "<34>1 2026-10-03T10:37:00Z fs02 vssadmin 4242 - vssadmin.exe delete shadows /all /quiet"
	benignLine   = "<34>1 2026-10-03T10:36:00Z cron01 CRON 1111 - (root) CMD (/usr/local/bin/backup.sh)"
	sshFailure   = "Oct 11 22:14:15 web01 sshd[4721]: Failed password for root from 185.220.101.4 port 52211 ssh2"
)

func TestRulesFirstSkipsLLMOnMatch(t *testing.T) {
	llm := &fakeLLM{severity: models.SeverityP4}
	var indexed []models.ClassifiedEvent
	c := NewClassifier(llm, builtinEngine(t), ModeRulesFirst, func(e models.ClassifiedEvent) { indexed = append(indexed, e) })

	out, err := c.Classify(context.Background(), parse(shadowDelete))
	if err != nil {
		t.Fatal(err)
	}
	if llm.calls != 0 {
		t.Fatalf("LLM should be skipped on a rule match, called %d times", llm.calls)
	}
	if out.ClassifiedBy != models.ClassifiedByRules || out.Severity != models.SeverityP1 {
		t.Fatalf("unexpected verdict: %+v", out)
	}
	if out.MITRE.TechniqueID != "T1490" || out.MITRE.Tactic != "Impact" || out.MITRE.Technique == "" {
		t.Fatalf("MITRE not derived from tags: %+v", out.MITRE)
	}
	if out.IOCs == nil {
		t.Fatal("IOCs must be an empty list, not nil (JSON null)")
	}
	if out.Confidence != 0.95 || out.Remediation == "" || out.Summary == "" {
		t.Fatalf("verdict missing rule metadata: %+v", out)
	}
	if len(indexed) != 1 {
		t.Fatal("rule verdicts must be indexed for semantic search")
	}

	// No match: falls through to the LLM.
	out, err = c.Classify(context.Background(), parse(benignLine))
	if err != nil || llm.calls != 1 || out.ClassifiedBy != models.ClassifiedByLLM || len(out.Detections) != 0 {
		t.Fatalf("unmatched event should go to the LLM: %+v, err %v", out, err)
	}
}

func TestEnrichAttachesRulesAndRaisesSeverity(t *testing.T) {
	llm := &fakeLLM{severity: models.SeverityP4}
	c := NewClassifier(llm, builtinEngine(t), ModeEnrich, nil)

	out, err := c.Classify(context.Background(), parse(shadowDelete))
	if err != nil || llm.calls != 1 {
		t.Fatalf("enrich always calls the LLM: calls=%d err=%v", llm.calls, err)
	}
	if out.ClassifiedBy != models.ClassifiedByBoth || out.AttackType != "LLM verdict" {
		t.Fatalf("LLM verdict should be kept and labelled llm+rules: %+v", out)
	}
	if out.Severity != models.SeverityP1 || len(out.Detections) == 0 {
		t.Fatalf("critical rule should raise severity to P1: %+v", out)
	}

	// A low rule never lowers a higher LLM severity.
	llm.severity = models.SeverityP2
	out, _ = c.Classify(context.Background(), parse(sshFailure))
	if out.Severity != models.SeverityP2 {
		t.Fatalf("low rule lowered severity to %s", out.Severity)
	}
}

func TestRuleVerdictWhenLLMFails(t *testing.T) {
	llm := &fakeLLM{err: errors.New("LLM down")}
	c := NewClassifier(llm, builtinEngine(t), ModeEnrich, nil)

	out, err := c.Classify(context.Background(), parse(shadowDelete))
	if err != nil || out.ClassifiedBy != models.ClassifiedByRules {
		t.Fatalf("a matched event must survive an LLM outage: %+v, %v", out, err)
	}
	if _, err := c.Classify(context.Background(), parse(benignLine)); err == nil {
		t.Fatal("unmatched event should surface the LLM error")
	}
}

func TestModeOffIgnoresRules(t *testing.T) {
	llm := &fakeLLM{severity: models.SeverityP5}
	c := NewClassifier(llm, builtinEngine(t), ModeOff, nil)
	out, _ := c.Classify(context.Background(), parse(shadowDelete))
	if llm.calls != 1 || len(out.Detections) != 0 {
		t.Fatalf("mode off must not evaluate rules: %+v", out)
	}
}

func TestParseMode(t *testing.T) {
	for in, want := range map[string]Mode{"": ModeRulesFirst, "rules-first": ModeRulesFirst, "enrich": ModeEnrich, "off": ModeOff} {
		if got, err := ParseMode(in); err != nil || got != want {
			t.Errorf("ParseMode(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := ParseMode("aggressive"); err == nil {
		t.Error("unknown mode should fail")
	}
}

func TestExtractIOCs(t *testing.T) {
	got := extractIOCs(`GET http://198.51.100.23/a.ps1, from 10.0.0.5 and 10.0.0.5 hash D41D8CD98F00B204E9800998ECF8427E 0.0.0.0`)
	want := []string{"http://198.51.100.23/a.ps1", "198.51.100.23", "10.0.0.5", "d41d8cd98f00b204e9800998ecf8427e"}
	if !slices.Equal(got, want) {
		t.Fatalf("IOCs = %q, want %q", got, want)
	}
}

func TestMITREFromTacticOnlyTags(t *testing.T) {
	info := mitreFromTags([]string{"attack.discovery", "cve.2024.1234"})
	if info.Tactic != "Discovery" || info.TechniqueID != "" {
		t.Fatalf("unexpected: %+v", info)
	}
	if mitreFromTags(nil).Tactic != "N/A" {
		t.Fatal("no tags should give N/A tactic")
	}
}

func TestRulesOnlyWithoutLLM(t *testing.T) {
	c := NewClassifier(nil, builtinEngine(t), ModeRulesFirst, nil)
	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("rules-only ping: %v", err)
	}
	out, err := c.Classify(context.Background(), parse(shadowDelete))
	if err != nil || out.ClassifiedBy != models.ClassifiedByRules || out.Severity != models.SeverityP1 {
		t.Fatalf("rule match: %+v %v", out, err)
	}
	out, err = c.Classify(context.Background(), parse(benignLine))
	if err != nil {
		t.Fatal(err)
	}
	if out.AttackType != UnclassifiedType || out.Severity != models.SeverityP5 || out.ClassifiedBy != models.ClassifiedByRules ||
		out.IOCs == nil || out.ProcessedAt.IsZero() || len(out.Detections) != 0 {
		t.Fatalf("unmatched event without an LLM: %+v", out)
	}
}
