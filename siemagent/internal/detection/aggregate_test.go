package detection

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

const bruteForceRule = `
title: Test Brute Force
id: test-bf
level: high
tags: [attack.t1110.001]
description: Many failures.
detection:
  sel: ['Failed password for']
  timeframe: 5m
  condition: sel | count() by src_ip > 2
`

func compileOne(t *testing.T, yml string) *Rule {
	t.Helper()
	rules, errs := ParseRules([]byte(yml), "test.yml")
	if len(errs) > 0 || len(rules) != 1 {
		t.Fatalf("compile: rules=%d errs=%v", len(rules), errs)
	}
	return rules[0]
}

func failed(ip string) string {
	return fmt.Sprintf("Oct 11 22:14:15 web01 sshd[1]: Failed password for root from %s port 22 ssh2", ip)
}

// clockEngine returns an engine whose clock the test advances.
func clockEngine(t *testing.T, r *Rule) (*Engine, *time.Time) {
	t.Helper()
	e, errs := NewEngine([]*Rule{r})
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	now := time.Date(2026, 10, 3, 10, 0, 0, 0, time.UTC)
	e.now = func() time.Time { return now }
	return e, &now
}

func TestThresholdFiresOncePerCrossing(t *testing.T) {
	r := compileOne(t, bruteForceRule)
	if r.Threshold() != "count() by src_ip >= 3 in 5m" {
		t.Fatalf("threshold = %q", r.Threshold())
	}
	e, now := clockEngine(t, r)

	var fired []int
	for i := 1; i <= 7; i++ {
		*now = now.Add(time.Second)
		if dets := e.Match(parse(failed("203.0.113.7"))); len(dets) > 0 {
			d := dets[0]
			if d.Count != 3 || d.Group != "src_ip=203.0.113.7" || d.Threshold == "" {
				t.Fatalf("detection = %+v", d)
			}
			fired = append(fired, i)
		}
	}
	// Fires on the 3rd event, starts over, fires again on the 6th.
	if fmt.Sprint(fired) != "[3 6]" {
		t.Fatalf("fired on events %v, want [3 6]", fired)
	}
	if r.Hits() != 2 {
		t.Fatalf("hits = %d, want 2 crossings", r.Hits())
	}
}

func TestThresholdGroupsAreIndependent(t *testing.T) {
	e, now := clockEngine(t, compileOne(t, bruteForceRule))
	for i := range 6 {
		*now = now.Add(time.Second)
		ip := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}[i%3]
		if dets := e.Match(parse(failed(ip))); len(dets) > 0 {
			t.Fatalf("two failures per IP must not fire, got %+v", dets)
		}
	}
}

func TestThresholdWindowExpires(t *testing.T) {
	e, now := clockEngine(t, compileOne(t, bruteForceRule))
	e.Match(parse(failed("10.0.0.1")))
	e.Match(parse(failed("10.0.0.1")))
	*now = now.Add(6 * time.Minute) // both earlier events fall out
	if dets := e.Match(parse(failed("10.0.0.1"))); len(dets) > 0 {
		t.Fatal("events outside the timeframe must not count")
	}
	*now = now.Add(time.Minute)
	e.Match(parse(failed("10.0.0.1")))
	*now = now.Add(time.Minute)
	if dets := e.Match(parse(failed("10.0.0.1"))); len(dets) != 1 {
		t.Fatal("three events within five minutes should fire")
	}
}

func TestThresholdIgnoresEventsWithoutGroupField(t *testing.T) {
	e, _ := clockEngine(t, compileOne(t, bruteForceRule))
	for range 5 {
		if dets := e.Match(parse("Oct 11 22:14:15 web01 sshd[1]: Failed password for root")); len(dets) > 0 {
			t.Fatal("no src_ip: event must not be counted")
		}
	}
}

func TestDistinctCount(t *testing.T) {
	r := compileOne(t, `
title: Spray
id: spray
detection:
  sel: ['Failed password for']
  timeframe: 10m
  condition: sel | count(user) by src_ip >= 3
`)
	e, now := clockEngine(t, r)
	line := func(user string) string {
		return fmt.Sprintf("Oct 11 22:14:15 h sshd[1]: Failed password for %s from 45.33.32.156 port 22 ssh2", user)
	}
	for _, u := range []string{"root", "root", "admin", "admin"} {
		*now = now.Add(time.Second)
		if len(e.Match(parse(line(u)))) > 0 {
			t.Fatal("two distinct users must not fire")
		}
	}
	if dets := e.Match(parse(line("oracle"))); len(dets) != 1 || dets[0].Count != 3 {
		t.Fatalf("third distinct user should fire: %+v", dets)
	}
}

func TestGlobalCountWithoutBy(t *testing.T) {
	e, _ := clockEngine(t, compileOne(t, `
title: Global
id: global
detection:
  sel: {message|contains: 'disk full'}
  timeframe: 1h
  condition: sel | count() > 1
`))
	e.Match(parse("Oct 11 22:14:15 a kernel: disk full"))
	dets := e.Match(parse("Oct 11 22:14:15 b kernel: disk full"))
	if len(dets) != 1 || dets[0].Group != "" {
		t.Fatalf("second event anywhere should fire with no group: %+v", dets)
	}
}

func TestGroupTableIsBounded(t *testing.T) {
	r := compileOne(t, bruteForceRule)
	now := time.Date(2026, 10, 3, 10, 0, 0, 0, time.UTC)
	for i := range maxGroupsPerRule + 50 {
		ip := fmt.Sprintf("10.%d.%d.%d", i/65536%256, i/256%256, i%256)
		r.agg.observe(eventFields(parse(failed(ip))), now)
	}
	if n := len(r.agg.groups); n > maxGroupsPerRule {
		t.Fatalf("groups = %d, cap is %d", n, maxGroupsPerRule)
	}
	// Once the window passes, stale groups make room again.
	later := now.Add(10 * time.Minute)
	r.agg.observe(eventFields(parse(failed("192.0.2.200"))), later)
	if _, ok := r.agg.groups["192.0.2.200"]; !ok {
		t.Fatal("stale groups should be evicted for new ones")
	}
}

func TestSetEnabled(t *testing.T) {
	r := compileOne(t, bruteForceRule)
	e, _ := clockEngine(t, r)
	e.Match(parse(failed("10.0.0.1")))
	e.Match(parse(failed("10.0.0.1")))
	if !e.SetEnabled("test-bf", false) || r.Enabled() {
		t.Fatal("rule should be disabled")
	}
	if dets := e.Match(parse(failed("10.0.0.1"))); len(dets) > 0 {
		t.Fatal("disabled rule fired")
	}
	e.SetEnabled("test-bf", true)
	if dets := e.Match(parse(failed("10.0.0.1"))); len(dets) > 0 {
		t.Fatal("disabling must reset counters")
	}
	if e.SetEnabled("missing", false) {
		t.Fatal("unknown rule should report false")
	}
}

func TestThresholdVerdictSummary(t *testing.T) {
	e, _ := clockEngine(t, compileOne(t, bruteForceRule))
	var dets = e.Match(parse(failed("10.0.0.9")))
	for range 2 {
		dets = e.Match(parse(failed("10.0.0.9")))
	}
	if len(dets) != 1 {
		t.Fatal("expected a crossing")
	}
	v := e.Verdict(parse(failed("10.0.0.9")), dets)
	if !strings.Contains(v.Summary, "3 matching events from src_ip=10.0.0.9") || v.Severity != "P2" {
		t.Fatalf("verdict = %q %s", v.Summary, v.Severity)
	}
}

func TestAggregationParseErrors(t *testing.T) {
	cases := map[string]struct {
		cond, timeframe string
		unsupported     bool
		want            string
	}{
		"no timeframe":   {"sel | count() > 5", "", false, "timeframe"},
		"less than":      {"sel | count() < 5", "5m", true, "only > and >="},
		"sum":            {"sel | sum(bytes) > 5", "5m", true, ""},
		"near":           {"sel | near other", "5m", true, ""},
		"threshold of 1": {"sel | count() > 0", "5m", false, "at least 2"},
		"garbage":        {"sel | whatever", "5m", false, "invalid aggregation"},
		"bad timeframe":  {"sel | count() > 5", "five minutes", false, "invalid timeframe"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			tf := ""
			if c.timeframe != "" {
				tf = "\n  timeframe: " + c.timeframe
			}
			_, errs := ParseRules([]byte("title: T\nid: t\ndetection:\n  sel: {message: x}"+tf+"\n  condition: '"+c.cond+"'\n"), "t.yml")
			if len(errs) != 1 {
				t.Fatalf("want one error, got %v", errs)
			}
			if errors.Is(errs[0], ErrUnsupported) != c.unsupported {
				t.Errorf("unsupported = %v: %v", !c.unsupported, errs[0])
			}
			if !strings.Contains(errs[0].Error(), c.want) {
				t.Errorf("error %q should mention %q", errs[0], c.want)
			}
		})
	}
}

func TestParseTimeframe(t *testing.T) {
	for in, want := range map[string]time.Duration{
		"30s": 30 * time.Second, "5m": 5 * time.Minute, "1h": time.Hour, "2d": 48 * time.Hour,
	} {
		if got, err := parseTimeframe(in); err != nil || got != want {
			t.Errorf("%s = %v, %v", in, got, err)
		}
	}
	for _, bad := range []string{"0m", "-1h", "xd", "soon"} {
		if _, err := parseTimeframe(bad); err == nil {
			t.Errorf("%q should fail", bad)
		}
	}
}

func TestExtractEntities(t *testing.T) {
	cases := []struct {
		line string
		want map[string]string
	}{
		{"Failed password for invalid user admin from 10.0.0.9 port 22 ssh2",
			map[string]string{"src_ip": "10.0.0.9", "user": "admin"}},
		{"Failed password for root from 185.220.101.4 port 52211 ssh2",
			map[string]string{"src_ip": "185.220.101.4", "user": "root"}},
		{`198.51.100.23 - - [11/Oct/2026:22:14:15 +0000] "GET /x HTTP/1.1" 404 1`,
			map[string]string{"src_ip": "198.51.100.23"}},
		{"[UFW BLOCK] SRC=203.0.113.50 DST=10.0.0.5 DPT=3389",
			map[string]string{"src_ip": "203.0.113.50", "dst_port": "3389"}},
		{"login failed user=alice ip=192.0.2.4",
			map[string]string{"src_ip": "192.0.2.4", "user": "alice"}},
		{"from 999.1.1.1 nonsense", map[string]string{}},
	}
	for _, c := range cases {
		got := extractEntities(c.line)
		if fmt.Sprint(got) != fmt.Sprint(c.want) {
			t.Errorf("%q\n got  %v\n want %v", c.line, got, c.want)
		}
	}
}

func TestJSONFieldsOverrideExtractedEntities(t *testing.T) {
	f := eventFields(parse(`{"message":"Failed password from 10.0.0.1","source":{"ip":"192.0.2.77"}}`))
	if f.values["source.ip"] != "192.0.2.77" {
		t.Fatalf("source.ip = %q, want the JSON field", f.values["source.ip"])
	}
}
