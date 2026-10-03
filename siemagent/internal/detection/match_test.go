package detection

import (
	"testing"

	"github.com/chverma/siemagent/internal/models"
)

// one compiles a single-rule engine from a detection block.
func one(t *testing.T, detection string) *Rule {
	t.Helper()
	rules, errs := ParseRules([]byte("title: T\nid: t\ndetection:\n"+detection), "test")
	if len(errs) > 0 || len(rules) != 1 {
		t.Fatalf("compile: %v", errs)
	}
	return rules[0]
}

func ev(msg string) models.LogEvent {
	return models.LogEvent{Raw: msg, Message: msg, Source: "raw"}
}

func TestModifiersAndWildcards(t *testing.T) {
	cases := []struct {
		name, detection, line string
		want                  bool
	}{
		{"exact is case-insensitive", "  s: {message: 'Hello World'}\n  condition: s", "hello world", true},
		{"exact is whole-value", "  s: {message: 'Hello'}\n  condition: s", "hello world", false},
		{"contains", "  s: {message|contains: 'EVIL'}\n  condition: s", "an evil thing", true},
		{"startswith", "  s: {message|startswith: 'GET'}\n  condition: s", "get /x", true},
		{"startswith negative", "  s: {message|startswith: 'GET'}\n  condition: s", "POST /get", false},
		{"endswith", "  s: {message|endswith: '.ps1'}\n  condition: s", "run a.PS1", true},
		{"list is OR", "  s: {message|contains: [aaa, bbb]}\n  condition: s", "xx bbb", true},
		{"all is AND", "  s: {message|contains|all: [aaa, bbb]}\n  condition: s", "xx bbb", false},
		{"all is AND positive", "  s: {message|contains|all: [aaa, bbb]}\n  condition: s", "aaa bbb", true},
		{"wildcard star", "  s: {message: 'user * logged in'}\n  condition: s", "user bob logged in", true},
		{"wildcard question", "  s: {message: 'v?.0'}\n  condition: s", "v2.0", true},
		{"escaped star is literal", "  s: {message: 'a\\*b'}\n  condition: s", "a*b", true},
		{"escaped star negative", "  s: {message: 'a\\*b'}\n  condition: s", "axxb", false},
		{"regex", "  s: {message|re: '^ERR-[0-9]{3}$'}\n  condition: s", "ERR-042", true},
		{"regex is case-sensitive", "  s: {message|re: '^err'}\n  condition: s", "ERR", false},
		{"regex i flag", "  s: {message|re|i: '^err'}\n  condition: s", "ERR", true},
		{"keywords search raw", "  k: [needle]\n  condition: k", "hay NEEDLE hay", true},
		{"keyword all", "  k: {'|all': [one, two]}\n  condition: k", "two then one", true},
		{"null matches missing field", "  s: {hostname: null}\n  condition: s", "x", true},
		{"exists false", "  s: {hostname|exists: false}\n  condition: s", "x", true},
		{"exists true", "  s: {message|exists: true}\n  condition: s", "x", true},
		{"unknown field never matches", "  s: {nosuchfield: x}\n  condition: s", "x", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := one(t, tc.detection)
			if got := r.matches(eventFields(ev(tc.line))); got != tc.want {
				t.Fatalf("match(%q) = %v, want %v", tc.line, got, tc.want)
			}
		})
	}
}

func TestCIDR(t *testing.T) {
	r := one(t, "  s: {src_ip|cidr: 10.0.0.0/8}\n  condition: s")
	in := models.LogEvent{Raw: `{"src_ip":"10.1.2.3"}`, Source: "json"}
	out := models.LogEvent{Raw: `{"src_ip":"192.168.1.1"}`, Source: "json"}
	if !r.matches(eventFields(in)) || r.matches(eventFields(out)) {
		t.Fatal("cidr matching wrong")
	}
}

func TestConditions(t *testing.T) {
	det := `  sel_a: {message|contains: alpha}
  sel_b: {message|contains: beta}
  filter: {message|contains: test}
`
	cases := []struct {
		cond, line string
		want       bool
	}{
		{"sel_a and sel_b", "alpha beta", true},
		{"sel_a and sel_b", "alpha", false},
		{"sel_a or sel_b", "beta", true},
		{"sel_a and not filter", "alpha test", false},
		{"sel_a and not filter", "alpha", true},
		{"(sel_a or sel_b) and not filter", "beta", true},
		{"1 of sel_*", "beta", true},
		{"all of sel_*", "beta", false},
		{"all of sel_*", "alpha beta", true},
		{"1 of them", "test", true},
		{"not 1 of them", "nothing", true},
		{"sel_a AND NOT filter", "alpha", true},
	}
	for _, tc := range cases {
		t.Run(tc.cond+"/"+tc.line, func(t *testing.T) {
			r := one(t, det+"  condition: "+tc.cond)
			if got := r.matches(eventFields(ev(tc.line))); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestConditionListMeansAnyOf(t *testing.T) {
	r := one(t, "  a: {message: one}\n  b: {message: two}\n  condition: [a, b]")
	if !r.matches(eventFields(ev("two"))) {
		t.Fatal("a condition list should OR its entries")
	}
}

func TestBadConditions(t *testing.T) {
	for _, cond := range []string{"sel and", "(sel", "sel or or sel", "1 of nothing_*", "sel near other", "sel !"} {
		_, errs := ParseRules([]byte("title: T\nid: t\ndetection:\n  sel: {message: x}\n  condition: "+cond), "t")
		if len(errs) == 0 {
			t.Errorf("condition %q should fail to compile", cond)
		}
	}
}

func TestJSONFieldsAndAliases(t *testing.T) {
	e := models.LogEvent{
		Raw:      `{"msg":"login","user":{"name":"Alice","roles":["admin","dev"]},"status":401,"latency":0.5}`,
		Message:  "login",
		Hostname: "web01",
		Source:   "json",
	}
	f := eventFields(e)
	for key, want := range map[string]string{
		"user.name":    "Alice",
		"user.roles":   "admin dev",
		"status":       "401",
		"latency":      "0.5",
		"computername": "web01",
		"commandline":  "login",
	} {
		if got := f.values[key]; got != want {
			t.Errorf("field %q = %q, want %q", key, got, want)
		}
	}
	r := one(t, "  s: {user.name: alice, status: 401}\n  condition: s")
	if !r.matches(f) {
		t.Fatal("rule on nested JSON fields should match")
	}
}
