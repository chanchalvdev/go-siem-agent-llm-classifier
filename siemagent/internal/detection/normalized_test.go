package detection

import (
	"testing"
)

// One rule on normalised fields matches the same activity whatever the log
// format: sshd over syslog, and a JSON auth log from an application.
func TestRuleOnNormalisedFieldsMatchesAcrossSources(t *testing.T) {
	rules, errs := ParseRules([]byte(`
title: Failed login for a privileged account
id: 3c1d7c46-0000-4000-8000-000000000001
level: medium
logsource: {category: authentication}
detection:
  sel:
    event.category: authentication
    event.outcome: failure
    user.name: [root, admin]
  condition: sel
`), "test")
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	engine, errs := NewEngine(rules)
	if len(errs) > 0 {
		t.Fatal(errs)
	}

	for name, line := range map[string]string{
		"sshd syslog": "<38>Oct  5 10:00:01 web01 sshd[4211]: Failed password for root from 203.0.113.7 port 52344 ssh2",
		"json app":    `{"event":{"category":"authentication","outcome":"failure"},"user":"admin","src_ip":"198.51.100.9"}`,
	} {
		if dets := engine.Match(parse(line)); len(dets) != 1 {
			t.Errorf("%s: want a match, got %v (fields %v)", name, dets, parse(line).Fields)
		}
	}
	if dets := engine.Match(parse("<38>Oct  5 10:00:01 web01 sshd[4211]: Accepted password for root from 203.0.113.7 port 52344 ssh2")); len(dets) != 0 {
		t.Errorf("a successful login must not match: %v", dets)
	}
}

// Sigma rules written for Windows/Sysmon field names find normalised values.
func TestSigmaFieldNamesFindNormalisedValues(t *testing.T) {
	rules, errs := ParseRules([]byte(`
title: Whoami via cmd
id: 3c1d7c46-0000-4000-8000-000000000002
level: high
logsource: {product: windows}
detection:
  sel:
    Image|endswith: '\cmd.exe'
    CommandLine|contains: whoami
  condition: sel
`), "test")
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	engine, _ := NewEngine(rules)
	line := `{"exe":"C:\\Windows\\System32\\cmd.exe","cmdline":"cmd.exe /c whoami /all","host":"ws-12"}`
	if dets := engine.Match(parse(line)); len(dets) != 1 {
		t.Fatalf("want a match through Image/CommandLine aliases, got %v (fields %v)", dets, parse(line).Fields)
	}
}

func TestEntitiesPreferNormalisedFields(t *testing.T) {
	ev := parse(`{"src_ip":"198.51.100.9","user":"alice","dst_port":3389,"msg":"from 203.0.113.1"}`)
	got := Entities(ev)
	if got["src_ip"] != "198.51.100.9" || got["user"] != "alice" || got["dst_port"] != "3389" {
		t.Fatalf("entities: %v", got)
	}
}
