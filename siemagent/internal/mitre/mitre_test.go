package mitre

import "testing"

func TestLookup(t *testing.T) {
	got, ok := Lookup(" t1110.001 ")
	if !ok || got.Tactic != "Credential Access" {
		t.Fatalf("Lookup: %+v %v", got, ok)
	}
	if _, ok := Lookup("T9999"); ok {
		t.Fatal("unknown technique should not resolve")
	}
}

func TestTacticName(t *testing.T) {
	for slug, want := range map[string]string{
		"credential_access":   "Credential Access",
		"command-and-control": "Command and Control",
		"IMPACT":              "Impact",
	} {
		if got, ok := TacticName(slug); !ok || got != want {
			t.Errorf("TacticName(%q) = %q, %v; want %q", slug, got, ok, want)
		}
	}
	if _, ok := TacticName("t1059"); ok {
		t.Error("a technique tag is not a tactic")
	}
}

func TestEveryTechniqueHasAKnownTactic(t *testing.T) {
	known := map[string]bool{}
	for _, name := range tactics {
		known[name] = true
	}
	for id, tech := range techniques {
		if !known[tech.Tactic] {
			t.Errorf("%s has unknown tactic %q", id, tech.Tactic)
		}
	}
}

func TestTacticStage(t *testing.T) {
	if TacticStage("Reconnaissance") != 0 || TacticStage("impact") != len(KillChain)-1 {
		t.Fatal("kill chain ends are wrong")
	}
	if TacticStage("Credential Access") <= TacticStage("Initial Access") {
		t.Fatal("credential access comes after initial access")
	}
	if TacticStage("N/A") != -1 || TacticStage("") != -1 {
		t.Fatal("non-tactics should be -1")
	}
	for slug, name := range tactics {
		if TacticStage(name) < 0 {
			t.Errorf("tactic %s (%s) missing from KillChain", slug, name)
		}
	}
}
