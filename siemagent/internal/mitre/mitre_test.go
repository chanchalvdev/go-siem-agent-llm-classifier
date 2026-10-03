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
