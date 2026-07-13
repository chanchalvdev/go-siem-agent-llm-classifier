package tools

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func mitreInput(id string) json.RawMessage {
	b, _ := json.Marshal(map[string]string{"technique_id": id})
	return b
}

func TestMITREKnown(t *testing.T) {
	out, err := MITRELookup{}.Execute(context.Background(), mitreInput("t1110.001"))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	for _, want := range []string{"Password Guessing", "Credential Access"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q: %s", want, out)
		}
	}
}

func TestMITREUnknown(t *testing.T) {
	out, err := MITRELookup{}.Execute(context.Background(), mitreInput("T9999"))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.Contains(out, "not in local") {
		t.Errorf("expected not-found note, got %s", out)
	}
}
