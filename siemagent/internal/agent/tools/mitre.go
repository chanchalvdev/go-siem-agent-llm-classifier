package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/chverma/siemagent/internal/mitre"
)

// MITRELookup returns local ATT&CK detail for a technique ID. No API key needed.
type MITRELookup struct{}

func (MITRELookup) Name() string        { return "lookup_mitre" }
func (MITRELookup) Description() string { return "Look up a MITRE ATT&CK technique by ID." }
func (MITRELookup) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"technique_id":{"type":"string","description":"e.g. T1110.001"}},"required":["technique_id"]}`)
}

func (MITRELookup) Execute(_ context.Context, input json.RawMessage) (string, error) {
	var in struct {
		TechniqueID string `json:"technique_id"`
	}
	if err := json.Unmarshal(input, &in); err != nil {
		return "", fmt.Errorf("mitre: bad input: %w", err)
	}
	id := strings.ToUpper(strings.TrimSpace(in.TechniqueID))
	t, ok := mitre.Lookup(id)
	if !ok {
		out, _ := json.Marshal(map[string]string{"technique_id": id, "note": "not in local ATT&CK subset"})
		return string(out), nil
	}
	out, _ := json.Marshal(map[string]string{
		"technique_id": id,
		"technique":    t.Name,
		"tactic":       t.Tactic,
		"detection":    t.Detection,
	})
	return string(out), nil
}
