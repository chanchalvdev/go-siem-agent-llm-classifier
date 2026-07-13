package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// technique is one entry in the local ATT&CK subset.
type technique struct {
	Name      string `json:"technique"`
	Tactic    string `json:"tactic"`
	Detection string `json:"detection"`
}

// attackSubset covers the techniques this SIEM actually classifies. Kept local
// and small on purpose (KISS): the tool stays offline, deterministic, testable.
var attackSubset = map[string]technique{
	"T1110":     {"Brute Force", "Credential Access", "Alert on repeated failed logins from one source."},
	"T1110.001": {"Brute Force: Password Guessing", "Credential Access", "Threshold failed auth attempts per account/IP."},
	"T1110.004": {"Brute Force: Credential Stuffing", "Credential Access", "Detect logins across many accounts from one IP."},
	"T1078":     {"Valid Accounts", "Defense Evasion", "Flag logins from anomalous geo/time for known accounts."},
	"T1190":     {"Exploit Public-Facing Application", "Initial Access", "Monitor WAF/app logs for exploit signatures."},
	"T1059":     {"Command and Scripting Interpreter", "Execution", "Alert on unexpected shell spawns from services."},
	"T1068":     {"Exploitation for Privilege Escalation", "Privilege Escalation", "Watch for setuid abuse and kernel exploit signatures."},
	"T1548":     {"Abuse Elevation Control Mechanism", "Privilege Escalation", "Audit sudo/UAC and unexpected privilege grants."},
	"T1046":     {"Network Service Discovery", "Discovery", "Detect port-scan patterns and connection fan-out."},
	"T1021":     {"Remote Services", "Lateral Movement", "Correlate RDP/SSH/SMB sessions across hosts."},
	"T1055":     {"Process Injection", "Defense Evasion", "Monitor cross-process memory writes and hollowing."},
	"T1003":     {"OS Credential Dumping", "Credential Access", "Alert on LSASS/shadow access and mimikatz behaviour."},
	"T1041":     {"Exfiltration Over C2 Channel", "Exfiltration", "Flag large egress to known C2 or new destinations."},
	"T1071":     {"Application Layer Protocol", "Command and Control", "Baseline DNS/HTTP beaconing intervals."},
	"T1486":     {"Data Encrypted for Impact", "Impact", "Detect mass file rename/entropy spikes (ransomware)."},
	"T1498":     {"Network Denial of Service", "Impact", "Alert on traffic-volume anomalies against services."},
	"T1566":     {"Phishing", "Initial Access", "Scan inbound mail for malicious links/attachments."},
	"T1567":     {"Exfiltration Over Web Service", "Exfiltration", "Monitor uploads to cloud/paste services."},
}

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
	t, ok := attackSubset[id]
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
