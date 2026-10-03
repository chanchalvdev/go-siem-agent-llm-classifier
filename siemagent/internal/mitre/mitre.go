// Package mitre is a small, offline subset of MITRE ATT&CK shared by the
// investigation agent and the detection engine.
package mitre

import "strings"

// Technique is one entry in the local ATT&CK subset.
type Technique struct {
	Name      string
	Tactic    string
	Detection string
}

// techniques covers what this SIEM classifies and detects. Kept local and
// small on purpose: lookups stay offline, deterministic and testable.
var techniques = map[string]Technique{
	"T1110":     {"Brute Force", "Credential Access", "Alert on repeated failed logins from one source."},
	"T1110.001": {"Brute Force: Password Guessing", "Credential Access", "Threshold failed auth attempts per account/IP."},
	"T1110.004": {"Brute Force: Credential Stuffing", "Credential Access", "Detect logins across many accounts from one IP."},
	"T1078":     {"Valid Accounts", "Defense Evasion", "Flag logins from anomalous geo/time for known accounts."},
	"T1190":     {"Exploit Public-Facing Application", "Initial Access", "Monitor WAF/app logs for exploit signatures."},
	"T1059":     {"Command and Scripting Interpreter", "Execution", "Alert on unexpected shell spawns from services."},
	"T1059.001": {"Command and Scripting Interpreter: PowerShell", "Execution", "Log PowerShell script blocks; alert on download cradles."},
	"T1059.004": {"Command and Scripting Interpreter: Unix Shell", "Execution", "Alert on interactive shells bound to network sockets."},
	"T1068":     {"Exploitation for Privilege Escalation", "Privilege Escalation", "Watch for setuid abuse and kernel exploit signatures."},
	"T1548":     {"Abuse Elevation Control Mechanism", "Privilege Escalation", "Audit sudo/UAC and unexpected privilege grants."},
	"T1548.003": {"Abuse Elevation Control Mechanism: Sudo and Sudo Caching", "Privilege Escalation", "Alert on sudo to interactive root shells."},
	"T1046":     {"Network Service Discovery", "Discovery", "Detect port-scan patterns and connection fan-out."},
	"T1083":     {"File and Directory Discovery", "Discovery", "Watch for enumeration of sensitive paths."},
	"T1595":     {"Active Scanning", "Reconnaissance", "Flag known scanner user agents and probe patterns."},
	"T1021":     {"Remote Services", "Lateral Movement", "Correlate RDP/SSH/SMB sessions across hosts."},
	"T1055":     {"Process Injection", "Defense Evasion", "Monitor cross-process memory writes and hollowing."},
	"T1070":     {"Indicator Removal", "Defense Evasion", "Alert on log and history deletion."},
	"T1003":     {"OS Credential Dumping", "Credential Access", "Alert on LSASS/shadow access and mimikatz behaviour."},
	"T1003.008": {"OS Credential Dumping: /etc/passwd and /etc/shadow", "Credential Access", "Alert on reads of /etc/shadow outside system tools."},
	"T1041":     {"Exfiltration Over C2 Channel", "Exfiltration", "Flag large egress to known C2 or new destinations."},
	"T1071":     {"Application Layer Protocol", "Command and Control", "Baseline DNS/HTTP beaconing intervals."},
	"T1105":     {"Ingress Tool Transfer", "Command and Control", "Alert on downloads piped straight into a shell."},
	"T1486":     {"Data Encrypted for Impact", "Impact", "Detect mass file rename/entropy spikes (ransomware)."},
	"T1490":     {"Inhibit System Recovery", "Impact", "Alert on shadow copy and backup deletion."},
	"T1498":     {"Network Denial of Service", "Impact", "Alert on traffic-volume anomalies against services."},
	"T1566":     {"Phishing", "Initial Access", "Scan inbound mail for malicious links/attachments."},
	"T1567":     {"Exfiltration Over Web Service", "Exfiltration", "Monitor uploads to cloud/paste services."},
}

// Lookup returns the technique for an ID such as "T1110.001" (case-insensitive).
func Lookup(id string) (Technique, bool) {
	t, ok := techniques[strings.ToUpper(strings.TrimSpace(id))]
	return t, ok
}

// tactics maps ATT&CK tactic slugs (as used in Sigma tags) to display names.
var tactics = map[string]string{
	"reconnaissance":       "Reconnaissance",
	"resource_development": "Resource Development",
	"initial_access":       "Initial Access",
	"execution":            "Execution",
	"persistence":          "Persistence",
	"privilege_escalation": "Privilege Escalation",
	"defense_evasion":      "Defense Evasion",
	"credential_access":    "Credential Access",
	"discovery":            "Discovery",
	"lateral_movement":     "Lateral Movement",
	"collection":           "Collection",
	"command_and_control":  "Command and Control",
	"exfiltration":         "Exfiltration",
	"impact":               "Impact",
}

// TacticName returns the display name for a tactic slug like "credential_access".
func TacticName(slug string) (string, bool) {
	n, ok := tactics[strings.ToLower(strings.ReplaceAll(strings.TrimSpace(slug), "-", "_"))]
	return n, ok
}
