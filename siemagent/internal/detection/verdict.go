package detection

import (
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/chverma/siemagent/internal/mitre"
	"github.com/chverma/siemagent/internal/models"
)

var levelSeverity = map[string]models.Severity{
	"critical":      models.SeverityP1,
	"high":          models.SeverityP2,
	"medium":        models.SeverityP3,
	"low":           models.SeverityP4,
	"informational": models.SeverityP5,
}

// SeverityForLevel maps a Sigma level to P1–P5.
func SeverityForLevel(level string) models.Severity {
	if s, ok := levelSeverity[level]; ok {
		return s
	}
	return models.SeverityP3
}

// Verdict builds a complete classification from rule matches alone, used
// when a rule fires and the LLM is skipped. dets must be non-empty and sorted
// most severe first (as Engine.Match returns them).
func (e *Engine) Verdict(ev models.LogEvent, dets []models.Detection) models.ClassifiedEvent {
	top := dets[0]
	rule, _ := e.Rule(top.RuleID)

	out := models.ClassifiedEvent{
		Event:        ev,
		AttackType:   top.Title,
		Severity:     SeverityForLevel(top.Level),
		Confidence:   0.8,
		IOCs:         extractIOCs(ev.Raw),
		Summary:      top.Title,
		Remediation:  "Review the matched activity and confirm whether it is expected.",
		ProcessedAt:  time.Now().UTC(),
		Detections:   dets,
		ClassifiedBy: models.ClassifiedByRules,
		MITRE:        mitreFromTags(top.Tags),
	}
	if rule != nil {
		out.Confidence = confidenceForStatus(rule.Status)
		if rule.Description != "" {
			out.Summary = rule.Description
		}
		if rule.Remediation != "" {
			out.Remediation = rule.Remediation
		}
	}
	return out
}

// mitreFromTags reads "attack.t1059.001" and "attack.execution" style tags.
func mitreFromTags(tags []string) models.MITREInfo {
	var info models.MITREInfo
	for _, t := range tags {
		name, ok := strings.CutPrefix(t, "attack.")
		if !ok {
			continue
		}
		if info.TechniqueID == "" && len(name) > 1 && name[0] == 't' && name[1] >= '0' && name[1] <= '9' {
			info.TechniqueID = strings.ToUpper(name)
			if tech, ok := mitre.Lookup(info.TechniqueID); ok {
				info.Technique = tech.Name
				if info.Tactic == "" {
					info.Tactic = tech.Tactic
				}
			}
			continue
		}
		if tactic, ok := mitre.TacticName(name); ok && info.Tactic == "" {
			info.Tactic = tactic
		}
	}
	if info.Tactic == "" {
		info.Tactic = "N/A"
	}
	return info
}

// confidenceForStatus reflects how battle-tested a rule is.
func confidenceForStatus(status string) float64 {
	switch status {
	case "stable":
		return 0.95
	case "test":
		return 0.85
	default: // experimental, unknown or unset
		return 0.75
	}
}

var (
	ipv4RE = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	urlRE  = regexp.MustCompile(`https?://[^\s"'<>()]+`)
	hashRE = regexp.MustCompile(`\b(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b`)
)

// extractIOCs pulls URLs, IPv4 addresses and file hashes out of a log line.
func extractIOCs(text string) []string {
	seen := map[string]bool{}
	out := []string{} // never nil: the API documents iocs as an array
	add := func(s string) {
		if !seen[s] && len(out) < 10 {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, u := range urlRE.FindAllString(text, -1) {
		add(strings.TrimRight(u, ".,;"))
	}
	for _, ip := range ipv4RE.FindAllString(text, -1) {
		if parsed := net.ParseIP(ip); parsed != nil && !parsed.IsUnspecified() {
			add(ip)
		}
	}
	for _, h := range hashRE.FindAllString(text, -1) {
		add(strings.ToLower(h))
	}
	return out
}
