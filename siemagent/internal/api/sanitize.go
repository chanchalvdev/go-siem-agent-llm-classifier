package api

import (
	"regexp"
	"strings"

	"github.com/chverma/siemagent/internal/models"
)

// ansiRE matches ANSI/VT100 escape sequences (e.g. colour codes) that a crafted
// log line could smuggle into an API response to attack a terminal/log viewer.
var ansiRE = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]`)

// stripControl removes ANSI escapes and C0 control characters (except tab and
// newline) from log-derived text, defending against log-injection.
func stripControl(s string) string {
	s = ansiRE.ReplaceAllString(s, "")
	return strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' {
			return r
		}
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}

// sanitizeEvent returns a copy of ev with all log-derived string fields cleaned.
// Structured fields the LLM produces are sanitised too, since they may echo raw
// log content back to the client.
func sanitizeEvent(ev models.ClassifiedEvent) models.ClassifiedEvent {
	ev.Event.Raw = stripControl(ev.Event.Raw)
	ev.Event.Message = stripControl(ev.Event.Message)
	ev.Event.Hostname = stripControl(ev.Event.Hostname)
	ev.Event.AppName = stripControl(ev.Event.AppName)
	ev.Summary = stripControl(ev.Summary)
	ev.AttackType = stripControl(ev.AttackType)
	ev.Remediation = stripControl(ev.Remediation)
	for i, ioc := range ev.IOCs {
		ev.IOCs[i] = stripControl(ioc)
	}
	return ev
}
