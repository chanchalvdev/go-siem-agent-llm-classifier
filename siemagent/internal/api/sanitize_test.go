package api

import (
	"strings"
	"testing"

	"github.com/chverma/siemagent/internal/models"
)

func TestStripControlRemovesANSIAndControls(t *testing.T) {
	in := "user \x1b[31mroot\x1b[0m logged\x00in\x07\ttabbed"
	got := stripControl(in)
	if strings.ContainsRune(got, 0x1b) {
		t.Errorf("ANSI escape survived: %q", got)
	}
	for _, bad := range []rune{0x00, 0x07} {
		if strings.ContainsRune(got, bad) {
			t.Errorf("control char %#x survived: %q", bad, got)
		}
	}
	if !strings.Contains(got, "root") || !strings.Contains(got, "\ttabbed") {
		t.Errorf("legitimate text/tab was stripped: %q", got)
	}
}

func TestSanitizeEventCleansFields(t *testing.T) {
	ev := models.ClassifiedEvent{
		AttackType:  "Brute\x1b[1m Force",
		Summary:     "line\x00break",
		Remediation: "do \x1b[32mthis",
		IOCs:        []string{"1.2.3.4\x07"},
		Event:       models.LogEvent{Raw: "raw\x1b[0mlog", Message: "msg\x1b[0m"},
	}
	out := sanitizeEvent(ev)
	for _, s := range []string{out.AttackType, out.Summary, out.Remediation, out.IOCs[0], out.Event.Raw, out.Event.Message} {
		if strings.ContainsRune(s, 0x1b) || strings.ContainsRune(s, 0x00) || strings.ContainsRune(s, 0x07) {
			t.Errorf("field not sanitised: %q", s)
		}
	}
	if out.AttackType != "Brute Force" {
		t.Errorf("AttackType = %q, want %q", out.AttackType, "Brute Force")
	}
}
