// Package logsafe makes untrusted text safe to put in log records.
//
// Log lines, URL parameters and error messages can carry attacker-controlled
// text. Line breaks in it could forge extra log entries for anyone reading
// raw logs, so they are removed before logging.
package logsafe

import "strings"

// maxLen bounds how much untrusted text one log field may carry.
const maxLen = 256

// String removes line breaks and other control characters and caps the length.
func String(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) > maxLen {
		s = s[:maxLen] + "…"
	}
	return s
}

// Err is String applied to an error's message.
func Err(err error) string {
	if err == nil {
		return ""
	}
	return String(err.Error())
}
