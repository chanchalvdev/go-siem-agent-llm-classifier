package parser

import (
	"testing"
	"time"
)

func TestParseJSON(t *testing.T) {
	p := New()
	now := time.Now()

	tests := []struct {
		name         string
		line         string
		wantSource   string // "json" or "raw"
		wantMsg      string
		wantHost     string
		wantApp      string
		wantTSApprox bool // timestamp should be approximately now (fallback)
		wantErr      bool // expect nil events or fallback to raw
	}{
		{
			name:       "logrus format",
			line:       `{"level":"error","msg":"connection refused","time":"2024-01-15T10:30:00Z","hostname":"webserver","app":"myservice"}`,
			wantSource: "json",
			wantMsg:    "connection refused",
			wantHost:   "webserver",
			wantApp:    "myservice",
		},
		{
			name:       "zap format with unix float ts",
			line:       `{"level":"warn","message":"disk full","ts":1705315800.0,"host":"storage01","service":"diskmon"}`,
			wantSource: "json",
			wantMsg:    "disk full",
			wantHost:   "storage01",
			wantApp:    "diskmon",
			// ts as unix float is not currently parsed — fallback to now is expected
			wantTSApprox: true,
		},
		{
			name:       "zerolog format with RFC3339 time",
			line:       `{"level":"error","message":"auth failed","time":"2024-01-15T10:30:00Z","host":"authsrv"}`,
			wantSource: "json",
			wantMsg:    "auth failed",
			wantHost:   "authsrv",
		},
		{
			name:       "bunyan format with int level and hostname",
			line:       `{"level":50,"msg":"uncaught exception","hostname":"worker-1","time":"2024-01-15T10:30:00Z"}`,
			wantSource: "json",
			wantMsg:    "uncaught exception",
			wantHost:   "worker-1",
		},
		{
			name:         "missing timestamp falls back to now",
			line:         `{"message":"something happened","hostname":"box1"}`,
			wantSource:   "json",
			wantMsg:      "something happened",
			wantTSApprox: true,
		},
		{
			name:       "invalid JSON falls back to raw",
			line:       `{not valid json`,
			wantSource: "raw",
		},
		{
			name:       "empty JSON object",
			line:       `{}`,
			wantSource: "json",
			wantMsg:    `{}`, // fallback: full line used as message
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			events := p.ParseLine(tc.line)
			if len(events) == 0 {
				t.Fatal("expected at least one event, got none")
			}

			ev := events[0]

			if ev.Source != tc.wantSource {
				t.Errorf("source: want %q, got %q", tc.wantSource, ev.Source)
			}
			if tc.wantMsg != "" && ev.Message != tc.wantMsg {
				t.Errorf("message: want %q, got %q", tc.wantMsg, ev.Message)
			}
			if tc.wantHost != "" && ev.Hostname != tc.wantHost {
				t.Errorf("hostname: want %q, got %q", tc.wantHost, ev.Hostname)
			}
			if tc.wantApp != "" && ev.AppName != tc.wantApp {
				t.Errorf("appName: want %q, got %q", tc.wantApp, ev.AppName)
			}
			if tc.wantTSApprox {
				diff := ev.Timestamp.Sub(now)
				if diff < 0 {
					diff = -diff
				}
				if diff > 5*time.Second {
					t.Errorf("timestamp fallback: expected approximately now, got %v (diff %v)", ev.Timestamp, diff)
				}
			}
		})
	}
}

// Ensure ParseLineWithFormat("json") rejects non-JSON as raw.
func TestParseLineWithFormat_JSON(t *testing.T) {
	p := New()
	line := `<165>1 2024-01-15T10:30:00Z host sshd 1 - msg`
	events := p.ParseLineWithFormat(line, "json")
	if len(events) == 0 {
		t.Fatal("expected fallback event")
	}
	// A syslog line passed with format=json should fall back to raw source
	if events[0].Source == "syslog" {
		t.Error("format=json should not parse as syslog")
	}
}
