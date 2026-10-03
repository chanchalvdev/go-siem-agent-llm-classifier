package parser

import (
	"testing"
	"time"
)

func TestParseSyslog_RFC5424(t *testing.T) {
	p := New()

	tests := []struct {
		name     string
		line     string
		wantOk   bool // should produce source=="syslog"
		hostname string
		appName  string
		procID   string
		message  string
		utc      bool // timestamp should be UTC
	}{
		{
			name:     "valid RFC5424",
			line:     `<165>1 2024-01-15T10:30:00Z webserver sshd 1234 - Failed password for root from 192.168.1.100 port 22`,
			wantOk:   true,
			hostname: "webserver",
			appName:  "sshd",
			procID:   "1234",
			message:  "Failed password for root from 192.168.1.100 port 22",
			utc:      true,
		},
		{
			name:     "NILVALUE procid dash",
			line:     `<34>1 2024-01-15T10:30:00Z host app - - some message`,
			wantOk:   true,
			hostname: "host",
			appName:  "app",
			procID:   "", // "-" should become empty
			message:  "some message",
		},
		{
			name:     "UTC timestamp preserved",
			line:     `<13>1 2024-06-01T00:00:00Z myhost myapp 42 - hello`,
			wantOk:   true,
			utc:      true,
			hostname: "myhost",
			appName:  "myapp",
			procID:   "42",
			message:  "hello",
		},
		{
			name:   "empty string returns nil",
			line:   "",
			wantOk: false,
		},
		{
			name:   "plain text without a syslog header falls back to raw",
			line:   "something happened at 10:30 on myhost",
			wantOk: false,
		},
		{
			// RFC 5424: [UFW BLOCK] is the structured-data element; the parser
			// strips it per the grammar, so the message starts after the SD.
			name:     "kernel log with PID 0 and brackets in message",
			line:     `<0>1 2024-01-15T10:30:00Z localhost kernel 0 - [UFW BLOCK] IN=eth0 OUT= MAC=00:11:22 SRC=10.0.0.1 DST=192.168.1.1 PROTO=TCP`,
			wantOk:   true,
			hostname: "localhost",
			appName:  "kernel",
			procID:   "0",
			message:  "IN=eth0 OUT= MAC=00:11:22 SRC=10.0.0.1 DST=192.168.1.1 PROTO=TCP",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			events := p.ParseLine(tc.line)

			if tc.line == "" {
				if len(events) != 0 {
					t.Errorf("expected nil events for empty line, got %d", len(events))
				}
				return
			}

			if len(events) == 0 {
				if tc.wantOk {
					t.Fatal("expected at least one event, got none")
				}
				return
			}

			ev := events[0]

			if tc.wantOk && ev.Source != "syslog" {
				t.Errorf("source: want syslog, got %q", ev.Source)
			}
			if !tc.wantOk && ev.Source == "syslog" {
				t.Errorf("source: expected non-syslog fallback, got syslog")
			}

			if tc.wantOk {
				if tc.hostname != "" && ev.Hostname != tc.hostname {
					t.Errorf("hostname: want %q, got %q", tc.hostname, ev.Hostname)
				}
				if tc.appName != "" && ev.AppName != tc.appName {
					t.Errorf("appName: want %q, got %q", tc.appName, ev.AppName)
				}
				if tc.procID != "" && ev.ProcID != tc.procID {
					t.Errorf("procID: want %q, got %q", tc.procID, ev.ProcID)
				}
				if tc.message != "" && ev.Message != tc.message {
					t.Errorf("message: want %q, got %q", tc.message, ev.Message)
				}
				if tc.utc && !ev.Timestamp.IsZero() {
					if ev.Timestamp.Location() != time.UTC && ev.Timestamp.Location().String() != "UTC" {
						t.Errorf("expected UTC timestamp, got zone %q", ev.Timestamp.Location())
					}
				}
				// Only check NILVALUE when the test explicitly expects empty procID.
				if tc.procID == "" && ev.ProcID != "" {
					t.Errorf("NILVALUE procID: expected empty, got %q", ev.ProcID)
				}
			}
		})
	}
}

func TestParseSyslog_BSD(t *testing.T) {
	p := New()
	cases := []struct {
		name, line, host, app, pid, msg string
	}{
		{"auth.log line without PRI", "Oct 11 22:14:15 web01 sshd[4721]: Failed password for root from 185.220.101.4 port 52211 ssh2",
			"web01", "sshd", "4721", "Failed password for root from 185.220.101.4 port 52211 ssh2"},
		{"with PRI", "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8",
			"mymachine", "su", "", "'su root' failed for lonvick on /dev/pts/8"},
		{"single-digit day padded", "Jun  5 09:01:02 db01 kernel: [UFW BLOCK] IN=eth0 SRC=203.0.113.50 DPT=22",
			"db01", "kernel", "", "[UFW BLOCK] IN=eth0 SRC=203.0.113.50 DPT=22"},
		{"sudo with colons in message", "Oct 11 22:21:00 app01 sudo:   deploy : TTY=pts/0 ; USER=root ; COMMAND=/bin/bash",
			"app01", "sudo", "", "deploy : TTY=pts/0 ; USER=root ; COMMAND=/bin/bash"},
		{"rsyslog high-precision timestamp", "2026-10-03T10:00:00.123456+00:00 web01 sshd[99]: Accepted publickey for deploy",
			"web01", "sshd", "99", "Accepted publickey for deploy"},
		{"ISO timestamp with Z", "2026-10-03T10:00:00Z gw01 dnsmasq[7]: query[A] example.com",
			"gw01", "dnsmasq", "7", "query[A] example.com"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			evs := p.ParseLine(c.line)
			if len(evs) != 1 {
				t.Fatalf("got %d events", len(evs))
			}
			ev := evs[0]
			if ev.Source != "syslog" || ev.Hostname != c.host || ev.AppName != c.app || ev.ProcID != c.pid || ev.Message != c.msg {
				t.Fatalf("got source=%q host=%q app=%q pid=%q msg=%q", ev.Source, ev.Hostname, ev.AppName, ev.ProcID, ev.Message)
			}
			if ev.Timestamp.IsZero() || ev.Raw != c.line {
				t.Fatalf("timestamp %v / raw %q", ev.Timestamp, ev.Raw)
			}
		})
	}
}

func TestBSDTimestampYear(t *testing.T) {
	p := New()
	now := time.Now().UTC()
	// A line from tomorrow+2 days can't be from this year's future; it is last year's.
	future := now.Add(72 * time.Hour)
	line := future.Format("Jan _2 15:04:05") + " h app: x"
	ev := p.ParseLine(line)[0]
	if ev.Timestamp.Year() != future.Year()-1 {
		t.Fatalf("future BSD date should roll back a year: %v", ev.Timestamp)
	}
	past := now.Add(-72 * time.Hour)
	ev = p.ParseLine(past.Format("Jan _2 15:04:05") + " h app: x")[0]
	if ev.Timestamp.Year() != past.Year() {
		t.Fatalf("recent BSD date keeps its year: %v", ev.Timestamp)
	}
}
