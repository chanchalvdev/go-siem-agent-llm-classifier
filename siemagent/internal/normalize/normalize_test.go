package normalize

import (
	"maps"
	"testing"

	"github.com/chverma/siemagent/internal/models"
)

func norm(ev models.LogEvent) map[string]string {
	Event(&ev)
	return ev.Fields
}

func expect(t *testing.T, name string, got, want map[string]string) {
	t.Helper()
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %s = %q, want %q (all: %v)", name, k, got[k], v, got)
		}
	}
}

func TestSSHD(t *testing.T) {
	expect(t, "failed", norm(models.LogEvent{
		AppName: "sshd", ProcID: "4211", Hostname: "WEB01",
		Message: "Failed password for invalid user admin from 185.220.101.77 port 52344 ssh2",
	}), map[string]string{
		"event.category": "authentication", "event.action": "ssh_login", "event.outcome": "failure",
		"user.name": "admin", "source.ip": "185.220.101.77", "source.port": "52344",
		"host.name": "web01", "process.name": "sshd", "process.pid": "4211", "network.protocol": "ssh",
	})
	expect(t, "accepted", norm(models.LogEvent{AppName: "sshd", Message: "Accepted publickey for deploy from 2001:db8::7 port 22 ssh2"}),
		map[string]string{"event.outcome": "success", "user.name": "deploy", "source.ip": "2001:db8::7"})
	expect(t, "invalid", norm(models.LogEvent{AppName: "sshd", Message: "Invalid user oracle from 203.0.113.4 port 4022"}),
		map[string]string{"event.outcome": "failure", "user.name": "oracle"})
}

func TestSudo(t *testing.T) {
	expect(t, "sudo", norm(models.LogEvent{AppName: "sudo", Message: "deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash -i"}),
		map[string]string{
			"event.category": "process", "event.action": "sudo", "event.outcome": "success",
			"user.name": "deploy", "user.target.name": "root", "process.command_line": "/bin/bash -i",
		})
	expect(t, "refused", norm(models.LogEvent{AppName: "sudo", Message: "mallory : user NOT in sudoers ; TTY=pts/1 ; PWD=/ ; USER=root ; COMMAND=/bin/sh"}),
		map[string]string{"event.outcome": "failure", "user.name": "mallory"})
}

func TestFirewall(t *testing.T) {
	expect(t, "ufw", norm(models.LogEvent{AppName: "kernel",
		Message: "[UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.50 DST=10.0.0.5 LEN=60 PROTO=TCP SPT=40001 DPT=3389 SYN"}),
		map[string]string{
			"event.category": "network", "event.action": "connection_denied", "event.outcome": "failure",
			"source.ip": "203.0.113.50", "destination.ip": "10.0.0.5", "network.transport": "tcp",
			"source.port": "40001", "destination.port": "3389",
		})
}

func TestWebAccess(t *testing.T) {
	line := `198.51.100.23 - - [05/Oct/2026:10:00:01 +0000] "GET /wp-login.php?x=1 HTTP/1.1" 404 153 "-" "sqlmap/1.7"`
	expect(t, "nginx", norm(models.LogEvent{Raw: line, Message: line, Source: "raw"}), map[string]string{
		"event.category": "web", "event.outcome": "failure", "source.ip": "198.51.100.23",
		"http.request.method": "GET", "url.original": "/wp-login.php?x=1",
		"http.response.status_code": "404", "user_agent.original": "sqlmap/1.7",
	})
}

func TestJSON(t *testing.T) {
	raw := `{"src_ip":"203.0.113.9","DstPort":443,"User":"alice","action":"denied","Image":"C:\\Windows\\System32\\cmd.exe",` +
		`"CommandLine":"cmd /c whoami","source":{"port":5555},"user_agent":"curl/8","EventID":4625,"destination.ip":"10.1.1.1"}`
	got := norm(models.LogEvent{Raw: raw, Message: raw, Source: "json"})
	expect(t, "json", got, map[string]string{
		"source.ip": "203.0.113.9", "user.name": "alice", "event.action": "denied",
		"process.executable": `C:\Windows\System32\cmd.exe`, "process.command_line": "cmd /c whoami",
		"source.port": "5555", "user_agent.original": "curl/8", "event.code": "4625", "destination.ip": "10.1.1.1",
		"destination.port": "443", // keys are matched case-insensitively
	})
}

func TestKeyValues(t *testing.T) {
	expect(t, "kv", norm(models.LogEvent{Message: `login failed user=bob src=198.51.100.9 dst_port=8443 outcome=denied reason="bad token"`}),
		map[string]string{"user.name": "bob", "source.ip": "198.51.100.9", "destination.port": "8443", "event.outcome": "failure"})
}

func TestCleaning(t *testing.T) {
	got := norm(models.LogEvent{Message: `src=not-an-ip dpt=99999 pid=abc status=ok method=post proto=UDP`})
	for _, k := range []string{"source.ip", "destination.port", "process.pid", "http.response.status_code"} {
		if _, ok := got[k]; ok {
			t.Errorf("%s should be dropped: %v", k, got)
		}
	}
	if got["http.request.method"] != "POST" || got["network.transport"] != "udp" {
		t.Errorf("case normalisation: %v", got)
	}
	if got := norm(models.LogEvent{Message: "ip=::ffff:203.0.113.9"}); got["source.ip"] != "203.0.113.9" {
		t.Errorf("mapped IPv4: %v", got)
	}
}

func TestParserFieldsWin(t *testing.T) {
	ev := models.LogEvent{AppName: "sshd", Message: "Failed password for root from 203.0.113.7 port 22 ssh2",
		Fields: map[string]string{"source.ip": "198.51.100.1", "observer.product": "Suricata"}}
	Event(&ev)
	if ev.Fields["source.ip"] != "198.51.100.1" || ev.Fields["user.name"] != "root" || ev.Fields["observer.product"] != "Suricata" {
		t.Fatalf("a parser's fields must win: %v", ev.Fields)
	}
}

func TestNothingToExtract(t *testing.T) {
	got := norm(models.LogEvent{Message: "cron[311]: (root) CMD (run-parts /etc/cron.hourly)", Hostname: "-"})
	if len(got) != 0 {
		t.Fatalf("unexpected fields: %v", got)
	}
}

func TestSchemaCoversEverythingWeSet(t *testing.T) {
	all := map[string]string{}
	for _, ev := range []models.LogEvent{
		{AppName: "sshd", ProcID: "1", Hostname: "h", Message: "Failed password for root from 203.0.113.7 port 22 ssh2"},
		{AppName: "sudo", Message: "d : USER=root ; COMMAND=/bin/sh"},
		{Message: "BLOCK SRC=203.0.113.50 DST=10.0.0.5 PROTO=TCP SPT=1 DPT=2"},
		{Raw: `198.51.100.23 - bob [x] "GET / HTTP/1.1" 200 1 "-" "ua"`},
		{Raw: `{"query":"evil.example","sha256":"abc","md5":"d","file":"/tmp/x","rule":"ET SCAN","app_proto":"dns","parentimage":"p"}`, Source: "json"},
	} {
		maps.Copy(all, norm(ev))
	}
	for k := range all {
		if _, ok := Schema[k]; !ok {
			t.Errorf("%s is set but not in Schema", k)
		}
	}
	for to := range jsonAliases {
		if _, ok := Schema[jsonAliases[to]]; !ok {
			t.Errorf("alias %s maps to %s, not in Schema", to, jsonAliases[to])
		}
	}
	for k := range SigmaAliases {
		if _, ok := Schema[k]; !ok {
			t.Errorf("SigmaAliases has %s, not in Schema", k)
		}
	}
}
