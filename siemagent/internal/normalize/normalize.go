// Package normalize maps parsed log events onto one common field schema, a
// subset of the Elastic Common Schema (ECS): source.ip, user.name,
// event.outcome, process.command_line and so on. Detection rules, watchlists,
// incident correlation and hunting then work the same way whichever log
// source an event came from.
//
// Values come from three places, first match wins: fields a parser already
// set (e.g. a Suricata or CloudTrail parser), structured JSON keys (by name
// and common aliases), and extractors for well-known text formats (sshd,
// sudo, kernel firewall, web access logs, key=value pairs).
package normalize

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/chverma/siemagent/internal/models"
)

// Schema lists every normalised field with a short description. Fields
// outside it are never set by this package (parsers may add their own).
var Schema = map[string]string{
	"event.category":            "authentication, network, process, web, dns, file, intrusion_detection, iam, configuration",
	"event.action":              "what happened, e.g. ssh_login, sudo, connection_denied, http_request",
	"event.outcome":             "success, failure or unknown",
	"event.code":                "the source's event ID (e.g. Windows 4625)",
	"event.dataset":             "the log source, e.g. sshd, nginx.access, suricata.alert",
	"source.ip":                 "client / attacker IP",
	"source.port":               "client port",
	"destination.ip":            "server / target IP",
	"destination.port":          "server port",
	"network.transport":         "tcp, udp, icmp",
	"network.protocol":          "application protocol, e.g. ssh, http, dns",
	"user.name":                 "the account acting",
	"user.target.name":          "the account acted on (sudo target, account changed)",
	"host.name":                 "the host that logged the event",
	"process.name":              "program name",
	"process.pid":               "process ID",
	"process.executable":        "full path of the program",
	"process.command_line":      "full command line",
	"process.parent.executable": "parent program path",
	"url.original":              "requested URL or path",
	"http.request.method":       "GET, POST, …",
	"http.response.status_code": "HTTP status",
	"user_agent.original":       "client User-Agent",
	"dns.question.name":         "queried domain",
	"file.path":                 "file acted on",
	"file.hash.sha256":          "SHA-256 of the file",
	"file.hash.md5":             "MD5 of the file",
	"rule.name":                 "the rule or signature that fired at the source (IDS, firewall)",
	"observer.product":          "the product that produced the log (e.g. Suricata, CloudTrail)",
}

// jsonAliases maps lower-case JSON keys (flattened with dots) onto schema
// fields. Keys that already are schema names map onto themselves.
var jsonAliases = map[string]string{
	"src_ip": "source.ip", "srcip": "source.ip", "src": "source.ip", "source_ip": "source.ip",
	"client_ip": "source.ip", "clientip": "source.ip", "remote_addr": "source.ip", "remote_ip": "source.ip",
	"sourceipaddress": "source.ip", "ipaddress": "source.ip", "c-ip": "source.ip", "ip": "source.ip",
	"src_port": "source.port", "srcport": "source.port", "sport": "source.port", "source_port": "source.port", "spt": "source.port",
	"dst_ip": "destination.ip", "dest_ip": "destination.ip", "dstip": "destination.ip", "dst": "destination.ip",
	"destination_ip": "destination.ip",
	"dst_port":       "destination.port", "dest_port": "destination.port", "dport": "destination.port",
	"dstport": "destination.port", "destination_port": "destination.port", "dpt": "destination.port",
	"proto": "network.transport", "protocol": "network.transport", "transport": "network.transport",
	"app_proto": "network.protocol",
	"user":      "user.name", "username": "user.name", "user_name": "user.name", "usr": "user.name",
	"login": "user.name", "account": "user.name", "subjectusername": "user.name",
	"targetusername": "user.target.name", "target_user": "user.target.name",
	"host": "host.name", "hostname": "host.name", "computer": "host.name", "computername": "host.name",
	"process": "process.name", "process_name": "process.name", "program": "process.name",
	"image": "process.executable", "exe": "process.executable", "executable": "process.executable",
	"commandline": "process.command_line", "command_line": "process.command_line", "cmdline": "process.command_line",
	"cmd":         "process.command_line",
	"parentimage": "process.parent.executable",
	"pid":         "process.pid", "processid": "process.pid",
	"action": "event.action", "eventname": "event.action",
	"outcome": "event.outcome", "result": "event.outcome",
	"eventid": "event.code", "event_id": "event.code",
	"url": "url.original", "uri": "url.original", "request_uri": "url.original", "path": "url.original",
	"method": "http.request.method", "http_method": "http.request.method", "request_method": "http.request.method",
	"status": "http.response.status_code", "status_code": "http.response.status_code", "response_code": "http.response.status_code",
	"user_agent": "user_agent.original", "useragent": "user_agent.original", "http_user_agent": "user_agent.original",
	"query": "dns.question.name", "qname": "dns.question.name", "dns_query": "dns.question.name",
	"file": "file.path", "filename": "file.path", "file_path": "file.path", "targetfilename": "file.path",
	"sha256": "file.hash.sha256", "md5": "file.hash.md5",
	"signature": "rule.name", "rule": "rule.name",
}

// SigmaAliases lists, for each schema field, the field names Sigma rules
// and other pipelines use for it. Detection exposes values under all of them.
var SigmaAliases = map[string][]string{
	"source.ip":                 {"src_ip", "sourceip", "ipaddress", "client_ip", "remote_addr", "c-ip", "clientip"},
	"source.port":               {"src_port", "sourceport", "ipport"},
	"destination.ip":            {"dst_ip", "destinationip", "dest_ip"},
	"destination.port":          {"dst_port", "destinationport", "dport"},
	"user.name":                 {"user", "username", "subjectusername", "accountname"},
	"user.target.name":          {"targetusername"},
	"process.executable":        {"image"},
	"process.command_line":      {"commandline", "command_line"},
	"process.parent.executable": {"parentimage"},
	"process.pid":               {"processid", "pid"},
	"event.code":                {"eventid"},
	"url.original":              {"url", "cs-uri", "c-uri", "cs-uri-stem", "uri"},
	"http.request.method":       {"cs-method", "method"},
	"http.response.status_code": {"sc-status", "status"},
	"user_agent.original":       {"cs-useragent", "c-useragent", "useragent"},
	"dns.question.name":         {"query", "queryname"},
	"file.path":                 {"targetfilename", "file_path"},
	"network.transport":         {"protocol"},
}

// Event fills ev.Fields. Fields already present are kept.
func Event(ev *models.LogEvent) {
	if ev.Fields == nil {
		ev.Fields = map[string]string{}
	}
	f := setter(ev.Fields)

	if ev.Source == "json" {
		var obj map[string]any
		if err := json.Unmarshal([]byte(ev.Raw), &obj); err == nil {
			flat := map[string]string{}
			flatten("", obj, flat)
			for k, v := range flat {
				if _, ok := Schema[k]; ok {
					f.set(k, v)
				}
			}
			for k, v := range flat {
				if to, ok := jsonAliases[k]; ok {
					f.set(to, v)
				}
			}
		}
	}

	text := ev.Message
	if text == "" {
		text = ev.Raw
	}
	app := strings.ToLower(ev.AppName)
	switch {
	case app == "sshd" || strings.Contains(text, "sshd"):
		sshd(text, f)
	}
	if app == "sudo" || strings.HasPrefix(text, "sudo:") {
		sudo(text, f)
	}
	firewall(text, f)
	webAccess(ev.Raw, f)
	keyValues(text, f)

	f.set("host.name", strings.ToLower(nilDash(ev.Hostname)))
	f.set("process.name", nilDash(ev.AppName))
	f.set("process.pid", nilDash(ev.ProcID))
	f.clean()
}

type fieldSetter map[string]string

func setter(m map[string]string) fieldSetter { return fieldSetter(m) }

// set records v under k unless k already has a value.
func (f fieldSetter) set(k, v string) {
	v = strings.TrimSpace(v)
	if v == "" || f[k] != "" {
		return
	}
	f[k] = v
}

// clean drops values that are not what the field promises (an "IP" that is
// not an address, a port out of range) and lower-cases enumerations.
func (f fieldSetter) clean() {
	for _, k := range []string{"source.ip", "destination.ip"} {
		if v, ok := f[k]; ok {
			a, err := netip.ParseAddr(v)
			if err != nil {
				delete(f, k)
				continue
			}
			f[k] = a.Unmap().String()
		}
	}
	for _, k := range []string{"source.port", "destination.port", "process.pid", "http.response.status_code"} {
		if v, ok := f[k]; ok {
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 || (strings.HasSuffix(k, "port") && n > 65535) {
				delete(f, k)
			}
		}
	}
	for _, k := range []string{"event.outcome", "network.transport", "network.protocol", "event.category"} {
		if v, ok := f[k]; ok {
			f[k] = strings.ToLower(v)
		}
	}
	if v, ok := f["http.request.method"]; ok {
		f["http.request.method"] = strings.ToUpper(v)
	}
	if v, ok := f["event.outcome"]; ok && v != "success" && v != "failure" && v != "unknown" {
		switch v {
		case "succeeded", "ok", "allow", "allowed", "accept", "accepted", "true", "pass":
			f["event.outcome"] = "success"
		case "failed", "fail", "deny", "denied", "drop", "dropped", "reject", "rejected", "blocked", "false", "error":
			f["event.outcome"] = "failure"
		default:
			f["event.outcome"] = "unknown"
		}
	}
	for k, v := range f {
		if v == "" {
			delete(f, k)
		}
	}
}

func nilDash(s string) string {
	if s == "-" {
		return ""
	}
	return s
}

var (
	sshFail     = regexp.MustCompile(`Failed (?:password|publickey|keyboard-interactive/pam|none) for (?:invalid user )?(\S+) from (\S+) port (\d+)`)
	sshAccept   = regexp.MustCompile(`Accepted (?:password|publickey|keyboard-interactive/pam|gssapi-with-mic) for (\S+) from (\S+) port (\d+)`)
	sshInvalid  = regexp.MustCompile(`Invalid user (\S*) from (\S+)(?: port (\d+))?`)
	sudoCommand = regexp.MustCompile(`^\s*(?:sudo:\s*)?(\S+)\s*:.*?USER=(\S+)\s*;\s*COMMAND=(.+)$`)
	fwKV        = regexp.MustCompile(`\b(SRC|DST|PROTO|SPT|DPT)=(\S+)`)
	webAccessRE = regexp.MustCompile(`^(\S+) \S+ (\S+) \[[^\]]+\] "([A-Z]+) (\S+)[^"]*" (\d{3}) \S+(?: "[^"]*" "([^"]*)")?`)
	kvPair      = regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_.-]{1,31})=("([^"]*)"|[^\s,;]+)`)
)

func sshd(text string, f fieldSetter) {
	set := func(user, ip, port, outcome string) {
		f.set("event.category", "authentication")
		f.set("event.action", "ssh_login")
		f.set("event.outcome", outcome)
		f.set("event.dataset", "sshd")
		f.set("network.protocol", "ssh")
		f.set("user.name", user)
		f.set("source.ip", ip)
		f.set("source.port", port)
	}
	if m := sshFail.FindStringSubmatch(text); m != nil {
		set(m[1], m[2], m[3], "failure")
	} else if m := sshAccept.FindStringSubmatch(text); m != nil {
		set(m[1], m[2], m[3], "success")
	} else if m := sshInvalid.FindStringSubmatch(text); m != nil {
		set(m[1], m[2], m[3], "failure")
	}
}

func sudo(text string, f fieldSetter) {
	m := sudoCommand.FindStringSubmatch(text)
	if m == nil {
		return
	}
	f.set("event.category", "process")
	f.set("event.action", "sudo")
	f.set("event.dataset", "sudo")
	f.set("user.name", m[1])
	f.set("user.target.name", m[2])
	f.set("process.command_line", strings.TrimSpace(m[3]))
	if !strings.Contains(text, "incorrect password") && !strings.Contains(text, "NOT in sudoers") {
		f.set("event.outcome", "success")
	} else {
		f.set("event.outcome", "failure")
	}
}

// firewall reads iptables/ufw kernel lines: SRC=… DST=… PROTO=TCP SPT=… DPT=….
func firewall(text string, f fieldSetter) {
	ms := fwKV.FindAllStringSubmatch(text, -1)
	if len(ms) < 2 {
		return
	}
	for _, m := range ms {
		switch m[1] {
		case "SRC":
			f.set("source.ip", m[2])
		case "DST":
			f.set("destination.ip", m[2])
		case "PROTO":
			f.set("network.transport", m[2])
		case "SPT":
			f.set("source.port", m[2])
		case "DPT":
			f.set("destination.port", m[2])
		}
	}
	f.set("event.category", "network")
	f.set("event.dataset", "firewall")
	switch {
	case strings.Contains(text, "BLOCK") || strings.Contains(text, "DROP") || strings.Contains(text, "REJECT") || strings.Contains(text, "DENY"):
		f.set("event.action", "connection_denied")
		f.set("event.outcome", "failure")
	case strings.Contains(text, "ALLOW") || strings.Contains(text, "ACCEPT"):
		f.set("event.action", "connection_allowed")
		f.set("event.outcome", "success")
	}
}

// webAccess reads combined/common access log lines (nginx, Apache).
func webAccess(raw string, f fieldSetter) {
	m := webAccessRE.FindStringSubmatch(raw)
	if m == nil {
		return
	}
	if _, err := netip.ParseAddr(m[1]); err != nil {
		return
	}
	f.set("event.category", "web")
	f.set("event.action", "http_request")
	f.set("event.dataset", "web.access")
	f.set("network.protocol", "http")
	f.set("source.ip", m[1])
	if m[2] != "-" {
		f.set("user.name", m[2])
	}
	f.set("http.request.method", m[3])
	f.set("url.original", m[4])
	f.set("http.response.status_code", m[5])
	f.set("user_agent.original", m[6])
	if code, _ := strconv.Atoi(m[5]); code >= 400 {
		f.set("event.outcome", "failure")
	} else {
		f.set("event.outcome", "success")
	}
}

// keyValues reads generic key=value pairs (app and appliance logs) whose
// keys are known aliases.
func keyValues(text string, f fieldSetter) {
	for _, m := range kvPair.FindAllStringSubmatch(text, 64) {
		key := strings.ToLower(m[1])
		value := m[2]
		if m[3] != "" || strings.HasPrefix(value, `"`) {
			value = m[3]
		}
		if to, ok := jsonAliases[key]; ok {
			f.set(to, value)
		} else if _, ok := Schema[key]; ok {
			f.set(key, value)
		}
	}
}

func flatten(prefix string, v any, out map[string]string) {
	switch x := v.(type) {
	case map[string]any:
		for k, child := range x {
			key := strings.ToLower(k)
			if prefix != "" {
				key = prefix + "." + key
			}
			flatten(key, child, out)
		}
	case []any:
		parts := make([]string, 0, len(x))
		for _, item := range x {
			parts = append(parts, fmt.Sprint(item))
		}
		out[prefix] = strings.Join(parts, " ")
	case nil:
	case float64:
		if x == float64(int64(x)) {
			out[prefix] = strconv.FormatInt(int64(x), 10)
		} else {
			out[prefix] = strconv.FormatFloat(x, 'f', -1, 64)
		}
	case bool:
		out[prefix] = strconv.FormatBool(x)
	default:
		out[prefix] = fmt.Sprint(x)
	}
}
