package detection

import (
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/chverma/siemagent/internal/models"
)

// fields is the searchable view of one event: named values (lower-case keys)
// and the full text that keyword selections search.
type fields struct {
	values map[string]string
	text   string
}

// fieldAliases maps common Sigma field names onto the parsed event, so rules
// written for other log pipelines still find their data.
var fieldAliases = map[string][]string{
	"message":  {"message", "msg", "commandline", "command_line", "payload"},
	"hostname": {"hostname", "host", "computer", "computername", "dvc_host"},
	"app_name": {"app_name", "app", "application", "program", "process", "processname", "image", "syslog_identifier"},
	"proc_id":  {"proc_id", "pid", "processid", "process_id"},
	"source":   {"source", "log_format"},
	"raw":      {"raw"},
	// Extracted from the message text (see extractEntities).
	"src_ip":   {"src_ip", "source.ip", "sourceip", "ipaddress", "client_ip", "remote_addr"},
	"user":     {"user", "user.name", "username", "targetusername", "subjectusername"},
	"dst_port": {"dst_port", "destination.port", "destinationport", "dport"},
}

func eventFields(ev models.LogEvent) fields {
	canonical := map[string]string{
		"message":  ev.Message,
		"hostname": ev.Hostname,
		"app_name": ev.AppName,
		"proc_id":  ev.ProcID,
		"source":   ev.Source,
		"raw":      ev.Raw,
	}
	text := ev.Raw
	if text == "" {
		text = ev.Message
	}
	for k, v := range extractEntities(text) {
		canonical[k] = v
	}
	values := make(map[string]string, 32)
	for key, aliases := range fieldAliases {
		if v := canonical[key]; v != "" {
			for _, a := range aliases {
				values[a] = v
			}
		}
	}

	// Structured logs keep every original field (nested keys flattened with
	// dots), overriding aliases with the real data.
	if ev.Source == "json" {
		var obj map[string]any
		if err := json.Unmarshal([]byte(ev.Raw), &obj); err == nil {
			flatten("", obj, values)
		}
	}

	return fields{values: values, text: text}
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
		out[prefix] = ""
	case float64:
		// JSON numbers: print integers without an exponent or decimals.
		if x == float64(int64(x)) {
			out[prefix] = fmt.Sprintf("%d", int64(x))
		} else {
			out[prefix] = fmt.Sprint(x)
		}
	default:
		out[prefix] = fmt.Sprint(x)
	}
}

var (
	// Ordered most to least specific: "from <ip>" in auth logs, key=value
	// pairs in firewall and app logs, then the leading client IP of web
	// access logs.
	srcIPPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\bfrom\s+((?:\d{1,3}\.){3}\d{1,3})\b`),
		regexp.MustCompile(`(?i)\b(?:src|src_ip|client|rhost|remote_addr|ip)[=:]\s*((?:\d{1,3}\.){3}\d{1,3})\b`),
		regexp.MustCompile(`^((?:\d{1,3}\.){3}\d{1,3})\s`),
	}
	userPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\bfor\s+(?:invalid\s+user\s+)?([A-Za-z0-9._@\\-]+)\s+from\b`),
		regexp.MustCompile(`(?i)\binvalid\s+user\s+([A-Za-z0-9._@\\-]+)`),
		regexp.MustCompile(`(?i)\b(?:user|username|ruser|login)[=:]\s*([A-Za-z0-9._@\\-]+)`),
	}
	dstPortPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\b(?:dpt|dport|dst_port|dstport)[=:]\s*(\d{1,5})\b`),
	}
)

// extractEntities pulls the source IP, user name and destination port out of
// free-text log lines, so rules can group by them ("count() by src_ip")
// without a parser per log format. JSON logs override these with their
// real fields.
func extractEntities(text string) map[string]string {
	out := map[string]string{}
	if ip := firstSubmatch(srcIPPatterns, text); ip != "" && net.ParseIP(ip) != nil {
		out["src_ip"] = ip
	}
	if u := firstSubmatch(userPatterns, text); u != "" {
		out["user"] = u
	}
	if p := firstSubmatch(dstPortPatterns, text); p != "" {
		out["dst_port"] = p
	}
	return out
}

func firstSubmatch(res []*regexp.Regexp, text string) string {
	for _, re := range res {
		if m := re.FindStringSubmatch(text); m != nil {
			return m[1]
		}
	}
	return ""
}
