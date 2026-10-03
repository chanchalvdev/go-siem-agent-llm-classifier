package detection

import (
	"encoding/json"
	"fmt"
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

	text := ev.Raw
	if text == "" {
		text = ev.Message
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
