// Package response proposes and runs response actions (block an IP, disable
// a user, notify a channel) from declarative playbooks.
//
// Humans approve actions: a playbook in "approval" mode only proposes, and
// an analyst approves each action before it runs. "dry_run" records what
// would have happened without doing it, so a playbook can be trusted before
// it is switched to "auto".
package response

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/chverma/siemagent/internal/models"
)

//go:embed playbooks/*.yml
var builtinPlaybooks embed.FS

// Mode decides what happens when a playbook matches.
type Mode string

const (
	// ModeApproval proposes actions; an analyst approves each one. Default.
	ModeApproval Mode = "approval"
	// ModeDryRun records what would have run, without running it.
	ModeDryRun Mode = "dry_run"
	// ModeAuto runs actions immediately. Only for well-tested playbooks.
	ModeAuto Mode = "auto"
)

// Action types.
const (
	ActionBlockIP     = "block_ip"
	ActionDisableUser = "disable_user"
	ActionIsolateHost = "isolate_host"
	ActionNotify      = "notify"
	ActionWebhook     = "webhook"
)

// actionTargets lists the entity kind each action acts on ("" = the incident).
var actionTargets = map[string]string{
	ActionBlockIP:     "ip",
	ActionDisableUser: "user",
	ActionIsolateHost: "host",
	ActionNotify:      "",
	ActionWebhook:     "",
}

// Trigger selects the incidents a playbook applies to. Every set field must
// match; list fields match when any element does.
type Trigger struct {
	MinSeverity models.Severity `yaml:"min_severity" json:"min_severity,omitempty"`
	Tactics     []string        `yaml:"tactics" json:"tactics,omitempty"`
	Techniques  []string        `yaml:"techniques" json:"techniques,omitempty"`
	// AttackTypes match (case-insensitive substring) the alert's attack type
	// or a matched rule title.
	AttackTypes []string `yaml:"attack_types" json:"attack_types,omitempty"`
}

// ActionSpec is one step of a playbook.
type ActionSpec struct {
	Type string `yaml:"type" json:"type"`
	// Message is the text for notify actions. {{title}}, {{severity}},
	// {{id}} and {{entities}} are replaced with incident values.
	Message string `yaml:"message" json:"message,omitempty"`
	// URL is required for webhook actions. Never serialised: webhook URLs
	// often embed a secret token.
	URL string `yaml:"url" json:"-"`
}

// Playbook is a compiled response playbook.
type Playbook struct {
	ID          string       `yaml:"id" json:"id"`
	Name        string       `yaml:"name" json:"name"`
	Description string       `yaml:"description" json:"description,omitempty"`
	Mode        Mode         `yaml:"mode" json:"mode"`
	Enabled     *bool        `yaml:"enabled" json:"-"`
	Trigger     Trigger      `yaml:"trigger" json:"trigger"`
	Actions     []ActionSpec `yaml:"actions" json:"actions"`
	// AllowPrivateIPs lets block_ip target private and reserved addresses.
	// Off by default: blocking an internal gateway is a self-inflicted outage.
	AllowPrivateIPs bool   `yaml:"allow_private_ips" json:"allow_private_ips,omitempty"`
	Source          string `yaml:"-" json:"source"`
}

// IsEnabled reports whether the playbook is active (default true).
func (p *Playbook) IsEnabled() bool { return p.Enabled == nil || *p.Enabled }

var idRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,63}$`)

func (p *Playbook) validate() error {
	if !idRE.MatchString(p.ID) {
		return fmt.Errorf("id %q must be lowercase kebab-case", p.ID)
	}
	if strings.TrimSpace(p.Name) == "" {
		return errors.New("missing name")
	}
	switch p.Mode {
	case "":
		p.Mode = ModeApproval
	case ModeApproval, ModeDryRun, ModeAuto:
	default:
		return fmt.Errorf("mode %q must be approval, dry_run or auto", p.Mode)
	}
	if s := p.Trigger.MinSeverity; s != "" {
		if _, ok := severityRank[s]; !ok {
			return fmt.Errorf("trigger.min_severity %q must be P1–P5", s)
		}
	}
	if len(p.Actions) == 0 {
		return errors.New("playbook has no actions")
	}
	for i, a := range p.Actions {
		if _, ok := actionTargets[a.Type]; !ok {
			return fmt.Errorf("action %d: unknown type %q", i+1, a.Type)
		}
		if a.Type == ActionWebhook && !strings.HasPrefix(a.URL, "https://") && !strings.HasPrefix(a.URL, "http://") {
			return fmt.Errorf("action %d: webhook needs an http(s) url", i+1)
		}
	}
	return nil
}

var severityRank = map[models.Severity]int{
	models.SeverityP1: 1, models.SeverityP2: 2, models.SeverityP3: 3, models.SeverityP4: 4, models.SeverityP5: 5,
}

// ParsePlaybooks reads one or more YAML documents.
func ParsePlaybooks(data []byte, source string) ([]*Playbook, []error) {
	var out []*Playbook
	var errs []error
	dec := yaml.NewDecoder(bytes.NewReader(data))
	for doc := 1; ; doc++ {
		var p Playbook
		err := dec.Decode(&p)
		if errors.Is(err, io.EOF) {
			return out, errs
		}
		if err != nil {
			return out, append(errs, fmt.Errorf("%s: document %d: %w", source, doc, err))
		}
		if err := p.validate(); err != nil {
			errs = append(errs, fmt.Errorf("%s: playbook %q: %w", source, p.ID, err))
			continue
		}
		p.Source = source
		out = append(out, &p)
	}
}

// LoadBuiltin returns the playbooks shipped in the binary.
func LoadBuiltin() ([]*Playbook, []error) {
	var out []*Playbook
	var errs []error
	entries, err := builtinPlaybooks.ReadDir("playbooks")
	if err != nil {
		return nil, []error{err}
	}
	for _, e := range entries {
		data, err := builtinPlaybooks.ReadFile("playbooks/" + e.Name())
		if err != nil {
			errs = append(errs, err)
			continue
		}
		ps, es := ParsePlaybooks(data, "builtin")
		out = append(out, ps...)
		errs = append(errs, es...)
	}
	return out, errs
}

// LoadDir loads every .yml/.yaml file under dir.
func LoadDir(dir string) ([]*Playbook, []error) {
	var out []*Playbook
	var errs []error
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		ext := strings.ToLower(filepath.Ext(path))
		if d.IsDir() || (ext != ".yml" && ext != ".yaml") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			errs = append(errs, err)
			return nil
		}
		ps, es := ParsePlaybooks(data, path)
		out = append(out, ps...)
		errs = append(errs, es...)
		return nil
	})
	if err != nil {
		errs = append(errs, fmt.Errorf("load playbooks from %s: %w", dir, err))
	}
	return out, errs
}

// dedupe drops playbooks whose ID was already loaded (first wins) and sorts by name.
func dedupe(in []*Playbook) ([]*Playbook, []error) {
	seen := map[string]string{}
	var out []*Playbook
	var errs []error
	for _, p := range in {
		if prev, ok := seen[p.ID]; ok {
			errs = append(errs, fmt.Errorf("%s: playbook id %s already loaded from %s", p.Source, p.ID, prev))
			continue
		}
		seen[p.ID] = p.Source
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, errs
}
