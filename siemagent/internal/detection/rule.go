package detection

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync/atomic"

	"gopkg.in/yaml.v3"
)

// Levels in Sigma order, most severe last.
var levelRank = map[string]int{
	"informational": 1,
	"low":           2,
	"medium":        3,
	"high":          4,
	"critical":      5,
}

// Rule is a compiled Sigma rule.
type Rule struct {
	ID          string
	Title       string
	Description string
	Status      string
	Level       string
	Tags        []string
	Author      string
	References  []string
	// Remediation is an extension field (not in the Sigma spec) used as the
	// recommended action when the rule alone classifies an event.
	Remediation string
	Source      string // "builtin" or the file it was loaded from

	// Samples are example log lines the rule must (Match) and must not
	// (NoMatch) fire on. Rule tests replay them — detection as code.
	Samples Samples

	selections map[string]selection
	condition  cond
	hits       atomic.Int64
}

// Samples holds a rule's test log lines.
type Samples struct {
	Match   []string `yaml:"match"`
	NoMatch []string `yaml:"no_match"`
}

// Hits reports how many events the rule has matched since start.
func (r *Rule) Hits() int64 { return r.hits.Load() }

type ruleYAML struct {
	Title          string         `yaml:"title"`
	ID             string         `yaml:"id"`
	Status         string         `yaml:"status"`
	Description    string         `yaml:"description"`
	Author         string         `yaml:"author"`
	References     []string       `yaml:"references"`
	Tags           []string       `yaml:"tags"`
	Level          string         `yaml:"level"`
	Detection      map[string]any `yaml:"detection"`
	Remediation    string         `yaml:"remediation"`
	Samples        Samples        `yaml:"samples"`
	Action         string         `yaml:"action"`
	Correlation    any            `yaml:"correlation"`
	FalsePositives []string       `yaml:"falsepositives"`
}

// ErrUnsupported marks valid Sigma that this engine deliberately does not
// evaluate (aggregations, correlations, multi-document collections).
var ErrUnsupported = errors.New("unsupported sigma feature")

// ParseRules reads every YAML document in data. Rules that fail to compile are
// reported in errs; the valid ones are still returned.
func ParseRules(data []byte, source string) (rules []*Rule, errs []error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	for doc := 1; ; doc++ {
		var raw ruleYAML
		err := dec.Decode(&raw)
		if errors.Is(err, io.EOF) {
			return rules, errs
		}
		if err != nil {
			return rules, append(errs, fmt.Errorf("%s: document %d: %w", source, doc, err))
		}
		r, err := compileRule(raw, source)
		if err != nil {
			label := raw.Title
			if label == "" {
				label = fmt.Sprintf("document %d", doc)
			}
			errs = append(errs, fmt.Errorf("%s: %s: %w", source, label, err))
			continue
		}
		rules = append(rules, r)
	}
}

func compileRule(raw ruleYAML, source string) (*Rule, error) {
	if raw.Action != "" || raw.Correlation != nil {
		return nil, fmt.Errorf("%w: rule collections and correlations", ErrUnsupported)
	}
	if strings.TrimSpace(raw.Title) == "" {
		return nil, errors.New("missing title")
	}
	if strings.TrimSpace(raw.ID) == "" {
		return nil, errors.New("missing id")
	}
	level := strings.ToLower(strings.TrimSpace(raw.Level))
	if level == "" {
		level = "medium"
	}
	if _, ok := levelRank[level]; !ok {
		return nil, fmt.Errorf("unknown level %q", raw.Level)
	}
	if raw.Detection == nil {
		return nil, errors.New("missing detection")
	}

	condNode, ok := raw.Detection["condition"]
	if !ok {
		return nil, errors.New("detection has no condition")
	}
	selections := map[string]selection{}
	var names []string
	for name, node := range raw.Detection {
		if name == "condition" || name == "timeframe" {
			continue
		}
		sel, err := compileSelection(name, node)
		if err != nil {
			return nil, err
		}
		selections[name] = sel
		names = append(names, name)
	}
	sort.Strings(names)

	var exprs []string
	switch c := condNode.(type) {
	case string:
		exprs = []string{c}
	case []any:
		// A list of conditions means any of them.
		for _, item := range c {
			s, ok := item.(string)
			if !ok {
				return nil, errors.New("condition list must contain strings")
			}
			exprs = append(exprs, s)
		}
	default:
		return nil, errors.New("condition must be a string or list of strings")
	}
	var conds []cond
	for _, e := range exprs {
		c, err := parseCondition(e, names)
		if err != nil {
			return nil, err
		}
		conds = append(conds, c)
	}
	var condition cond = orCond{conds}
	if len(conds) == 1 {
		condition = conds[0]
	}

	tags := make([]string, 0, len(raw.Tags))
	for _, t := range raw.Tags {
		tags = append(tags, strings.ToLower(strings.TrimSpace(t)))
	}
	return &Rule{
		ID:          strings.TrimSpace(raw.ID),
		Title:       strings.TrimSpace(raw.Title),
		Description: strings.TrimSpace(raw.Description),
		Status:      strings.ToLower(strings.TrimSpace(raw.Status)),
		Level:       level,
		Tags:        tags,
		Author:      raw.Author,
		References:  raw.References,
		Remediation: strings.TrimSpace(raw.Remediation),
		Source:      source,
		Samples:     raw.Samples,
		selections:  selections,
		condition:   condition,
	}, nil
}

// matches evaluates the rule against an event's fields.
func (r *Rule) matches(f fields) bool {
	results := make(map[string]bool, len(r.selections))
	for name, sel := range r.selections {
		results[name] = sel.eval(f)
	}
	return r.condition.eval(results)
}
