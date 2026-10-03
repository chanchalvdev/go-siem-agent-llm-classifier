// Package detection evaluates Sigma rules against parsed log events.
//
// Supported: field selections with the contains, startswith, endswith, all,
// re (with i), cidr and exists modifiers; Sigma wildcards (* ?) with
// case-insensitive matching; keyword lists; null values; conditions with
// and/or/not, parentheses and "1 of" / "all of" patterns or "them"; and
// count() thresholds over a timeframe ("| count() by src_ip > 10").
// Other aggregations, correlations and rule collections are skipped.
package detection

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/chverma/siemagent/internal/metrics"
	"github.com/chverma/siemagent/internal/models"
)

//go:embed rules/*.yml
var builtinRules embed.FS

// Engine holds a fixed set of compiled rules. It is safe for concurrent use.
type Engine struct {
	rules []*Rule
	byID  map[string]*Rule
	now   func() time.Time // clock for threshold windows; replaced in tests
}

// NewEngine builds an engine. Rules with duplicate IDs are reported and
// skipped (first one wins).
func NewEngine(rules []*Rule) (*Engine, []error) {
	e := &Engine{byID: make(map[string]*Rule, len(rules)), now: time.Now}
	var errs []error
	for _, r := range rules {
		if prev, dup := e.byID[r.ID]; dup {
			errs = append(errs, fmt.Errorf("%s: rule id %s already loaded from %s", r.Source, r.ID, prev.Source))
			continue
		}
		e.byID[r.ID] = r
		e.rules = append(e.rules, r)
	}
	sort.Slice(e.rules, func(i, j int) bool { return e.rules[i].Title < e.rules[j].Title })
	return e, errs
}

// LoadBuiltin returns the rule pack shipped inside the binary.
func LoadBuiltin() ([]*Rule, []error) {
	var rules []*Rule
	var errs []error
	entries, err := builtinRules.ReadDir("rules")
	if err != nil {
		return nil, []error{err}
	}
	for _, ent := range entries {
		data, err := builtinRules.ReadFile("rules/" + ent.Name())
		if err != nil {
			errs = append(errs, err)
			continue
		}
		rs, es := ParseRules(data, "builtin")
		rules = append(rules, rs...)
		errs = append(errs, es...)
	}
	return rules, errs
}

// LoadDir loads every .yml/.yaml file under dir, e.g. a checkout of the
// SigmaHQ rule repository or a team's own rules.
func LoadDir(dir string) ([]*Rule, []error) {
	var rules []*Rule
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
		rs, es := ParseRules(data, path)
		rules = append(rules, rs...)
		errs = append(errs, es...)
		return nil
	})
	if err != nil {
		errs = append(errs, fmt.Errorf("load rules from %s: %w", dir, err))
	}
	return rules, errs
}

// Rules returns the loaded rules sorted by title.
func (e *Engine) Rules() []*Rule { return e.rules }

// Rule returns a rule by ID.
func (e *Engine) Rule(id string) (*Rule, bool) {
	r, ok := e.byID[id]
	return r, ok
}

// SetEnabled turns a rule on or off. Disabling a threshold rule clears its
// counters, so re-enabling starts from zero.
func (e *Engine) SetEnabled(id string, enabled bool) bool {
	r, ok := e.byID[id]
	if !ok {
		return false
	}
	r.disabled.Store(!enabled)
	if !enabled && r.agg != nil {
		r.agg.reset()
	}
	return true
}

// Match returns every rule that fires on ev, most severe first. A threshold
// rule fires on the event that crosses its threshold.
func (e *Engine) Match(ev models.LogEvent) []models.Detection {
	if len(e.rules) == 0 {
		return nil
	}
	f := eventFields(ev)
	now := e.now()
	var out []models.Detection
	for _, r := range e.rules {
		if !r.Enabled() || !r.matches(f) {
			continue
		}
		d := models.Detection{RuleID: r.ID, Title: r.Title, Level: r.Level, Tags: r.Tags}
		if r.agg != nil {
			res, fired := r.agg.observe(f, now)
			if !fired {
				continue
			}
			d.Count, d.Group, d.Threshold = res.Count, res.Group, r.agg.describe()
		}
		r.hits.Add(1)
		metrics.DetectionMatchesTotal.WithLabelValues(r.ID, r.Level).Inc()
		out = append(out, d)
	}
	sort.SliceStable(out, func(i, j int) bool { return levelRank[out[i].Level] > levelRank[out[j].Level] })
	return out
}
