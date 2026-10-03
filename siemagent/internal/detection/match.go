package detection

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

// valueMatcher tests one field value.
type valueMatcher func(v string, present bool) bool

// fieldMatcher is one "field|modifiers: values" entry of a selection.
type fieldMatcher struct {
	field   string // lower-case; "" means keyword search over the whole log
	all     bool   // values are ANDed (|all) instead of ORed
	matches []valueMatcher
}

// selection is a map (fields ANDed) or a list of maps/keywords (ORed).
type selection struct {
	alternatives [][]fieldMatcher // OR of AND-groups
}

func (s selection) eval(f fields) bool {
	for _, group := range s.alternatives {
		if groupMatches(group, f) {
			return true
		}
	}
	return false
}

func groupMatches(group []fieldMatcher, f fields) bool {
	for _, fm := range group {
		if !fm.eval(f) {
			return false
		}
	}
	return true
}

func (fm fieldMatcher) eval(f fields) bool {
	v, present := f.text, true
	if fm.field != "" {
		v, present = f.values[fm.field]
	}
	if fm.all {
		for _, m := range fm.matches {
			if !m(v, present) {
				return false
			}
		}
		return true
	}
	for _, m := range fm.matches {
		if m(v, present) {
			return true
		}
	}
	return false
}

var supportedModifiers = map[string]bool{
	"contains": true, "startswith": true, "endswith": true,
	"all": true, "re": true, "i": true, "cidr": true, "exists": true,
}

// compileSelection turns a YAML selection node into matchers.
func compileSelection(name string, node any) (selection, error) {
	switch n := node.(type) {
	case map[string]any:
		group, err := compileGroup(n)
		if err != nil {
			return selection{}, fmt.Errorf("selection %q: %w", name, err)
		}
		return selection{alternatives: [][]fieldMatcher{group}}, nil
	case []any:
		var sel selection
		var keywords []any
		for _, item := range n {
			switch it := item.(type) {
			case map[string]any:
				group, err := compileGroup(it)
				if err != nil {
					return selection{}, fmt.Errorf("selection %q: %w", name, err)
				}
				sel.alternatives = append(sel.alternatives, group)
			default:
				keywords = append(keywords, it)
			}
		}
		if len(keywords) > 0 {
			fm, err := compileField("", keywords)
			if err != nil {
				return selection{}, fmt.Errorf("selection %q: %w", name, err)
			}
			sel.alternatives = append(sel.alternatives, []fieldMatcher{fm})
		}
		if len(sel.alternatives) == 0 {
			return selection{}, fmt.Errorf("selection %q is empty", name)
		}
		return sel, nil
	default:
		return selection{}, fmt.Errorf("selection %q must be a map or a list", name)
	}
}

func compileGroup(m map[string]any) ([]fieldMatcher, error) {
	if len(m) == 0 {
		return nil, fmt.Errorf("empty field map")
	}
	group := make([]fieldMatcher, 0, len(m))
	for key, val := range m {
		fm, err := compileField(key, val)
		if err != nil {
			return nil, err
		}
		group = append(group, fm)
	}
	return group, nil
}

// compileField parses "Field|mod1|mod2" (a key starting with "|" is a
// keyword search with modifiers) and its value(s).
func compileField(key string, val any) (fieldMatcher, error) {
	parts := strings.Split(key, "|")
	fm := fieldMatcher{field: strings.ToLower(strings.TrimSpace(parts[0]))}
	mods := map[string]bool{}
	for _, m := range parts[1:] {
		m = strings.ToLower(strings.TrimSpace(m))
		if !supportedModifiers[m] {
			return fieldMatcher{}, fmt.Errorf("unsupported modifier %q on %q", m, key)
		}
		mods[m] = true
	}
	fm.all = mods["all"]

	values, ok := val.([]any)
	if !ok {
		values = []any{val}
	}
	if len(values) == 0 {
		return fieldMatcher{}, fmt.Errorf("no values for %q", key)
	}
	for _, v := range values {
		m, err := compileValue(fm.field == "", mods, v)
		if err != nil {
			return fieldMatcher{}, fmt.Errorf("%q: %w", key, err)
		}
		fm.matches = append(fm.matches, m)
	}
	return fm, nil
}

func compileValue(keyword bool, mods map[string]bool, v any) (valueMatcher, error) {
	if mods["exists"] {
		want, ok := v.(bool)
		if !ok {
			return nil, fmt.Errorf("|exists needs true or false")
		}
		return func(s string, present bool) bool { return (present && s != "") == want }, nil
	}
	if v == nil {
		// null matches a missing or empty field.
		return func(s string, present bool) bool { return !present || s == "" }, nil
	}
	pattern := fmt.Sprint(v)

	if mods["re"] {
		flags := ""
		if mods["i"] {
			flags = "(?i)"
		}
		re, err := regexp.Compile(flags + pattern)
		if err != nil {
			return nil, fmt.Errorf("bad regular expression: %w", err)
		}
		return func(s string, present bool) bool { return present && re.MatchString(s) }, nil
	}
	if mods["cidr"] {
		_, network, err := net.ParseCIDR(pattern)
		if err != nil {
			return nil, fmt.Errorf("bad CIDR: %w", err)
		}
		return func(s string, present bool) bool {
			ip := net.ParseIP(strings.TrimSpace(s))
			return present && ip != nil && network.Contains(ip)
		}, nil
	}

	// Plain values: case-insensitive with Sigma wildcards (* and ?).
	// Keywords and |contains match anywhere in the value.
	switch {
	case keyword || mods["contains"]:
		pattern = "*" + pattern + "*"
	case mods["startswith"]:
		pattern += "*"
	case mods["endswith"]:
		pattern = "*" + pattern
	}
	return globMatcher(pattern)
}

// globMatcher compiles a Sigma wildcard pattern. Escapes: \* \? \\.
// Patterns that are only a fixed string around leading/trailing * use fast
// string operations instead of a regular expression.
func globMatcher(pattern string) (valueMatcher, error) {
	var re strings.Builder
	re.WriteString("(?is)^")
	literal := true // pattern has no wildcard except leading/trailing *
	var core strings.Builder
	runes := []rune(pattern)
	lead := len(runes) > 0 && runes[0] == '*'
	trail := false
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		switch {
		case r == '\\' && i+1 < len(runes) && (runes[i+1] == '*' || runes[i+1] == '?' || runes[i+1] == '\\'):
			i++
			re.WriteString(regexp.QuoteMeta(string(runes[i])))
			core.WriteRune(runes[i])
		case r == '*':
			re.WriteString(".*")
			if i != 0 && i != len(runes)-1 {
				literal = false
			}
			if i == len(runes)-1 && i != 0 {
				trail = true
			}
		case r == '?':
			re.WriteString(".")
			literal = false
		default:
			re.WriteString(regexp.QuoteMeta(string(r)))
			core.WriteRune(r)
		}
	}
	re.WriteString("$")

	if literal {
		needle := strings.ToLower(core.String())
		switch {
		case lead && trail:
			return func(s string, p bool) bool { return p && strings.Contains(strings.ToLower(s), needle) }, nil
		case lead:
			return func(s string, p bool) bool { return p && strings.HasSuffix(strings.ToLower(s), needle) }, nil
		case trail:
			return func(s string, p bool) bool { return p && strings.HasPrefix(strings.ToLower(s), needle) }, nil
		default:
			return func(s string, p bool) bool { return p && strings.EqualFold(s, core.String()) }, nil
		}
	}
	compiled, err := regexp.Compile(re.String())
	if err != nil {
		return nil, fmt.Errorf("bad wildcard pattern %q: %w", pattern, err)
	}
	return func(s string, p bool) bool { return p && compiled.MatchString(s) }, nil
}
