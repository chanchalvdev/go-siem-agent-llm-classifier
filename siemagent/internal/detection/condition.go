package detection

import (
	"fmt"
	"path"
	"strings"
	"unicode"
)

// cond is a compiled Sigma condition evaluated against per-selection results.
type cond interface {
	eval(results map[string]bool) bool
}

type refCond struct{ name string }
type notCond struct{ c cond }
type andCond struct{ cs []cond }
type orCond struct{ cs []cond }

// ofCond implements "1 of <pattern>" / "all of <pattern>" ("them" = every selection).
type ofCond struct {
	all   bool
	names []string
}

func (c refCond) eval(r map[string]bool) bool { return r[c.name] }
func (c notCond) eval(r map[string]bool) bool { return !c.c.eval(r) }

func (c andCond) eval(r map[string]bool) bool {
	for _, x := range c.cs {
		if !x.eval(r) {
			return false
		}
	}
	return true
}

func (c orCond) eval(r map[string]bool) bool {
	for _, x := range c.cs {
		if x.eval(r) {
			return true
		}
	}
	return false
}

func (c ofCond) eval(r map[string]bool) bool {
	for _, n := range c.names {
		if r[n] != c.all {
			// all: one false fails; any: one true succeeds.
			return !c.all
		}
	}
	return c.all
}

// parseCondition compiles a Sigma condition such as
// "selection and not 1 of filter_*". selections lists the defined names.
// Aggregations ("| count() > 5") are split off by compileRule first.
func parseCondition(expr string, selections []string) (cond, error) {
	if strings.Contains(expr, "|") {
		return nil, fmt.Errorf("%w: aggregation in condition %q", ErrUnsupported, expr)
	}
	toks, err := tokenize(expr)
	if err != nil {
		return nil, err
	}
	p := &condParser{toks: toks, selections: selections}
	c, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.pos != len(p.toks) {
		return nil, fmt.Errorf("unexpected %q in condition %q", p.toks[p.pos], expr)
	}
	return c, nil
}

func tokenize(s string) ([]string, error) {
	var toks []string
	for i := 0; i < len(s); {
		r := rune(s[i])
		switch {
		case unicode.IsSpace(r):
			i++
		case r == '(' || r == ')':
			toks = append(toks, string(r))
			i++
		case isIdentChar(r):
			j := i
			for j < len(s) && isIdentChar(rune(s[j])) {
				j++
			}
			toks = append(toks, s[i:j])
			i = j
		default:
			return nil, fmt.Errorf("invalid character %q in condition %q", r, s)
		}
	}
	if len(toks) == 0 {
		return nil, fmt.Errorf("empty condition")
	}
	return toks, nil
}

func isIdentChar(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '-' || r == '.' || r == '*' || r == '?'
}

type condParser struct {
	toks       []string
	pos        int
	selections []string
}

func (p *condParser) peek() string {
	if p.pos < len(p.toks) {
		return p.toks[p.pos]
	}
	return ""
}

func (p *condParser) next() string {
	t := p.peek()
	p.pos++
	return t
}

func (p *condParser) parseOr() (cond, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	cs := []cond{left}
	for strings.EqualFold(p.peek(), "or") {
		p.next()
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		cs = append(cs, right)
	}
	if len(cs) == 1 {
		return left, nil
	}
	return orCond{cs}, nil
}

func (p *condParser) parseAnd() (cond, error) {
	left, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	cs := []cond{left}
	for strings.EqualFold(p.peek(), "and") {
		p.next()
		right, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		cs = append(cs, right)
	}
	if len(cs) == 1 {
		return left, nil
	}
	return andCond{cs}, nil
}

func (p *condParser) parseNot() (cond, error) {
	if strings.EqualFold(p.peek(), "not") {
		p.next()
		c, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		return notCond{c}, nil
	}
	return p.parsePrimary()
}

func (p *condParser) parsePrimary() (cond, error) {
	tok := p.next()
	switch {
	case tok == "":
		return nil, fmt.Errorf("condition ends unexpectedly")
	case tok == "(":
		c, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if p.next() != ")" {
			return nil, fmt.Errorf("missing closing parenthesis")
		}
		return c, nil
	case tok == "1" || strings.EqualFold(tok, "any") || strings.EqualFold(tok, "all"):
		if !strings.EqualFold(p.next(), "of") {
			return nil, fmt.Errorf("expected \"of\" after %q", tok)
		}
		target := p.next()
		names, err := p.expand(target)
		if err != nil {
			return nil, err
		}
		return ofCond{all: strings.EqualFold(tok, "all"), names: names}, nil
	case isKeyword(tok) || tok == ")":
		return nil, fmt.Errorf("unexpected %q in condition", tok)
	default:
		if !contains(p.selections, tok) {
			return nil, fmt.Errorf("condition references undefined selection %q", tok)
		}
		return refCond{tok}, nil
	}
}

// expand resolves "them" or a wildcard pattern to selection names.
func (p *condParser) expand(target string) ([]string, error) {
	if target == "" {
		return nil, fmt.Errorf("expected a selection pattern after \"of\"")
	}
	if strings.EqualFold(target, "them") {
		var out []string
		for _, s := range p.selections {
			// Sigma convention: "them" excludes names starting with "_".
			if !strings.HasPrefix(s, "_") {
				out = append(out, s)
			}
		}
		return out, nil
	}
	var out []string
	for _, s := range p.selections {
		if ok, _ := path.Match(target, s); ok {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("pattern %q matches no selection", target)
	}
	return out, nil
}

func isKeyword(t string) bool {
	switch strings.ToLower(t) {
	case "and", "or", "not", "of", "them":
		return true
	}
	return false
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
