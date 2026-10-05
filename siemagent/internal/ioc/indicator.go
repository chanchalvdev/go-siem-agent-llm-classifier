// Package ioc matches events against watchlists of indicators of compromise
// (IPs, CIDR ranges, domains and file hashes) from threat feeds, local files
// or analysts. A match adds a detection to the event and raises its severity,
// so known-bad infrastructure alerts even when no rule or model flags it.
package ioc

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
)

// Type is the kind of an indicator.
type Type string

const (
	TypeIP     Type = "ip"
	TypeCIDR   Type = "cidr"
	TypeDomain Type = "domain"
	TypeHash   Type = "hash" // MD5, SHA-1 or SHA-256, lower-case hex
)

// Indicator is one value on a watchlist.
type Indicator struct {
	Value string `json:"value"`
	Type  Type   `json:"type"`
	// Note, AddedBy and AddedAt are set for indicators analysts add by hand.
	Note    string `json:"note,omitempty"`
	AddedBy string `json:"added_by,omitempty"`
}

var (
	// ErrInvalid wraps validation failures; the message is safe to show.
	ErrInvalid = errors.New("invalid")

	hashRE   = regexp.MustCompile(`^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$`)
	domainRE = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$`)
)

// minPrefix rejects ranges so broad that a typo would flag the whole internet.
const (
	minPrefixV4 = 8
	minPrefixV6 = 32
)

// Parse normalises one indicator and works out its type: IPs and ranges are
// canonicalised, domains and hashes lower-cased, URLs reduced to their host.
func Parse(raw string) (Indicator, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return Indicator{}, fmt.Errorf("%w: empty indicator", ErrInvalid)
	}
	// Defanged values from reports: hxxp://evil[.]com
	s = strings.NewReplacer("[.]", ".", "(.)", ".", "hxxp", "http").Replace(s)
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil && u.Hostname() != "" {
			s = u.Hostname()
		}
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return Indicator{}, fmt.Errorf("%w: %q is not an IP range", ErrInvalid, raw)
		}
		p = p.Masked()
		if (p.Addr().Is4() && p.Bits() < minPrefixV4) || (p.Addr().Is6() && p.Bits() < minPrefixV6) {
			return Indicator{}, fmt.Errorf("%w: range %s is too broad (at most /%d for IPv4, /%d for IPv6)", ErrInvalid, p, minPrefixV4, minPrefixV6)
		}
		if p.IsSingleIP() {
			return Indicator{Value: p.Addr().String(), Type: TypeIP}, nil
		}
		return Indicator{Value: p.String(), Type: TypeCIDR}, nil
	}
	if a, err := netip.ParseAddr(s); err == nil {
		a = a.Unmap()
		if a.IsUnspecified() || a.IsLoopback() {
			return Indicator{}, fmt.Errorf("%w: %s cannot be an indicator", ErrInvalid, a)
		}
		return Indicator{Value: a.String(), Type: TypeIP}, nil
	}
	low := strings.TrimSuffix(strings.ToLower(s), ".")
	if hashRE.MatchString(low) {
		return Indicator{Value: low, Type: TypeHash}, nil
	}
	if len(low) <= 253 && domainRE.MatchString(low) {
		return Indicator{Value: low, Type: TypeDomain}, nil
	}
	return Indicator{}, fmt.Errorf("%w: %q is not an IP, range, domain or hash", ErrInvalid, raw)
}

// ParseList reads a feed or file: one indicator per line, # or ; comments,
// hosts-file lines ("0.0.0.0 evil.example") and CSV (first column) are
// understood. Lines that are not indicators are counted, not fatal. At most
// max indicators are read.
func ParseList(r io.Reader, maxIndicators int) (inds []Indicator, skipped int, err error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	seen := map[string]bool{}
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "//") {
			continue
		}
		if i := strings.IndexAny(line, "#"); i > 0 {
			line = strings.TrimSpace(line[:i]) // trailing comment
		}
		fields := strings.FieldsFunc(line, func(r rune) bool { return r == ' ' || r == '\t' || r == ',' })
		if len(fields) == 0 {
			continue
		}
		value := strings.Trim(fields[0], `"`)
		if len(fields) >= 2 && (value == "0.0.0.0" || value == "127.0.0.1" || value == "::") {
			value = strings.Trim(fields[1], `"`) // hosts-file format
		}
		ind, perr := Parse(value)
		if perr != nil {
			skipped++
			continue
		}
		if seen[ind.Value] {
			continue
		}
		if len(inds) == maxIndicators {
			return inds, skipped, fmt.Errorf("list has more than %d indicators", maxIndicators)
		}
		seen[ind.Value] = true
		inds = append(inds, ind)
	}
	return inds, skipped, sc.Err()
}
