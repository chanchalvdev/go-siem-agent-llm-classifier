package ioc

import (
	"net/netip"
	"regexp"
	"slices"
	"strings"
)

// index answers "which watchlists contain this value?" in constant time per
// candidate: exact maps for IPs, domains and hashes, and one map per prefix
// length for ranges.
type index struct {
	ips      map[netip.Addr][]string
	prefixes map[int]map[netip.Prefix][]string // keyed by prefix length
	bits     []int                             // prefix lengths present, longest first
	domains  map[string][]string
	hashes   map[string][]string
	size     int
}

func newIndex() *index {
	return &index{
		ips:      map[netip.Addr][]string{},
		prefixes: map[int]map[netip.Prefix][]string{},
		domains:  map[string][]string{},
		hashes:   map[string][]string{},
	}
}

func appendID(ids []string, id string) []string {
	if slices.Contains(ids, id) {
		return ids
	}
	return append(ids, id)
}

func (x *index) add(listID string, ind Indicator) {
	x.size++
	switch ind.Type {
	case TypeIP:
		if a, err := netip.ParseAddr(ind.Value); err == nil {
			x.ips[a] = appendID(x.ips[a], listID)
		}
	case TypeCIDR:
		if p, err := netip.ParsePrefix(ind.Value); err == nil {
			m := x.prefixes[p.Bits()]
			if m == nil {
				m = map[netip.Prefix][]string{}
				x.prefixes[p.Bits()] = m
				x.bits = append(x.bits, p.Bits())
				slices.SortFunc(x.bits, func(a, b int) int { return b - a })
			}
			m[p] = appendID(m[p], listID)
		}
	case TypeDomain:
		x.domains[ind.Value] = appendID(x.domains[ind.Value], listID)
	case TypeHash:
		x.hashes[ind.Value] = appendID(x.hashes[ind.Value], listID)
	}
}

// hit is one value in an event that is on one or more watchlists.
type hit struct {
	Value     string   // what appeared in the event
	Indicator string   // the listed indicator it matched (a range or parent domain may differ)
	Type      Type     //
	Lists     []string // watchlist IDs
}

func (x *index) lookupIP(a netip.Addr) (string, []string) {
	if ids := x.ips[a]; len(ids) > 0 {
		return a.String(), ids
	}
	for _, b := range x.bits {
		if (a.Is4() && b > 32) || b > a.BitLen() {
			continue
		}
		p, err := a.Prefix(b)
		if err != nil {
			continue
		}
		if ids := x.prefixes[b][p]; len(ids) > 0 {
			return p.String(), ids
		}
	}
	return "", nil
}

// lookupDomain matches the domain or any parent: listing evil.example also
// flags www.evil.example.
func (x *index) lookupDomain(d string) (string, []string) {
	for {
		if ids := x.domains[d]; len(ids) > 0 {
			return d, ids
		}
		i := strings.IndexByte(d, '.')
		if i < 0 || !strings.Contains(d[i+1:], ".") {
			return "", nil
		}
		d = d[i+1:]
	}
}

var (
	ipv4Cand   = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	ipv6Cand   = regexp.MustCompile(`(?i)\b[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}\b`)
	hashCand   = regexp.MustCompile(`(?i)\b(?:[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})\b`)
	domainCand = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}\b`)
)

// maxCandidates bounds the work per event; log lines are attacker-controlled.
const maxCandidates = 64

// match returns every watchlisted value found in texts.
func (x *index) match(texts ...string) []hit {
	if x == nil || x.size == 0 {
		return nil
	}
	var hits []hit
	seen := map[string]bool{}
	budget := maxCandidates
	// fresh reports whether value is new and still within the budget of
	// distinct values; repeats cost nothing and are not looked up again.
	fresh := func(value string) bool {
		if seen[value] || budget == 0 {
			return false
		}
		seen[value] = true
		budget--
		return true
	}
	for _, text := range texts {
		if text == "" {
			continue
		}
		for _, s := range ipv4Cand.FindAllString(text, -1) {
			if !fresh(s) {
				continue
			}
			if a, err := netip.ParseAddr(s); err == nil {
				if listed, ids := x.lookupIP(a); ids != nil {
					hits = append(hits, hit{Value: s, Indicator: listed, Type: TypeIP, Lists: ids})
				}
			}
		}
		for _, s := range ipv6Cand.FindAllString(text, -1) {
			if !strings.Contains(s, "::") && strings.Count(s, ":") < 7 {
				continue // times like 10:30:00 are not addresses
			}
			if !fresh(s) {
				continue
			}
			if a, err := netip.ParseAddr(s); err == nil {
				if listed, ids := x.lookupIP(a); ids != nil {
					hits = append(hits, hit{Value: a.String(), Indicator: listed, Type: TypeIP, Lists: ids})
				}
			}
		}
		if len(x.hashes) > 0 {
			for _, s := range hashCand.FindAllString(text, -1) {
				s = strings.ToLower(s)
				if !fresh(s) {
					continue
				}
				if ids := x.hashes[s]; len(ids) > 0 {
					hits = append(hits, hit{Value: s, Indicator: s, Type: TypeHash, Lists: ids})
				}
			}
		}
		if len(x.domains) > 0 {
			for _, s := range domainCand.FindAllString(text, -1) {
				s = strings.ToLower(s)
				if !fresh(s) {
					continue
				}
				if listed, ids := x.lookupDomain(s); ids != nil {
					hits = append(hits, hit{Value: s, Indicator: listed, Type: TypeDomain, Lists: ids})
				}
			}
		}
	}
	return hits
}
