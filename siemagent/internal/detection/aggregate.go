package detection

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/chverma/siemagent/internal/metrics"
)

// maxGroupsPerRule bounds aggregation memory. An attacker controls group
// keys (source IPs, user names), so without a cap a spray of unique values
// would grow the state without limit.
const maxGroupsPerRule = 10_000

// aggregation is a Sigma threshold: "<condition> | count([field]) [by field] > N"
// over the rule's timeframe.
//
// Windows use the time each event is evaluated, not the timestamp inside the
// log line: log timestamps are attacker-controlled and often skewed, and a
// forged old timestamp must not let events slip out of the window.
type aggregation struct {
	countField string        // empty: count events; set: count distinct values
	groupBy    string        // empty: one global group
	threshold  int           // fire when the count reaches this
	timeframe  time.Duration // sliding window

	mu     sync.Mutex
	groups map[string]*aggWindow
}

type aggWindow struct {
	times    []time.Time          // count(): times of the last threshold events
	distinct map[string]time.Time // count(field): value -> last seen
	lastSeen time.Time
}

// aggregateResult describes a threshold crossing.
type aggregateResult struct {
	Count int
	Group string // "src_ip=1.2.3.4", empty without "by"
}

var aggRE = regexp.MustCompile(`^count\(\s*([A-Za-z0-9_.\-]*)\s*\)(?:\s+by\s+([A-Za-z0-9_.\-]+))?\s*(>=|>)\s*(\d+)$`)

// parseAggregation compiles the part of a condition after "|".
func parseAggregation(expr string, timeframe time.Duration) (*aggregation, error) {
	expr = strings.TrimSpace(expr)
	m := aggRE.FindStringSubmatch(expr)
	if m == nil {
		lower := strings.ToLower(expr)
		for _, fn := range []string{"min(", "max(", "avg(", "sum(", "near "} {
			if strings.HasPrefix(lower, fn) {
				return nil, fmt.Errorf("%w: aggregation %q", ErrUnsupported, expr)
			}
		}
		if strings.HasPrefix(lower, "count(") {
			// count() with <, <= or = cannot be decided on a stream.
			return nil, fmt.Errorf("%w: aggregation %q (only > and >= thresholds)", ErrUnsupported, expr)
		}
		return nil, fmt.Errorf("invalid aggregation %q", expr)
	}
	if timeframe <= 0 {
		return nil, errors.New("aggregation needs a timeframe (e.g. timeframe: 5m)")
	}
	n, err := strconv.Atoi(m[4])
	if err != nil {
		return nil, fmt.Errorf("invalid threshold in %q", expr)
	}
	threshold := n
	if m[3] == ">" {
		threshold = n + 1
	}
	if threshold < 2 {
		return nil, fmt.Errorf("aggregation threshold must be at least 2 events in %q; use a plain rule instead", expr)
	}
	return &aggregation{
		countField: strings.ToLower(m[1]),
		groupBy:    strings.ToLower(m[2]),
		threshold:  threshold,
		timeframe:  timeframe,
		groups:     map[string]*aggWindow{},
	}, nil
}

// parseTimeframe reads Sigma timeframes: 30s, 5m, 1h, 1d.
func parseTimeframe(s string) (time.Duration, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return 0, nil
	}
	if strings.HasSuffix(s, "d") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil || n <= 0 {
			return 0, fmt.Errorf("invalid timeframe %q", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("invalid timeframe %q", s)
	}
	return d, nil
}

// observe records one event that matched the rule's base condition and
// reports whether the threshold was crossed. After firing, the group starts
// over, so a sustained attack alerts once per threshold's worth of events
// instead of on every event.
func (a *aggregation) observe(f fields, now time.Time) (aggregateResult, bool) {
	group := ""
	if a.groupBy != "" {
		v, ok := f.values[a.groupBy]
		if !ok || v == "" {
			// Sigma semantics: events without the group-by field are not counted.
			return aggregateResult{}, false
		}
		group = v
	}
	value := ""
	if a.countField != "" {
		v, ok := f.values[a.countField]
		if !ok || v == "" {
			return aggregateResult{}, false
		}
		value = v
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	w, ok := a.groups[group]
	if !ok {
		if len(a.groups) >= maxGroupsPerRule {
			a.evictStale(now)
		}
		if len(a.groups) >= maxGroupsPerRule {
			metrics.DetectionGroupsDroppedTotal.Inc()
			return aggregateResult{}, false
		}
		w = &aggWindow{}
		a.groups[group] = w
	}
	w.lastSeen = now
	cutoff := now.Add(-a.timeframe)

	count := 0
	if a.countField == "" {
		w.times = append(w.times, now)
		// Drop events outside the window; only the newest threshold
		// events can ever matter.
		start := 0
		for start < len(w.times) && !w.times[start].After(cutoff) {
			start++
		}
		if keep := len(w.times) - a.threshold; keep > start {
			start = keep
		}
		w.times = w.times[start:]
		count = len(w.times)
	} else {
		if w.distinct == nil {
			w.distinct = map[string]time.Time{}
		}
		w.distinct[value] = now
		for v, t := range w.distinct {
			if !t.After(cutoff) {
				delete(w.distinct, v)
			}
		}
		count = len(w.distinct)
	}

	if count < a.threshold {
		return aggregateResult{}, false
	}
	delete(a.groups, group)
	res := aggregateResult{Count: count}
	if a.groupBy != "" {
		res.Group = a.groupBy + "=" + group
	}
	return res, true
}

// evictStale drops groups with no events inside the window. Caller holds mu.
func (a *aggregation) evictStale(now time.Time) {
	cutoff := now.Add(-a.timeframe)
	for k, w := range a.groups {
		if !w.lastSeen.After(cutoff) {
			delete(a.groups, k)
		}
	}
}

// reset clears all state, used when a rule is disabled.
func (a *aggregation) reset() {
	a.mu.Lock()
	a.groups = map[string]*aggWindow{}
	a.mu.Unlock()
}

// describe renders the threshold for display, e.g. "count() by src_ip >= 10 in 5m".
func (a *aggregation) describe() string {
	var b strings.Builder
	fmt.Fprintf(&b, "count(%s)", a.countField)
	if a.groupBy != "" {
		fmt.Fprintf(&b, " by %s", a.groupBy)
	}
	fmt.Fprintf(&b, " >= %d in %s", a.threshold, formatDuration(a.timeframe))
	return b.String()
}

func formatDuration(d time.Duration) string {
	switch {
	case d%(24*time.Hour) == 0:
		return fmt.Sprintf("%dd", d/(24*time.Hour))
	case d%time.Hour == 0:
		return fmt.Sprintf("%dh", d/time.Hour)
	case d%time.Minute == 0:
		return fmt.Sprintf("%dm", d/time.Minute)
	}
	return d.String()
}
