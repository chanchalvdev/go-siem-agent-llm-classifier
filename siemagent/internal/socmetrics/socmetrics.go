// Package socmetrics computes the numbers a SOC is run by: time to detect,
// acknowledge and resolve, alert and incident volume, false-positive rate and
// analyst workload, over a window of days.
package socmetrics

import (
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/chverma/siemagent/internal/incident"
	"github.com/chverma/siemagent/internal/store"
)

// Duration summarises a set of durations in seconds. Nil fields mean there
// were no samples.
type Duration struct {
	Samples int      `json:"samples"`
	Mean    *float64 `json:"mean_seconds"`
	Median  *float64 `json:"median_seconds"`
	P90     *float64 `json:"p90_seconds"`
}

func summarise(ds []time.Duration) Duration {
	out := Duration{Samples: len(ds)}
	if len(ds) == 0 {
		return out
	}
	slices.Sort(ds)
	var sum time.Duration
	for _, d := range ds {
		sum += d
	}
	mean := (sum / time.Duration(len(ds))).Seconds()
	median := percentile(ds, 50).Seconds()
	p90 := percentile(ds, 90).Seconds()
	out.Mean, out.Median, out.P90 = &mean, &median, &p90
	return out
}

// percentile uses nearest-rank on sorted durations.
func percentile(sorted []time.Duration, p int) time.Duration {
	rank := (p*len(sorted) + 99) / 100 // ceil(p/100 * n)
	return sorted[max(rank, 1)-1]
}

// Day is one day of activity.
type Day struct {
	Day               string `json:"day"` // YYYY-MM-DD (UTC)
	Events            int    `json:"events"`
	Alerts            int    `json:"alerts"`
	Suppressed        int    `json:"suppressed"`
	IncidentsOpened   int    `json:"incidents_opened"`
	IncidentsResolved int    `json:"incidents_resolved"`
}

// Analyst is one person's share of the queue.
type Analyst struct {
	Name     string   `json:"name"`
	Open     int      `json:"open"`
	Resolved int      `json:"resolved"` // in the window
	MTTR     Duration `json:"mttr"`     // of the incidents they resolved in the window
}

// Count is a labelled number.
type Count struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// Report is the SOC metrics for a window.
type Report struct {
	Days        int       `json:"days"`
	Since       time.Time `json:"since"`
	GeneratedAt time.Time `json:"generated_at"`

	IncidentsOpened   int `json:"incidents_opened"`
	IncidentsResolved int `json:"incidents_resolved"`
	OpenNow           int `json:"open_now"`
	UnassignedOpen    int `json:"unassigned_open"`
	// OpenOver24h counts open incidents older than a day (backlog ageing).
	OpenOver24h int `json:"open_over_24h"`

	// MTTD: alert's log time → incident opened. MTTA: opened → first
	// analyst action. MTTR: opened → resolved. All for incidents opened
	// (MTTD, MTTA) or resolved (MTTR) in the window.
	MTTD Duration `json:"mttd"`
	MTTA Duration `json:"mtta"`
	MTTR Duration `json:"mttr"`

	// FalsePositiveRate is false positives / incidents resolved in the
	// window; nil when none were resolved.
	FalsePositiveRate *float64        `json:"false_positive_rate"`
	OpenedBySeverity  map[string]int  `json:"opened_by_severity"`
	ByResolution      map[string]int  `json:"by_resolution"`
	TopAttackTypes    []Count         `json:"top_attack_types"`
	Daily             []Day           `json:"daily"`
	Workload          []Analyst       `json:"workload"`
	EventTotals       store.DayVolume `json:"event_totals"`
}

// Compute builds the report for the days ending at now from incidents
// (anything active in the window, see incident.Filter.ActiveSince) and the
// daily event volume.
func Compute(now time.Time, days int, incidents []incident.Incident, volume []store.DayVolume) Report {
	now = now.UTC()
	since := startOfDay(now).AddDate(0, 0, -(days - 1))
	r := Report{
		Days: days, Since: since, GeneratedAt: now,
		OpenedBySeverity: map[string]int{}, ByResolution: map[string]int{},
		TopAttackTypes: []Count{}, Workload: []Analyst{},
	}

	daily := make([]Day, days)
	index := map[string]int{}
	for i := range days {
		d := since.AddDate(0, 0, i).Format(time.DateOnly)
		daily[i] = Day{Day: d}
		index[d] = i
	}
	for _, v := range volume {
		if i, ok := index[v.Day.UTC().Format(time.DateOnly)]; ok {
			daily[i].Events += v.Events
			daily[i].Alerts += v.Alerts
			daily[i].Suppressed += v.Suppressed
			r.EventTotals.Events += v.Events
			r.EventTotals.Alerts += v.Alerts
			r.EventTotals.Suppressed += v.Suppressed
		}
	}

	var mttd, mtta, mttr []time.Duration
	types := map[string]int{}
	analysts := map[string]*Analyst{}
	analystMTTR := map[string][]time.Duration{}
	falsePos := 0
	analyst := func(name string) *Analyst {
		a := analysts[name]
		if a == nil {
			a = &Analyst{Name: name}
			analysts[name] = a
		}
		return a
	}

	for _, inc := range incidents {
		openedInWindow := !inc.CreatedAt.Before(since)
		if openedInWindow {
			r.IncidentsOpened++
			r.OpenedBySeverity[string(inc.Severity)]++
			types[attackType(inc)]++
			if i, ok := index[inc.CreatedAt.UTC().Format(time.DateOnly)]; ok {
				daily[i].IncidentsOpened++
			}
			if inc.OccurredAt != nil && !inc.OccurredAt.After(inc.CreatedAt) {
				mttd = append(mttd, inc.CreatedAt.Sub(*inc.OccurredAt))
			}
			if inc.AcknowledgedAt != nil {
				mtta = append(mtta, inc.AcknowledgedAt.Sub(inc.CreatedAt))
			}
		}
		if inc.Open() {
			r.OpenNow++
			if inc.Assignee == "" {
				r.UnassignedOpen++
			} else {
				analyst(inc.Assignee).Open++
			}
			if now.Sub(inc.CreatedAt) > 24*time.Hour {
				r.OpenOver24h++
			}
			continue
		}
		if inc.ResolvedAt == nil || inc.ResolvedAt.Before(since) {
			continue
		}
		r.IncidentsResolved++
		res := string(inc.Resolution)
		if res == "" {
			res = "unspecified"
		}
		r.ByResolution[res]++
		if inc.Resolution == incident.ResolutionFalsePositive {
			falsePos++
		}
		took := inc.ResolvedAt.Sub(inc.CreatedAt)
		mttr = append(mttr, took)
		if i, ok := index[inc.ResolvedAt.UTC().Format(time.DateOnly)]; ok {
			daily[i].IncidentsResolved++
		}
		if inc.Assignee != "" {
			analyst(inc.Assignee).Resolved++
			analystMTTR[inc.Assignee] = append(analystMTTR[inc.Assignee], took)
		}
	}

	r.MTTD, r.MTTA, r.MTTR = summarise(mttd), summarise(mtta), summarise(mttr)
	if r.IncidentsResolved > 0 {
		rate := float64(falsePos) / float64(r.IncidentsResolved)
		r.FalsePositiveRate = &rate
	}
	r.Daily = daily

	for name, n := range types {
		r.TopAttackTypes = append(r.TopAttackTypes, Count{Name: name, Count: n})
	}
	sort.Slice(r.TopAttackTypes, func(i, j int) bool {
		a, b := r.TopAttackTypes[i], r.TopAttackTypes[j]
		return a.Count > b.Count || (a.Count == b.Count && a.Name < b.Name)
	})
	if len(r.TopAttackTypes) > 8 {
		r.TopAttackTypes = r.TopAttackTypes[:8]
	}

	for name, a := range analysts {
		a.MTTR = summarise(analystMTTR[name])
		r.Workload = append(r.Workload, *a)
	}
	sort.Slice(r.Workload, func(i, j int) bool {
		a, b := r.Workload[i], r.Workload[j]
		if a.Open != b.Open {
			return a.Open > b.Open
		}
		return strings.ToLower(a.Name) < strings.ToLower(b.Name)
	})
	return r
}

// attackType is the incident's title up to " from "/" on ", e.g.
// "SSH Brute Force from 203.0.113.7" → "SSH Brute Force".
func attackType(inc incident.Incident) string {
	t := inc.Title
	for _, sep := range []string{" from ", " on ", " by "} {
		if i := strings.Index(t, sep); i > 0 {
			t = t[:i]
		}
	}
	if t == "" {
		return "Unknown"
	}
	return t
}

func startOfDay(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
}

// ValidDays reports whether days is an accepted window.
func ValidDays(days int) bool { return days >= 1 && days <= 365 }
