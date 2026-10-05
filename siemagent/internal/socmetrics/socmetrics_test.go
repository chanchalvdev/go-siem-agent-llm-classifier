package socmetrics

import (
	"testing"
	"time"

	"github.com/chverma/siemagent/internal/incident"
	"github.com/chverma/siemagent/internal/models"
	"github.com/chverma/siemagent/internal/store"
)

var now = time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)

func at(daysAgo int, h int) time.Time {
	return time.Date(2026, 10, 5-daysAgo, h, 0, 0, 0, time.UTC)
}

func ptr(t time.Time) *time.Time { return &t }

func TestCompute(t *testing.T) {
	incidents := []incident.Incident{
		{ // opened 2 days ago, detected in 2 min, acked in 10 min, resolved TP in 2h by ana
			Title: "SSH Brute Force from 203.0.113.7", Severity: models.SeverityP2, Status: incident.StatusResolved,
			Resolution: incident.ResolutionTruePositive, Assignee: "ana",
			CreatedAt: at(2, 9), OccurredAt: ptr(at(2, 9).Add(-2 * time.Minute)),
			AcknowledgedAt: ptr(at(2, 9).Add(10 * time.Minute)), ResolvedAt: ptr(at(2, 11)),
		},
		{ // opened yesterday, false positive resolved in 30 min by bob
			Title: "Port Scan From One Source from 198.51.100.4", Severity: models.SeverityP3, Status: incident.StatusResolved,
			Resolution: incident.ResolutionFalsePositive, Assignee: "bob",
			CreatedAt: at(1, 8), OccurredAt: ptr(at(1, 8).Add(-30 * time.Second)),
			AcknowledgedAt: ptr(at(1, 8).Add(5 * time.Minute)), ResolvedAt: ptr(at(1, 8).Add(30 * time.Minute)),
		},
		{ // open, assigned to ana, from today
			Title: "SSH Brute Force from 203.0.113.9", Severity: models.SeverityP2, Status: incident.StatusInvestigating,
			Assignee: "ana", CreatedAt: at(0, 10), AcknowledgedAt: ptr(at(0, 10).Add(20 * time.Minute)),
		},
		{ // open, unassigned, 3 days old: backlog; no OccurredAt (replayed logs)
			Title: "Shadow Copies Deleted on app02", Severity: models.SeverityP1, Status: incident.StatusNew,
			CreatedAt: at(3, 6),
		},
		{ // opened before the window, resolved inside it
			Title: "Old Thing on db01", Severity: models.SeverityP3, Status: incident.StatusResolved,
			Resolution: incident.ResolutionBenign, Assignee: "bob",
			CreatedAt: at(20, 6), ResolvedAt: ptr(at(1, 6)),
		},
	}
	volume := []store.DayVolume{
		{Day: at(1, 0), Events: 100, Alerts: 7, Suppressed: 3},
		{Day: at(0, 0), Events: 40, Alerts: 2},
		{Day: at(30, 0), Events: 999}, // outside the window
	}

	r := Compute(now, 7, incidents, volume)

	if r.Since != at(6, 0) || len(r.Daily) != 7 || r.Daily[6].Day != "2026-10-05" {
		t.Fatalf("window: since %v, %d days, last %+v", r.Since, len(r.Daily), r.Daily[len(r.Daily)-1])
	}
	if r.IncidentsOpened != 4 || r.IncidentsResolved != 3 || r.OpenNow != 2 || r.UnassignedOpen != 1 || r.OpenOver24h != 1 {
		t.Fatalf("counts: %+v", r)
	}
	if r.EventTotals.Events != 140 || r.EventTotals.Alerts != 9 || r.EventTotals.Suppressed != 3 {
		t.Fatalf("event totals: %+v", r.EventTotals)
	}
	if d := r.Daily[5]; d.Events != 100 || d.IncidentsOpened != 1 || d.IncidentsResolved != 2 {
		t.Fatalf("yesterday: %+v", d)
	}

	if r.MTTD.Samples != 2 || *r.MTTD.Mean != 75 || *r.MTTD.Median != 30 || *r.MTTD.P90 != 120 {
		t.Fatalf("MTTD: %+v mean %v", r.MTTD, *r.MTTD.Mean)
	}
	if r.MTTA.Samples != 3 || *r.MTTA.Median != 600 {
		t.Fatalf("MTTA: %+v", r.MTTA)
	}
	if r.MTTR.Samples != 3 {
		t.Fatalf("MTTR samples: %+v", r.MTTR)
	}
	if r.FalsePositiveRate == nil || *r.FalsePositiveRate != 1.0/3 {
		t.Fatalf("FP rate: %v", r.FalsePositiveRate)
	}
	if r.ByResolution["true_positive"] != 1 || r.ByResolution["false_positive"] != 1 || r.ByResolution["benign"] != 1 {
		t.Fatalf("resolutions: %v", r.ByResolution)
	}
	if r.OpenedBySeverity["P2"] != 2 || r.OpenedBySeverity["P1"] != 1 {
		t.Fatalf("by severity: %v", r.OpenedBySeverity)
	}
	if len(r.TopAttackTypes) != 3 || r.TopAttackTypes[0] != (Count{"SSH Brute Force", 2}) {
		t.Fatalf("top types: %+v", r.TopAttackTypes)
	}
	if len(r.Workload) != 2 || r.Workload[0].Name != "ana" || r.Workload[0].Open != 1 || r.Workload[0].Resolved != 1 ||
		r.Workload[1].Name != "bob" || r.Workload[1].Resolved != 2 || r.Workload[1].MTTR.Samples != 2 {
		t.Fatalf("workload: %+v", r.Workload)
	}
}

func TestComputeEmpty(t *testing.T) {
	r := Compute(now, 30, nil, nil)
	if r.IncidentsOpened != 0 || r.MTTR.Mean != nil || r.FalsePositiveRate != nil || len(r.Daily) != 30 ||
		r.Workload == nil || r.TopAttackTypes == nil {
		t.Fatalf("empty report: %+v", r)
	}
}

func TestPercentileAndValidDays(t *testing.T) {
	ds := []time.Duration{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	if percentile(ds, 50) != 5 || percentile(ds, 90) != 9 || percentile(ds[:1], 90) != 1 {
		t.Fatal("nearest-rank percentile")
	}
	for d, ok := range map[int]bool{0: false, 1: true, 30: true, 365: true, 366: false} {
		if ValidDays(d) != ok {
			t.Errorf("ValidDays(%d)", d)
		}
	}
}
