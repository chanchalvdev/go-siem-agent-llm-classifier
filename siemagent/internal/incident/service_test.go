package incident

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/chverma/siemagent/internal/models"
)

func classified(raw, host, attack, tactic, technique string, sev models.Severity) models.ClassifiedEvent {
	return models.ClassifiedEvent{
		Event:      models.LogEvent{Raw: raw, Message: raw, Hostname: host},
		AttackType: attack,
		Severity:   sev,
		Summary:    attack + " summary",
		MITRE:      models.MITREInfo{Tactic: tactic, TechniqueID: technique},
		Detections: []models.Detection{{RuleID: "r", Title: attack + " rule", Level: "high"}},
	}
}

var (
	bruteForce = classified("sshd[1]: Failed password for root from 203.0.113.7 port 22 ssh2",
		"web01", "SSH Brute Force", "Credential Access", "T1110.001", models.SeverityP2)
	acceptedLogin = classified("sshd[1]: Accepted password for root from 203.0.113.7 port 22 ssh2",
		"web01", "Suspicious Login", "Initial Access", "T1078", models.SeverityP3)
	rootShell = classified("sudo: deploy : USER=root ; COMMAND=/bin/bash",
		"web01", "Sudo to Root Shell", "Privilege Escalation", "T1548.003", models.SeverityP1)
	otherHost = classified("sshd[1]: Failed password for admin from 198.51.100.9 port 22 ssh2",
		"db01", "SSH Brute Force", "Credential Access", "T1110.001", models.SeverityP2)
)

// testService returns a service over store whose clock the test controls.
func testService(t *testing.T, st Store) (*Service, *time.Time) {
	t.Helper()
	svc := NewService(st, Config{Window: time.Hour, MinSeverity: models.SeverityP3})
	now := time.Date(2026, 10, 3, 10, 0, 0, 0, time.UTC)
	svc.now = func() time.Time { return now }
	return svc, &now
}

func observe(t *testing.T, svc *Service, ev models.ClassifiedEvent) Result {
	t.Helper()
	res, ok, err := svc.Observe(context.Background(), ev)
	if err != nil || !ok {
		t.Fatalf("observe: ok=%v err=%v", ok, err)
	}
	return res
}

func TestKillChainCorrelatesIntoOneIncident(t *testing.T) {
	svc, now := testService(t, NewMemory())

	first := observe(t, svc, bruteForce)
	if !first.Created || first.Incident.Title != "SSH Brute Force from 203.0.113.7" {
		t.Fatalf("first alert should open an incident: %+v", first)
	}
	*now = now.Add(10 * time.Minute)
	second := observe(t, svc, acceptedLogin) // same IP
	*now = now.Add(10 * time.Minute)
	third := observe(t, svc, rootShell) // no IP, same host

	if second.Created || third.Created {
		t.Fatal("related alerts must join the open incident")
	}
	if second.Incident.ID != first.Incident.ID || third.Incident.ID != first.Incident.ID {
		t.Fatal("alerts landed in different incidents")
	}
	inc := third.Incident
	if !third.Escalated || inc.Severity != models.SeverityP1 || inc.Title != "Sudo to Root Shell from 203.0.113.7" {
		t.Fatalf("P1 alert should escalate and retitle: %+v", inc)
	}
	if got := strings.Join(inc.Tactics, ","); got != "Initial Access,Privilege Escalation,Credential Access" {
		t.Fatalf("tactics in ATT&CK matrix order, got %s", got)
	}
	if inc.AlertCount != 3 || len(inc.Techniques) != 3 {
		t.Fatalf("counts: %+v", inc)
	}

	d, err := svc.Get(context.Background(), inc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Alerts) != 3 || d.Alerts[0].Rules[0] != "SSH Brute Force rule" {
		t.Fatalf("alerts: %+v", d.Alerts)
	}
	kinds := []string{}
	for _, a := range d.Activity {
		kinds = append(kinds, a.Kind)
	}
	if strings.Join(kinds, ",") != "created,escalated" {
		t.Fatalf("history = %v", kinds)
	}
}

func TestUnrelatedAlertsOpenSeparateIncidents(t *testing.T) {
	svc, _ := testService(t, NewMemory())
	a := observe(t, svc, bruteForce)
	b := observe(t, svc, otherHost)
	if !b.Created || a.Incident.ID == b.Incident.ID {
		t.Fatal("different IP, user and host must not correlate")
	}
}

func TestWindowAndResolutionEndCorrelation(t *testing.T) {
	svc, now := testService(t, NewMemory())
	a := observe(t, svc, bruteForce)

	*now = now.Add(2 * time.Hour) // past the window
	b := observe(t, svc, bruteForce)
	if !b.Created || b.Incident.ID == a.Incident.ID {
		t.Fatal("an alert after the window should open a new incident")
	}

	resolved := StatusResolved
	if _, err := svc.Update(context.Background(), b.Incident.ID, Update{Status: &resolved}, "alice"); err != nil {
		t.Fatal(err)
	}
	c := observe(t, svc, bruteForce)
	if !c.Created {
		t.Fatal("resolved incidents must not absorb new alerts")
	}
}

func TestLowSeverityStaysOutOfIncidents(t *testing.T) {
	svc, _ := testService(t, NewMemory())
	ev := bruteForce
	ev.Severity = models.SeverityP4
	if _, ok, err := svc.Observe(context.Background(), ev); ok || err != nil {
		t.Fatalf("P4 should be ignored: ok=%v err=%v", ok, err)
	}
}

func TestAlertsWithoutEntitiesGroupBySignature(t *testing.T) {
	svc, _ := testService(t, NewMemory())
	ev := classified("weird payload", "", "SQL Injection", "Initial Access", "T1190", models.SeverityP2)
	a := observe(t, svc, ev)
	b := observe(t, svc, ev)
	if b.Created || a.Incident.ID != b.Incident.ID {
		t.Fatal("repeats of an entity-less attack should share an incident")
	}
	if a.Incident.Entities[0].Kind != EntitySignature {
		t.Fatalf("entities = %+v", a.Incident.Entities)
	}
}

func TestUpdateRecordsHistory(t *testing.T) {
	svc, now := testService(t, NewMemory())
	ctx := context.Background()
	inc := observe(t, svc, bruteForce).Incident

	investigating, resolved := StatusInvestigating, StatusResolved
	fp := ResolutionFalsePositive
	alice := "alice"
	p3 := models.SeverityP3

	if _, err := svc.Update(ctx, inc.ID, Update{Resolution: &fp}, "alice"); err == nil {
		t.Fatal("resolution on an open incident should be rejected")
	}
	if _, err := svc.Update(ctx, inc.ID, Update{Status: &investigating, Assignee: &alice}, "alice"); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(30 * time.Minute)
	got, err := svc.Update(ctx, inc.ID, Update{Status: &resolved, Resolution: &fp, Severity: &p3}, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusResolved || got.Resolution != fp || got.ResolvedAt == nil || got.Severity != p3 {
		t.Fatalf("update not applied: %+v", got)
	}
	if _, err := svc.Comment(ctx, inc.ID, "bob", "  Confirmed: our own pentest.  "); err != nil {
		t.Fatal(err)
	}

	d, _ := svc.Get(ctx, inc.ID)
	var lines []string
	for _, a := range d.Activity {
		lines = append(lines, a.Actor+"|"+a.Kind+"|"+a.Body)
	}
	want := []string{
		"system|created|Opened from P2 alert: SSH Brute Force",
		"alice|status|Status changed from new to investigating",
		"alice|assignee|Assigned to alice",
		"alice|status|Status changed from investigating to resolved",
		"alice|resolution|Resolution set to false positive",
		"alice|severity|Severity changed from P2 to P3",
		"bob|comment|Confirmed: our own pentest.",
	}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Fatalf("history:\n%s", strings.Join(lines, "\n"))
	}

	stats, _ := svc.Stats(ctx)
	if stats.Resolved != 1 || stats.FalsePositive != 1 || stats.MTTRSeconds != 1800 || stats.Open != 0 {
		t.Fatalf("stats = %+v", stats)
	}

	// Reopening clears the resolution.
	reopened, _ := svc.Update(ctx, inc.ID, Update{Status: &investigating}, "alice")
	if reopened.Resolution != ResolutionNone || reopened.ResolvedAt != nil {
		t.Fatalf("reopen should clear resolution: %+v", reopened)
	}
}

func TestUpdateValidation(t *testing.T) {
	svc, _ := testService(t, NewMemory())
	ctx := context.Background()
	inc := observe(t, svc, bruteForce).Incident
	bad := Status("closed")
	sev := models.Severity("P9")
	long := strings.Repeat("x", 101)
	for name, u := range map[string]Update{
		"empty":    {},
		"status":   {Status: &bad},
		"severity": {Severity: &sev},
		"assignee": {Assignee: &long},
	} {
		if _, err := svc.Update(ctx, inc.ID, u, "a"); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
	s := StatusResolved
	if _, err := svc.Update(ctx, "INC-NOPE", Update{Status: &s}, "a"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown id: %v", err)
	}
	if _, err := svc.Comment(ctx, inc.ID, "a", "   "); err == nil {
		t.Error("empty comment accepted")
	}
	if _, err := svc.Comment(ctx, inc.ID, "a", strings.Repeat("é", maxCommentLen+1)); err == nil {
		t.Error("over-long comment accepted")
	}
}

func TestParseEntity(t *testing.T) {
	if e, err := ParseEntity("ip:10.0.0.1"); err != nil || e != (Entity{EntityIP, "10.0.0.1"}) {
		t.Fatalf("got %v %v", e, err)
	}
	for _, bad := range []string{"10.0.0.1", "ip:", "mac:aa"} {
		if _, err := ParseEntity(bad); err == nil {
			t.Errorf("%q should fail", bad)
		}
	}
}

func TestMemoryStoreContract(t *testing.T) {
	testStoreContract(t, NewMemory())
}

// testStoreContract checks behaviour every Store must share. st must be empty.
func testStoreContract(t *testing.T, st Store) {
	t.Helper()
	ctx := context.Background()
	svc, now := testService(t, st)

	a := observe(t, svc, bruteForce).Incident
	*now = now.Add(time.Minute)
	b := observe(t, svc, otherHost).Incident
	*now = now.Add(time.Minute)
	observe(t, svc, acceptedLogin) // joins a, making it most recent

	list, err := st.List(ctx, Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].ID != a.ID || list[1].ID != b.ID {
		t.Fatalf("list should be most recent first: %+v", list)
	}
	if list[0].AlertCount != 2 {
		t.Fatalf("alert count = %d", list[0].AlertCount)
	}

	ip := Entity{EntityIP, "198.51.100.9"}
	if got, _ := st.List(ctx, Filter{Entity: &ip}); len(got) != 1 || got[0].ID != b.ID {
		t.Fatalf("entity filter: %+v", got)
	}
	if got, _ := st.List(ctx, Filter{Severity: models.SeverityP2, Limit: 1}); len(got) != 1 {
		t.Fatalf("severity + limit: %+v", got)
	}

	found, err := st.FindOpen(ctx, []Entity{{EntityHost, "web01"}}, now.Add(-time.Hour))
	if err != nil || found == nil || found.ID != a.ID {
		t.Fatalf("find open by host: %+v %v", found, err)
	}
	if found, _ := st.FindOpen(ctx, []Entity{{EntityHost, "web01"}}, now.Add(time.Minute)); found != nil {
		t.Fatal("since must exclude older incidents")
	}

	resolved, fp, bob := StatusResolved, ResolutionFalsePositive, "bob"
	if _, err := svc.Update(ctx, b.ID, Update{Status: &resolved, Resolution: &fp, Assignee: &bob}, "bob"); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.List(ctx, Filter{Status: StatusResolved, Assignee: "bob"}); len(got) != 1 || got[0].ID != b.ID {
		t.Fatalf("status + assignee filter: %+v", got)
	}
	if found, _ := st.FindOpen(ctx, []Entity{ip}, now.Add(-time.Hour)); found != nil {
		t.Fatal("resolved incident returned by FindOpen")
	}

	d, err := st.Get(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Alerts) != 2 || d.Alerts[0].ID == 0 || d.Alerts[0].IncidentID != a.ID || len(d.Activity) != 1 {
		t.Fatalf("detail: %+v", d)
	}
	if _, err := st.Get(ctx, "INC-MISSING"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}

	stats, err := st.Stats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Open != 1 || stats.Resolved != 1 || stats.FalsePositive != 1 ||
		stats.OpenBySev["P2"] != 1 || stats.ByStatus[StatusNew] != 1 || stats.MTTRSeconds <= 0 {
		t.Fatalf("stats = %+v", stats)
	}
}

func TestDetectAndAcknowledgeTimes(t *testing.T) {
	ctx := context.Background()
	svc, now := testService(t, NewMemory())

	ev := bruteForce
	ev.Event.Timestamp = now.Add(-90 * time.Second)
	inc := observe(t, svc, ev).Incident
	if inc.OccurredAt == nil || now.Sub(*inc.OccurredAt) != 90*time.Second {
		t.Fatalf("OccurredAt = %v", inc.OccurredAt)
	}

	// Replayed (too old), future or missing log times do not count.
	for _, tc := range []struct {
		name, ip string
		ts       time.Time
	}{
		{"replayed", "198.51.100.1", now.Add(-48 * time.Hour)},
		{"future", "198.51.100.2", now.Add(time.Hour)},
		{"missing", "198.51.100.3", time.Time{}},
	} {
		e := otherHost // a different IP and host keep the incidents apart
		e.Event.Raw = strings.ReplaceAll(e.Event.Raw, "198.51.100.9", tc.ip)
		e.Event.Hostname = "host-" + tc.name
		e.Event.Timestamp = tc.ts
		if got := observe(t, svc, e).Incident; got.OccurredAt != nil {
			t.Errorf("%s log time must not count towards MTTD: %v", tc.name, got.OccurredAt)
		}
	}

	// A comment is not an acknowledgement; assigning or changing status is.
	*now = now.Add(5 * time.Minute)
	if _, err := svc.Comment(ctx, inc.ID, "ana", "looking"); err != nil {
		t.Fatal(err)
	}
	d, _ := svc.Get(ctx, inc.ID)
	if d.AcknowledgedAt != nil {
		t.Fatal("a comment must not acknowledge")
	}
	*now = now.Add(5 * time.Minute)
	who := "ana"
	got, err := svc.Update(ctx, inc.ID, Update{Assignee: &who}, "ana")
	if err != nil || got.AcknowledgedAt == nil || got.AcknowledgedAt.Sub(got.CreatedAt) != 10*time.Minute {
		t.Fatalf("assigning acknowledges: %+v %v", got.AcknowledgedAt, err)
	}
	first := *got.AcknowledgedAt
	*now = now.Add(time.Hour)
	st := StatusResolved
	got, _ = svc.Update(ctx, inc.ID, Update{Status: &st}, "ana")
	if !got.AcknowledgedAt.Equal(first) {
		t.Fatal("the first acknowledgement is kept")
	}
}

func TestActiveSinceFilter(t *testing.T) {
	ctx := context.Background()
	st := NewMemory()
	svc, now := testService(t, st)
	oldResolved := observe(t, svc, bruteForce).Incident
	resolved := StatusResolved
	if _, err := svc.Update(ctx, oldResolved.ID, Update{Status: &resolved}, "ana"); err != nil {
		t.Fatal(err)
	}
	stillOpen := observe(t, svc, otherHost).Incident
	*now = now.Add(48 * time.Hour)
	fresh := observe(t, svc, rootShell).Incident

	list, _ := st.List(ctx, Filter{ActiveSince: now.Add(-24 * time.Hour)})
	ids := map[string]bool{}
	for _, i := range list {
		ids[i.ID] = true
	}
	if ids[oldResolved.ID] || !ids[stillOpen.ID] || !ids[fresh.ID] {
		t.Fatalf("ActiveSince kept %v", ids)
	}
}
