package response

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chverma/siemagent/internal/incident"
	"github.com/chverma/siemagent/internal/models"
)

// fakeExec records executions and returns a fixed outcome.
type fakeExec struct {
	mu   sync.Mutex
	runs []Action
	err  error
}

func (f *fakeExec) Execute(_ context.Context, a Action, _ ActionSpec, _ incident.Incident) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.runs = append(f.runs, a)
	if f.err != nil {
		return "", f.err
	}
	return "ok", nil
}

func (f *fakeExec) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.runs)
}

const testPlaybooks = `
id: block-bf
name: Block brute force
trigger:
  min_severity: P2
  techniques: [T1110]
actions:
  - type: block_ip
---
id: disable-users
name: Disable users
mode: approval
trigger:
  tactics: [privilege escalation]
actions:
  - type: disable_user
---
id: dry-notify
name: Dry notify
mode: dry_run
trigger:
  attack_types: [shadow]
actions:
  - type: notify
    message: "{{severity}} {{title}} on {{entities}}"
---
id: auto-hook
name: Auto webhook
mode: auto
trigger:
  min_severity: P1
actions:
  - type: webhook
    url: https://hooks.example/x
`

type fixture struct {
	eng  *Engine
	exec *fakeExec
	inc  *incident.Service
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	pbs, errs := ParsePlaybooks([]byte(testPlaybooks), "test")
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	svc := incident.NewService(incident.NewMemory(), incident.DefaultConfig())
	exec := &fakeExec{}
	eng, errs := NewEngine(pbs, NewMemory(), exec, svc)
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	eng.async = func(f func()) { f() } // run auto actions inline
	return &fixture{eng: eng, exec: exec, inc: svc}
}

func alert(raw, host, attack, tactic, technique string, sev models.Severity) models.ClassifiedEvent {
	return models.ClassifiedEvent{
		Event:      models.LogEvent{Raw: raw, Hostname: host},
		AttackType: attack, Severity: sev,
		MITRE: models.MITREInfo{Tactic: tactic, TechniqueID: technique},
	}
}

// observe correlates ev and runs the engine, as the API does.
func (fx *fixture) observe(t *testing.T, ev models.ClassifiedEvent) (incident.Incident, []Action) {
	t.Helper()
	res, ok, err := fx.inc.Observe(context.Background(), ev)
	if err != nil || !ok {
		t.Fatalf("observe: %v %v", ok, err)
	}
	return res.Incident, fx.eng.OnAlert(context.Background(), res.Incident, ev)
}

var bruteForce = alert("sshd: Failed password for root from 185.220.101.4 port 22", "web01",
	"SSH Brute Force", "Credential Access", "T1110.001", models.SeverityP2)

func TestTriggerProposesForApproval(t *testing.T) {
	fx := newFixture(t)
	inc, acts := fx.observe(t, bruteForce)
	if len(acts) != 1 || acts[0].Type != ActionBlockIP || acts[0].Target != "185.220.101.4" || acts[0].Status != StatusPending {
		t.Fatalf("actions = %+v", acts)
	}
	if fx.exec.count() != 0 {
		t.Fatal("approval mode must not execute")
	}
	// Same incident again: no duplicate proposal.
	if _, again := fx.observe(t, bruteForce); len(again) != 0 {
		t.Fatalf("duplicate proposals: %+v", again)
	}
	d, _ := fx.inc.Get(context.Background(), inc.ID)
	last := d.Activity[len(d.Activity)-1]
	if last.Kind != incident.ActivityResponse || !strings.Contains(last.Body, "Proposed block_ip 185.220.101.4") {
		t.Fatalf("history = %+v", last)
	}
}

func TestApproveRunsAndAudits(t *testing.T) {
	fx := newFixture(t)
	ctx := context.Background()
	inc, acts := fx.observe(t, bruteForce)

	got, err := fx.eng.Approve(ctx, acts[0].ID, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusSucceeded || got.DecidedBy != "alice" || got.ExecutedAt == nil || got.Result != "ok" {
		t.Fatalf("approved action = %+v", got)
	}
	if _, err := fx.eng.Approve(ctx, acts[0].ID, "bob"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("second approval: %v", err)
	}
	if fx.exec.count() != 1 {
		t.Fatalf("executed %d times", fx.exec.count())
	}
	d, _ := fx.inc.Get(ctx, inc.ID)
	var bodies []string
	for _, a := range d.Activity {
		if a.Kind == incident.ActivityResponse {
			bodies = append(bodies, a.Actor+": "+a.Body)
		}
	}
	want := "playbook:block-bf: Proposed block_ip 185.220.101.4 (Block brute force); waiting for approval|" +
		"alice: Approved block_ip 185.220.101.4 (Block brute force)|" +
		"response: Executed block_ip 185.220.101.4: ok"
	if strings.Join(bodies, "|") != want {
		t.Fatalf("audit trail:\n%s", strings.Join(bodies, "\n"))
	}
}

func TestFailedExecutionIsRecorded(t *testing.T) {
	fx := newFixture(t)
	fx.exec.err = errors.New("firewall unreachable")
	_, acts := fx.observe(t, bruteForce)
	got, err := fx.eng.Approve(context.Background(), acts[0].ID, "alice")
	if err != nil || got.Status != StatusFailed || got.Result != "firewall unreachable" {
		t.Fatalf("got %+v %v", got, err)
	}
}

func TestReject(t *testing.T) {
	fx := newFixture(t)
	ctx := context.Background()
	_, acts := fx.observe(t, bruteForce)
	got, err := fx.eng.Reject(ctx, acts[0].ID, "alice", "  our pentest  ")
	if err != nil || got.Status != StatusRejected || got.Result != "our pentest" {
		t.Fatalf("got %+v %v", got, err)
	}
	if _, err := fx.eng.Approve(ctx, acts[0].ID, "bob"); !errors.Is(err, ErrInvalid) {
		t.Fatal("rejected action approved")
	}
	if _, err := fx.eng.Reject(ctx, "ACT-NOPE", "a", ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown: %v", err)
	}
	if fx.exec.count() != 0 {
		t.Fatal("rejected action ran")
	}
}

func TestSafetyGuards(t *testing.T) {
	fx := newFixture(t)
	private := bruteForce
	private.Event.Raw = "sshd: Failed password for root from 10.0.0.8 port 22"
	if _, acts := fx.observe(t, private); len(acts) != 0 {
		t.Fatalf("private IPs must not be proposed for blocking: %+v", acts)
	}
	esc := alert("sudo: alice : USER=root ; COMMAND=/bin/bash user=root", "db01",
		"Sudo Root Shell", "Privilege Escalation", "T1548.003", models.SeverityP2)
	if _, acts := fx.observe(t, esc); len(acts) != 0 {
		t.Fatalf("built-in accounts must not be proposed for disabling: %+v", acts)
	}
	esc.Event.Raw = "sudo: session opened user=deploy"
	esc.Event.Hostname = "db02"
	if _, acts := fx.observe(t, esc); len(acts) != 1 || acts[0].Target != "deploy" {
		t.Fatalf("regular accounts can be proposed: %+v", acts)
	}
}

func TestDryRunAndAutoModes(t *testing.T) {
	fx := newFixture(t)
	ransom := alert("vssadmin delete shadows /all", "app02", "Shadow Copies Deleted", "Impact", "T1490", models.SeverityP1)
	_, acts := fx.observe(t, ransom)
	byPlaybook := map[string]Action{}
	for _, a := range acts {
		byPlaybook[a.PlaybookID] = a
	}
	dry := byPlaybook["dry-notify"]
	if dry.Status != StatusDryRun || dry.Message != "P1 Shadow Copies Deleted on app02 on host:app02" {
		t.Fatalf("dry run = %+v", dry)
	}
	auto, _ := fx.eng.Get(context.Background(), byPlaybook["auto-hook"].ID)
	if auto.Status != StatusSucceeded || auto.DecidedBy != "playbook:auto-hook" {
		t.Fatalf("auto = %+v", auto)
	}
	if fx.exec.count() != 1 {
		t.Fatalf("only the auto action should run, ran %d", fx.exec.count())
	}
}

func TestRunPlaybookManually(t *testing.T) {
	fx := newFixture(t)
	ctx := context.Background()
	low := bruteForce
	low.Severity = models.SeverityP3 // below the trigger
	inc, acts := fx.observe(t, low)
	if len(acts) != 0 {
		t.Fatal("P3 should not trigger block-bf")
	}
	acts, err := fx.eng.RunPlaybook(ctx, "block-bf", inc.ID, "alice")
	if err != nil || len(acts) != 1 || acts[0].Reason != "run manually by alice" {
		t.Fatalf("manual run: %+v %v", acts, err)
	}
	if _, err := fx.eng.RunPlaybook(ctx, "nope", inc.ID, "alice"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown playbook: %v", err)
	}
	if _, err := fx.eng.RunPlaybook(ctx, "block-bf", "INC-NOPE", "alice"); !errors.Is(err, incident.ErrNotFound) {
		t.Fatalf("unknown incident: %v", err)
	}
}

func TestTriggerMatching(t *testing.T) {
	inc := incident.Incident{Severity: models.SeverityP2, Tactics: []string{"Credential Access"}, Techniques: []string{"T1110.001"}}
	ev := models.ClassifiedEvent{AttackType: "Brute Force", Detections: []models.Detection{{Title: "SSH Brute Force"}}}
	cases := []struct {
		t    Trigger
		want bool
	}{
		{Trigger{}, true},
		{Trigger{MinSeverity: models.SeverityP2}, true},
		{Trigger{MinSeverity: models.SeverityP1}, false},
		{Trigger{Tactics: []string{"credential access"}}, true},
		{Trigger{Tactics: []string{"Impact"}}, false},
		{Trigger{Techniques: []string{"T1110"}}, true},
		{Trigger{Techniques: []string{"T111"}}, false},
		{Trigger{AttackTypes: []string{"ssh brute"}}, true},
		{Trigger{AttackTypes: []string{"ransom"}}, false},
	}
	for _, c := range cases {
		if got := c.t.Matches(inc, ev); got != c.want {
			t.Errorf("%+v: got %v", c.t, got)
		}
	}
}

func TestParsePlaybooksValidation(t *testing.T) {
	_, errs := ParsePlaybooks([]byte(`
id: Bad_ID
name: x
actions: [{type: notify}]
---
id: no-actions
name: x
---
id: bad-type
name: x
actions: [{type: format_disk}]
---
id: bad-mode
name: x
mode: yolo
actions: [{type: notify}]
---
id: bad-hook
name: x
actions: [{type: webhook, url: "ftp://x"}]
---
id: bad-sev
name: x
trigger: {min_severity: P9}
actions: [{type: notify}]
`), "t")
	if len(errs) != 6 {
		t.Fatalf("want 6 errors, got %d: %v", len(errs), errs)
	}
	pbs, _ := ParsePlaybooks([]byte("id: ok-one\nname: OK\nactions: [{type: notify}]\n"), "t")
	if pbs[0].Mode != ModeApproval || !pbs[0].IsEnabled() {
		t.Fatalf("defaults: %+v", pbs[0])
	}
}

func TestBuiltinPlaybooksLoad(t *testing.T) {
	pbs, errs := LoadBuiltin()
	if len(errs) > 0 || len(pbs) < 4 {
		t.Fatalf("builtin: %d %v", len(pbs), errs)
	}
	for _, p := range pbs {
		if p.Mode == ModeAuto {
			t.Errorf("built-in playbook %s must not run automatically", p.ID)
		}
	}
}

func TestHTTPExecutor(t *testing.T) {
	var got []map[string]any
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		mu.Lock()
		got = append(got, m)
		mu.Unlock()
		if strings.Contains(r.URL.Path, "fail") {
			http.Error(w, "nope", http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte("blocked"))
	}))
	defer srv.Close()

	inc := incident.Incident{ID: "INC-1", Title: "T", Severity: models.SeverityP1}
	x := NewHTTPExecutor(Connectors{ContainmentURL: srv.URL + "/contain", SlackURL: srv.URL + "/slack"})
	ctx := context.Background()

	res, err := x.Execute(ctx, Action{ID: "ACT-1", Type: ActionBlockIP, Target: "203.0.113.9", DecidedBy: "alice"}, ActionSpec{}, inc)
	if err != nil || !strings.Contains(res, "HTTP 200: blocked") {
		t.Fatalf("block: %q %v", res, err)
	}
	if got[0]["action"] != "block_ip" || got[0]["target"] != "203.0.113.9" || got[0]["approved_by"] != "alice" {
		t.Fatalf("containment body = %v", got[0])
	}
	if _, err := x.Execute(ctx, Action{Type: ActionNotify, Message: "hi"}, ActionSpec{}, inc); err != nil || got[1]["text"] != "hi" {
		t.Fatalf("slack: %v %v", got[1], err)
	}
	_, err = x.Execute(ctx, Action{Type: ActionWebhook}, ActionSpec{URL: srv.URL + "/fail?token=secret"}, inc)
	if err == nil || !strings.Contains(err.Error(), "HTTP 403") || strings.Contains(err.Error(), "secret") {
		t.Fatalf("webhook failure must report status without the URL token: %v", err)
	}

	none := NewHTTPExecutor(Connectors{})
	if _, err := none.Execute(ctx, Action{Type: ActionIsolateHost}, ActionSpec{}, inc); err == nil || !strings.Contains(err.Error(), "RESPONSE_WEBHOOK_URL") {
		t.Fatalf("missing connector: %v", err)
	}
	if _, err := none.Execute(ctx, Action{Type: ActionNotify}, ActionSpec{}, inc); err == nil || !strings.Contains(err.Error(), "SLACK_WEBHOOK_URL") {
		t.Fatalf("missing slack: %v", err)
	}
}

func TestHostOf(t *testing.T) {
	for in, want := range map[string]string{
		"https://hooks.slack.com/services/T/B/secret": "hooks.slack.com",
		"http://user:pw@host:8080/x?y":                "host:8080",
	} {
		if got := hostOf(in); got != want {
			t.Errorf("%s = %s", in, got)
		}
	}
}

func TestMemoryStoreContract(t *testing.T) { testStoreContract(t, NewMemory()) }

func testStoreContract(t *testing.T, st Store) {
	t.Helper()
	ctx := context.Background()
	base := time.Date(2026, 10, 3, 10, 0, 0, 0, time.UTC)
	a := Action{ID: "ACT-A", IncidentID: "INC-1", Type: ActionBlockIP, Target: "1.2.3.4", Status: StatusPending, ProposedAt: base, DedupKey: "k1"}
	b := Action{ID: "ACT-B", IncidentID: "INC-2", Type: ActionNotify, Status: StatusDryRun, ProposedAt: base.Add(time.Minute), DedupKey: "k2"}
	for _, x := range []Action{a, b} {
		if ok, err := st.Create(ctx, x); !ok || err != nil {
			t.Fatalf("create %s: %v %v", x.ID, ok, err)
		}
	}
	dup := a
	dup.ID = "ACT-DUP"
	if ok, err := st.Create(ctx, dup); ok || err != nil {
		t.Fatalf("duplicate key must be ignored: %v %v", ok, err)
	}
	list, _ := st.List(ctx, Filter{})
	if len(list) != 2 || list[0].ID != "ACT-B" {
		t.Fatalf("newest first: %+v", list)
	}
	if l, _ := st.List(ctx, Filter{Status: StatusPending}); len(l) != 1 || l[0].ID != "ACT-A" {
		t.Fatalf("status filter: %+v", l)
	}
	if l, _ := st.List(ctx, Filter{IncidentID: "INC-2", Limit: 5}); len(l) != 1 || l[0].ID != "ACT-B" {
		t.Fatalf("incident filter: %+v", l)
	}
	a.Status, a.Result = StatusSucceeded, "done"
	if err := st.Update(ctx, a); err != nil {
		t.Fatal(err)
	}
	got, err := st.Get(ctx, "ACT-A")
	if err != nil || got.Status != StatusSucceeded || got.Result != "done" || got.DedupKey != "k1" {
		t.Fatalf("get after update: %+v %v", got, err)
	}
	if _, err := st.Get(ctx, "ACT-NOPE"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	if err := st.Update(ctx, Action{ID: "ACT-NOPE"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("update missing: %v", err)
	}
}

func TestPlaybookJSONHidesWebhookURL(t *testing.T) {
	pbs, _ := ParsePlaybooks([]byte("id: hook\nname: Hook\nactions: [{type: webhook, url: 'https://hooks.example/T0K3N'}]\n"), "t")
	b, _ := json.Marshal(pbs[0])
	if strings.Contains(string(b), "T0K3N") {
		t.Fatalf("webhook URL leaked: %s", b)
	}
	if pbs[0].Actions[0].URL == "" {
		t.Fatal("URL must still be loaded for execution")
	}
}
