package response

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/chverma/siemagent/internal/incident"
	"github.com/chverma/siemagent/internal/metrics"
	"github.com/chverma/siemagent/internal/models"
)

// Incidents is what the engine needs from the incident service.
type Incidents interface {
	Get(ctx context.Context, id string) (incident.Detail, error)
	Note(ctx context.Context, id, actor, kind, body string) (incident.Activity, error)
}

// Engine matches playbooks to incidents, proposes actions and runs them.
type Engine struct {
	playbooks []*Playbook
	byID      map[string]*Playbook
	store     Store
	exec      Executor
	incidents Incidents
	now       func() time.Time
	// async runs auto-mode actions; tests replace it to run inline.
	async func(func())
	// decide serialises approve/reject so two analysts clicking at once
	// cannot both run the same action (single process).
	decide sync.Mutex
}

// NewEngine builds an engine. Duplicate playbook IDs are reported (first wins).
func NewEngine(playbooks []*Playbook, store Store, exec Executor, incidents Incidents) (*Engine, []error) {
	pbs, errs := dedupe(playbooks)
	e := &Engine{
		playbooks: pbs, byID: map[string]*Playbook{}, store: store, exec: exec, incidents: incidents,
		now: time.Now, async: func(f func()) { go f() },
	}
	for _, p := range pbs {
		e.byID[p.ID] = p
	}
	return e, errs
}

// Playbooks returns the loaded playbooks sorted by name.
func (e *Engine) Playbooks() []*Playbook { return e.playbooks }

// Matches reports whether the trigger selects this incident and alert.
func (t Trigger) Matches(inc incident.Incident, ev models.ClassifiedEvent) bool {
	if t.MinSeverity != "" && severityRank[inc.Severity] > severityRank[t.MinSeverity] {
		return false
	}
	if len(t.Tactics) > 0 && !anyFold(t.Tactics, inc.Tactics, strings.EqualFold) {
		return false
	}
	if len(t.Techniques) > 0 && !anyFold(t.Techniques, inc.Techniques, func(want, have string) bool {
		// "T1110" also matches sub-techniques such as "T1110.001".
		return strings.EqualFold(want, have) || strings.HasPrefix(strings.ToUpper(have), strings.ToUpper(want)+".")
	}) {
		return false
	}
	if len(t.AttackTypes) > 0 {
		names := []string{ev.AttackType}
		for _, d := range ev.Detections {
			names = append(names, d.Title)
		}
		if !anyFold(t.AttackTypes, names, func(want, have string) bool {
			return strings.Contains(strings.ToLower(have), strings.ToLower(want))
		}) {
			return false
		}
	}
	return true
}

func anyFold(wants, haves []string, eq func(want, have string) bool) bool {
	for _, w := range wants {
		for _, h := range haves {
			if eq(w, h) {
				return true
			}
		}
	}
	return false
}

// OnAlert runs every enabled playbook whose trigger matches the incident the
// alert just joined or opened, and returns the actions it proposed.
func (e *Engine) OnAlert(ctx context.Context, inc incident.Incident, ev models.ClassifiedEvent) []Action {
	var out []Action
	for _, p := range e.playbooks {
		if !p.IsEnabled() || !p.Trigger.Matches(inc, ev) {
			continue
		}
		out = append(out, e.propose(ctx, p, inc, "matched trigger on "+ev.AttackType)...)
	}
	return out
}

// RunPlaybook proposes a playbook's actions for an incident on an analyst's
// request, regardless of its trigger. The playbook's mode still applies.
func (e *Engine) RunPlaybook(ctx context.Context, playbookID, incidentID, actor string) ([]Action, error) {
	p, ok := e.byID[playbookID]
	if !ok {
		return nil, fmt.Errorf("%w: unknown playbook %q", ErrInvalid, playbookID)
	}
	d, err := e.incidents.Get(ctx, incidentID)
	if err != nil {
		return nil, err
	}
	return e.propose(ctx, p, d.Incident, "run manually by "+actor), nil
}

// propose creates the playbook's actions for every matching target.
func (e *Engine) propose(ctx context.Context, p *Playbook, inc incident.Incident, reason string) []Action {
	var out []Action
	for step, spec := range p.Actions {
		for _, target := range e.targets(p, spec, inc) {
			a := Action{
				ID: newActionID(), IncidentID: inc.ID, PlaybookID: p.ID, PlaybookName: p.Name,
				Type: spec.Type, Target: target, Step: step, Reason: reason, ProposedAt: e.now().UTC(),
				DedupKey: fmt.Sprintf("%s|%d|%s|%s", p.ID, step, inc.ID, target),
			}
			if spec.Type == ActionNotify || spec.Type == ActionWebhook {
				a.Message = render(spec.Message, inc)
			}
			switch p.Mode {
			case ModeDryRun:
				a.Status, a.Result = StatusDryRun, "Dry run: not executed."
			case ModeAuto:
				a.Status, a.DecidedBy = StatusRunning, "playbook:"+p.ID
			default:
				a.Status = StatusPending
			}
			created, err := e.store.Create(ctx, a)
			if err != nil {
				slog.Error("save proposed action failed", "component", "response", "playbook", p.ID, "error", err)
				continue
			}
			if !created {
				continue // already proposed for this incident and target
			}
			metrics.ResponseActionsTotal.WithLabelValues(a.Type, string(a.Status)).Inc()
			e.note(ctx, a.IncidentID, "playbook:"+p.ID, proposalNote(a, p.Mode))
			if p.Mode == ModeAuto {
				a := a
				e.async(func() {
					runCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
					defer cancel()
					_, _ = e.execute(runCtx, a)
				})
			}
			out = append(out, a)
		}
	}
	return out
}

func proposalNote(a Action, mode Mode) string {
	switch mode {
	case ModeDryRun:
		return fmt.Sprintf("Dry run: would %s (%s)", a.Describe(), a.PlaybookName)
	case ModeAuto:
		return fmt.Sprintf("Running %s automatically (%s)", a.Describe(), a.PlaybookName)
	}
	return fmt.Sprintf("Proposed %s (%s); waiting for approval", a.Describe(), a.PlaybookName)
}

// targets returns the entity values an action applies to, or [""] for
// incident-level actions.
func (e *Engine) targets(p *Playbook, spec ActionSpec, inc incident.Incident) []string {
	kind := actionTargets[spec.Type]
	if kind == "" {
		return []string{""}
	}
	var out []string
	for _, ent := range inc.Entities {
		if ent.Kind != kind {
			continue
		}
		if spec.Type == ActionBlockIP && !p.AllowPrivateIPs && !blockable(ent.Value) {
			slog.Info("not proposing block of non-public IP", "component", "response", "ip", ent.Value, "playbook", p.ID)
			continue
		}
		if spec.Type == ActionDisableUser && builtinAccount(ent.Value) {
			slog.Info("not proposing to disable built-in account", "component", "response", "user", ent.Value, "playbook", p.ID)
			continue
		}
		out = append(out, ent.Value)
	}
	return out
}

// blockable reports whether an IP is public. Private, loopback, link-local
// and other reserved ranges are where your own infrastructure lives.
func blockable(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.IsGlobalUnicast() && !ip.IsPrivate()
}

// builtinAccount reports system accounts that must never be disabled by
// automation: doing so locks out recovery and breaks services.
func builtinAccount(user string) bool {
	switch strings.ToLower(user) {
	case "root", "administrator", "system", "localsystem", "nt authority\\system", "nobody", "daemon":
		return true
	}
	return false
}

func render(tmpl string, inc incident.Incident) string {
	if tmpl == "" {
		tmpl = "[{{severity}}] {{title}} ({{id}})"
	}
	ents := make([]string, 0, len(inc.Entities))
	for _, e := range inc.Entities {
		ents = append(ents, e.String())
	}
	return strings.NewReplacer(
		"{{title}}", inc.Title, "{{severity}}", string(inc.Severity), "{{id}}", inc.ID,
		"{{entities}}", strings.Join(ents, ", "), "{{status}}", string(inc.Status),
	).Replace(tmpl)
}

// Approve runs a pending action on an analyst's approval and returns it in
// its final state.
func (e *Engine) Approve(ctx context.Context, id, actor string) (Action, error) {
	e.decide.Lock()
	a, err := e.claim(ctx, id, actor, StatusRunning)
	e.decide.Unlock()
	if err != nil {
		return Action{}, err
	}
	e.note(ctx, a.IncidentID, actor, fmt.Sprintf("Approved %s (%s)", a.Describe(), a.PlaybookName))
	return e.execute(ctx, a)
}

// claim moves a pending action to status, recording who decided.
func (e *Engine) claim(ctx context.Context, id, actor string, status Status) (Action, error) {
	a, err := e.store.Get(ctx, id)
	if err != nil {
		return Action{}, err
	}
	if a.Status != StatusPending {
		return Action{}, fmt.Errorf("%w: action is %s; only pending actions can be decided", ErrInvalid, a.Status)
	}
	now := e.now().UTC()
	a.Status, a.DecidedBy, a.DecidedAt = status, actor, &now
	if err := e.store.Update(ctx, a); err != nil {
		return Action{}, err
	}
	return a, nil
}

// Reject declines a pending action.
func (e *Engine) Reject(ctx context.Context, id, actor, reason string) (Action, error) {
	reason = strings.TrimSpace(reason)
	if len(reason) > 1000 {
		return Action{}, fmt.Errorf("%w: reason is longer than 1000 characters", ErrInvalid)
	}
	e.decide.Lock()
	a, err := e.claim(ctx, id, actor, StatusRejected)
	if err == nil && reason != "" {
		a.Result = reason
		err = e.store.Update(ctx, a)
	}
	e.decide.Unlock()
	if err != nil {
		return Action{}, err
	}
	metrics.ResponseActionsTotal.WithLabelValues(a.Type, string(a.Status)).Inc()
	body := fmt.Sprintf("Rejected %s (%s)", a.Describe(), a.PlaybookName)
	if a.Result != "" {
		body += ": " + a.Result
	}
	e.note(ctx, a.IncidentID, actor, body)
	return a, nil
}

// execute runs an action that is in StatusRunning and records the outcome.
func (e *Engine) execute(ctx context.Context, a Action) (Action, error) {
	result, err := e.run(ctx, a)
	now := e.now().UTC()
	a.ExecutedAt = &now
	if err != nil {
		a.Status, a.Result = StatusFailed, err.Error()
	} else {
		a.Status, a.Result = StatusSucceeded, result
	}
	if uerr := e.store.Update(ctx, a); uerr != nil {
		return Action{}, uerr
	}
	metrics.ResponseActionsTotal.WithLabelValues(a.Type, string(a.Status)).Inc()
	verb := "Executed"
	if a.Status == StatusFailed {
		verb = "Failed"
	}
	e.note(ctx, a.IncidentID, "response", fmt.Sprintf("%s %s: %s", verb, a.Describe(), a.Result))
	return a, nil
}

func (e *Engine) run(ctx context.Context, a Action) (string, error) {
	p, ok := e.byID[a.PlaybookID]
	if !ok || a.Step >= len(p.Actions) {
		return "", errors.New("the playbook that proposed this action is no longer loaded")
	}
	if a.Type == ActionBlockIP && !p.AllowPrivateIPs && !blockable(a.Target) {
		return "", fmt.Errorf("refusing to block non-public address %s", a.Target)
	}
	if a.Type == ActionDisableUser && builtinAccount(a.Target) {
		return "", fmt.Errorf("refusing to disable built-in account %s", a.Target)
	}
	d, err := e.incidents.Get(ctx, a.IncidentID)
	if err != nil {
		return "", fmt.Errorf("load incident: %w", err)
	}
	return e.exec.Execute(ctx, a, p.Actions[a.Step], d.Incident)
}

func (e *Engine) note(ctx context.Context, incidentID, actor, body string) {
	if _, err := e.incidents.Note(ctx, incidentID, actor, incident.ActivityResponse, body); err != nil {
		slog.Error("record response activity failed", "component", "response", "incident", incidentID, "error", err)
	}
}

// Get and List expose stored actions.

func (e *Engine) Get(ctx context.Context, id string) (Action, error) { return e.store.Get(ctx, id) }

func (e *Engine) List(ctx context.Context, f Filter) ([]Action, error) { return e.store.List(ctx, f) }
