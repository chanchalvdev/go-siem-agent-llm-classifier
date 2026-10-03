package incident

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/chverma/siemagent/internal/detection"
	"github.com/chverma/siemagent/internal/metrics"
	"github.com/chverma/siemagent/internal/models"
)

// EntitySignature correlates alerts that carry no IP, user or host: repeats
// of the same attack type join one incident instead of opening one each.
const EntitySignature = "signature"

// SystemActor is recorded for changes the platform makes on its own.
const SystemActor = "system"

const maxCommentLen = 5000

// Config tunes correlation.
type Config struct {
	// Window is how long an incident keeps absorbing alerts after its last one.
	Window time.Duration
	// MinSeverity is the least severe alert that opens or joins an incident;
	// P4/P5 events stay in the event list only.
	MinSeverity models.Severity
}

// DefaultConfig correlates P1–P3 alerts within one hour.
func DefaultConfig() Config {
	return Config{Window: time.Hour, MinSeverity: models.SeverityP3}
}

// Result says what an observed alert did.
type Result struct {
	Incident Incident
	Created  bool
	// Escalated is true when the alert raised the incident's severity.
	Escalated bool
}

// Service correlates alerts into incidents and applies analyst changes.
// All writes are serialised by one mutex, so two alerts from the same IP
// arriving together cannot open two incidents. That holds within one
// process; running several API replicas needs a shared lock (not yet).
type Service struct {
	store Store
	cfg   Config
	now   func() time.Time
	mu    sync.Mutex
}

func NewService(store Store, cfg Config) *Service {
	if cfg.Window <= 0 {
		cfg.Window = DefaultConfig().Window
	}
	if cfg.MinSeverity == "" {
		cfg.MinSeverity = DefaultConfig().MinSeverity
	}
	return &Service{store: store, cfg: cfg, now: time.Now}
}

// EntitiesOf returns the entities an event can be correlated on.
func EntitiesOf(ev models.ClassifiedEvent) []Entity {
	var out []Entity
	ents := detection.Entities(ev.Event)
	if ip := ents["src_ip"]; ip != "" {
		out = append(out, Entity{EntityIP, ip})
	}
	if u := ents["user"]; u != "" {
		out = append(out, Entity{EntityUser, u})
	}
	if h := strings.TrimSpace(ev.Event.Hostname); h != "" && h != "-" {
		out = append(out, Entity{EntityHost, strings.ToLower(h)})
	}
	return out
}

// Observe correlates one classified event. ok is false when the event is
// below MinSeverity and stays out of incidents.
func (s *Service) Observe(ctx context.Context, ev models.ClassifiedEvent) (res Result, ok bool, err error) {
	if severityRank(ev.Severity) > severityRank(s.cfg.MinSeverity) {
		return Result{}, false, nil
	}
	entities := EntitiesOf(ev)
	match := entities
	if len(entities) == 0 {
		match = []Entity{{EntitySignature, ev.AttackType}}
	}
	now := s.now().UTC()
	alert := Alert{
		At:          now,
		Severity:    ev.Severity,
		AttackType:  ev.AttackType,
		Summary:     ev.Summary,
		Tactic:      ev.MITRE.Tactic,
		TechniqueID: ev.MITRE.TechniqueID,
		Hostname:    ev.Event.Hostname,
		Raw:         ev.Event.Raw,
		Entities:    entities,
	}
	for _, d := range ev.Detections {
		alert.Rules = append(alert.Rules, d.Title)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	existing, err := s.store.FindOpen(ctx, match, now.Add(-s.cfg.Window))
	if err != nil {
		return Result{}, false, fmt.Errorf("find incident: %w", err)
	}
	if existing == nil {
		inc := Incident{
			ID:         newID(),
			Severity:   ev.Severity,
			Status:     StatusNew,
			Entities:   match,
			Tactics:    mergeTactics(nil, ev.MITRE.Tactic),
			Techniques: mergeStrings([]string{}, ev.MITRE.TechniqueID),
			AlertCount: 1,
			FirstSeen:  now, LastSeen: now, CreatedAt: now, UpdatedAt: now,
		}
		inc.Title = title(ev, match)
		act := Activity{At: now, Actor: SystemActor, Kind: ActivityCreated,
			Body: fmt.Sprintf("Opened from %s alert: %s", ev.Severity, ev.AttackType)}
		if err := s.store.Save(ctx, inc, &alert, act); err != nil {
			return Result{}, false, fmt.Errorf("save incident: %w", err)
		}
		metrics.IncidentsCreatedTotal.WithLabelValues(string(inc.Severity)).Inc()
		return Result{Incident: inc, Created: true}, true, nil
	}

	inc := *existing
	inc.AlertCount++
	inc.LastSeen, inc.UpdatedAt = now, now
	inc.Entities = mergeEntities(inc.Entities, match)
	inc.Tactics = mergeTactics(inc.Tactics, ev.MITRE.Tactic)
	inc.Techniques = mergeStrings(inc.Techniques, ev.MITRE.TechniqueID)
	var acts []Activity
	escalated := higher(ev.Severity, inc.Severity)
	if escalated {
		acts = append(acts, Activity{At: now, Actor: SystemActor, Kind: ActivityEscalated,
			Body: fmt.Sprintf("Severity raised from %s to %s by %s", inc.Severity, ev.Severity, ev.AttackType)})
		inc.Severity = ev.Severity
		inc.Title = title(ev, inc.Entities)
	}
	if err := s.store.Save(ctx, inc, &alert, acts...); err != nil {
		return Result{}, false, fmt.Errorf("save incident: %w", err)
	}
	metrics.IncidentAlertsCorrelatedTotal.Inc()
	return Result{Incident: inc, Escalated: escalated}, true, nil
}

// title names an incident after its most severe alert and main entity.
func title(ev models.ClassifiedEvent, entities []Entity) string {
	t := ev.AttackType
	if t == "" {
		t = "Suspicious activity"
	}
	for _, kind := range []string{EntityIP, EntityUser, EntityHost} {
		for _, e := range entities {
			if e.Kind != kind {
				continue
			}
			switch kind {
			case EntityIP:
				return t + " from " + e.Value
			case EntityUser:
				return t + " by " + e.Value
			default:
				return t + " on " + e.Value
			}
		}
	}
	return t
}

// Update applies an analyst change and records each field change in history.
func (s *Service) Update(ctx context.Context, id string, u Update, actor string) (Incident, error) {
	if err := u.Validate(); err != nil {
		return Incident{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	d, err := s.store.Get(ctx, id)
	if err != nil {
		return Incident{}, err
	}
	inc := d.Incident
	now := s.now().UTC()
	var acts []Activity
	record := func(kind, body string) {
		acts = append(acts, Activity{At: now, Actor: actor, Kind: kind, Body: body})
	}

	if u.Status != nil && *u.Status != inc.Status {
		record(ActivityStatus, fmt.Sprintf("Status changed from %s to %s", inc.Status, *u.Status))
		if *u.Status == StatusResolved {
			inc.ResolvedAt = &now
		} else {
			// Reopened: the old resolution no longer applies.
			inc.ResolvedAt, inc.Resolution = nil, ResolutionNone
		}
		inc.Status = *u.Status
	}
	if u.Resolution != nil && *u.Resolution != inc.Resolution {
		if inc.Status != StatusResolved && *u.Resolution != ResolutionNone {
			return Incident{}, invalid("set status to resolved to record a resolution")
		}
		record(ActivityResolution, "Resolution set to "+resolutionLabel(*u.Resolution))
		inc.Resolution = *u.Resolution
	}
	if u.Assignee != nil {
		a := strings.TrimSpace(*u.Assignee)
		if a != inc.Assignee {
			if a == "" {
				record(ActivityAssignee, "Unassigned")
			} else {
				record(ActivityAssignee, "Assigned to "+a)
			}
			inc.Assignee = a
		}
	}
	if u.Severity != nil && *u.Severity != inc.Severity {
		record(ActivitySeverity, fmt.Sprintf("Severity changed from %s to %s", inc.Severity, *u.Severity))
		inc.Severity = *u.Severity
	}
	if len(acts) == 0 {
		return inc, nil
	}
	inc.UpdatedAt = now
	if err := s.store.Save(ctx, inc, nil, acts...); err != nil {
		return Incident{}, err
	}
	if inc.Status == StatusResolved && u.Status != nil {
		metrics.IncidentsResolvedTotal.WithLabelValues(string(inc.Resolution)).Inc()
	}
	return inc, nil
}

func resolutionLabel(r Resolution) string {
	if r == ResolutionNone {
		return "none"
	}
	return strings.ReplaceAll(string(r), "_", " ")
}

// Comment adds an analyst note to the incident history.
func (s *Service) Comment(ctx context.Context, id, actor, body string) (Activity, error) {
	body = strings.TrimSpace(body)
	if body == "" {
		return Activity{}, invalid("comment is empty")
	}
	if utf8.RuneCountInString(body) > maxCommentLen {
		return Activity{}, invalid(fmt.Sprintf("comment is longer than %d characters", maxCommentLen))
	}
	return s.addActivity(ctx, id, Activity{Actor: actor, Kind: ActivityComment, Body: body})
}

// Feedback records whether the latest AI investigation was helpful. The
// ratings feed the AI quality metrics and, later, the evaluation set.
func (s *Service) Feedback(ctx context.Context, id, actor string, helpful bool, note string) (Activity, error) {
	note = strings.TrimSpace(note)
	if utf8.RuneCountInString(note) > maxCommentLen {
		return Activity{}, invalid(fmt.Sprintf("note is longer than %d characters", maxCommentLen))
	}
	d, err := s.store.Get(ctx, id)
	if err != nil {
		return Activity{}, err
	}
	if _, ok := LatestInvestigation(d); !ok {
		return Activity{}, invalid("this incident has no AI investigation to rate")
	}
	rating, body := "unhelpful", "Rated the AI investigation not helpful"
	if helpful {
		rating, body = "helpful", "Rated the AI investigation helpful"
	}
	if note != "" {
		body += ": " + note
	}
	act, err := s.addActivity(ctx, id, Activity{Actor: actor, Kind: ActivityFeedback, Body: body})
	if err == nil {
		metrics.AIFeedbackTotal.WithLabelValues(rating).Inc()
	}
	return act, err
}

// Note records a platform-generated entry (e.g. an AI investigation) in the
// incident history.
func (s *Service) Note(ctx context.Context, id, actor, kind, body string) (Activity, error) {
	return s.addActivity(ctx, id, Activity{Actor: actor, Kind: kind, Body: body})
}

func (s *Service) addActivity(ctx context.Context, id string, act Activity) (Activity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, err := s.store.Get(ctx, id)
	if err != nil {
		return Activity{}, err
	}
	now := s.now().UTC()
	act.At = now
	inc := d.Incident
	inc.UpdatedAt = now
	if err := s.store.Save(ctx, inc, nil, act); err != nil {
		return Activity{}, err
	}
	act.IncidentID = id
	return act, nil
}

// Read-only access goes straight to the store.

func (s *Service) Get(ctx context.Context, id string) (Detail, error) { return s.store.Get(ctx, id) }

func (s *Service) List(ctx context.Context, f Filter) ([]Incident, error) {
	return s.store.List(ctx, f)
}

func (s *Service) Stats(ctx context.Context) (Stats, error) { return s.store.Stats(ctx) }
