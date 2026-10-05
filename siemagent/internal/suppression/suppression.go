// Package suppression snoozes known-noisy alerts.
//
// A suppression matches events by entity (ip, user or host), detection rule
// and/or attack type. Matching events are still stored, marked with the
// suppression's ID, but they do not open or join incidents, trigger playbooks
// or start AI investigations. Suppressions can expire; hit counts measure how
// much noise each one absorbs (alert fatigue).
package suppression

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/chverma/siemagent/internal/incident"
	"github.com/chverma/siemagent/internal/metrics"
	"github.com/chverma/siemagent/internal/models"
)

var (
	// ErrNotFound means no suppression has the ID.
	ErrNotFound = errors.New("suppression not found")
	// ErrInvalid wraps validation failures; the message is safe to show.
	ErrInvalid = errors.New("invalid suppression")
)

const (
	// MaxActive bounds active suppressions, which every event is checked against.
	MaxActive    = 500
	maxReasonLen = 500
	// MaxDuration is the longest snooze; "until lifted" has no expiry.
	MaxDuration = 90 * 24 * time.Hour
)

// Suppression is one snooze rule. Every set matcher must match.
type Suppression struct {
	ID         string           `json:"id"`
	Entity     *incident.Entity `json:"entity,omitempty"`
	RuleID     string           `json:"rule_id,omitempty"`
	AttackType string           `json:"attack_type,omitempty"`
	Reason     string           `json:"reason"`
	CreatedBy  string           `json:"created_by"`
	CreatedAt  time.Time        `json:"created_at"`
	// ExpiresAt is nil for a suppression that lasts until it is lifted.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`

	// Hits and LastHit count matches since the server started.
	Hits    int64      `json:"hits"`
	LastHit *time.Time `json:"last_hit,omitempty"`
}

// Active reports whether the suppression applies at now.
func (s Suppression) Active(now time.Time) bool {
	return s.ExpiresAt == nil || now.Before(*s.ExpiresAt)
}

// Matches reports whether ev (with its extracted entities) is covered.
func (s Suppression) Matches(ev models.ClassifiedEvent, entities []incident.Entity) bool {
	if s.Entity != nil && !slices.Contains(entities, *s.Entity) {
		return false
	}
	if s.RuleID != "" && !slices.ContainsFunc(ev.Detections, func(d models.Detection) bool { return d.RuleID == s.RuleID }) {
		return false
	}
	if s.AttackType != "" && !strings.EqualFold(strings.TrimSpace(ev.AttackType), s.AttackType) {
		return false
	}
	return true
}

// New is a request to create a suppression.
type New struct {
	// Entity is "ip:1.2.3.4", "user:alice" or "host:web01".
	Entity     string `json:"entity"`
	RuleID     string `json:"rule_id"`
	AttackType string `json:"attack_type"`
	Reason     string `json:"reason"`
	// Duration such as "1h", "24h" or "168h"; empty lasts until lifted.
	Duration string `json:"duration"`
}

func invalid(msg string) error { return fmt.Errorf("%w: %s", ErrInvalid, msg) }

func (n New) build(actor string, now time.Time) (Suppression, error) {
	s := Suppression{
		ID:         newID(),
		RuleID:     strings.TrimSpace(n.RuleID),
		AttackType: strings.TrimSpace(n.AttackType),
		Reason:     strings.TrimSpace(n.Reason),
		CreatedBy:  actor,
		CreatedAt:  now,
	}
	if e := strings.TrimSpace(n.Entity); e != "" {
		ent, err := incident.ParseEntity(e)
		if err != nil {
			return Suppression{}, invalid(strings.TrimPrefix(err.Error(), incident.ErrInvalid.Error()+": "))
		}
		if ent.Kind == incident.EntityHost {
			ent.Value = strings.ToLower(ent.Value) // hosts are matched lower-case
		}
		s.Entity = &ent
	}
	if s.Entity == nil && s.RuleID == "" && s.AttackType == "" {
		return Suppression{}, invalid("set at least one of entity, rule_id or attack_type")
	}
	if len(s.RuleID) > 200 || len(s.AttackType) > 200 || (s.Entity != nil && len(s.Entity.Value) > 255) {
		return Suppression{}, invalid("matcher is too long")
	}
	if s.Reason == "" || len(s.Reason) > maxReasonLen {
		return Suppression{}, invalid(fmt.Sprintf("reason is required (up to %d characters)", maxReasonLen))
	}
	if d := strings.TrimSpace(n.Duration); d != "" {
		dur, err := time.ParseDuration(d)
		if err != nil || dur < time.Minute || dur > MaxDuration {
			return Suppression{}, invalid("duration must be between 1m and 2160h (90 days), or empty to last until lifted")
		}
		exp := now.Add(dur)
		s.ExpiresAt = &exp
	}
	return s, nil
}

func newID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return "SUP-" + strings.ToUpper(hex.EncodeToString(b))
}

// Store persists suppressions.
type Store interface {
	List(ctx context.Context) ([]Suppression, error)
	Create(ctx context.Context, s Suppression) error
	Delete(ctx context.Context, id string) error
}

// Service checks events against the cached suppressions and manages them.
type Service struct {
	store Store
	now   func() time.Time

	mu   sync.RWMutex
	list []Suppression // newest first; Hits/LastHit live here
}

// NewService loads the stored suppressions.
func NewService(ctx context.Context, st Store) (*Service, error) {
	list, err := st.List(ctx)
	if err != nil {
		return nil, err
	}
	slices.SortFunc(list, func(a, b Suppression) int { return b.CreatedAt.Compare(a.CreatedAt) })
	return &Service{store: st, now: time.Now, list: list}, nil
}

// Match returns the first active suppression covering ev and counts the hit.
func (s *Service) Match(ev models.ClassifiedEvent) (Suppression, bool) {
	s.mu.RLock()
	empty := len(s.list) == 0
	s.mu.RUnlock()
	if empty {
		return Suppression{}, false // the common case: no lock contention
	}
	now := s.now()
	entities := incident.EntitiesOf(ev)

	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.list {
		sup := &s.list[i]
		if !sup.Active(now) || !sup.Matches(ev, entities) {
			continue
		}
		sup.Hits++
		t := now.UTC()
		sup.LastHit = &t
		metrics.EventsSuppressedTotal.Inc()
		return *sup, true
	}
	return Suppression{}, false
}

// List returns every suppression, newest first, active and expired.
func (s *Service) List() []Suppression {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return slices.Clone(s.list)
}

// Create validates and stores a suppression.
func (s *Service) Create(ctx context.Context, actor string, n New) (Suppression, error) {
	now := s.now().UTC()
	sup, err := n.build(actor, now)
	if err != nil {
		return Suppression{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	active := 0
	for _, x := range s.list {
		if x.Active(now) {
			active++
		}
	}
	if active >= MaxActive {
		return Suppression{}, invalid(fmt.Sprintf("at most %d active suppressions; lift some first", MaxActive))
	}
	if err := s.store.Create(ctx, sup); err != nil {
		return Suppression{}, err
	}
	s.list = append([]Suppression{sup}, s.list...)
	return sup, nil
}

// Lift deletes a suppression; matching events alert again at once.
func (s *Service) Lift(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := slices.IndexFunc(s.list, func(x Suppression) bool { return x.ID == id })
	if idx < 0 {
		return ErrNotFound
	}
	if err := s.store.Delete(ctx, id); err != nil {
		return err
	}
	s.list = slices.Delete(s.list, idx, idx+1)
	return nil
}

// Memory is the in-memory Store used without a database.
type Memory struct {
	mu   sync.Mutex
	byID map[string]Suppression
}

// NewMemory returns an empty in-memory store.
func NewMemory() *Memory { return &Memory{byID: map[string]Suppression{}} }

func (m *Memory) List(context.Context) ([]Suppression, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Suppression, 0, len(m.byID))
	for _, s := range m.byID {
		out = append(out, s)
	}
	return out, nil
}

func (m *Memory) Create(_ context.Context, s Suppression) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.byID[s.ID] = s
	return nil
}

func (m *Memory) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.byID[id]; !ok {
		return ErrNotFound
	}
	delete(m.byID, id)
	return nil
}
