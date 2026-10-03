package store

import (
	"context"
	"fmt"
	"sync"
)

// RuleStates persists analyst overrides of detection rules (enabled or
// disabled), so tuning survives restarts. Rules without a stored state use
// their default (enabled).
type RuleStates interface {
	RuleStates(ctx context.Context) (map[string]bool, error)
	SetRuleEnabled(ctx context.Context, ruleID string, enabled bool) error
}

// memoryRuleStates is the in-memory RuleStates used without a database.
type memoryRuleStates struct {
	mu     sync.RWMutex
	states map[string]bool
}

func (m *memoryRuleStates) RuleStates(context.Context) (map[string]bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string]bool, len(m.states))
	for k, v := range m.states {
		out[k] = v
	}
	return out, nil
}

func (m *memoryRuleStates) SetRuleEnabled(_ context.Context, ruleID string, enabled bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.states == nil {
		m.states = map[string]bool{}
	}
	m.states[ruleID] = enabled
	return nil
}

func (p *Postgres) RuleStates(ctx context.Context) (map[string]bool, error) {
	rows, err := p.pool.Query(ctx, `SELECT rule_id, enabled FROM rule_states`)
	if err != nil {
		return nil, fmt.Errorf("query rule states: %w", err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		var enabled bool
		if err := rows.Scan(&id, &enabled); err != nil {
			return nil, fmt.Errorf("scan rule state: %w", err)
		}
		out[id] = enabled
	}
	return out, rows.Err()
}

func (p *Postgres) SetRuleEnabled(ctx context.Context, ruleID string, enabled bool) error {
	_, err := p.pool.Exec(ctx, `
		INSERT INTO rule_states (rule_id, enabled, updated_at) VALUES ($1, $2, now())
		ON CONFLICT (rule_id) DO UPDATE SET enabled = EXCLUDED.enabled, updated_at = now()`,
		ruleID, enabled)
	if err != nil {
		return fmt.Errorf("save rule state: %w", err)
	}
	return nil
}
