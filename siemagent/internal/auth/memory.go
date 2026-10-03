package auth

import (
	"context"
	"sort"
	"sync"
	"time"
)

// maxMemoryAudit bounds the in-memory audit log.
const maxMemoryAudit = 10_000

// Memory is the in-memory Store used without a database.
type Memory struct {
	mu       sync.RWMutex
	users    map[string]User
	sessions map[string]Session
	audit    []AuditEntry
	nextID   int64
}

func NewMemory() *Memory {
	return &Memory{users: map[string]User{}, sessions: map[string]Session{}}
}

func (m *Memory) CreateUser(_ context.Context, u User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, o := range m.users {
		if o.Username == u.Username {
			return invalid("username is already taken")
		}
	}
	m.users[u.ID] = u
	return nil
}

func (m *Memory) UpdateUser(_ context.Context, u User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.users[u.ID]; !ok {
		return ErrNotFound
	}
	m.users[u.ID] = u
	return nil
}

func (m *Memory) TouchLogin(_ context.Context, id string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[id]
	if !ok {
		return ErrNotFound
	}
	u.LastLoginAt = &at
	m.users[id] = u
	return nil
}

func (m *Memory) UserByID(_ context.Context, id string) (User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	u, ok := m.users[id]
	if !ok {
		return User{}, ErrNotFound
	}
	return u, nil
}

func (m *Memory) UserByName(_ context.Context, name string) (User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, u := range m.users {
		if u.Username == name {
			return u, nil
		}
	}
	return User{}, ErrNotFound
}

func (m *Memory) ListUsers(_ context.Context) ([]User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]User, 0, len(m.users))
	for _, u := range m.users {
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out, nil
}

func (m *Memory) CountUsers(_ context.Context) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.users), nil
}

func (m *Memory) CreateSession(_ context.Context, s Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[s.TokenHash] = s
	return nil
}

func (m *Memory) SessionUser(_ context.Context, tokenHash string, now time.Time) (User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[tokenHash]
	if !ok {
		return User{}, ErrNotFound
	}
	if !now.Before(s.ExpiresAt) {
		delete(m.sessions, tokenHash)
		return User{}, ErrNotFound
	}
	u, ok := m.users[s.UserID]
	if !ok {
		return User{}, ErrNotFound
	}
	return u, nil
}

func (m *Memory) DeleteSession(_ context.Context, tokenHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, tokenHash)
	return nil
}

func (m *Memory) DeleteUserSessions(_ context.Context, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, s := range m.sessions {
		if s.UserID == userID {
			delete(m.sessions, k)
		}
	}
	return nil
}

func (m *Memory) AddAudit(_ context.Context, e AuditEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextID++
	e.ID = m.nextID
	m.audit = append(m.audit, e)
	if len(m.audit) > maxMemoryAudit {
		m.audit = m.audit[len(m.audit)-maxMemoryAudit:]
	}
	return nil
}

func (m *Memory) ListAudit(_ context.Context, f AuditFilter) ([]AuditEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := []AuditEntry{}
	for i := len(m.audit) - 1; i >= 0; i-- {
		e := m.audit[i]
		if f.Actor != "" && e.Actor != f.Actor {
			continue
		}
		out = append(out, e)
		if f.Limit > 0 && len(out) >= f.Limit {
			break
		}
	}
	return out, nil
}
