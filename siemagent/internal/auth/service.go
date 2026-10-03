package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/chverma/siemagent/internal/metrics"
)

const (
	// DefaultSessionTTL is how long a login lasts.
	DefaultSessionTTL = 12 * time.Hour
	// Lockout: this many failures for one username within the window block
	// further attempts for that username until the window passes.
	maxFailures   = 5
	failureWindow = 15 * time.Minute
)

// Service is the entry point for accounts, sessions and auditing.
type Service struct {
	store      Store
	now        func() time.Time
	cost       int // bcrypt cost; lowered in tests
	sessionTTL time.Duration
	hasUsers   atomic.Bool
	// mu serialises user changes so the last-admin check cannot race.
	mu       sync.Mutex
	failures *failureTracker
	// dummyHash is compared against when a username doesn't exist, so a
	// failed login takes as long either way. Built on first use.
	dummyOnce sync.Once
	dummyHash []byte
}

// NewService builds the service and notes whether any account exists.
func NewService(ctx context.Context, store Store, sessionTTL time.Duration) (*Service, error) {
	if sessionTTL <= 0 {
		sessionTTL = DefaultSessionTTL
	}
	s := &Service{
		store: store, now: time.Now, cost: bcrypt.DefaultCost + 2, sessionTTL: sessionTTL,
		failures: newFailureTracker(),
	}
	n, err := store.CountUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("count users: %w", err)
	}
	s.hasUsers.Store(n > 0)
	return s, nil
}

// UsersEnabled reports whether any account exists, which makes login
// required for the dashboard. Accounts are never deleted, only disabled.
func (s *Service) UsersEnabled() bool { return s.hasUsers.Load() }

// Bootstrap creates the first admin when no account exists yet. It is a
// no-op once any user exists, so the variables can stay set safely.
func (s *Service) Bootstrap(ctx context.Context, username, password string) (bool, error) {
	if username == "" && password == "" {
		return false, nil
	}
	n, err := s.store.CountUsers(ctx)
	if err != nil {
		return false, err
	}
	if n > 0 {
		return false, nil
	}
	if _, err := s.CreateUser(ctx, "bootstrap", NewUser{Username: username, Password: password, Role: RoleAdmin}); err != nil {
		return false, err
	}
	return true, nil
}

// NewUser is the input for CreateUser.
type NewUser struct {
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	Password    string `json:"password"`
	Role        Role   `json:"role"`
}

// CreateUser adds an account.
func (s *Service) CreateUser(ctx context.Context, actor string, in NewUser) (User, error) {
	name, err := NormalizeUsername(in.Username)
	if err != nil {
		return User{}, err
	}
	role, err := ParseRole(string(in.Role))
	if err != nil {
		return User{}, err
	}
	if err := validatePassword(in.Password); err != nil {
		return User{}, err
	}
	if len(in.DisplayName) > 100 {
		return User{}, invalid("display name is too long")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(in.Password), s.cost)
	if err != nil {
		return User{}, fmt.Errorf("hash password: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.store.UserByName(ctx, name); err == nil {
		return User{}, invalid("username is already taken")
	} else if !errors.Is(err, ErrNotFound) {
		return User{}, err
	}
	u := User{
		ID: "usr_" + randomHex(8), Username: name, DisplayName: strings.TrimSpace(in.DisplayName),
		Role: role, CreatedAt: s.now().UTC(), PasswordHash: hash,
	}
	if err := s.store.CreateUser(ctx, u); err != nil {
		return User{}, err
	}
	s.hasUsers.Store(true)
	s.audit(ctx, AuditEntry{Actor: actor, Action: "user.create", Target: name + " (" + string(role) + ")"})
	return u, nil
}

// UserUpdate changes an account. Nil fields are left as they are.
type UserUpdate struct {
	DisplayName *string `json:"display_name"`
	Role        *Role   `json:"role"`
	Disabled    *bool   `json:"disabled"`
	Password    *string `json:"password"` // admin reset
}

// UpdateUser applies an admin's change. The last enabled admin cannot be
// demoted or disabled, so the deployment can't lock itself out. Disabling
// an account or resetting its password ends its sessions.
func (s *Service) UpdateUser(ctx context.Context, actor, id string, up UserUpdate) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, err := s.store.UserByID(ctx, id)
	if err != nil {
		return User{}, err
	}
	var changes []string
	endSessions := false
	if up.DisplayName != nil {
		if len(*up.DisplayName) > 100 {
			return User{}, invalid("display name is too long")
		}
		u.DisplayName = strings.TrimSpace(*up.DisplayName)
		changes = append(changes, "display name")
	}
	losingAdmin := false
	if up.Role != nil {
		role, err := ParseRole(string(*up.Role))
		if err != nil {
			return User{}, err
		}
		if u.Role == RoleAdmin && role != RoleAdmin {
			losingAdmin = true
		}
		if role != u.Role {
			changes = append(changes, fmt.Sprintf("role %s→%s", u.Role, role))
		}
		u.Role = role
	}
	if up.Disabled != nil && *up.Disabled != u.Disabled {
		if *up.Disabled && u.Role == RoleAdmin {
			losingAdmin = true
		}
		u.Disabled = *up.Disabled
		endSessions = endSessions || u.Disabled
		if u.Disabled {
			changes = append(changes, "disabled")
		} else {
			changes = append(changes, "enabled")
		}
	}
	if up.Password != nil {
		if err := validatePassword(*up.Password); err != nil {
			return User{}, err
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(*up.Password), s.cost)
		if err != nil {
			return User{}, fmt.Errorf("hash password: %w", err)
		}
		u.PasswordHash = hash
		endSessions = true
		changes = append(changes, "password reset")
	}
	if losingAdmin {
		if err := s.ensureAnotherAdmin(ctx, u.ID); err != nil {
			return User{}, err
		}
	}
	if len(changes) == 0 {
		return u, nil
	}
	if err := s.store.UpdateUser(ctx, u); err != nil {
		return User{}, err
	}
	if endSessions {
		if err := s.store.DeleteUserSessions(ctx, u.ID); err != nil {
			return User{}, err
		}
	}
	s.audit(ctx, AuditEntry{Actor: actor, Action: "user.update", Target: u.Username + ": " + strings.Join(changes, ", ")})
	return u, nil
}

func (s *Service) ensureAnotherAdmin(ctx context.Context, exceptID string) error {
	users, err := s.store.ListUsers(ctx)
	if err != nil {
		return err
	}
	for _, o := range users {
		if o.ID != exceptID && o.Role == RoleAdmin && !o.Disabled {
			return nil
		}
	}
	return invalid("this is the last active admin; make another user admin first")
}

// ChangePassword lets a user change their own password.
func (s *Service) ChangePassword(ctx context.Context, userID, current, next string) error {
	if err := validatePassword(next); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	u, err := s.store.UserByID(ctx, userID)
	if err != nil {
		return err
	}
	if bcrypt.CompareHashAndPassword(u.PasswordHash, []byte(current)) != nil {
		return invalid("current password is wrong")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(next), s.cost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	u.PasswordHash = hash
	if err := s.store.UpdateUser(ctx, u); err != nil {
		return err
	}
	s.audit(ctx, AuditEntry{Actor: u.Username, Action: "user.password", Target: u.Username})
	return nil
}

// Login checks credentials and starts a session. It returns the session
// token (to put in a cookie) and the user.
func (s *Service) Login(ctx context.Context, username, password, ip string) (string, User, error) {
	name := strings.ToLower(strings.TrimSpace(username))
	now := s.now()
	if s.failures.locked(name, now) {
		metrics.AuthLoginsTotal.WithLabelValues("locked").Inc()
		s.audit(ctx, AuditEntry{Actor: name, Action: "login.locked", IP: ip})
		return "", User{}, ErrLocked
	}
	u, err := s.store.UserByName(ctx, name)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return "", User{}, err
	}
	s.dummyOnce.Do(func() { s.dummyHash, _ = bcrypt.GenerateFromPassword([]byte(randomHex(16)), s.cost) })
	hash := s.dummyHash
	if err == nil {
		hash = u.PasswordHash
	}
	ok := bcrypt.CompareHashAndPassword(hash, []byte(password)) == nil
	if err != nil || !ok || u.Disabled {
		s.failures.add(name, now)
		metrics.AuthLoginsTotal.WithLabelValues("failed").Inc()
		s.audit(ctx, AuditEntry{Actor: name, Action: "login.failed", IP: ip})
		return "", User{}, ErrBadCredentials
	}
	s.failures.reset(name)

	token := randomHex(32)
	sess := Session{TokenHash: HashToken(token), UserID: u.ID, CreatedAt: now.UTC(), ExpiresAt: now.Add(s.sessionTTL).UTC()}
	if err := s.store.CreateSession(ctx, sess); err != nil {
		return "", User{}, err
	}
	t := now.UTC()
	u.LastLoginAt = &t
	if err := s.store.TouchLogin(ctx, u.ID, t); err != nil {
		slog.Warn("record last login failed", "component", "auth", "error", err)
	}
	metrics.AuthLoginsTotal.WithLabelValues("success").Inc()
	s.audit(ctx, AuditEntry{Actor: u.Username, Action: "login", IP: ip})
	return token, u, nil
}

// SessionTTL is how long a new session lasts.
func (s *Service) SessionTTL() time.Duration { return s.sessionTTL }

// Authenticate returns the active user for a session token.
func (s *Service) Authenticate(ctx context.Context, token string) (User, error) {
	if token == "" {
		return User{}, ErrNotFound
	}
	u, err := s.store.SessionUser(ctx, HashToken(token), s.now())
	if err != nil {
		return User{}, err
	}
	if u.Disabled {
		return User{}, ErrNotFound
	}
	return u, nil
}

// Logout ends a session.
func (s *Service) Logout(ctx context.Context, token, actor string) error {
	if err := s.store.DeleteSession(ctx, HashToken(token)); err != nil {
		return err
	}
	s.audit(ctx, AuditEntry{Actor: actor, Action: "logout"})
	return nil
}

// Audit records an entry, logging (not failing) if the store is down: an
// audit write must never break the action it describes.
func (s *Service) Audit(ctx context.Context, e AuditEntry) { s.audit(ctx, e) }

func (s *Service) audit(ctx context.Context, e AuditEntry) {
	if e.At.IsZero() {
		e.At = s.now().UTC()
	}
	if err := s.store.AddAudit(ctx, e); err != nil {
		// e's fields can carry request data, so only the error is logged.
		slog.Error("audit write failed", "component", "auth", "error", err)
	}
}

func (s *Service) ListAudit(ctx context.Context, f AuditFilter) ([]AuditEntry, error) {
	return s.store.ListAudit(ctx, f)
}

func (s *Service) ListUsers(ctx context.Context) ([]User, error) { return s.store.ListUsers(ctx) }

// failureTracker counts recent failed logins per username, in memory.
type failureTracker struct {
	mu    sync.Mutex
	fails map[string][]time.Time
}

func newFailureTracker() *failureTracker { return &failureTracker{fails: map[string][]time.Time{}} }

func (f *failureTracker) recent(name string, now time.Time) []time.Time {
	var keep []time.Time
	for _, t := range f.fails[name] {
		if now.Sub(t) < failureWindow {
			keep = append(keep, t)
		}
	}
	if len(keep) == 0 {
		delete(f.fails, name)
	} else {
		f.fails[name] = keep
	}
	return keep
}

func (f *failureTracker) locked(name string, now time.Time) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.recent(name, now)) >= maxFailures
}

func (f *failureTracker) add(name string, now time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	// Bound memory against username sprays: keep at most maxFailures per name
	// and drop the table if it grows huge.
	if len(f.fails) > 100_000 {
		f.fails = map[string][]time.Time{}
	}
	f.fails[name] = append(f.recent(name, now), now)
	if n := len(f.fails[name]); n > maxFailures {
		f.fails[name] = f.fails[name][n-maxFailures:]
	}
}

func (f *failureTracker) reset(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.fails, name)
}

// SetHashCost changes the bcrypt cost for new hashes. Production keeps the
// default; tests lower it so they run quickly.
func (s *Service) SetHashCost(cost int) { s.cost = cost }
