// Package auth manages user accounts, login sessions, roles and the audit log.
//
// Three roles cover a SOC team: viewers read everything, analysts also work
// incidents and approve response actions, admins also manage users, rules and
// read the audit log. Passwords are bcrypt hashes; sessions are random
// tokens stored only as SHA-256 hashes, so a database leak exposes neither.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

// Role is a user's permission level.
type Role string

const (
	RoleViewer  Role = "viewer"
	RoleAnalyst Role = "analyst"
	RoleAdmin   Role = "admin"
)

// Permission is what a route requires.
type Permission int

const (
	// PermRead views events, incidents, rules and actions.
	PermRead Permission = iota
	// PermWrite classifies logs, works incidents and approves actions.
	PermWrite
	// PermAdmin manages users and detection rules and reads the audit log.
	PermAdmin
)

func (p Permission) String() string {
	return [...]string{"read", "write", "admin"}[p]
}

// Can reports whether the role grants the permission.
func (r Role) Can(p Permission) bool {
	switch r {
	case RoleAdmin:
		return true
	case RoleAnalyst:
		return p <= PermWrite
	case RoleViewer:
		return p == PermRead
	}
	return false
}

// ParseRole validates a role name.
func ParseRole(s string) (Role, error) {
	switch Role(s) {
	case RoleViewer, RoleAnalyst, RoleAdmin:
		return Role(s), nil
	}
	return "", invalid("role must be viewer, analyst or admin")
}

// User is an account. The password hash never leaves this package's stores.
type User struct {
	ID           string     `json:"id"`
	Username     string     `json:"username"`
	DisplayName  string     `json:"display_name,omitempty"`
	Role         Role       `json:"role"`
	Disabled     bool       `json:"disabled"`
	CreatedAt    time.Time  `json:"created_at"`
	LastLoginAt  *time.Time `json:"last_login_at,omitempty"`
	PasswordHash []byte     `json:"-"`
}

// Session is a login session. Only the token's hash is stored.
type Session struct {
	TokenHash string
	UserID    string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// AuditEntry is one record in the global audit log.
type AuditEntry struct {
	ID     int64     `json:"id,omitempty"`
	At     time.Time `json:"at"`
	Actor  string    `json:"actor"`
	Action string    `json:"action"` // e.g. "login", "POST /api/incidents/{id}/comments"
	Target string    `json:"target,omitempty"`
	Status int       `json:"status,omitempty"` // HTTP status for API calls
	IP     string    `json:"ip,omitempty"`
}

// AuditFilter narrows the audit log. Zero values match everything.
type AuditFilter struct {
	Actor string
	Limit int
}

var (
	ErrNotFound = errors.New("not found")
	ErrInvalid  = errors.New("invalid input")
	// ErrBadCredentials is returned for every failed login, whatever the
	// reason, so responses don't reveal which usernames exist.
	ErrBadCredentials = errors.New("invalid username or password")
	ErrLocked         = errors.New("too many failed logins; try again later")
)

func invalid(msg string) error { return fmt.Errorf("%w: %s", ErrInvalid, msg) }

var usernameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._@-]{1,62}$`)

// NormalizeUsername lower-cases and validates a username.
func NormalizeUsername(s string) (string, error) {
	u := strings.ToLower(strings.TrimSpace(s))
	if !usernameRE.MatchString(u) {
		return "", invalid("username must be 2–63 characters: letters, digits, . _ @ -")
	}
	return u, nil
}

// MinPasswordLength follows NIST SP 800-63B guidance for user-chosen secrets.
const MinPasswordLength = 12

func validatePassword(pw string) error {
	if utf8.RuneCountInString(pw) < MinPasswordLength {
		return invalid(fmt.Sprintf("password must be at least %d characters", MinPasswordLength))
	}
	// bcrypt ignores everything after 72 bytes.
	if len(pw) > 72 {
		return invalid("password must be at most 72 bytes")
	}
	return nil
}

// Store persists users, sessions and the audit log.
type Store interface {
	CreateUser(ctx context.Context, u User) error
	UpdateUser(ctx context.Context, u User) error
	// TouchLogin records a successful login without rewriting the account.
	TouchLogin(ctx context.Context, id string, at time.Time) error
	UserByID(ctx context.Context, id string) (User, error)
	UserByName(ctx context.Context, username string) (User, error)
	ListUsers(ctx context.Context) ([]User, error)
	CountUsers(ctx context.Context) (int, error)

	CreateSession(ctx context.Context, s Session) error
	// SessionUser returns the user of an unexpired session.
	SessionUser(ctx context.Context, tokenHash string, now time.Time) (User, error)
	DeleteSession(ctx context.Context, tokenHash string) error
	DeleteUserSessions(ctx context.Context, userID string) error

	AddAudit(ctx context.Context, e AuditEntry) error
	ListAudit(ctx context.Context, f AuditFilter) ([]AuditEntry, error)
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// HashToken returns the stored form of a session token.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
