package auth

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed schema.sql
var schemaSQL string

// Postgres stores users, sessions and the audit log.
type Postgres struct {
	pool *pgxpool.Pool
}

// NewPostgres applies the schema and returns the store.
func NewPostgres(ctx context.Context, pool *pgxpool.Pool) (*Postgres, error) {
	if _, err := pool.Exec(ctx, schemaSQL); err != nil {
		return nil, fmt.Errorf("auth schema: %w", err)
	}
	return &Postgres{pool: pool}, nil
}

const userCols = `id, username, display_name, role, disabled, password_hash, created_at, last_login_at`

func scanUser(row pgx.Row) (User, error) {
	var u User
	var role string
	err := row.Scan(&u.ID, &u.Username, &u.DisplayName, &role, &u.Disabled, &u.PasswordHash, &u.CreatedAt, &u.LastLoginAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("scan user: %w", err)
	}
	u.Role = Role(role)
	return u, nil
}

func (p *Postgres) CreateUser(ctx context.Context, u User) error {
	_, err := p.pool.Exec(ctx, `INSERT INTO users (`+userCols+`) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		u.ID, u.Username, u.DisplayName, string(u.Role), u.Disabled, u.PasswordHash, u.CreatedAt, u.LastLoginAt)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return invalid("username is already taken")
	}
	if err != nil {
		return fmt.Errorf("insert user: %w", err)
	}
	return nil
}

func (p *Postgres) UpdateUser(ctx context.Context, u User) error {
	tag, err := p.pool.Exec(ctx, `
		UPDATE users SET display_name = $2, role = $3, disabled = $4, password_hash = $5
		WHERE id = $1`, u.ID, u.DisplayName, string(u.Role), u.Disabled, u.PasswordHash)
	if err != nil {
		return fmt.Errorf("update user: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (p *Postgres) TouchLogin(ctx context.Context, id string, at time.Time) error {
	if _, err := p.pool.Exec(ctx, `UPDATE users SET last_login_at = $2 WHERE id = $1`, id, at); err != nil {
		return fmt.Errorf("touch login: %w", err)
	}
	return nil
}

func (p *Postgres) UserByID(ctx context.Context, id string) (User, error) {
	return scanUser(p.pool.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE id = $1`, id))
}

func (p *Postgres) UserByName(ctx context.Context, name string) (User, error) {
	return scanUser(p.pool.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE username = $1`, name))
}

func (p *Postgres) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+userCols+` FROM users ORDER BY username`)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()
	out := []User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (p *Postgres) CountUsers(ctx context.Context) (int, error) {
	var n int
	if err := p.pool.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&n); err != nil {
		return 0, fmt.Errorf("count users: %w", err)
	}
	return n, nil
}

func (p *Postgres) CreateSession(ctx context.Context, s Session) error {
	// Opportunistic cleanup keeps the table from growing without a cron job.
	if _, err := p.pool.Exec(ctx, `DELETE FROM sessions WHERE expires_at < $1`, s.CreatedAt); err != nil {
		return fmt.Errorf("expire sessions: %w", err)
	}
	if _, err := p.pool.Exec(ctx, `INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES ($1, $2, $3, $4)`,
		s.TokenHash, s.UserID, s.CreatedAt, s.ExpiresAt); err != nil {
		return fmt.Errorf("insert session: %w", err)
	}
	return nil
}

func (p *Postgres) SessionUser(ctx context.Context, tokenHash string, now time.Time) (User, error) {
	return scanUser(p.pool.QueryRow(ctx, `
		SELECT u.id, u.username, u.display_name, u.role, u.disabled, u.password_hash, u.created_at, u.last_login_at
		FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.token_hash = $1 AND s.expires_at > $2`, tokenHash, now))
}

func (p *Postgres) DeleteSession(ctx context.Context, tokenHash string) error {
	if _, err := p.pool.Exec(ctx, `DELETE FROM sessions WHERE token_hash = $1`, tokenHash); err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}

func (p *Postgres) DeleteUserSessions(ctx context.Context, userID string) error {
	if _, err := p.pool.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1`, userID); err != nil {
		return fmt.Errorf("delete sessions: %w", err)
	}
	return nil
}

func (p *Postgres) AddAudit(ctx context.Context, e AuditEntry) error {
	if _, err := p.pool.Exec(ctx, `INSERT INTO audit_log (at, actor, action, target, status, ip) VALUES ($1, $2, $3, $4, $5, $6)`,
		e.At, e.Actor, e.Action, e.Target, e.Status, e.IP); err != nil {
		return fmt.Errorf("insert audit: %w", err)
	}
	return nil
}

func (p *Postgres) ListAudit(ctx context.Context, f AuditFilter) ([]AuditEntry, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 1000
	}
	q := `SELECT id, at, actor, action, target, status, ip FROM audit_log`
	args := []any{}
	if f.Actor != "" {
		args = append(args, f.Actor)
		q += ` WHERE actor = $1`
	}
	args = append(args, limit)
	q += fmt.Sprintf(` ORDER BY at DESC, id DESC LIMIT $%d`, len(args))
	rows, err := p.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list audit: %w", err)
	}
	defer rows.Close()
	out := []AuditEntry{}
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.At, &e.Actor, &e.Action, &e.Target, &e.Status, &e.IP); err != nil {
			return nil, fmt.Errorf("scan audit: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
