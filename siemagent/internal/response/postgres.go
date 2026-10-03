package response

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/chverma/siemagent/internal/migrate"
)

// Postgres stores response actions.
type Postgres struct {
	pool *pgxpool.Pool
}

// NewPostgres migrates the database and returns the store.
func NewPostgres(ctx context.Context, pool *pgxpool.Pool) (*Postgres, error) {
	if _, err := migrate.Up(ctx, pool); err != nil {
		return nil, fmt.Errorf("response schema: %w", err)
	}
	return &Postgres{pool: pool}, nil
}

func (p *Postgres) Create(ctx context.Context, a Action) (bool, error) {
	data, err := json.Marshal(a)
	if err != nil {
		return false, fmt.Errorf("encode action: %w", err)
	}
	tag, err := p.pool.Exec(ctx, `
		INSERT INTO response_actions (id, dedup_key, incident_id, status, proposed_at, data)
		VALUES ($1, $2, $3, $4, $5, $6::jsonb)
		ON CONFLICT (dedup_key) DO NOTHING`,
		a.ID, a.DedupKey, a.IncidentID, string(a.Status), a.ProposedAt, string(data))
	if err != nil {
		return false, fmt.Errorf("insert action: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

func (p *Postgres) Get(ctx context.Context, id string) (Action, error) {
	var data []byte
	var key string
	err := p.pool.QueryRow(ctx, `SELECT data, dedup_key FROM response_actions WHERE id = $1`, id).Scan(&data, &key)
	if errors.Is(err, pgx.ErrNoRows) {
		return Action{}, ErrNotFound
	}
	if err != nil {
		return Action{}, fmt.Errorf("get action: %w", err)
	}
	var a Action
	if err := json.Unmarshal(data, &a); err != nil {
		return Action{}, fmt.Errorf("decode action: %w", err)
	}
	a.DedupKey = key
	return a, nil
}

func (p *Postgres) Update(ctx context.Context, a Action) error {
	data, err := json.Marshal(a)
	if err != nil {
		return fmt.Errorf("encode action: %w", err)
	}
	tag, err := p.pool.Exec(ctx, `UPDATE response_actions SET status = $2, data = $3::jsonb WHERE id = $1`,
		a.ID, string(a.Status), string(data))
	if err != nil {
		return fmt.Errorf("update action: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (p *Postgres) List(ctx context.Context, f Filter) ([]Action, error) {
	var where []string
	var args []any
	if f.Status != "" {
		args = append(args, string(f.Status))
		where = append(where, fmt.Sprintf("status = $%d", len(args)))
	}
	if f.IncidentID != "" {
		args = append(args, f.IncidentID)
		where = append(where, fmt.Sprintf("incident_id = $%d", len(args)))
	}
	q := "SELECT data, dedup_key FROM response_actions"
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	limit := f.Limit
	if limit <= 0 {
		limit = 1000
	}
	args = append(args, limit)
	q += fmt.Sprintf(" ORDER BY proposed_at DESC, id DESC LIMIT $%d", len(args))
	rows, err := p.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list actions: %w", err)
	}
	defer rows.Close()
	out := []Action{}
	for rows.Next() {
		var data []byte
		var key string
		if err := rows.Scan(&data, &key); err != nil {
			return nil, fmt.Errorf("scan action: %w", err)
		}
		var a Action
		if err := json.Unmarshal(data, &a); err != nil {
			return nil, fmt.Errorf("decode action: %w", err)
		}
		a.DedupKey = key
		out = append(out, a)
	}
	return out, rows.Err()
}
