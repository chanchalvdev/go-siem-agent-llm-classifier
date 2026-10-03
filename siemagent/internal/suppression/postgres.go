package suppression

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/chverma/siemagent/internal/migrate"
)

// Postgres stores suppressions in the suppressions table.
type Postgres struct {
	pool *pgxpool.Pool
}

// NewPostgres migrates the database and returns the store.
func NewPostgres(ctx context.Context, pool *pgxpool.Pool) (*Postgres, error) {
	if _, err := migrate.Up(ctx, pool); err != nil {
		return nil, fmt.Errorf("suppression schema: %w", err)
	}
	return &Postgres{pool: pool}, nil
}

func (p *Postgres) List(ctx context.Context) ([]Suppression, error) {
	rows, err := p.pool.Query(ctx, `SELECT data FROM suppressions ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list suppressions: %w", err)
	}
	defer rows.Close()
	out := []Suppression{}
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			return nil, fmt.Errorf("scan suppression: %w", err)
		}
		var s Suppression
		if err := json.Unmarshal(data, &s); err != nil {
			return nil, fmt.Errorf("decode suppression: %w", err)
		}
		s.Hits, s.LastHit = 0, nil // counted per process
		out = append(out, s)
	}
	return out, rows.Err()
}

func (p *Postgres) Create(ctx context.Context, s Suppression) error {
	s.Hits, s.LastHit = 0, nil
	data, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("encode suppression: %w", err)
	}
	if _, err := p.pool.Exec(ctx, `INSERT INTO suppressions (id, created_at, expires_at, data) VALUES ($1, $2, $3, $4::jsonb)`,
		s.ID, s.CreatedAt, s.ExpiresAt, string(data)); err != nil {
		return fmt.Errorf("insert suppression: %w", err)
	}
	return nil
}

func (p *Postgres) Delete(ctx context.Context, id string) error {
	tag, err := p.pool.Exec(ctx, `DELETE FROM suppressions WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete suppression: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
