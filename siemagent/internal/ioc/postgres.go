package ioc

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/chverma/siemagent/internal/migrate"
)

// Postgres stores watchlists and manual indicators.
type Postgres struct {
	pool *pgxpool.Pool
}

// NewPostgres migrates the database and returns the store.
func NewPostgres(ctx context.Context, pool *pgxpool.Pool) (*Postgres, error) {
	if _, err := migrate.Up(ctx, pool); err != nil {
		return nil, fmt.Errorf("watchlist schema: %w", err)
	}
	return &Postgres{pool: pool}, nil
}

func (p *Postgres) ListWatchlists(ctx context.Context) ([]Watchlist, error) {
	rows, err := p.pool.Query(ctx, `SELECT data FROM watchlists ORDER BY created_at`)
	if err != nil {
		return nil, fmt.Errorf("list watchlists: %w", err)
	}
	defer rows.Close()
	out := []Watchlist{}
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			return nil, fmt.Errorf("scan watchlist: %w", err)
		}
		var w Watchlist
		if err := json.Unmarshal(data, &w); err != nil {
			return nil, fmt.Errorf("decode watchlist: %w", err)
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

func (p *Postgres) SaveWatchlist(ctx context.Context, w Watchlist) error {
	data, err := json.Marshal(persisted(w))
	if err != nil {
		return fmt.Errorf("encode watchlist: %w", err)
	}
	if _, err := p.pool.Exec(ctx, `
		INSERT INTO watchlists (id, created_at, data) VALUES ($1, $2, $3::jsonb)
		ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data`, w.ID, w.CreatedAt, string(data)); err != nil {
		return fmt.Errorf("save watchlist: %w", err)
	}
	return nil
}

func (p *Postgres) DeleteWatchlist(ctx context.Context, id string) error {
	tag, err := p.pool.Exec(ctx, `DELETE FROM watchlists WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete watchlist: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (p *Postgres) Indicators(ctx context.Context, id string) ([]Indicator, error) {
	rows, err := p.pool.Query(ctx, `SELECT value, type, note, added_by FROM watchlist_indicators
		WHERE watchlist_id = $1 ORDER BY seq`, id)
	if err != nil {
		return nil, fmt.Errorf("list indicators: %w", err)
	}
	defer rows.Close()
	out := []Indicator{}
	for rows.Next() {
		var ind Indicator
		var typ string
		if err := rows.Scan(&ind.Value, &typ, &ind.Note, &ind.AddedBy); err != nil {
			return nil, fmt.Errorf("scan indicator: %w", err)
		}
		ind.Type = Type(typ)
		out = append(out, ind)
	}
	return out, rows.Err()
}

func (p *Postgres) AddIndicators(ctx context.Context, id string, inds []Indicator) error {
	batch := &pgx.Batch{}
	for _, ind := range inds {
		batch.Queue(`INSERT INTO watchlist_indicators (watchlist_id, value, type, note, added_by)
			VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING`, id, ind.Value, string(ind.Type), ind.Note, ind.AddedBy)
	}
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("add indicators: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := tx.SendBatch(ctx, batch).Close(); err != nil {
		return fmt.Errorf("add indicators: %w", err)
	}
	return tx.Commit(ctx)
}

func (p *Postgres) RemoveIndicator(ctx context.Context, id, value string) error {
	tag, err := p.pool.Exec(ctx, `DELETE FROM watchlist_indicators WHERE watchlist_id = $1 AND value = $2`, id, value)
	if err != nil {
		return fmt.Errorf("remove indicator: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: %s is not on the list", ErrNotFound, value)
	}
	return nil
}
