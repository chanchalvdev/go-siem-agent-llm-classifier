package retention

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// batchSize bounds each DELETE so a large purge never holds long locks or
// one huge transaction.
const batchSize = 5000

// Postgres purges the platform's tables.
type Postgres struct {
	pool  *pgxpool.Pool
	batch int
}

// NewPostgres returns a Purger for the database behind pool.
func NewPostgres(pool *pgxpool.Pool) *Postgres { return &Postgres{pool: pool, batch: batchSize} }

// Purge implements Purger.
func (p *Postgres) Purge(ctx context.Context, kind Kind, cutoff time.Time) (int64, error) {
	switch kind {
	case Events:
		return p.batched(ctx, `DELETE FROM events WHERE id IN (
			SELECT id FROM events WHERE processed_at < $1 LIMIT $2)`, cutoff)
	case Audit:
		return p.batched(ctx, `DELETE FROM audit_log WHERE id IN (
			SELECT id FROM audit_log WHERE at < $1 LIMIT $2)`, cutoff)
	case Incidents:
		// Alerts, entities and history go with the incident (ON DELETE CASCADE).
		n, err := p.batched(ctx, `DELETE FROM incidents WHERE id IN (
			SELECT id FROM incidents WHERE status = 'resolved' AND resolved_at < $1 LIMIT $2)`, cutoff)
		if err != nil {
			return n, err
		}
		// Response actions reference incidents without a foreign key; remove
		// the ones whose incident is gone. The cutoff keeps an action that
		// was just proposed for an incident still being written.
		if _, err := p.pool.Exec(ctx, `DELETE FROM response_actions a WHERE a.proposed_at < $1
			AND NOT EXISTS (SELECT 1 FROM incidents i WHERE i.id = a.incident_id)`, cutoff); err != nil {
			return n, fmt.Errorf("purge response actions: %w", err)
		}
		return n, nil
	case Sessions:
		tag, err := p.pool.Exec(ctx, `DELETE FROM sessions WHERE expires_at < $1`, cutoff)
		if err != nil {
			return 0, fmt.Errorf("purge sessions: %w", err)
		}
		return tag.RowsAffected(), nil
	default:
		return 0, fmt.Errorf("retention: unknown kind %q", kind)
	}
}

func (p *Postgres) batched(ctx context.Context, sql string, cutoff time.Time) (int64, error) {
	var total int64
	for {
		tag, err := p.pool.Exec(ctx, sql, cutoff, p.batch)
		if err != nil {
			return total, fmt.Errorf("purge: %w", err)
		}
		total += tag.RowsAffected()
		if tag.RowsAffected() < int64(p.batch) || ctx.Err() != nil {
			return total, ctx.Err()
		}
	}
}
