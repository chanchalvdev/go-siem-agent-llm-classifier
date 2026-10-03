package store

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/chverma/siemagent/internal/models"
)

//go:embed schema.sql
var schemaSQL string

// Postgres stores every classified event durably. The full event is kept as
// JSONB; the columns analytics filter and group on are stored alongside it.
type Postgres struct {
	pool *pgxpool.Pool
}

// OpenPostgres connects, verifies the connection and applies the schema.
func OpenPostgres(ctx context.Context, dsn string) (*Postgres, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("postgres config: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres connect: %w", err)
	}
	if _, err := pool.Exec(ctx, schemaSQL); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres schema: %w", err)
	}
	return &Postgres{pool: pool}, nil
}

func (p *Postgres) Close() { p.pool.Close() }

// Pool exposes the connection pool so other packages (incidents) can keep
// their tables in the same database.
func (p *Postgres) Pool() *pgxpool.Pool { return p.pool }

func (p *Postgres) Ping(ctx context.Context) error { return p.pool.Ping(ctx) }

func (p *Postgres) Add(ctx context.Context, ev models.ClassifiedEvent) error {
	data, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("encode event: %w", err)
	}
	processedAt := ev.ProcessedAt
	if processedAt.IsZero() {
		processedAt = time.Now().UTC()
	}
	_, err = p.pool.Exec(ctx, `
		INSERT INTO events (processed_at, severity, attack_type, mitre_tactic, hostname, source, data)
		VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)`,
		processedAt, string(ev.Severity), ev.AttackType, ev.MITRE.Tactic,
		ev.Event.Hostname, ev.Event.Source, string(data))
	if err != nil {
		return fmt.Errorf("insert event: %w", err)
	}
	return nil
}

func (p *Postgres) Recent(ctx context.Context, limit int) ([]models.ClassifiedEvent, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT data FROM events ORDER BY processed_at DESC, id DESC LIMIT $1`, max(limit, 0))
	if err != nil {
		return nil, fmt.Errorf("query events: %w", err)
	}
	defer rows.Close()

	out := []models.ClassifiedEvent{}
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			return nil, fmt.Errorf("scan event: %w", err)
		}
		var ev models.ClassifiedEvent
		if err := json.Unmarshal(data, &ev); err != nil {
			return nil, fmt.Errorf("decode event: %w", err)
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}

// Summary aggregates in SQL so it covers every stored event, not a window.
func (p *Postgres) Summary(ctx context.Context) (AnalyticsSummary, error) {
	b := newSummaryBuilder(time.Now())

	if err := p.pool.QueryRow(ctx, `SELECT count(*) FROM events`).Scan(&b.sum.TotalEvents); err != nil {
		return AnalyticsSummary{}, fmt.Errorf("count events: %w", err)
	}

	// Severity strings sort P1 < P5, so min() is the highest severity.
	if err := p.each(ctx, func(attackType, sev string, n int) { b.addAttack(attackType, sev, n) },
		`SELECT attack_type, min(severity), count(*) FROM events GROUP BY attack_type`); err != nil {
		return AnalyticsSummary{}, err
	}

	if err := p.each(ctx, func(tactic, _ string, n int) { b.addTactic(tactic, n) },
		`SELECT mitre_tactic, '', count(*) FROM events GROUP BY mitre_tactic`); err != nil {
		return AnalyticsSummary{}, err
	}

	rows, err := p.pool.Query(ctx, `
		SELECT floor(extract(epoch FROM processed_at - $1) / $2)::int, severity, count(*)
		FROM events
		WHERE processed_at > $1 AND severity IN ('P1', 'P2', 'P3')
		GROUP BY 1, 2`, b.cutoff, bucketWidth.Seconds())
	if err != nil {
		return AnalyticsSummary{}, fmt.Errorf("timeline: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var idx, n int
		var sev string
		if err := rows.Scan(&idx, &sev, &n); err != nil {
			return AnalyticsSummary{}, fmt.Errorf("scan timeline: %w", err)
		}
		b.addTimelineBucket(idx, sev, n)
	}
	if err := rows.Err(); err != nil {
		return AnalyticsSummary{}, fmt.Errorf("timeline: %w", err)
	}
	return b.sum, nil
}

// each runs a (text, text, count) aggregate query and feeds every row to fn.
func (p *Postgres) each(ctx context.Context, fn func(a, b string, n int), query string) error {
	rows, err := p.pool.Query(ctx, query)
	if err != nil {
		return fmt.Errorf("aggregate: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var a, b string
		var n int
		if err := rows.Scan(&a, &b, &n); err != nil {
			return fmt.Errorf("scan aggregate: %w", err)
		}
		fn(a, b, n)
	}
	return rows.Err()
}
