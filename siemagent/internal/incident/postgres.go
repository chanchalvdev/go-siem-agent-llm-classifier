package incident

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/chverma/siemagent/internal/migrate"
)

// Postgres stores incidents in the same database as events.
type Postgres struct {
	pool *pgxpool.Pool
}

// NewPostgres migrates the database and returns the store.
func NewPostgres(ctx context.Context, pool *pgxpool.Pool) (*Postgres, error) {
	if _, err := migrate.Up(ctx, pool); err != nil {
		return nil, fmt.Errorf("incident schema: %w", err)
	}
	return &Postgres{pool: pool}, nil
}

func (p *Postgres) FindOpen(ctx context.Context, entities []Entity, since time.Time) (*Incident, error) {
	if len(entities) == 0 {
		return nil, nil
	}
	kinds := make([]string, len(entities))
	values := make([]string, len(entities))
	for i, e := range entities {
		kinds[i], values[i] = e.Kind, e.Value
	}
	var data []byte
	err := p.pool.QueryRow(ctx, `
		SELECT i.data FROM incidents i
		WHERE i.status <> 'resolved' AND i.last_seen > $1
		  AND EXISTS (
		    SELECT 1 FROM incident_entities e
		    WHERE e.incident_id = i.id
		      AND (e.kind, e.value) IN (SELECT * FROM unnest($2::text[], $3::text[])))
		ORDER BY i.last_seen DESC
		LIMIT 1`, since, kinds, values).Scan(&data)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("find open incident: %w", err)
	}
	var inc Incident
	if err := json.Unmarshal(data, &inc); err != nil {
		return nil, fmt.Errorf("decode incident: %w", err)
	}
	return &inc, nil
}

func (p *Postgres) Save(ctx context.Context, inc Incident, alert *Alert, acts ...Activity) error {
	data, err := json.Marshal(inc)
	if err != nil {
		return fmt.Errorf("encode incident: %w", err)
	}
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	_, err = tx.Exec(ctx, `
		INSERT INTO incidents (id, title, severity, status, resolution, assignee, alert_count,
		                       first_seen, last_seen, created_at, updated_at, resolved_at, data)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13::jsonb)
		ON CONFLICT (id) DO UPDATE SET
		  title = EXCLUDED.title, severity = EXCLUDED.severity, status = EXCLUDED.status,
		  resolution = EXCLUDED.resolution, assignee = EXCLUDED.assignee,
		  alert_count = EXCLUDED.alert_count, last_seen = EXCLUDED.last_seen,
		  updated_at = EXCLUDED.updated_at, resolved_at = EXCLUDED.resolved_at, data = EXCLUDED.data`,
		inc.ID, inc.Title, string(inc.Severity), string(inc.Status), string(inc.Resolution), inc.Assignee,
		inc.AlertCount, inc.FirstSeen, inc.LastSeen, inc.CreatedAt, inc.UpdatedAt, inc.ResolvedAt, string(data))
	if err != nil {
		return fmt.Errorf("upsert incident: %w", err)
	}
	for _, e := range inc.Entities {
		if _, err := tx.Exec(ctx, `
			INSERT INTO incident_entities (incident_id, kind, value) VALUES ($1, $2, $3)
			ON CONFLICT DO NOTHING`, inc.ID, e.Kind, e.Value); err != nil {
			return fmt.Errorf("save entity: %w", err)
		}
	}
	if alert != nil {
		a := *alert
		a.IncidentID = inc.ID
		ad, err := json.Marshal(a)
		if err != nil {
			return fmt.Errorf("encode alert: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO incident_alerts (incident_id, at, data)
			SELECT $1, $2, $3::jsonb
			WHERE (SELECT count(*) FROM incident_alerts WHERE incident_id = $1) < $4`,
			inc.ID, a.At, string(ad), maxStoredAlerts); err != nil {
			return fmt.Errorf("save alert: %w", err)
		}
	}
	for _, act := range acts {
		if _, err := tx.Exec(ctx, `
			INSERT INTO incident_activity (incident_id, at, actor, kind, body) VALUES ($1, $2, $3, $4, $5)`,
			inc.ID, act.At, act.Actor, act.Kind, act.Body); err != nil {
			return fmt.Errorf("save activity: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

func (p *Postgres) Get(ctx context.Context, id string) (Detail, error) {
	var data []byte
	err := p.pool.QueryRow(ctx, `SELECT data FROM incidents WHERE id = $1`, id).Scan(&data)
	if errors.Is(err, pgx.ErrNoRows) {
		return Detail{}, ErrNotFound
	}
	if err != nil {
		return Detail{}, fmt.Errorf("get incident: %w", err)
	}
	d := Detail{Alerts: []Alert{}, Activity: []Activity{}}
	if err := json.Unmarshal(data, &d.Incident); err != nil {
		return Detail{}, fmt.Errorf("decode incident: %w", err)
	}

	rows, err := p.pool.Query(ctx, `SELECT id, data FROM incident_alerts WHERE incident_id = $1 ORDER BY at, id`, id)
	if err != nil {
		return Detail{}, fmt.Errorf("query alerts: %w", err)
	}
	for rows.Next() {
		var aid int64
		var ad []byte
		if err := rows.Scan(&aid, &ad); err != nil {
			rows.Close()
			return Detail{}, fmt.Errorf("scan alert: %w", err)
		}
		var a Alert
		if err := json.Unmarshal(ad, &a); err != nil {
			rows.Close()
			return Detail{}, fmt.Errorf("decode alert: %w", err)
		}
		a.ID = aid
		d.Alerts = append(d.Alerts, a)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return Detail{}, fmt.Errorf("query alerts: %w", err)
	}

	rows, err = p.pool.Query(ctx, `
		SELECT id, at, actor, kind, body FROM incident_activity WHERE incident_id = $1 ORDER BY at, id`, id)
	if err != nil {
		return Detail{}, fmt.Errorf("query activity: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		a := Activity{IncidentID: id}
		if err := rows.Scan(&a.ID, &a.At, &a.Actor, &a.Kind, &a.Body); err != nil {
			return Detail{}, fmt.Errorf("scan activity: %w", err)
		}
		d.Activity = append(d.Activity, a)
	}
	return d, rows.Err()
}

func (p *Postgres) List(ctx context.Context, f Filter) ([]Incident, error) {
	var where []string
	var args []any
	arg := func(v any) string {
		args = append(args, v)
		return fmt.Sprintf("$%d", len(args))
	}
	if f.Status != "" {
		where = append(where, "status = "+arg(string(f.Status)))
	}
	if f.Severity != "" {
		where = append(where, "severity = "+arg(string(f.Severity)))
	}
	if f.Assignee != "" {
		where = append(where, "assignee = "+arg(f.Assignee))
	}
	if f.Entity != nil {
		where = append(where, fmt.Sprintf(
			"EXISTS (SELECT 1 FROM incident_entities e WHERE e.incident_id = incidents.id AND e.kind = %s AND e.value = %s)",
			arg(f.Entity.Kind), arg(f.Entity.Value)))
	}
	q := "SELECT data FROM incidents"
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	limit := f.Limit
	if limit <= 0 {
		limit = 1000
	}
	q += " ORDER BY last_seen DESC LIMIT " + arg(limit)

	rows, err := p.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list incidents: %w", err)
	}
	defer rows.Close()
	out := []Incident{}
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			return nil, fmt.Errorf("scan incident: %w", err)
		}
		var inc Incident
		if err := json.Unmarshal(data, &inc); err != nil {
			return nil, fmt.Errorf("decode incident: %w", err)
		}
		out = append(out, inc)
	}
	return out, rows.Err()
}

func (p *Postgres) Stats(ctx context.Context) (Stats, error) {
	s := Stats{ByStatus: map[Status]int{}, OpenBySev: map[string]int{}}
	rows, err := p.pool.Query(ctx, `SELECT status, severity, count(*) FROM incidents GROUP BY 1, 2`)
	if err != nil {
		return Stats{}, fmt.Errorf("incident stats: %w", err)
	}
	for rows.Next() {
		var status, sev string
		var n int
		if err := rows.Scan(&status, &sev, &n); err != nil {
			rows.Close()
			return Stats{}, fmt.Errorf("scan stats: %w", err)
		}
		s.ByStatus[Status(status)] += n
		if Status(status) == StatusResolved {
			s.Resolved += n
		} else {
			s.Open += n
			s.OpenBySev[sev] += n
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return Stats{}, fmt.Errorf("incident stats: %w", err)
	}
	var mttr *float64
	if err := p.pool.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE status = 'resolved' AND resolution = 'false_positive'),
		       avg(extract(epoch FROM resolved_at - created_at)) FILTER (WHERE status = 'resolved' AND resolved_at IS NOT NULL)
		FROM incidents`).Scan(&s.FalsePositive, &mttr); err != nil {
		return Stats{}, fmt.Errorf("incident mttr: %w", err)
	}
	if mttr != nil {
		s.MTTRSeconds = *mttr
	}
	return s, nil
}
