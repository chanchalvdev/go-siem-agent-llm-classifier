//go:build integration

package retention

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/chverma/siemagent/internal/migrate"
)

// isolatedPool migrates a throwaway schema so the purge cannot touch data
// other packages' tests are using in the same database.
func isolatedPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_TEST_DSN not set")
	}
	ctx := context.Background()
	schema := fmt.Sprintf("retention_test_%d", time.Now().UnixNano())
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	if _, err := admin.Exec(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(context.Background(), `DROP SCHEMA `+schema+` CASCADE`) })
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if _, err := migrate.Up(ctx, pool); err != nil {
		t.Fatal(err)
	}
	return pool
}

func count(t *testing.T, pool *pgxpool.Pool, sql string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), sql).Scan(&n); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	return n
}

func TestPostgresPurge(t *testing.T) {
	pool := isolatedPool(t)
	ctx := context.Background()
	now := time.Now().UTC()
	old := now.Add(-48 * time.Hour)
	cutoff := now.Add(-24 * time.Hour)

	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	for i := range 7 {
		at := old
		if i >= 5 {
			at = now
		}
		exec(`INSERT INTO events (processed_at, severity, attack_type, data) VALUES ($1, 'P3', 'x', '{}')`, at)
		exec(`INSERT INTO audit_log (at, actor, action) VALUES ($1, 'admin', 'login')`, at)
	}
	incident := func(id, status string, resolvedAt *time.Time) {
		exec(`INSERT INTO incidents (id, title, severity, status, first_seen, last_seen, created_at, updated_at, resolved_at, data)
			VALUES ($1, 't', 'P2', $2, $3, $3, $3, $3, $4, '{}')`, id, status, old, resolvedAt)
		exec(`INSERT INTO incident_alerts (incident_id, at, data) VALUES ($1, $2, '{}')`, id, old)
		exec(`INSERT INTO incident_entities (incident_id, kind, value) VALUES ($1, 'ip', '203.0.113.9')`, id)
		exec(`INSERT INTO response_actions (id, dedup_key, incident_id, status, proposed_at, data) VALUES ($1, $1, $2, 'succeeded', $3, '{}')`,
			"act-"+id, id, old)
	}
	recent := now.Add(-time.Hour)
	incident("INC-old-resolved", "resolved", &old)
	incident("INC-recent-resolved", "resolved", &recent)
	incident("INC-old-open", "investigating", nil)
	exec(`INSERT INTO users (id, username, role, password_hash, created_at) VALUES ('u1', 'a', 'admin', '\x00', $1)`, now)
	exec(`INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES ('expired', 'u1', $1, $1), ('live', 'u1', $2, $3)`,
		old, now, now.Add(time.Hour))

	p := NewPostgres(pool)
	p.batch = 2 // exercise the batching loop

	for _, tc := range []struct {
		kind   Kind
		cutoff time.Time
		want   int64
	}{
		{Events, cutoff, 5},
		{Audit, cutoff, 5},
		{Incidents, cutoff, 1},
		{Sessions, now, 1},
	} {
		n, err := p.Purge(ctx, tc.kind, tc.cutoff)
		if err != nil || n != tc.want {
			t.Errorf("purge %s: n=%d err=%v, want %d", tc.kind, n, err, tc.want)
		}
	}

	checks := map[string]int{
		`SELECT count(*) FROM events`:                                                   2,
		`SELECT count(*) FROM audit_log`:                                                2,
		`SELECT count(*) FROM incidents`:                                                2,
		`SELECT count(*) FROM incidents WHERE id = 'INC-old-resolved'`:                  0,
		`SELECT count(*) FROM incident_alerts WHERE incident_id = 'INC-old-resolved'`:   0,
		`SELECT count(*) FROM incident_entities WHERE incident_id = 'INC-old-resolved'`: 0,
		`SELECT count(*) FROM response_actions`:                                         2,
		`SELECT count(*) FROM response_actions WHERE incident_id = 'INC-old-resolved'`:  0,
		`SELECT count(*) FROM sessions`:                                                 1,
	}
	for sql, want := range checks {
		if got := count(t, pool, sql); got != want {
			t.Errorf("%s = %d, want %d", sql, got, want)
		}
	}

	if _, err := p.Purge(ctx, Kind("nope"), now); err == nil {
		t.Error("unknown kind must fail")
	}
}
