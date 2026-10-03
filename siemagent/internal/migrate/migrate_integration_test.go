//go:build integration

package migrate

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// isolatedPool returns a pool whose tables live in a throwaway schema, so the
// test sees an empty database without disturbing other packages' tests that
// share it.
func isolatedPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_TEST_DSN not set")
	}
	ctx := context.Background()
	schema := fmt.Sprintf("migrate_test_%d", time.Now().UnixNano())
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
	return pool
}

func TestUpOnEmptyDatabase(t *testing.T) {
	pool := isolatedPool(t)
	ctx := context.Background()
	all, _ := All()

	before, err := Status(ctx, pool)
	if err != nil || len(before) != 0 {
		t.Fatalf("status before: %v, %v", before, err)
	}
	n, err := Up(ctx, pool)
	if err != nil || n != len(all) {
		t.Fatalf("up: n=%d err=%v", n, err)
	}
	n, err = Up(ctx, pool)
	if err != nil || n != 0 {
		t.Fatalf("second up: n=%d err=%v", n, err)
	}
	applied, err := Status(ctx, pool)
	if err != nil || len(applied) != len(all) || applied[0].Checksum != all[0].Checksum {
		t.Fatalf("status: %+v, %v", applied, err)
	}
	for _, table := range []string{"events", "rule_states", "incidents", "response_actions", "users", "sessions", "audit_log"} {
		var ok bool
		if err := pool.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, table).Scan(&ok); err != nil || !ok {
			t.Errorf("table %s missing after migrate (err %v)", table, err)
		}
	}
}

// Replicas starting together must not apply a migration twice.
func TestUpIsSafeConcurrently(t *testing.T) {
	pool := isolatedPool(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	var mu sync.Mutex
	total := 0
	errs := make(chan error, 6)
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n, err := Up(ctx, pool)
			if err != nil {
				errs <- err
				return
			}
			mu.Lock()
			total += n
			mu.Unlock()
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	all, _ := All()
	if total != len(all) {
		t.Errorf("migrations applied %d times in total, want %d", total, len(all))
	}
}

// A database created by the old start-up schema files adopts the baseline.
func TestUpAdoptsPreMigrationDatabase(t *testing.T) {
	pool := isolatedPool(t)
	ctx := context.Background()
	all, _ := All()
	if _, err := pool.Exec(ctx, all[0].SQL); err != nil {
		t.Fatalf("old schema: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO rule_states (rule_id, enabled) VALUES ('keep-me', false)`); err != nil {
		t.Fatal(err)
	}
	if _, err := Up(ctx, pool); err != nil {
		t.Fatalf("up: %v", err)
	}
	var enabled bool
	if err := pool.QueryRow(ctx, `SELECT enabled FROM rule_states WHERE rule_id = 'keep-me'`).Scan(&enabled); err != nil {
		t.Fatalf("existing data lost: %v", err)
	}
}

func TestUpRefusesEditedMigration(t *testing.T) {
	pool := isolatedPool(t)
	ctx := context.Background()
	if _, err := Up(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE schema_migrations SET checksum = 'edited' WHERE version = 1`); err != nil {
		t.Fatal(err)
	}
	if _, err := Up(ctx, pool); err == nil || !strings.Contains(err.Error(), "changed after it was applied") {
		t.Fatalf("want checksum error, got %v", err)
	}
}
