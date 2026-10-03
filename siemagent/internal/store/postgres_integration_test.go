//go:build integration

package store

import (
	"context"
	"os"
	"testing"
)

// Requires a reachable Postgres, e.g. `make docker-up` then
// POSTGRES_TEST_DSN=postgres://siemagent:siemagent@localhost:5433/siemagent?sslmode=disable
func TestPostgresContract(t *testing.T) {
	dsn := os.Getenv("POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_TEST_DSN not set")
	}
	ctx := context.Background()

	pg, err := OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer pg.Close()
	if _, err := pg.pool.Exec(ctx, `TRUNCATE events`); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	// Opening twice must be safe: the schema is applied on every start.
	pg2, err := OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	pg2.Close()

	testStoreContract(t, pg)
}
