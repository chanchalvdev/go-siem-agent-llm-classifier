//go:build integration

package incident

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Requires a reachable Postgres, e.g. `make docker-up` then
// POSTGRES_TEST_DSN=postgres://siemagent:siemagent@localhost:5433/siemagent?sslmode=disable
func TestPostgresStoreContract(t *testing.T) {
	dsn := os.Getenv("POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_TEST_DSN not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	pg, err := NewPostgres(ctx, pool)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := NewPostgres(ctx, pool); err != nil {
		t.Fatalf("schema must be re-appliable: %v", err)
	}
	if _, err := pool.Exec(ctx, `TRUNCATE incidents CASCADE`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	testStoreContract(t, pg)
}
