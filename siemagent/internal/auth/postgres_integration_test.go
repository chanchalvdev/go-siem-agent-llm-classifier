//go:build integration

package auth

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

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
		t.Fatal(err)
	}
	if _, err := NewPostgres(ctx, pool); err != nil {
		t.Fatalf("schema must be re-appliable: %v", err)
	}
	if _, err := pool.Exec(ctx, `TRUNCATE users, sessions, audit_log`); err != nil {
		t.Fatal(err)
	}
	testStoreContract(t, pg)
}
