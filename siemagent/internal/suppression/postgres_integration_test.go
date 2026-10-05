//go:build integration

package suppression

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Requires a reachable Postgres, e.g. `make docker-up` then
// POSTGRES_TEST_DSN=postgres://siemagent:siemagent@localhost:5433/siemagent?sslmode=disable
func TestPostgresStore(t *testing.T) {
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
	if _, err := pool.Exec(ctx, `TRUNCATE suppressions`); err != nil {
		t.Fatal(err)
	}

	svc, err := NewService(ctx, pg)
	if err != nil {
		t.Fatal(err)
	}
	timed, err := svc.Create(ctx, "ana", New{Entity: "ip:203.0.113.9", Reason: "pentest", Duration: "24h"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Create(ctx, "ada", New{RuleID: "ssh-brute", AttackType: "Brute Force", Reason: "tuning"}); err != nil {
		t.Fatal(err)
	}
	svc.Match(bruteForce)

	// A restart reloads the definitions; hit counts start over.
	again, err := NewService(ctx, pg)
	if err != nil {
		t.Fatal(err)
	}
	list := again.List()
	if len(list) != 2 {
		t.Fatalf("reloaded %d suppressions", len(list))
	}
	var got *Suppression
	for i := range list {
		if list[i].ID == timed.ID {
			got = &list[i]
		}
	}
	if got == nil || got.Entity == nil || got.Entity.String() != "ip:203.0.113.9" || got.Reason != "pentest" ||
		got.ExpiresAt == nil || !got.ExpiresAt.Equal(*timed.ExpiresAt) || got.Hits != 0 {
		t.Fatalf("round trip: %+v", got)
	}

	if err := again.Lift(ctx, timed.ID); err != nil {
		t.Fatal(err)
	}
	if err := pg.Delete(ctx, timed.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete twice: %v", err)
	}
	if l, _ := pg.List(ctx); len(l) != 1 {
		t.Fatalf("after lift: %d", len(l))
	}
}
