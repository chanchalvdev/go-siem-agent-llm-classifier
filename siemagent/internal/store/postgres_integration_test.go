//go:build integration

package store

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/chverma/siemagent/internal/models"
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
	if _, err := pg.pool.Exec(ctx, `TRUNCATE events, rule_states`); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	// Opening twice must be safe: the schema is applied on every start.
	pg2, err := OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	pg2.Close()

	testStoreContract(t, pg)
	testRuleStatesContract(t, pg)
}

func TestPostgresDailyVolume(t *testing.T) {
	dsn := os.Getenv("POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_TEST_DSN not set")
	}
	ctx := context.Background()
	pg, err := OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	if _, err := pg.pool.Exec(ctx, `TRUNCATE events`); err != nil {
		t.Fatal(err)
	}
	today := time.Now().UTC()
	yesterday := today.AddDate(0, 0, -1)
	for _, ev := range []models.ClassifiedEvent{
		{Severity: models.SeverityP2, ProcessedAt: yesterday},
		{Severity: models.SeverityP5, ProcessedAt: yesterday, SuppressedBy: "SUP-1"},
		{Severity: models.SeverityP1, ProcessedAt: today},
		{Severity: models.SeverityP1, ProcessedAt: today.AddDate(0, 0, -40)}, // outside
	} {
		if err := pg.Add(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}
	got, err := pg.DailyVolume(ctx, today.AddDate(0, 0, -7))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Events != 2 || got[0].Alerts != 1 || got[0].Suppressed != 1 ||
		got[1].Events != 1 || got[1].Alerts != 1 || !got[1].Day.Equal(day(today)) {
		t.Fatalf("volume: %+v", got)
	}
}
