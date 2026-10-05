//go:build integration

package ioc

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/chverma/siemagent/internal/models"
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
	if _, err := pool.Exec(ctx, `TRUNCATE watchlists CASCADE`); err != nil {
		t.Fatal(err)
	}

	svc, err := NewService(ctx, pg)
	if err != nil {
		t.Fatal(err)
	}
	manual, err := svc.Create(ctx, "ana", NewWatchlist{Name: "Case 42", Source: SourceManual, Severity: models.SeverityP1})
	if err != nil {
		t.Fatal(err)
	}
	feed, err := svc.Create(ctx, "ada", NewWatchlist{Name: "Feodo", Source: SourceFeed, URL: "https://feeds.example/ip.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.AddIndicators(ctx, manual.ID, "ana", "phishing", []string{"evil.example", "203.0.113.0/24"}); err != nil {
		t.Fatal(err)
	}
	// Adding an existing value again is a no-op, not an error.
	if added, _, err := svc.AddIndicators(ctx, manual.ID, "ana", "", []string{"evil.example"}); err != nil || len(added) != 0 {
		t.Fatalf("re-add: %v %v", added, err)
	}
	off := false
	if _, err := svc.Update(ctx, feed.ID, Update{Enabled: &off}); err != nil {
		t.Fatal(err)
	}

	again, err := NewService(ctx, pg)
	if err != nil {
		t.Fatal(err)
	}
	if len(again.List()) != 2 {
		t.Fatalf("reloaded %d lists", len(again.List()))
	}
	if f, _ := again.Get(feed.ID); f.Enabled || f.URL != "https://feeds.example/ip.txt" || f.Count != 0 {
		t.Fatalf("feed round trip: %+v", f)
	}
	inds, total, _ := again.Indicators(manual.ID, 10)
	if total != 2 || inds[0].Value != "evil.example" || inds[0].Note != "phishing" || inds[1].Type != TypeCIDR {
		t.Fatalf("indicators: %+v", inds)
	}
	if res := again.Lookup("203.0.113.77"); len(res) != 1 || res[0].Severity != models.SeverityP1 {
		t.Fatalf("lookup: %+v", res)
	}
	if err := again.RemoveIndicator(ctx, manual.ID, "evil.example"); err != nil {
		t.Fatal(err)
	}
	if err := pg.RemoveIndicator(ctx, manual.ID, "evil.example"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("remove twice: %v", err)
	}
	if err := again.Delete(ctx, manual.ID); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM watchlist_indicators`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("indicators must go with their list: %d %v", n, err)
	}
}
