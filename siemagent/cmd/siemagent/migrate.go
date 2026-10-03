package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/chverma/siemagent/internal/migrate"
)

// runMigrations applies pending migrations and prints the schema history.
// The server also migrates on start; this lets operators upgrade the schema
// as a separate deploy step (e.g. a Kubernetes init job).
func runMigrations(dsn string) error {
	if dsn == "" {
		return errors.New("--migrate needs POSTGRES_DSN")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return fmt.Errorf("postgres config: %w", err)
	}
	defer pool.Close()
	n, err := migrate.Up(ctx, pool)
	if err != nil {
		return err
	}
	applied, err := migrate.Status(ctx, pool)
	if err != nil {
		return err
	}
	version := 0
	for _, a := range applied {
		version = a.Version
		fmt.Printf("%04d  %-32s %s\n", a.Version, a.Name, a.AppliedAt.UTC().Format(time.RFC3339))
	}
	fmt.Printf("applied %d migration(s); schema at version %d\n", n, version)
	return nil
}
