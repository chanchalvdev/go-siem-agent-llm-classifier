// Package migrate applies versioned SQL migrations to the Postgres database.
//
// Migrations live in migrations/NNNN_name.sql and are embedded in the binary.
// Each runs once, in its own transaction, and is recorded in
// schema_migrations with a checksum. An advisory lock serialises replicas
// starting at the same time. Never edit a migration that has shipped: add a
// new one instead (start-up fails when an applied migration's checksum no
// longer matches).
package migrate

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"regexp"
	"slices"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var files embed.FS

// lockID is the pg_advisory_lock key; any constant unique to this application.
const lockID = 0x5349454d // "SIEM"

// Migration is one versioned schema change.
type Migration struct {
	Version  int
	Name     string
	SQL      string
	Checksum string
}

// Applied is a migration recorded in schema_migrations.
type Applied struct {
	Version   int
	Name      string
	Checksum  string
	AppliedAt time.Time
}

var fileName = regexp.MustCompile(`^(\d{4})_([a-z0-9_]+)\.sql$`)

// All returns the embedded migrations in version order.
func All() ([]Migration, error) {
	return load(files, "migrations")
}

func load(fsys fs.FS, dir string) ([]Migration, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("read migrations: %w", err)
	}
	var out []Migration
	seen := map[int]string{}
	for _, e := range entries {
		m := fileName.FindStringSubmatch(e.Name())
		if e.IsDir() || m == nil {
			return nil, fmt.Errorf("migration %q: name must look like 0001_name.sql", e.Name())
		}
		version, _ := strconv.Atoi(m[1])
		if version == 0 {
			return nil, fmt.Errorf("migration %q: versions start at 0001", e.Name())
		}
		if prev, dup := seen[version]; dup {
			return nil, fmt.Errorf("migrations %q and %q share version %d", prev, e.Name(), version)
		}
		seen[version] = e.Name()
		body, err := fs.ReadFile(fsys, dir+"/"+e.Name())
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", e.Name(), err)
		}
		sum := sha256.Sum256(body)
		out = append(out, Migration{Version: version, Name: m[2], SQL: string(body), Checksum: hex.EncodeToString(sum[:])})
	}
	slices.SortFunc(out, func(a, b Migration) int { return a.Version - b.Version })
	return out, nil
}

// ErrNewerDatabase means the database was migrated by a newer release.
var ErrNewerDatabase = errors.New("database schema is newer than this binary")

// Pending checks the applied history against the known migrations and returns
// the ones still to run. It refuses to continue when a shipped migration was
// edited, or when the database has migrations this binary does not know.
func Pending(all []Migration, applied []Applied) ([]Migration, error) {
	known := make(map[int]Migration, len(all))
	for _, m := range all {
		known[m.Version] = m
	}
	done := make(map[int]bool, len(applied))
	for _, a := range applied {
		m, ok := known[a.Version]
		if !ok {
			return nil, fmt.Errorf("%w: it has migration %04d_%s; upgrade siemagent instead of downgrading", ErrNewerDatabase, a.Version, a.Name)
		}
		if a.Checksum != m.Checksum {
			return nil, fmt.Errorf("migration %04d_%s was changed after it was applied; add a new migration instead of editing it", m.Version, m.Name)
		}
		done[a.Version] = true
	}
	var pending []Migration
	for _, m := range all {
		if !done[m.Version] {
			pending = append(pending, m)
		}
	}
	return pending, nil
}

// Up applies every pending migration and returns how many ran.
func Up(ctx context.Context, pool *pgxpool.Pool) (int, error) {
	all, err := All()
	if err != nil {
		return 0, err
	}
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return 0, fmt.Errorf("migrate: %w", err)
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, lockID); err != nil {
		return 0, fmt.Errorf("migrate lock: %w", err)
	}
	defer func() {
		// Use a fresh context so the lock is released even when ctx was cancelled.
		unlockCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := conn.Exec(unlockCtx, `SELECT pg_advisory_unlock($1)`, lockID); err != nil {
			slog.Warn("migrate: release advisory lock", "component", "migrate", "error", err)
		}
	}()

	if _, err := conn.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    INTEGER     PRIMARY KEY,
			name       TEXT        NOT NULL,
			checksum   TEXT        NOT NULL,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`); err != nil {
		return 0, fmt.Errorf("migrate: create schema_migrations: %w", err)
	}
	applied, err := status(ctx, conn.Conn().Query)
	if err != nil {
		return 0, err
	}
	pending, err := Pending(all, applied)
	if err != nil {
		return 0, err
	}
	for _, m := range pending {
		start := time.Now()
		tx, err := conn.Begin(ctx)
		if err != nil {
			return 0, fmt.Errorf("migrate %04d: %w", m.Version, err)
		}
		if _, err := tx.Exec(ctx, m.SQL); err != nil {
			_ = tx.Rollback(ctx)
			return 0, fmt.Errorf("migration %04d_%s: %w", m.Version, m.Name, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version, name, checksum) VALUES ($1, $2, $3)`,
			m.Version, m.Name, m.Checksum); err != nil {
			_ = tx.Rollback(ctx)
			return 0, fmt.Errorf("record migration %04d: %w", m.Version, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return 0, fmt.Errorf("commit migration %04d: %w", m.Version, err)
		}
		slog.Info("migration applied", "component", "migrate", "version", m.Version, "name", m.Name,
			"duration_ms", time.Since(start).Milliseconds())
	}
	return len(pending), nil
}

// Status returns the migrations recorded in the database, oldest first.
func Status(ctx context.Context, pool *pgxpool.Pool) ([]Applied, error) {
	var exists bool
	if err := pool.QueryRow(ctx, `SELECT to_regclass('schema_migrations') IS NOT NULL`).Scan(&exists); err != nil {
		return nil, fmt.Errorf("migrate status: %w", err)
	}
	if !exists {
		return nil, nil
	}
	return status(ctx, pool.Query)
}

type queryFunc func(ctx context.Context, sql string, args ...any) (pgx.Rows, error)

func status(ctx context.Context, query queryFunc) ([]Applied, error) {
	rows, err := query(ctx, `SELECT version, name, checksum, applied_at FROM schema_migrations ORDER BY version`)
	if err != nil {
		return nil, fmt.Errorf("read schema_migrations: %w", err)
	}
	defer rows.Close()
	var out []Applied
	for rows.Next() {
		var a Applied
		if err := rows.Scan(&a.Version, &a.Name, &a.Checksum, &a.AppliedAt); err != nil {
			return nil, fmt.Errorf("scan schema_migrations: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
