package db

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
)

// migrationFS holds the schema migrations, applied in version order by
// [DB.migrate]. Migrations are append-only: a released migration file is
// never edited; a schema change adds the next NNNN_<name>.sql.
//
//go:embed migrations/*.sql
var migrationFS embed.FS

// ErrSchemaTooNew is returned by [Open] when the database's schema
// version is higher than this build of peipkg understands — the
// database was written by a newer peipkg. peipkg never downgrades a
// schema; the operator must use a peipkg at least as new.
var ErrSchemaTooNew = errors.New("peipkg/db: database schema is newer than this peipkg")

// migration is one numbered schema migration loaded from migrationFS.
type migration struct {
	version int
	name    string
	sql     string
}

// migrate brings the database schema up to date by applying, in order,
// every migration newer than the database's current schema version.
func (db *DB) migrate(ctx context.Context) error {
	migrations, err := loadMigrations()
	if err != nil {
		return err
	}
	current, err := db.schemaVersion(ctx)
	if err != nil {
		return err
	}
	latest := len(migrations) // versions are contiguous from 1

	if current > latest {
		return fmt.Errorf("%w (database is at version %d, this peipkg knows up to %d)",
			ErrSchemaTooNew, current, latest)
	}
	for _, m := range migrations {
		if m.version <= current {
			continue
		}
		if err := db.applyMigration(ctx, m); err != nil {
			return err
		}
	}
	return nil
}

// schemaVersion reports the database's current schema version, or 0 for
// a fresh database that has had no migration applied.
func (db *DB) schemaVersion(ctx context.Context) (int, error) {
	// meta itself is created by the first migration, so a database
	// without it is simply at version 0.
	var hasMeta int
	err := db.sql.QueryRowContext(ctx,
		"SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'meta'").
		Scan(&hasMeta)
	if err != nil {
		return 0, fmt.Errorf("peipkg/db: probe schema: %w", err)
	}
	if hasMeta == 0 {
		return 0, nil
	}

	var raw string
	err = db.sql.QueryRowContext(ctx,
		"SELECT value FROM meta WHERE key = 'schema_version'").Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("peipkg/db: read schema version: %w", err)
	}
	version, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("peipkg/db: schema version %q is not a number: %w", raw, err)
	}
	return version, nil
}

// applyMigration runs one migration's DDL and records the new schema
// version, atomically: SQLite DDL is transactional, so a migration that
// fails partway leaves the schema untouched.
func (db *DB) applyMigration(ctx context.Context, m migration) error {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("peipkg/db: begin migration %s: %w", m.name, err)
	}
	if _, err := tx.ExecContext(ctx, m.sql); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("peipkg/db: apply migration %s: %w", m.name, err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO meta (key, value) VALUES ('schema_version', ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		strconv.Itoa(m.version)); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("peipkg/db: record schema version %d: %w", m.version, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("peipkg/db: commit migration %s: %w", m.name, err)
	}
	return nil
}

// loadMigrations reads the embedded migration files in version order.
// Filenames are NNNN_<name>.sql, where NNNN is the schema version the
// migration produces; versions must run 1, 2, 3, … with no gap.
func loadMigrations() ([]migration, error) {
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return nil, fmt.Errorf("peipkg/db: read migrations: %w", err)
	}

	var migrations []migration
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		prefix, _, ok := strings.Cut(entry.Name(), "_")
		if !ok {
			return nil, fmt.Errorf("peipkg/db: malformed migration filename %q", entry.Name())
		}
		version, err := strconv.Atoi(prefix)
		if err != nil {
			return nil, fmt.Errorf("peipkg/db: malformed migration version in %q: %w",
				entry.Name(), err)
		}
		body, err := migrationFS.ReadFile("migrations/" + entry.Name())
		if err != nil {
			return nil, fmt.Errorf("peipkg/db: read migration %q: %w", entry.Name(), err)
		}
		migrations = append(migrations, migration{
			version: version,
			name:    entry.Name(),
			sql:     string(body),
		})
	}

	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].version < migrations[j].version
	})
	for i, m := range migrations {
		if m.version != i+1 {
			return nil, fmt.Errorf(
				"peipkg/db: migration versions are not contiguous from 1 "+
					"(found version %d in position %d)", m.version, i+1)
		}
	}
	return migrations, nil
}
