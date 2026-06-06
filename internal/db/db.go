// Package db is peipkg's private package database: the SQLite store at
// /var/lib/peipkg/db.sqlite that records every installed package and the
// transaction journal.
//
// A database is opened with [Open], which configures the connection and
// brings the schema up to date by applying any pending migrations.
//
// Accessor methods are defined on [queries] and are therefore available
// identically on a [DB] — where each call is its own autocommit
// statement — and on a [Tx] — where calls are grouped into one atomic
// SQLite transaction by [DB.Tx]. The commit phase of an install groups
// all of its writes into a single [DB.Tx] call; that SQLite transaction
// is peipkg's durability boundary.
package db

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"path/filepath"

	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

// driverName is the database/sql driver registered by modernc.org/sqlite
// — a pure-Go SQLite, so peipkg still builds CGO-free and static.
const driverName = "sqlite"

// DB is an open handle to the peipkg package database. It is safe for
// the connection pool to be used by multiple goroutines; the higher
// layers nonetheless serialise mutation through the journal.
type DB struct {
	sql *sql.DB
	*queries
}

// Tx is an in-progress database transaction. Every accessor method
// available on a [DB] is available on a [Tx]; calls on a Tx are grouped
// into one atomic SQLite transaction. Obtain one through [DB.Tx].
type Tx struct {
	*queries
}

// querier is the read/write surface shared by *sql.DB and *sql.Tx, so a
// single set of accessor methods works identically inside or outside a
// transaction.
type querier interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	PrepareContext(ctx context.Context, query string) (*sql.Stmt, error)
}

// queries carries the accessor methods, bound either to the connection
// pool (autocommit) or to a single transaction.
type queries struct {
	q querier
}

// scanner is satisfied by both *sql.Row and *sql.Rows, so a row-scanning
// helper can serve a single-row query and an iterated one alike.
type scanner interface {
	Scan(dest ...any) error
}

// Open opens the package database at path — creating an empty one if it
// does not exist — configures the connection, and applies any pending
// schema migrations. The path is resolved to an absolute path before use:
// modernc.org/sqlite takes a file: URI, and a relative path would be
// misparsed (its first segment read as a URI authority). Opening the
// absolute path is identical to opening its relative form. The caller
// must [DB.Close] the returned handle.
func Open(ctx context.Context, path string) (*DB, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("peipkg/db: resolve %q: %w", path, err)
	}
	sqlDB, err := sql.Open(driverName, dsn(abs))
	if err != nil {
		return nil, fmt.Errorf("peipkg/db: open %q: %w", abs, err)
	}
	db := &DB{sql: sqlDB, queries: &queries{q: sqlDB}}

	if err := db.configure(ctx); err != nil {
		_ = sqlDB.Close()
		return nil, err
	}
	if err := db.migrate(ctx); err != nil {
		_ = sqlDB.Close()
		return nil, err
	}
	return db, nil
}

// Close releases the database handle and its connections.
func (db *DB) Close() error {
	if err := db.sql.Close(); err != nil {
		return fmt.Errorf("peipkg/db: close: %w", err)
	}
	return nil
}

// Tx runs fn inside a single SQLite transaction. If fn returns nil the
// transaction is committed; if it returns an error — or panics — the
// transaction is rolled back and that error (or panic) propagates
// unchanged. The *Tx passed to fn must not be retained beyond fn.
func (db *DB) Tx(ctx context.Context, fn func(*Tx) error) (err error) {
	sqlTx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("peipkg/db: begin transaction: %w", err)
	}
	defer func() {
		if p := recover(); p != nil {
			_ = sqlTx.Rollback()
			panic(p)
		}
		if err != nil {
			_ = sqlTx.Rollback()
		}
	}()

	if err = fn(&Tx{queries: &queries{q: sqlTx}}); err != nil {
		return err
	}
	if err = sqlTx.Commit(); err != nil {
		return fmt.Errorf("peipkg/db: commit transaction: %w", err)
	}
	return nil
}

// configure verifies that the connection-level PRAGMAs took effect.
// peipkg's referential integrity (foreign_keys) and crash-safety
// (journal_mode) both depend on them, so a silent failure to apply them
// must abort Open rather than let peipkg run degraded.
func (db *DB) configure(ctx context.Context) error {
	if err := db.sql.PingContext(ctx); err != nil {
		return fmt.Errorf("peipkg/db: connect: %w", err)
	}
	var foreignKeys int
	if err := db.sql.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&foreignKeys); err != nil {
		return fmt.Errorf("peipkg/db: check foreign_keys pragma: %w", err)
	}
	if foreignKeys != 1 {
		return fmt.Errorf("peipkg/db: foreign key enforcement is not active")
	}
	var journalMode string
	if err := db.sql.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journalMode); err != nil {
		return fmt.Errorf("peipkg/db: check journal_mode pragma: %w", err)
	}
	if journalMode != "wal" {
		return fmt.Errorf("peipkg/db: journal mode is %q, want wal", journalMode)
	}
	return nil
}

// dsn builds the modernc.org/sqlite connection string. Each _pragma
// parameter is applied to every connection the pool opens:
//
//   - foreign_keys   referential integrity and ON DELETE CASCADE.
//   - journal_mode   WAL — a reader (Phase 1, queries) never blocks on
//     an in-flight writer.
//   - synchronous    FULL — a committed transaction survives power loss,
//     so an operator told "installed" is told the truth. peipkg commits
//     rarely, so the extra fsync is free in practice.
//   - busy_timeout   wait briefly, rather than fail immediately, when a
//     concurrent writer holds the database lock.
func dsn(path string) string {
	q := url.Values{}
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "synchronous(FULL)")
	q.Add("_pragma", "busy_timeout(5000)")
	u := url.URL{Scheme: "file", Path: path, RawQuery: q.Encode()}
	return u.String()
}

// nullString maps Go's empty-string sentinel to a SQL NULL. The columns
// it is used for (origin_repo, hash, symlink_target, version columns)
// never hold a legitimately-empty string, so "" unambiguously means
// "absent".
func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
