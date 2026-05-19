package db_test

import (
	"database/sql"
	"errors"
	"testing"

	"github.com/peios/peipkg/internal/db"
)

func TestOpenFreshDatabaseReachesLatestSchema(t *testing.T) {
	d, _ := newTestDB(t)
	v, err := d.SchemaVersion(t.Context())
	if err != nil {
		t.Fatalf("SchemaVersion: %v", err)
	}
	if v != 1 {
		t.Errorf("schema version of a fresh database: got %d, want 1", v)
	}
}

func TestOpenIsIdempotent(t *testing.T) {
	ctx := t.Context()
	path := tempDBPath(t)

	first, err := db.Open(ctx, path)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	if err := first.InsertPackage(ctx, samplePackage("persisted")); err != nil {
		t.Fatalf("InsertPackage: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	second, err := db.Open(ctx, path)
	if err != nil {
		t.Fatalf("reopening the database: %v", err)
	}
	defer second.Close()

	if v, err := second.SchemaVersion(ctx); err != nil || v != 1 {
		t.Errorf("schema version after reopen: got %d (err %v), want 1", v, err)
	}
	if _, found, err := second.GetPackage(ctx, "persisted"); err != nil || !found {
		t.Errorf("data did not survive reopen: found=%v err=%v", found, err)
	}
}

func TestSchemaTooNewIsRejected(t *testing.T) {
	ctx := t.Context()
	path := tempDBPath(t)

	d, err := db.Open(ctx, path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	// Simulate a database written by a future peipkg.
	if err := d.SetMeta(ctx, "schema_version", "999"); err != nil {
		t.Fatalf("SetMeta: %v", err)
	}
	if err := d.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if _, err := db.Open(ctx, path); !errors.Is(err, db.ErrSchemaTooNew) {
		t.Fatalf("reopening a newer-schema database: got %v, want ErrSchemaTooNew", err)
	}
}

// TestSchemaShape verifies the migration created every table and index.
// It doubles as proof that the multi-statement migration ran in full.
func TestSchemaShape(t *testing.T) {
	_, path := newTestDB(t)

	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open raw connection: %v", err)
	}
	defer raw.Close()

	for _, table := range []string{
		"meta", "package", "package_file", "repository", "txn", "txn_op", "txn_file",
	} {
		if !objectExists(t, raw, "table", table) {
			t.Errorf("expected table %q to exist", table)
		}
	}
	for _, index := range []string{
		"idx_package_file_collision", "idx_package_file_path", "idx_txn_one_pending",
	} {
		if !objectExists(t, raw, "index", index) {
			t.Errorf("expected index %q to exist", index)
		}
	}
}

// objectExists reports whether a table or index of the given name is
// present in the database schema.
func objectExists(t *testing.T, raw *sql.DB, objType, name string) bool {
	t.Helper()
	var count int
	err := raw.QueryRow(
		"SELECT count(*) FROM sqlite_master WHERE type = ? AND name = ?", objType, name).
		Scan(&count)
	if err != nil {
		t.Fatalf("probe %s %q: %v", objType, name, err)
	}
	return count == 1
}
