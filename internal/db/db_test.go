package db_test

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/peios/peipkg/internal/db"
)

// newTestDB opens a fresh, migrated database in a temporary directory
// and registers its cleanup. It returns the handle and the file path
// (some tests open a second, raw connection to that path).
func newTestDB(t *testing.T) (*db.DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "db.sqlite")
	d, err := db.Open(t.Context(), path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d, path
}

// tempDBPath returns a database path in a temporary directory without
// opening it — for tests that manage Open/Close themselves.
func tempDBPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "db.sqlite")
}

// samplePackage builds a representative installed-package row.
func samplePackage(name string) db.Package {
	return db.Package{
		Name:         name,
		Version:      "1.0.0",
		Architecture: "amd64",
		OriginRepo:   "official",
		InstalledAt:  time.Unix(1_700_000_000, 0),
		Manifest:     `{"name":"` + name + `","version":"1.0.0"}`,
	}
}

// assertSamePackage compares two package rows, treating timestamps by
// instant rather than by struct identity.
func assertSamePackage(t *testing.T, got, want db.Package) {
	t.Helper()
	if got.Name != want.Name || got.Version != want.Version ||
		got.Architecture != want.Architecture || got.OriginRepo != want.OriginRepo ||
		got.Manifest != want.Manifest {
		t.Errorf("package mismatch:\n got %+v\nwant %+v", got, want)
	}
	if !got.InstalledAt.Equal(want.InstalledAt) {
		t.Errorf("InstalledAt: got %v, want %v", got.InstalledAt, want.InstalledAt)
	}
}

func TestOpenCreatesAndConfiguresDatabase(t *testing.T) {
	// A successful Open implies configure passed — foreign-key
	// enforcement and WAL journalling are both verified there.
	d, _ := newTestDB(t)
	if v, err := d.SchemaVersion(t.Context()); err != nil || v != 1 {
		t.Fatalf("SchemaVersion after Open: got %d (err %v), want 1", v, err)
	}
}

func TestTxCommitsOnSuccess(t *testing.T) {
	d, _ := newTestDB(t)
	ctx := t.Context()

	err := d.Tx(ctx, func(tx *db.Tx) error {
		return tx.InsertPackage(ctx, samplePackage("alpha"))
	})
	if err != nil {
		t.Fatalf("Tx: %v", err)
	}
	if _, found, err := d.GetPackage(ctx, "alpha"); err != nil || !found {
		t.Errorf("package not persisted after a committed transaction: found=%v err=%v", found, err)
	}
}

func TestTxRollsBackOnError(t *testing.T) {
	d, _ := newTestDB(t)
	ctx := t.Context()
	sentinel := errors.New("deliberate failure")

	err := d.Tx(ctx, func(tx *db.Tx) error {
		if e := tx.InsertPackage(ctx, samplePackage("beta")); e != nil {
			t.Fatalf("InsertPackage inside Tx: %v", e)
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Tx error: got %v, want the sentinel", err)
	}
	if _, found, err := d.GetPackage(ctx, "beta"); err != nil || found {
		t.Errorf("package persisted despite a rolled-back transaction: found=%v err=%v", found, err)
	}
}

func TestTxRollsBackOnPanic(t *testing.T) {
	d, _ := newTestDB(t)
	ctx := t.Context()

	func() {
		defer func() {
			if recover() == nil {
				t.Error("expected the panic to propagate out of Tx")
			}
		}()
		_ = d.Tx(ctx, func(tx *db.Tx) error {
			if e := tx.InsertPackage(ctx, samplePackage("gamma")); e != nil {
				t.Fatalf("InsertPackage inside Tx: %v", e)
			}
			panic("deliberate panic")
		})
	}()

	if _, found, err := d.GetPackage(ctx, "gamma"); err != nil || found {
		t.Errorf("package persisted despite a panicking transaction: found=%v err=%v", found, err)
	}
}
