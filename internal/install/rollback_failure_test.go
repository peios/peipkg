package install

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/peios/peipkg/internal/db"
)

// §7.5.1.4: a rollback that cannot restore the pre-transaction state is
// a failed rollback. The journal row must stay `pending`, because
// recoverPending queries for exactly that — closing the row moves the
// transaction out of recovery's reach, so the next invocation never
// retries and the operator is never told (PEI-377).
func TestFinishRolledBackLeavesAFailedRollbackPending(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores the directory permissions this test relies on")
	}
	ctx := t.Context()
	store, err := db.Open(ctx, filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	env := Env{DB: store}

	// A committed create whose final path cannot be removed: rolling it
	// back leaves the new file in place, which is the pre-transaction
	// state not restored.
	root := t.TempDir()
	victim := filepath.Join(root, "locked")
	if err := os.MkdirAll(victim, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	final := filepath.Join(victim, "nginx")
	writeFile(t, final, "the new content")

	pins, err := newPinnedDirs(root)
	if err != nil {
		t.Fatalf("newPinnedDirs: %v", err)
	}
	defer pins.close()
	d, err := pins.dirFor(final)
	if err != nil {
		t.Fatalf("dirFor: %v", err)
	}
	if err := os.Chmod(victim, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(victim, 0o755) })

	txnID, err := store.BeginTxn(ctx, "0.1.0-test", journalSchemaVersion)
	if err != nil {
		t.Fatalf("BeginTxn: %v", err)
	}
	op := fileOp{finalPath: final, action: actionCreate, dir: d,
		stagedPath: tempPath(final, stagedMarker, txnID)}

	if err := finishRolledBack(ctx, env, pins, txnID, []fileOp{op}, nil, "test"); err == nil {
		t.Fatal("finishRolledBack reported success for a rollback that could not undo anything")
	}

	txn, found, err := store.PendingTxn(ctx)
	if err != nil {
		t.Fatalf("PendingTxn: %v", err)
	}
	if !found {
		t.Fatal("the journal row was closed, so recovery will never retry the rollback")
	}
	if txn.ID != txnID {
		t.Errorf("pending txn is %d, want %d", txn.ID, txnID)
	}
}

// The ordinary path still closes the row: a rollback that restores the
// previous state is a completed rollback, not an indeterminate one.
func TestFinishRolledBackClosesASuccessfulRollback(t *testing.T) {
	ctx := t.Context()
	store, err := db.Open(ctx, filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	root := t.TempDir()
	final := filepath.Join(root, "nginx")
	writeFile(t, final, "the new content")
	pins, err := newPinnedDirs(root)
	if err != nil {
		t.Fatalf("newPinnedDirs: %v", err)
	}
	defer pins.close()
	d, err := pins.dirFor(final)
	if err != nil {
		t.Fatalf("dirFor: %v", err)
	}
	txnID, err := store.BeginTxn(ctx, "0.1.0-test", journalSchemaVersion)
	if err != nil {
		t.Fatalf("BeginTxn: %v", err)
	}
	op := fileOp{finalPath: final, action: actionCreate, dir: d,
		stagedPath: tempPath(final, stagedMarker, txnID)}

	if err := finishRolledBack(ctx, Env{DB: store}, pins, txnID, []fileOp{op}, nil, "test"); err != nil {
		t.Fatalf("finishRolledBack: %v", err)
	}
	assertAbsent(t, final)
	if _, found, err := store.PendingTxn(ctx); err != nil {
		t.Fatalf("PendingTxn: %v", err)
	} else if found {
		t.Error("a successful rollback left the journal row pending")
	}
}
