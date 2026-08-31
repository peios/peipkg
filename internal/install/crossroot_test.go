package install_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/peios/peipkg/internal/db"
	"github.com/peios/peipkg/internal/install"
	"github.com/peios/peipkg/internal/resolver"
)

// rootEnv opens a database and returns an install Env for a root under a
// controlled-name subdirectory, so a test can fix the resolved-path
// ordering the cross-root executor sorts by.
func rootEnv(t *testing.T, parent, name string, prov install.PackageProvider) (*db.DB, string, install.Env) {
	t.Helper()
	sub := filepath.Join(parent, name)
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", sub, err)
	}
	store, err := db.Open(t.Context(), filepath.Join(sub, "db.sqlite"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	root := filepath.Join(sub, "root")
	env := install.Env{
		Root: root, DB: store, LockPath: filepath.Join(sub, "lock"),
		PeipkgVersion: "0.1.0-test", Provider: prov,
	}
	return store, root, env
}

func crossRootOp(t *testing.T, name, ver, root string) resolver.Operation {
	op := installOp(t, name, ver)
	op.Root = root
	return op
}

// TestExecuteCrossRoot drives the happy path: one plan installs into two
// roots as a single cross-root transaction. Both payloads land, both
// databases record their package, both journal rows share the cross-root
// id, and neither root is left pending.
func TestExecuteCrossRoot(t *testing.T) {
	ctx := t.Context()
	dir := t.TempDir()
	prov := fakeProvider{
		"live-boot": provide(t, testPkg{name: "live-boot", version: "1.0-1",
			files: map[string]string{"usr/bin/live-boot": "lb"}}),
		"busybox": provide(t, testPkg{name: "busybox", version: "1.0-1",
			files: map[string]string{"usr/bin/busybox": "bb"}}),
	}
	storeA, rootA, envA := rootEnv(t, dir, "a", prov) // the anchor root "/"
	storeB, rootB, envB := rootEnv(t, dir, "b", prov) // the initramfs root

	plan := resolver.Plan{Operations: []resolver.Operation{
		crossRootOp(t, "busybox", "1.0-1", rootB),   // dependency, placed in B
		crossRootOp(t, "live-boot", "1.0-1", rootA), // dependent, in A
	}}
	envs := map[string]install.Env{rootA: envA, rootB: envB}

	results, err := install.ExecuteCrossRoot(ctx, plan, envs, "xrt-1")
	if err != nil {
		t.Fatalf("ExecuteCrossRoot: %v", err)
	}
	if len(results) != 2 {
		t.Errorf("expected a result per root, got %d", len(results))
	}

	// Both payloads landed in their respective roots.
	if b, err := os.ReadFile(filepath.Join(rootA, "usr/bin/live-boot")); err != nil || string(b) != "lb" {
		t.Errorf("live-boot payload in root A: %q err %v", b, err)
	}
	if b, err := os.ReadFile(filepath.Join(rootB, "usr/bin/busybox")); err != nil || string(b) != "bb" {
		t.Errorf("busybox payload in root B: %q err %v", b, err)
	}
	// Each root's database records its own package.
	if _, found, _ := storeA.GetPackage(ctx, "live-boot"); !found {
		t.Error("root A did not record live-boot")
	}
	if _, found, _ := storeB.GetPackage(ctx, "busybox"); !found {
		t.Error("root B did not record busybox")
	}
	// Both transactions carry the shared cross-root id and committed.
	for name, store := range map[string]*db.DB{"A": storeA, "B": storeB} {
		txns, err := store.ListTxns(ctx, 0)
		if err != nil || len(txns) != 1 {
			t.Fatalf("root %s txns: %+v err %v", name, txns, err)
		}
		if txns[0].CrossRootID != "xrt-1" {
			t.Errorf("root %s cross_root_id: got %q, want %q", name, txns[0].CrossRootID, "xrt-1")
		}
		if txns[0].State != db.TxnCommitted {
			t.Errorf("root %s txn state: got %q, want committed", name, txns[0].State)
		}
		if _, pending, _ := store.PendingTxn(ctx); pending {
			t.Errorf("root %s still has a pending transaction", name)
		}
	}
}

// TestExecuteCrossRootPrepareFailureRollsBackAll: if any root fails to
// prepare, every root that already voted is rolled back and the system is
// left as it was — no payloads, no recorded packages, no pending journals.
func TestExecuteCrossRootPrepareFailureRollsBackAll(t *testing.T) {
	ctx := t.Context()
	dir := t.TempDir()
	// The provider serves the package for the root that sorts first ("a")
	// but not the one for "b", so "a" prepares (and must be rolled back)
	// before "b" fails to prepare.
	prov := fakeProvider{
		"live-boot": provide(t, testPkg{name: "live-boot", version: "1.0-1",
			files: map[string]string{"usr/bin/live-boot": "lb"}}),
	}
	storeA, rootA, envA := rootEnv(t, dir, "a", prov)
	storeB, rootB, envB := rootEnv(t, dir, "b", prov)

	plan := resolver.Plan{Operations: []resolver.Operation{
		crossRootOp(t, "live-boot", "1.0-1", rootA),
		crossRootOp(t, "busybox", "1.0-1", rootB), // no candidate served → prepare fails
	}}
	envs := map[string]install.Env{rootA: envA, rootB: envB}

	if _, err := install.ExecuteCrossRoot(ctx, plan, envs, "xrt-2"); err == nil {
		t.Fatal("a prepare failure in one root should fail the whole cross-root transaction")
	}

	// Root A, which sorted first and prepared, must be fully rolled back.
	if _, err := os.Lstat(filepath.Join(rootA, "usr/bin/live-boot")); !os.IsNotExist(err) {
		t.Errorf("root A payload should have been rolled back: %v", err)
	}
	if _, found, _ := storeA.GetPackage(ctx, "live-boot"); found {
		t.Error("root A should not have recorded live-boot")
	}
	for name, store := range map[string]*db.DB{"A": storeA, "B": storeB} {
		if _, pending, _ := store.PendingTxn(ctx); pending {
			t.Errorf("root %s should have no pending transaction after rollback", name)
		}
		_ = storeB
	}
}

// TestRecoverPendingRefusesCrossRoot guards the safety property: a normal
// single-root recovery must refuse to roll back a pending cross-root
// participant in isolation, rather than tear the transaction.
func TestRecoverPendingRefusesCrossRoot(t *testing.T) {
	ctx := t.Context()
	store, _, _ := freshEnv(t)
	// Simulate a crash that left a cross-root participant pending.
	if _, err := store.BeginCrossRootTxn(ctx, "0.1.0-test", 2, "xrt-3"); err != nil {
		t.Fatalf("BeginCrossRootTxn: %v", err)
	}
	dir := t.TempDir()
	env := install.Env{Root: filepath.Join(dir, "root"), DB: store,
		LockPath: filepath.Join(dir, "lock"), PeipkgVersion: "0.1.0-test"}

	if err := install.Recover(ctx, env); err == nil {
		t.Fatal("single-root recovery should refuse a pending cross-root transaction")
	}
	// It stays pending — untouched — for cross-root recovery to reconcile.
	if _, pending, _ := store.PendingTxn(ctx); !pending {
		t.Error("the cross-root transaction should remain pending, not be rolled back")
	}
}

// pendingState reports a root's single pending transaction's id, and
// whether one is pending.
func latestTxnState(t *testing.T, store *db.DB, ctx context.Context) db.TxnState {
	t.Helper()
	txns, err := store.ListTxns(ctx, 1)
	if err != nil || len(txns) == 0 {
		t.Fatalf("ListTxns: %+v err %v", txns, err)
	}
	return txns[0].State
}

// TestRecoverCrossRootRollsBackWhenNoneCommitted: an interrupted cross-root
// transaction with no committed participant is rolled back in every root.
func TestRecoverCrossRootRollsBackWhenNoneCommitted(t *testing.T) {
	ctx := t.Context()
	dir := t.TempDir()
	storeA, rootA, envA := rootEnv(t, dir, "a", nil)
	storeB, rootB, envB := rootEnv(t, dir, "b", nil)
	// Simulate a crash that left both roots prepared (pending) under one id.
	if _, err := storeA.BeginCrossRootTxn(ctx, "0.1.0-test", 2, "xid"); err != nil {
		t.Fatalf("begin A: %v", err)
	}
	if _, err := storeB.BeginCrossRootTxn(ctx, "0.1.0-test", 2, "xid"); err != nil {
		t.Fatalf("begin B: %v", err)
	}

	rolledBack, err := install.RecoverCrossRoot(ctx,
		map[string]install.Env{rootA: envA, rootB: envB}, "xid")
	if err != nil || !rolledBack {
		t.Fatalf("RecoverCrossRoot: rolledBack=%v err=%v", rolledBack, err)
	}
	for name, store := range map[string]*db.DB{"A": storeA, "B": storeB} {
		if _, pending, _ := store.PendingTxn(ctx); pending {
			t.Errorf("root %s should no longer be pending", name)
		}
		if s := latestTxnState(t, store, ctx); s != db.TxnRolledBack {
			t.Errorf("root %s txn state: got %q, want rolled-back", name, s)
		}
	}
}

// TestRecoverCrossRootRefusesTornCommit: a torn transaction whose pending
// root carries no forward payload (a degenerate or hand-built state)
// cannot be rolled forward, so recovery refuses and leaves every root
// untouched rather than tearing it further. (The normal torn case, with a
// payload, rolls forward — see TestRecoverCrossRootRollsForwardWhenTorn.)
func TestRecoverCrossRootRefusesTornCommit(t *testing.T) {
	ctx := t.Context()
	dir := t.TempDir()
	storeA, rootA, envA := rootEnv(t, dir, "a", nil)
	storeB, rootB, envB := rootEnv(t, dir, "b", nil)
	// Root A committed; root B is still pending — a torn commit.
	idA, err := storeA.BeginCrossRootTxn(ctx, "0.1.0-test", 2, "xid")
	if err != nil {
		t.Fatalf("begin A: %v", err)
	}
	if err := storeA.FinishTxn(ctx, idA, db.TxnCommitted, "committed"); err != nil {
		t.Fatalf("commit A: %v", err)
	}
	if _, err := storeB.BeginCrossRootTxn(ctx, "0.1.0-test", 2, "xid"); err != nil {
		t.Fatalf("begin B: %v", err)
	}

	rolledBack, err := install.RecoverCrossRoot(ctx,
		map[string]install.Env{rootA: envA, rootB: envB}, "xid")
	if err == nil || rolledBack {
		t.Fatalf("a torn cross-root transaction should be refused, got rolledBack=%v err=%v",
			rolledBack, err)
	}
	// A stays committed, B stays pending — nothing was torn further.
	if s := latestTxnState(t, storeA, ctx); s != db.TxnCommitted {
		t.Errorf("root A should remain committed, got %q", s)
	}
	if _, pending, _ := storeB.PendingTxn(ctx); !pending {
		t.Error("root B should remain pending")
	}
}

// §5.26: a consumer installing several packages together completes
// verification for EVERY package before extracting ANY package's
// payload, across every root the operation touches.
//
// ExecuteCrossRoot used to prepare root by root, and prepare runs
// commitOps — so root A's payload was live on disk before root B's
// packages had been fetched, let alone verified. Unwinding afterwards is
// not the same as never having extracted: a tool was installed, a
// directory created, a symlink planted (PEI-375's ancestor), for as long
// as B's download took (PEI-390).
//
// The observable difference is that root A now never opens a
// transaction at all, rather than opening one and rolling it back.
func TestCrossRootVerifiesEveryRootBeforeExtractingAny(t *testing.T) {
	ctx := t.Context()
	dir := t.TempDir()

	// Root B's package cannot be provided; root A's can.
	prov := fakeProvider{
		"live-boot": provide(t, testPkg{name: "live-boot", version: "1.0-1",
			files: map[string]string{"usr/bin/live-boot": "lb"}}),
	}
	storeA, rootA, envA := rootEnv(t, dir, "a", prov)
	_, rootB, envB := rootEnv(t, dir, "b", prov)

	plan := resolver.Plan{Operations: []resolver.Operation{
		crossRootOp(t, "live-boot", "1.0-1", rootA),
		crossRootOp(t, "busybox", "1.0-1", rootB), // no such package
	}}
	envs := map[string]install.Env{rootA: envA, rootB: envB}

	if _, err := install.ExecuteCrossRoot(ctx, plan, envs, "xrt-fail"); err == nil {
		t.Fatal("ExecuteCrossRoot succeeded although a root's package could not be provided")
	}

	// Nothing of root A's reached disk.
	if _, err := os.Lstat(filepath.Join(rootA, "usr/bin/live-boot")); !os.IsNotExist(err) {
		t.Errorf("root A's payload is on disk (err %v)", err)
	}
	// And root A never began a transaction: verification for every root
	// completed — and failed — before any root was touched.
	txns, err := storeA.ListTxns(ctx, 10)
	if err != nil {
		t.Fatalf("ListTxns: %v", err)
	}
	if len(txns) != 0 {
		t.Errorf("root A opened %d transaction(s) before the other root was verified: %+v",
			len(txns), txns)
	}
}
