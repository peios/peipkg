package install

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/peios/peipkg/internal/db"
)

// whiteboxRoot opens a database and an Env for a root under a
// controlled-name subdirectory. It is a white-box helper (package install)
// so the roll-forward tests can build commit payloads directly — a black-
// box test cannot construct the unexported payload type.
func whiteboxRoot(t *testing.T, parent, name string) (*db.DB, Env) {
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
	return store, Env{
		Root: filepath.Join(sub, "root"), DB: store,
		LockPath: filepath.Join(sub, "lock"), PeipkgVersion: "0.1.0-test",
	}
}

// samplePayload is a one-package install payload.
func samplePayload(name, ver string) commitPayload {
	return commitPayload{
		Version: commitPayloadVersion,
		Ops: []payloadOp{{
			Kind: "install", Name: name,
			Package: &db.Package{
				Name: name, Version: ver, Architecture: "x86_64",
				InstalledAt: time.Unix(1_700_000_000, 0), Manifest: "{}",
			},
			Files: []db.PackageFile{
				{PackageName: name, Path: "/usr/bin/" + name, Type: db.FileTypeFile, Hash: "abc"},
			},
		}},
	}
}

func TestCommitPayloadRoundTrip(t *testing.T) {
	cp := samplePayload("nginx", "1.0-1")
	raw, err := cp.marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got, err := unmarshalCommitPayload(raw)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got.Ops) != 1 || got.Ops[0].Name != "nginx" || got.Ops[0].Package.Version != "1.0-1" {
		t.Errorf("round-trip lost data: %+v", got)
	}
	// An unrecognised payload version is refused, not misapplied.
	if _, err := unmarshalCommitPayload(`{"v":99}`); err == nil {
		t.Error("an unknown payload version should be rejected")
	}
}

// TestApplyCommitPayloadRecordsState confirms replaying a payload writes
// the same package and file rows a live commit would.
func TestApplyCommitPayloadRecordsState(t *testing.T) {
	ctx := t.Context()
	store, _ := whiteboxRoot(t, t.TempDir(), "r")
	cp := samplePayload("nginx", "1.0-1")
	if err := store.Tx(ctx, func(tx *db.Tx) error {
		return applyCommitPayload(ctx, tx, cp)
	}); err != nil {
		t.Fatalf("applyCommitPayload: %v", err)
	}
	if _, found, _ := store.GetPackage(ctx, "nginx"); !found {
		t.Error("package row was not recorded")
	}
	if files, _ := store.PackageFiles(ctx, "nginx"); len(files) != 1 {
		t.Errorf("package_file rows: got %d, want 1", len(files))
	}
}

// TestRecoverCrossRootRollsForwardWhenTorn: a torn transaction — one root
// committed, the other pending with a forward payload (as prepare wrote) —
// is rolled forward, completing the pending root rather than tearing it.
func TestRecoverCrossRootRollsForwardWhenTorn(t *testing.T) {
	ctx := t.Context()
	dir := t.TempDir()
	storeA, envA := whiteboxRoot(t, dir, "a")
	storeB, envB := whiteboxRoot(t, dir, "b")

	// Root A committed; root B is prepared (pending) with its forward
	// payload — the state a crash between the two commits leaves.
	idA, err := storeA.BeginCrossRootTxn(ctx, "0.1.0-test", journalSchemaVersion, "xid")
	if err != nil {
		t.Fatalf("begin A: %v", err)
	}
	if err := storeA.FinishTxn(ctx, idA, db.TxnCommitted, "committed"); err != nil {
		t.Fatalf("commit A: %v", err)
	}
	idB, err := storeB.BeginCrossRootTxn(ctx, "0.1.0-test", journalSchemaVersion, "xid")
	if err != nil {
		t.Fatalf("begin B: %v", err)
	}
	raw, err := samplePayload("peiosutils", "1.0-1").marshal()
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	if err := storeB.SetCommitPayload(ctx, idB, raw); err != nil {
		t.Fatalf("set payload: %v", err)
	}

	reconciled, err := RecoverCrossRoot(ctx,
		map[string]Env{envA.Root: envA, envB.Root: envB}, "xid")
	if err != nil || !reconciled {
		t.Fatalf("RecoverCrossRoot: reconciled=%v err=%v", reconciled, err)
	}
	// Root B is now committed and records its package.
	if _, found, _ := storeB.GetPackage(ctx, "peiosutils"); !found {
		t.Error("root B did not record peiosutils after roll-forward")
	}
	if _, pending, _ := storeB.PendingTxn(ctx); pending {
		t.Error("root B should no longer be pending")
	}
}
