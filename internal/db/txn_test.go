package db_test

import (
	"slices"
	"testing"
	"time"

	"github.com/peios/peipkg/internal/db"
)

const (
	testVersion       = "0.1.0-test" // a stand-in started_by_version
	testJournalSchema = 1            // a stand-in journal_schema_version
)

func TestBeginTxnCreatesPendingEntry(t *testing.T) {
	d, _ := newTestDB(t)
	ctx := t.Context()
	before := time.Now()

	id, err := d.BeginTxn(ctx, testVersion, testJournalSchema)
	if err != nil {
		t.Fatalf("BeginTxn: %v", err)
	}
	if id <= 0 {
		t.Errorf("BeginTxn id: got %d, want a positive id", id)
	}

	txn, found, err := d.PendingTxn(ctx)
	if err != nil || !found {
		t.Fatalf("PendingTxn: found=%v err=%v", found, err)
	}
	if txn.ID != id {
		t.Errorf("PendingTxn id: got %d, want %d", txn.ID, id)
	}
	if txn.State != db.TxnPending {
		t.Errorf("state: got %q, want pending", txn.State)
	}
	if !txn.FinishedAt.IsZero() {
		t.Errorf("FinishedAt: got %v, want the zero Time while pending", txn.FinishedAt)
	}
	if txn.StartedByVersion != testVersion {
		t.Errorf("StartedByVersion: got %q, want %q", txn.StartedByVersion, testVersion)
	}
	if txn.JournalSchemaVersion != testJournalSchema {
		t.Errorf("JournalSchemaVersion: got %d, want %d", txn.JournalSchemaVersion, testJournalSchema)
	}
	if txn.StartedAt.Before(before.Add(-time.Minute)) || txn.StartedAt.After(time.Now().Add(time.Minute)) {
		t.Errorf("StartedAt %v is not close to now", txn.StartedAt)
	}
}

// TestOnlyOnePendingTransaction exercises the partial unique index that
// makes the single-writer rule structural.
func TestOnlyOnePendingTransaction(t *testing.T) {
	d, _ := newTestDB(t)
	ctx := t.Context()
	if _, err := d.BeginTxn(ctx, testVersion, testJournalSchema); err != nil {
		t.Fatalf("first BeginTxn: %v", err)
	}
	if _, err := d.BeginTxn(ctx, testVersion, testJournalSchema); err == nil {
		t.Error("a second pending transaction should be rejected (single-writer rule)")
	}
}

func TestFinishThenBeginAgain(t *testing.T) {
	d, _ := newTestDB(t)
	ctx := t.Context()

	first, err := d.BeginTxn(ctx, testVersion, testJournalSchema)
	if err != nil {
		t.Fatalf("BeginTxn: %v", err)
	}
	if err := d.FinishTxn(ctx, first, db.TxnCommitted, "installed alpha"); err != nil {
		t.Fatalf("FinishTxn: %v", err)
	}
	second, err := d.BeginTxn(ctx, testVersion, testJournalSchema)
	if err != nil {
		t.Fatalf("BeginTxn after finishing the first: %v", err)
	}
	if second == first {
		t.Error("transaction ids must never be reused")
	}
}

func TestFinishTxnCommitted(t *testing.T) {
	d, _ := newTestDB(t)
	ctx := t.Context()

	id, err := d.BeginTxn(ctx, testVersion, testJournalSchema)
	if err != nil {
		t.Fatalf("BeginTxn: %v", err)
	}
	if err := d.FinishTxn(ctx, id, db.TxnCommitted, "installed nginx 1.0.0"); err != nil {
		t.Fatalf("FinishTxn: %v", err)
	}

	if _, found, err := d.PendingTxn(ctx); err != nil || found {
		t.Errorf("PendingTxn after finish: found=%v err=%v, want not found", found, err)
	}
	txn, found, err := d.GetTxn(ctx, id)
	if err != nil || !found {
		t.Fatalf("GetTxn: found=%v err=%v", found, err)
	}
	if txn.State != db.TxnCommitted {
		t.Errorf("state: got %q, want committed", txn.State)
	}
	if txn.FinishedAt.IsZero() {
		t.Error("FinishedAt should be set on a finished transaction")
	}
	if txn.OpSummary != "installed nginx 1.0.0" {
		t.Errorf("OpSummary: got %q, want the recorded summary", txn.OpSummary)
	}
}

func TestFinishTxnRejectsNonTerminalState(t *testing.T) {
	d, _ := newTestDB(t)
	ctx := t.Context()
	id, err := d.BeginTxn(ctx, testVersion, testJournalSchema)
	if err != nil {
		t.Fatalf("BeginTxn: %v", err)
	}
	if err := d.FinishTxn(ctx, id, db.TxnPending, ""); err == nil {
		t.Error("FinishTxn to the pending state should be rejected")
	}
}

func TestFinishTxnRejectsUnknownAndFinished(t *testing.T) {
	d, _ := newTestDB(t)
	ctx := t.Context()

	if err := d.FinishTxn(ctx, 9999, db.TxnCommitted, ""); err == nil {
		t.Error("finishing an unknown transaction should fail")
	}

	id, err := d.BeginTxn(ctx, testVersion, testJournalSchema)
	if err != nil {
		t.Fatalf("BeginTxn: %v", err)
	}
	if err := d.FinishTxn(ctx, id, db.TxnCommitted, ""); err != nil {
		t.Fatalf("FinishTxn: %v", err)
	}
	if err := d.FinishTxn(ctx, id, db.TxnRolledBack, ""); err == nil {
		t.Error("finishing an already-finished transaction should fail")
	}
}

func TestListTxnsMostRecentFirst(t *testing.T) {
	d, _ := newTestDB(t)
	ctx := t.Context()

	var ids []int64
	for range 3 {
		id, err := d.BeginTxn(ctx, testVersion, testJournalSchema)
		if err != nil {
			t.Fatalf("BeginTxn: %v", err)
		}
		if err := d.FinishTxn(ctx, id, db.TxnCommitted, ""); err != nil {
			t.Fatalf("FinishTxn: %v", err)
		}
		ids = append(ids, id)
	}

	all, err := d.ListTxns(ctx, 0)
	if err != nil {
		t.Fatalf("ListTxns(0): %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("ListTxns(0): got %d transactions, want 3", len(all))
	}
	if all[0].ID != ids[2] || all[2].ID != ids[0] {
		t.Errorf("ListTxns order: got first=%d last=%d, want most-recent first",
			all[0].ID, all[2].ID)
	}

	limited, err := d.ListTxns(ctx, 2)
	if err != nil {
		t.Fatalf("ListTxns(2): %v", err)
	}
	if len(limited) != 2 {
		t.Errorf("ListTxns(2): got %d, want 2", len(limited))
	}
}

func TestTxnOpsRoundTrip(t *testing.T) {
	d, _ := newTestDB(t)
	ctx := t.Context()
	id, err := d.BeginTxn(ctx, testVersion, testJournalSchema)
	if err != nil {
		t.Fatalf("BeginTxn: %v", err)
	}
	ops := []db.TxnOp{
		{Seq: 0, PackageName: "libc", Action: db.OpInstall, ToVersion: "2.39", OriginRepo: "official"},
		{Seq: 1, PackageName: "nginx", Action: db.OpUpgrade, FromVersion: "1.0", ToVersion: "1.1", OriginRepo: "official"},
		{Seq: 2, PackageName: "oldpkg", Action: db.OpRemove, FromVersion: "0.9"},
	}
	if err := d.InsertTxnOps(ctx, id, ops); err != nil {
		t.Fatalf("InsertTxnOps: %v", err)
	}
	got, err := d.TxnOps(ctx, id)
	if err != nil {
		t.Fatalf("TxnOps: %v", err)
	}
	want := make([]db.TxnOp, len(ops))
	for i, op := range ops {
		op.TxnID = id
		want[i] = op
	}
	if !slices.Equal(got, want) {
		t.Errorf("TxnOps round-trip:\n got %+v\nwant %+v", got, want)
	}
}

func TestTxnFilesRoundTrip(t *testing.T) {
	d, _ := newTestDB(t)
	ctx := t.Context()
	id, err := d.BeginTxn(ctx, testVersion, testJournalSchema)
	if err != nil {
		t.Fatalf("BeginTxn: %v", err)
	}
	if err := d.InsertTxnOps(ctx, id, []db.TxnOp{
		{Seq: 0, PackageName: "app", Action: db.OpInstall, ToVersion: "1.0"},
	}); err != nil {
		t.Fatalf("InsertTxnOps: %v", err)
	}
	files := []db.TxnFile{
		{Seq: 0, PackageName: "app", FinalPath: "/usr/bin/app", Action: db.FileCreate,
			StagedPath: "/usr/bin/app.peipkg-staged-1"},
		{Seq: 1, PackageName: "app", FinalPath: "/etc/app.conf", Action: db.FileReplace,
			StagedPath: "/etc/app.conf.peipkg-staged-1", BackupPath: "/etc/app.conf.peipkg-backup-1"},
		{Seq: 2, PackageName: "app", FinalPath: "/usr/bin/old", Action: db.FileRemove,
			BackupPath: "/usr/bin/old.peipkg-backup-1"},
	}
	if err := d.InsertTxnFiles(ctx, id, files); err != nil {
		t.Fatalf("InsertTxnFiles: %v", err)
	}
	got, err := d.TxnFiles(ctx, id)
	if err != nil {
		t.Fatalf("TxnFiles: %v", err)
	}
	want := make([]db.TxnFile, len(files))
	for i, f := range files {
		f.TxnID = id
		want[i] = f
	}
	if !slices.Equal(got, want) {
		t.Errorf("TxnFiles round-trip:\n got %+v\nwant %+v", got, want)
	}
}

// TestTxnFileRequiresAnOp exercises the composite foreign key: every
// txn_file must belong to a declared package operation.
func TestTxnFileRequiresAnOp(t *testing.T) {
	d, _ := newTestDB(t)
	ctx := t.Context()
	id, err := d.BeginTxn(ctx, testVersion, testJournalSchema)
	if err != nil {
		t.Fatalf("BeginTxn: %v", err)
	}
	// No InsertTxnOps for "unannounced".
	err = d.InsertTxnFiles(ctx, id, []db.TxnFile{
		{Seq: 0, PackageName: "unannounced", FinalPath: "/x", Action: db.FileCreate,
			StagedPath: "/x.staged"},
	})
	if err == nil {
		t.Error("a txn_file whose package has no txn_op should be rejected (foreign key)")
	}
}

func TestDeleteTxnCascades(t *testing.T) {
	d, _ := newTestDB(t)
	ctx := t.Context()
	id, err := d.BeginTxn(ctx, testVersion, testJournalSchema)
	if err != nil {
		t.Fatalf("BeginTxn: %v", err)
	}
	if err := d.InsertTxnOps(ctx, id, []db.TxnOp{
		{Seq: 0, PackageName: "app", Action: db.OpInstall, ToVersion: "1.0"},
	}); err != nil {
		t.Fatalf("InsertTxnOps: %v", err)
	}
	if err := d.InsertTxnFiles(ctx, id, []db.TxnFile{
		{Seq: 0, PackageName: "app", FinalPath: "/usr/bin/app", Action: db.FileCreate,
			StagedPath: "/usr/bin/app.staged"},
	}); err != nil {
		t.Fatalf("InsertTxnFiles: %v", err)
	}
	if err := d.FinishTxn(ctx, id, db.TxnCommitted, ""); err != nil {
		t.Fatalf("FinishTxn: %v", err)
	}

	if err := d.DeleteTxn(ctx, id); err != nil {
		t.Fatalf("DeleteTxn: %v", err)
	}
	if ops, err := d.TxnOps(ctx, id); err != nil || len(ops) != 0 {
		t.Errorf("txn_op rows after DeleteTxn: got %d (err %v), want 0", len(ops), err)
	}
	if files, err := d.TxnFiles(ctx, id); err != nil || len(files) != 0 {
		t.Errorf("txn_file rows after DeleteTxn: got %d (err %v), want 0", len(files), err)
	}
	if _, found, err := d.GetTxn(ctx, id); err != nil || found {
		t.Errorf("GetTxn after DeleteTxn: found=%v err=%v", found, err)
	}
}

// TestTxnOpVersionInvariants exercises the CHECK constraints tying the
// version columns to the operation's action.
func TestTxnOpVersionInvariants(t *testing.T) {
	d, _ := newTestDB(t)
	ctx := t.Context()
	id, err := d.BeginTxn(ctx, testVersion, testJournalSchema)
	if err != nil {
		t.Fatalf("BeginTxn: %v", err)
	}
	cases := []struct {
		name string
		op   db.TxnOp
	}{
		{"install carrying a from-version", db.TxnOp{Seq: 0, PackageName: "a",
			Action: db.OpInstall, FromVersion: "0.9", ToVersion: "1.0"}},
		{"install without a to-version", db.TxnOp{Seq: 0, PackageName: "a",
			Action: db.OpInstall}},
		{"remove carrying a to-version", db.TxnOp{Seq: 0, PackageName: "a",
			Action: db.OpRemove, FromVersion: "1.0", ToVersion: "1.1"}},
		{"upgrade without a from-version", db.TxnOp{Seq: 0, PackageName: "a",
			Action: db.OpUpgrade, ToVersion: "1.1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := d.InsertTxnOps(ctx, id, []db.TxnOp{tc.op}); err == nil {
				t.Errorf("an %s should be rejected by the schema", tc.name)
			}
		})
	}
}

// TestTxnFileActionInvariants exercises the CHECK constraints tying the
// staged_path and backup_path columns to the file action.
func TestTxnFileActionInvariants(t *testing.T) {
	d, _ := newTestDB(t)
	ctx := t.Context()
	id, err := d.BeginTxn(ctx, testVersion, testJournalSchema)
	if err != nil {
		t.Fatalf("BeginTxn: %v", err)
	}
	if err := d.InsertTxnOps(ctx, id, []db.TxnOp{
		{Seq: 0, PackageName: "a", Action: db.OpInstall, ToVersion: "1.0"},
	}); err != nil {
		t.Fatalf("InsertTxnOps: %v", err)
	}
	cases := []struct {
		name string
		file db.TxnFile
	}{
		{"create carrying a backup path", db.TxnFile{Seq: 0, PackageName: "a",
			FinalPath: "/x", Action: db.FileCreate, StagedPath: "/x.staged", BackupPath: "/x.backup"}},
		{"create without staged content", db.TxnFile{Seq: 0, PackageName: "a",
			FinalPath: "/x", Action: db.FileCreate}},
		{"remove carrying staged content", db.TxnFile{Seq: 0, PackageName: "a",
			FinalPath: "/x", Action: db.FileRemove, StagedPath: "/x.staged", BackupPath: "/x.backup"}},
		{"remove without a backup", db.TxnFile{Seq: 0, PackageName: "a",
			FinalPath: "/x", Action: db.FileRemove}},
		{"replace without a backup", db.TxnFile{Seq: 0, PackageName: "a",
			FinalPath: "/x", Action: db.FileReplace, StagedPath: "/x.staged"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := d.InsertTxnFiles(ctx, id, []db.TxnFile{tc.file}); err == nil {
				t.Errorf("a %s should be rejected by the schema", tc.name)
			}
		})
	}
}
