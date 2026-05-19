package install

import (
	"context"
	"fmt"
	"strings"

	"github.com/peios/peipkg/internal/db"
	"github.com/peios/peipkg/internal/resolver"
)

// writeJournal records a transaction's per-package operations and
// per-file actions — the crash-recovery journal (§7.4).
func writeJournal(ctx context.Context, store *db.DB, txnID int64, staged []stagedOp) error {
	ops := make([]db.TxnOp, 0, len(staged))
	var files []db.TxnFile
	seq := 0
	for i, s := range staged {
		ops = append(ops, db.TxnOp{
			Seq:         i,
			PackageName: s.op.Name,
			Action:      txnOpAction(s.op.Kind),
			FromVersion: s.op.FromVersion.String(),
			ToVersion:   s.op.ToVersion.String(),
			OriginRepo:  originRepo(s.op),
		})
		for _, fo := range s.fileOps {
			files = append(files, db.TxnFile{
				Seq:         seq,
				PackageName: s.op.Name,
				FinalPath:   fo.finalPath,
				Action:      txnFileAction(fo.action),
				StagedPath:  fo.stagedPath,
				BackupPath:  fo.backupPath,
			})
			seq++
		}
	}
	if err := store.InsertTxnOps(ctx, txnID, ops); err != nil {
		return err
	}
	return store.InsertTxnFiles(ctx, txnID, files)
}

// applyMetadata records the post-transaction package state. It runs
// inside the commit's SQLite transaction (§7.4.5).
func applyMetadata(ctx context.Context, tx *db.Tx, staged []stagedOp) error {
	for _, s := range staged {
		if s.op.Kind == resolver.OpRemove {
			if err := tx.DeletePackage(ctx, s.op.Name); err != nil {
				return err
			}
			continue
		}
		// An upgrade or downgrade replaces the package and its files
		// wholesale — the delete cascades the old package_file rows.
		if s.op.Kind != resolver.OpInstall {
			if err := tx.DeletePackage(ctx, s.op.Name); err != nil {
				return err
			}
		}
		if err := tx.InsertPackage(ctx, *s.pkg); err != nil {
			return err
		}
		if err := tx.InsertPackageFiles(ctx, s.files); err != nil {
			return err
		}
	}
	return nil
}

// fileOpsFromJournal reconstructs file operations from journalled rows,
// for crash recovery.
func fileOpsFromJournal(files []db.TxnFile) []fileOp {
	ops := make([]fileOp, len(files))
	for i, f := range files {
		ops[i] = fileOp{
			finalPath:  f.FinalPath,
			action:     fileActionFromDB(f.Action),
			stagedPath: f.StagedPath,
			backupPath: f.BackupPath,
		}
	}
	return ops
}

// operationSummary renders a one-line summary of a plan, for the
// transaction history.
func operationSummary(plan resolver.Plan) string {
	var counts [4]int
	for _, op := range plan.Operations {
		counts[op.Kind]++
	}
	var parts []string
	for kind, label := range map[resolver.OpKind]string{
		resolver.OpInstall:   "installed",
		resolver.OpUpgrade:   "upgraded",
		resolver.OpDowngrade: "downgraded",
		resolver.OpRemove:    "removed",
	} {
		if counts[kind] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[kind], label))
		}
	}
	if len(parts) == 0 {
		return "no changes"
	}
	return strings.Join(parts, ", ")
}

func txnOpAction(k resolver.OpKind) db.OpAction {
	switch k {
	case resolver.OpInstall:
		return db.OpInstall
	case resolver.OpUpgrade:
		return db.OpUpgrade
	case resolver.OpDowngrade:
		return db.OpDowngrade
	default:
		return db.OpRemove
	}
}

func txnFileAction(a fileAction) db.FileAction {
	switch a {
	case actionCreate:
		return db.FileCreate
	case actionReplace:
		return db.FileReplace
	default:
		return db.FileRemove
	}
}

func fileActionFromDB(a db.FileAction) fileAction {
	switch a {
	case db.FileCreate:
		return actionCreate
	case db.FileReplace:
		return actionReplace
	default:
		return actionRemove
	}
}
