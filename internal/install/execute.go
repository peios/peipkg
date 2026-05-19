package install

import (
	"context"
	"fmt"
	"io"

	"github.com/peios/peipkg/internal/archive"
	"github.com/peios/peipkg/internal/db"
	"github.com/peios/peipkg/internal/resolver"
)

// journalSchemaVersion is the journal format this build writes and can
// recover (§7.4). A pending journal from a newer peipkg is left for
// manual recovery.
const journalSchemaVersion = 1

// ProvidedPackage is a fetched, verified .peipkg ready to be staged.
type ProvidedPackage struct {
	// Pkg is the verified package: its manifest, verbatim manifest
	// bytes, and payload entry list.
	Pkg *archive.Package
	// Archive is the .peipkg container, positioned for archive.Extract.
	Archive io.ReadSeeker
}

// PackageProvider fetches and verifies the .peipkg a plan operation
// needs. The repository layer supplies the production implementation;
// Provide performs the §3.5.3 fetch-and-verify flow.
type PackageProvider interface {
	Provide(ctx context.Context, op resolver.Operation) (ProvidedPackage, error)
}

// Env is the environment one execution runs in.
type Env struct {
	// Root is the filesystem root payloads install under — "/" in
	// production, a temporary directory under test.
	Root string
	// DB is the package database.
	DB *db.DB
	// Provider fetches and verifies the plan's packages.
	Provider PackageProvider
	// LockPath is the single-writer lock file.
	LockPath string
	// PeipkgVersion is recorded as the transaction's started_by_version.
	PeipkgVersion string
	// RunSideEffects enables the post-commit maintenance operations.
	RunSideEffects bool
}

// Result reports the outcome of a successful execution.
type Result struct {
	// Warnings are non-fatal problems — chiefly post-commit side-effect
	// failures — that the operator should see. The transaction
	// committed regardless.
	Warnings []string
}

// Execute applies a resolved plan to the system as one transaction
// (PSD-009 chapter 7): it stages every package, commits the file
// changes and the database state atomically, and runs the post-commit
// side effects. Any failure before the durability boundary leaves the
// system in its pre-transaction state.
func Execute(ctx context.Context, plan resolver.Plan, env Env) (Result, error) {
	lock, err := Acquire(env.LockPath)
	if err != nil {
		return Result{}, err
	}
	defer lock.Release()

	// A journal left pending by an interrupted earlier run is rolled
	// back before anything new begins (§7.4.7).
	if err := recoverPending(ctx, env); err != nil {
		return Result{}, err
	}
	if len(plan.Operations) == 0 {
		return Result{}, nil
	}
	return runTransaction(ctx, plan, env)
}

// Recover rolls back a transaction left pending by an interrupted run,
// independently of any new plan — the `peipkg recover` path. It is a
// no-op when no transaction is pending.
func Recover(ctx context.Context, env Env) error {
	lock, err := Acquire(env.LockPath)
	if err != nil {
		return err
	}
	defer lock.Release()
	return recoverPending(ctx, env)
}

// runTransaction stages, commits, and finalises one plan.
func runTransaction(ctx context.Context, plan resolver.Plan, env Env) (Result, error) {
	// §7.4.3: fetch and verify every package before staging any of them.
	provided := make(map[string]ProvidedPackage)
	for _, op := range plan.Operations {
		if op.Kind == resolver.OpRemove {
			continue
		}
		pp, err := env.Provider.Provide(ctx, op)
		if err != nil {
			return Result{}, fmt.Errorf("peipkg/install: providing %s: %w", op.Name, err)
		}
		provided[op.Name] = pp
	}

	txnID, err := env.DB.BeginTxn(ctx, env.PeipkgVersion, journalSchemaVersion)
	if err != nil {
		return Result{}, err
	}

	// Stage every operation. A failure rolls back whatever was staged
	// and abandons the transaction; nothing has been committed.
	staged := make([]stagedOp, 0, len(plan.Operations))
	for _, op := range plan.Operations {
		s, err := stageOperation(ctx, env, txnID, op, provided)
		staged = append(staged, s) // s carries its file ops even on failure
		if err != nil {
			abandon(ctx, env, txnID, staged, "staging failed")
			return Result{}, err
		}
	}

	if err := writeJournal(ctx, env.DB, txnID, staged); err != nil {
		abandon(ctx, env, txnID, staged, "recording the journal failed")
		return Result{}, err
	}

	ops := allFileOps(staged)
	if err := commitOps(ops); err != nil {
		_ = rollbackOps(ops)
		_ = env.DB.FinishTxn(ctx, txnID, db.TxnRolledBack, "applying file changes failed")
		return Result{}, err
	}

	// The durability boundary (§7.4.5, F2): the new package state and
	// the journal's closure commit together in one SQLite transaction.
	// Until it returns, a crash leaves a pending journal that recovery
	// rolls back; once it returns, the transaction is complete.
	err = env.DB.Tx(ctx, func(tx *db.Tx) error {
		if err := applyMetadata(ctx, tx, staged); err != nil {
			return err
		}
		return tx.FinishTxn(ctx, txnID, db.TxnCommitted, operationSummary(plan))
	})
	if err != nil {
		_ = rollbackOps(ops)
		_ = env.DB.FinishTxn(ctx, txnID, db.TxnRolledBack, "committing package state failed")
		return Result{}, fmt.Errorf("peipkg/install: committing transaction %d: %w", txnID, err)
	}

	// The transaction has committed. Surface the staging-time warnings
	// (§7.2.2 modified /etc files), discard the now-purposeless backups
	// (§7.2.2 step 4.3), and run the post-commit side effects.
	var result Result
	for _, s := range staged {
		result.Warnings = append(result.Warnings, s.warnings...)
	}
	result.Warnings = append(result.Warnings, discardBackups(ops)...)
	if env.RunSideEffects {
		result.Warnings = append(result.Warnings, runSideEffects(sideEffectsOf(staged))...)
	}
	return result, nil
}

// abandon rolls back a transaction that failed during staging and marks
// it rolled back in the journal.
func abandon(ctx context.Context, env Env, txnID int64, staged []stagedOp, reason string) {
	_ = rollbackOps(allFileOps(staged))
	_ = env.DB.FinishTxn(ctx, txnID, db.TxnRolledBack, reason)
}

// recoverPending rolls back a transaction left pending by an
// interrupted run (§7.4.7). Recovery reverses the journalled file
// operations idempotently and marks the transaction rolled back.
func recoverPending(ctx context.Context, env Env) error {
	txn, found, err := env.DB.PendingTxn(ctx)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}
	if txn.JournalSchemaVersion > journalSchemaVersion {
		return fmt.Errorf("peipkg/install: transaction %d was written by a newer peipkg "+
			"(journal schema %d); recover it with that version",
			txn.ID, txn.JournalSchemaVersion)
	}
	files, err := env.DB.TxnFiles(ctx, txn.ID)
	if err != nil {
		return err
	}
	if err := rollbackOps(fileOpsFromJournal(files)); err != nil {
		return fmt.Errorf("peipkg/install: recovering transaction %d: %w", txn.ID, err)
	}
	if err := env.DB.FinishTxn(ctx, txn.ID, db.TxnRolledBack,
		"rolled back after an interrupted run"); err != nil {
		return err
	}
	return nil
}

// allFileOps flattens the file operations of every staged operation, in
// order.
func allFileOps(staged []stagedOp) []fileOp {
	var ops []fileOp
	for _, s := range staged {
		ops = append(ops, s.fileOps...)
	}
	return ops
}

// sideEffectsOf collects, de-duplicated, the side effects declared by
// every package being installed or upgraded.
func sideEffectsOf(staged []stagedOp) []string {
	seen := map[string]bool{}
	var effects []string
	for _, s := range staged {
		if s.pkg == nil {
			continue // a removal declares no side effects
		}
		for _, e := range s.sideEffects {
			if !seen[e] {
				seen[e] = true
				effects = append(effects, e)
			}
		}
	}
	return effects
}
