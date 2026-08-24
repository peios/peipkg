package install

import (
	"context"
	"fmt"
	"io"
	"sort"

	"github.com/peios/peipkg/internal/archive"
	"github.com/peios/peipkg/internal/db"
	"github.com/peios/peipkg/internal/resolver"
)

// journalSchemaVersion is the journal format this build writes and can
// recover (§7.4). A pending journal from a newer peipkg is left for
// manual recovery.
const journalSchemaVersion = 2

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
	// Claims directs install-time claim behaviour (§7.7.2). The zero
	// value auto-claims unheld roles the installed packages provide.
	Claims ClaimDirective
	// BypassPathRestrictions waives the §3.4 payload layout check for
	// packages that declare special_system_package — the operator's half
	// of the two-key exemption (peipkg install
	// --dangerously-bypass-path-restrictions). It has no effect on a
	// package that does not declare itself special: a package cannot be
	// exempted without saying so, and saying so exempts nothing on its
	// own.
	BypassPathRestrictions bool
}

// Result reports the outcome of an execution.
type Result struct {
	// TxnID identifies the transaction this execution opened. It is set
	// whenever a transaction was begun — including on the failure paths
	// — so the caller can audit the outcome (§7.6); it is zero only when
	// the run failed before any transaction was opened.
	TxnID int64
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

// ExecuteCrossRoot applies a plan that spans several roots as one logical
// transaction (DESIGN-named-roots.md → cross-root dependencies). envs maps
// each root key an operation targets (resolver.Operation.Root) to that
// root's Env; every distinct target root in the plan MUST have an entry.
// crossRootID ties the participating roots' journal rows together so
// recovery can reconcile them as a unit. It returns each root's Result,
// keyed by root.
//
// It is a two-phase commit over the participating roots:
//
//  1. Acquire every root's single-writer lock in resolved-path order. A
//     total order means two concurrent cross-root operations cannot
//     deadlock. Release is in reverse.
//  2. Reconcile any pending journal in each root first.
//  3. Prepare every root — fetch, verify, journal, move payloads into
//     place (each root "votes to commit"). A prepare failure in any root
//     rolls every already-prepared root back, leaving the system
//     unchanged; nothing has crossed a durability boundary.
//  4. Commit each root's package state in path order. A commit failure
//     leaves the remaining roots' prepared journals in place for `peipkg
//     recover` to roll forward — already-committed roots stay committed —
//     and is reported. (Roll-forward, not roll-back, because every root
//     was already staged and verified in step 3.)
func ExecuteCrossRoot(ctx context.Context, plan resolver.Plan, envs map[string]Env,
	crossRootID string) (map[string]Result, error) {

	// Partition the plan by target root, preserving each root's relative
	// operation order from the globally dependency-ordered plan.
	byRoot := map[string][]resolver.Operation{}
	for _, op := range plan.Operations {
		byRoot[op.Root] = append(byRoot[op.Root], op)
	}
	roots := make([]string, 0, len(byRoot))
	for r := range byRoot {
		if _, ok := envs[r]; !ok {
			return nil, fmt.Errorf("peipkg/install: no environment for plan root %q", r)
		}
		roots = append(roots, r)
	}
	sort.Strings(roots) // resolved-path order: the lock and commit order

	// 1. Acquire every root's lock, in path order.
	var locks []*Lock
	defer func() {
		for i := len(locks) - 1; i >= 0; i-- {
			_ = locks[i].Release()
		}
	}()
	for _, r := range roots {
		lock, err := Acquire(envs[r].LockPath)
		if err != nil {
			return nil, err
		}
		locks = append(locks, lock)
	}

	// 2. Reconcile any pending journal in each root before starting.
	for _, r := range roots {
		if err := recoverPending(ctx, envs[r]); err != nil {
			return nil, err
		}
	}

	// 3. Prepare every root. On failure, roll back the roots that already
	//    voted; the failed root abandoned itself inside prepareTxn.
	prepared := make(map[string]preparedTxn, len(roots))
	var order []string // roots prepared so far, for ordered rollback
	for _, r := range roots {
		p, err := prepareTxn(ctx, resolver.Plan{Operations: byRoot[r]}, envs[r], crossRootID)
		if err != nil {
			for i := len(order) - 1; i >= 0; i-- {
				rollbackPrepared(ctx, prepared[order[i]])
			}
			return nil, fmt.Errorf("peipkg/install: preparing root %q: %w", r, err)
		}
		prepared[r] = p
		order = append(order, r)
	}

	// 4. Commit every root in path order. Keep going past a failure
	//    (roll forward); report any failure for `peipkg recover`.
	results := make(map[string]Result, len(roots))
	var firstErr error
	for _, r := range roots {
		res, err := commitTxn(ctx, prepared[r], false)
		results[r] = res
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if firstErr != nil {
		return results, fmt.Errorf("peipkg/install: cross-root transaction %s is partially "+
			"committed; run `peipkg recover` to roll it forward: %w", crossRootID, firstErr)
	}
	return results, nil
}

// runTransaction stages, commits, and finalises one single-root plan: it
// is prepare-then-commit with no cross-root id.
func runTransaction(ctx context.Context, plan resolver.Plan, env Env) (Result, error) {
	p, err := prepareTxn(ctx, plan, env, "")
	if err != nil {
		return Result{TxnID: p.txnID}, err
	}
	return commitTxn(ctx, p, true)
}

// preparedTxn is a transaction staged up to — but not past — its
// durability boundary: its payloads are fetched, verified, journalled,
// and moved into their final on-disk places (displaced files saved to
// backups), but the package state is not yet recorded. A prepared
// transaction is reversible (rollbackPrepared) or committable (commitTxn).
// In two-phase-commit terms, reaching this state is a root's "vote".
type preparedTxn struct {
	env           Env
	txnID         int64
	plan          resolver.Plan
	staged        []stagedOp
	claimW        claimWork
	claimWarnings []string
	ops           []fileOp
}

// prepareTxn runs a plan's prepare phase: §7.4.3 fetch-and-verify-all,
// open the journal (tagged with crossRootID, empty for a single-root
// transaction), compute and write the journal, then materialise and move
// every payload into place. On any failure it abandons the transaction —
// reversing whatever was staged and marking the journal rolled back — and
// returns the error; the returned preparedTxn still carries the txn id so
// the caller can audit the outcome. On success the transaction has
// "voted to commit": nothing is committed, but everything is in place and
// recorded in the journal, so it can be committed or cleanly reversed.
func prepareTxn(ctx context.Context, plan resolver.Plan, env Env, crossRootID string) (preparedTxn, error) {
	// §7.4.3: fetch and verify every package before staging any of them.
	provided := make(map[string]ProvidedPackage)
	for _, op := range plan.Operations {
		if op.Kind == resolver.OpRemove {
			continue
		}
		pp, err := env.Provider.Provide(ctx, op)
		if err != nil {
			return preparedTxn{}, fmt.Errorf("peipkg/install: providing %s: %w", op.Name, err)
		}
		provided[op.Name] = pp
	}

	txnID, err := env.DB.BeginCrossRootTxn(ctx, env.PeipkgVersion, journalSchemaVersion, crossRootID)
	if err != nil {
		return preparedTxn{}, err
	}
	p := preparedTxn{env: env, txnID: txnID, plan: plan}

	// Compute every journal row before touching the filesystem. Once the
	// journal is durable, any staged payload content has a recovery path.
	plannedDirs := map[string]bool{}
	for _, op := range plan.Operations {
		s, err := prepareOperation(ctx, env, txnID, op, provided, plannedDirs)
		p.staged = append(p.staged, s)
		if err != nil {
			abandon(ctx, env, txnID, p.staged, "preparing the journal failed")
			return p, err
		}
	}

	// Claim reconciliation (§4.4.4): compute the claim links this
	// transaction must create, repoint, or remove, and attach their file
	// operations to a carrier package op so they ride the same journal,
	// commit, and recovery path as payload files.
	p.claimW, p.claimWarnings, err = planClaims(ctx, env, plan, provided, env.Claims, txnID, plannedDirs)
	if err != nil {
		abandon(ctx, env, txnID, p.staged, "planning claims failed")
		return p, err
	}
	if !p.claimW.empty() {
		carrier := len(p.staged) - 1
		p.staged[carrier].fileOps = append(p.staged[carrier].fileOps, p.claimW.fileOps...)
		p.staged[carrier].createdDirs = append(p.staged[carrier].createdDirs, p.claimW.createdDirs...)
	}

	if err := writeJournal(ctx, env.DB, txnID, p.staged); err != nil {
		abandon(ctx, env, txnID, p.staged, "recording the journal failed")
		return p, err
	}

	// For a cross-root transaction, persist the forward-commit payload now
	// — while the journal is being made durable, before any root commits —
	// so a torn-commit recovery can roll this root forward. Single-root
	// transactions never roll forward, so they write none.
	if crossRootID != "" {
		payload, err := buildCommitPayload(p.staged, p.claimW).marshal()
		if err != nil {
			abandon(ctx, env, txnID, p.staged, "encoding the commit payload failed")
			return p, err
		}
		if err := env.DB.SetCommitPayload(ctx, txnID, payload); err != nil {
			abandon(ctx, env, txnID, p.staged, "recording the commit payload failed")
			return p, err
		}
	}

	// Materialize staged content after the journal exists. A failure
	// rolls back whatever was written and abandons the transaction;
	// nothing has been committed.
	for _, s := range p.staged {
		if s.op.Kind == resolver.OpRemove {
			continue
		}
		if err := materializePackage(env, s, provided[s.op.Name]); err != nil {
			abandon(ctx, env, txnID, p.staged, "staging failed")
			return p, err
		}
	}
	if err := materializeClaims(p.claimW); err != nil {
		abandon(ctx, env, txnID, p.staged, "staging claim links failed")
		return p, err
	}

	p.ops = allFileOps(p.staged)
	if err := commitOps(p.ops); err != nil {
		_ = rollbackOps(p.ops)
		_ = removeCreatedDirs(allCreatedDirs(p.staged))
		_ = env.DB.FinishTxn(ctx, txnID, db.TxnRolledBack, "applying file changes failed")
		return p, err
	}
	return p, nil
}

// commitTxn crosses the durability boundary (§7.4.5, F2): the new package
// state and the journal's closure commit together in one SQLite
// transaction. Until it returns, a crash leaves a pending journal that
// recovery resolves; once it returns, the transaction is complete.
//
// rollbackOnFailure governs what happens if that SQLite commit fails. A
// single-root transaction passes true: reverse the on-disk changes and
// mark the journal rolled back, leaving the system as it was. A cross-root
// participant passes false: leave the prepared changes and the pending
// journal in place so recovery can roll the whole cross-root transaction
// forward — un-committing this root in isolation would be the very torn
// state the cross-root id exists to avoid.
func commitTxn(ctx context.Context, p preparedTxn, rollbackOnFailure bool) (Result, error) {
	env := p.env
	err := env.DB.Tx(ctx, func(tx *db.Tx) error {
		if err := applyMetadata(ctx, tx, p.staged); err != nil {
			return err
		}
		if err := applyClaimMetadata(ctx, tx, p.claimW); err != nil {
			return err
		}
		return tx.FinishTxn(ctx, p.txnID, db.TxnCommitted, operationSummary(p.plan))
	})
	if err != nil {
		if rollbackOnFailure {
			_ = rollbackOps(p.ops)
			_ = removeCreatedDirs(allCreatedDirs(p.staged))
			_ = env.DB.FinishTxn(ctx, p.txnID, db.TxnRolledBack, "committing package state failed")
		}
		return Result{TxnID: p.txnID},
			fmt.Errorf("peipkg/install: committing transaction %d: %w", p.txnID, err)
	}

	// The transaction has committed. Surface the staging-time warnings
	// (§7.2.2 modified /etc files), discard the now-purposeless backups
	// (§7.2.2 step 4.3), and run the post-commit side effects.
	result := Result{TxnID: p.txnID}
	for _, s := range p.staged {
		result.Warnings = append(result.Warnings, s.warnings...)
	}
	result.Warnings = append(result.Warnings, p.claimWarnings...)
	result.Warnings = append(result.Warnings, discardBackups(p.ops)...)
	if env.RunSideEffects {
		effects, warnings := plannedSideEffects(p.staged)
		result.Warnings = append(result.Warnings, warnings...)
		result.Warnings = append(result.Warnings, runSideEffects(effects)...)
	}
	return result, nil
}

// rollbackPrepared reverses a prepared-but-uncommitted transaction: the
// on-disk changes are undone from the journal's backups and the journal is
// marked rolled back. It is how a cross-root transaction backs out a root
// that voted to commit when a sibling root failed to prepare.
func rollbackPrepared(ctx context.Context, p preparedTxn) {
	_ = rollbackOps(p.ops)
	_ = removeCreatedDirs(allCreatedDirs(p.staged))
	_ = p.env.DB.FinishTxn(ctx, p.txnID, db.TxnRolledBack, "rolled back: a sibling root failed to prepare")
}

// abandon rolls back a transaction that failed during staging and marks
// it rolled back in the journal.
func abandon(ctx context.Context, env Env, txnID int64, staged []stagedOp, reason string) {
	_ = rollbackOps(allFileOps(staged))
	_ = removeCreatedDirs(allCreatedDirs(staged))
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
	// A pending cross-root transaction must not be rolled back in
	// isolation: reversing one root while a sibling stayed committed is
	// the torn state the cross-root id exists to prevent. Reconciling it
	// (roll the whole cross-root transaction forward, else roll all back)
	// is the cross-root recovery path; refuse here rather than corrupt.
	if txn.CrossRootID != "" {
		return fmt.Errorf("peipkg/install: an interrupted cross-root transaction (%s) is "+
			"pending in this root; reconcile it with `peipkg recover` before continuing",
			txn.CrossRootID)
	}
	return rollbackTxn(ctx, env, txn, "rolled back after an interrupted run")
}

// rollbackTxn reverses a pending transaction's journalled file operations
// — idempotently — and marks it rolled back. It is the shared mechanism
// behind single-root recovery and cross-root roll-back-all. The caller
// must have decided that rolling this transaction back is correct (a
// pending cross-root participant is only rolled back once recovery has
// confirmed no sibling committed).
func rollbackTxn(ctx context.Context, env Env, txn db.Txn, reason string) error {
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
	if txn.JournalSchemaVersion >= 2 {
		dirs, err := env.DB.TxnDirs(ctx, txn.ID)
		if err != nil {
			return err
		}
		if err := removeCreatedDirs(dirs); err != nil {
			return fmt.Errorf("peipkg/install: recovering transaction %d: %w", txn.ID, err)
		}
	}
	return env.DB.FinishTxn(ctx, txn.ID, db.TxnRolledBack, reason)
}

// rollForwardTxn completes a prepared-but-pending transaction during
// cross-root recovery: its payloads are already in place on disk
// (commitOps ran during prepare), so it applies the persisted forward
// state, crosses the durability boundary, and discards the now-purposeless
// backups. It is the roll-forward half of cross-root reconciliation.
func rollForwardTxn(ctx context.Context, env Env, txn db.Txn, cp commitPayload) error {
	if txn.JournalSchemaVersion > journalSchemaVersion {
		return fmt.Errorf("peipkg/install: transaction %d was written by a newer peipkg "+
			"(journal schema %d); recover it with that version",
			txn.ID, txn.JournalSchemaVersion)
	}
	if err := env.DB.Tx(ctx, func(tx *db.Tx) error {
		if err := applyCommitPayload(ctx, tx, cp); err != nil {
			return err
		}
		return tx.FinishTxn(ctx, txn.ID, db.TxnCommitted, "rolled forward: cross-root recovery")
	}); err != nil {
		return fmt.Errorf("peipkg/install: rolling transaction %d forward: %w", txn.ID, err)
	}
	// The backups the prepared transaction retained are no longer needed
	// (best-effort cleanup, as a normal commit does).
	if files, err := env.DB.TxnFiles(ctx, txn.ID); err == nil {
		discardBackups(fileOpsFromJournal(files))
	}
	return nil
}

// RecoverCrossRoot reconciles an interrupted cross-root transaction
// (DESIGN-named-roots.md). envs are the environments of every reachable
// root; the participants are those whose database holds a transaction
// tagged crossRootID. It locks the participants in resolved-path order
// and then decides by whether any participant committed:
//
//   - none committed → the transaction never crossed a durability
//     boundary in any root, so every pending participant is rolled back.
//     This is the common interrupted case (a crash during prepare, or
//     before the commit loop committed anything).
//   - some committed → a torn commit: the executor's commit loop was
//     interrupted partway. The committed root cannot be undone (its
//     backups are gone), so the pending roots are rolled FORWARD from the
//     forward payload each persisted at prepare time, completing the
//     transaction. A pending root with no payload (a degenerate state)
//     cannot be completed; recovery then refuses rather than tear it.
//
// reconciled is true when recovery acted (rolled back or forward).
func RecoverCrossRoot(ctx context.Context, envs map[string]Env, crossRootID string) (reconciled bool, err error) {
	// Identify participants and order them by resolved path.
	type participant struct {
		root string
		env  Env
		txn  db.Txn
	}
	var parts []participant
	for root, env := range envs {
		txns, err := env.DB.TxnsByCrossRootID(ctx, crossRootID)
		if err != nil {
			return false, err
		}
		for _, txn := range txns {
			parts = append(parts, participant{root: root, env: env, txn: txn})
		}
	}
	if len(parts) == 0 {
		return false, fmt.Errorf("peipkg/install: no transaction with cross-root id %s in any "+
			"reachable root", crossRootID)
	}
	sort.Slice(parts, func(i, j int) bool { return parts[i].root < parts[j].root })

	// Lock every participating root in path order; release in reverse.
	var locks []*Lock
	defer func() {
		for i := len(locks) - 1; i >= 0; i-- {
			_ = locks[i].Release()
		}
	}()
	for _, p := range parts {
		lock, lockErr := Acquire(p.env.LockPath)
		if lockErr != nil {
			return false, lockErr
		}
		locks = append(locks, lock)
	}

	// Re-read each participant's state under lock: it may have changed
	// between the initial scan and acquiring the locks.
	var committed, pending []participant
	for _, p := range parts {
		txn, found, err := p.env.DB.GetTxn(ctx, p.txn.ID)
		if err != nil {
			return false, err
		}
		if !found {
			continue
		}
		p.txn = txn
		switch txn.State {
		case db.TxnCommitted:
			committed = append(committed, p)
		case db.TxnPending:
			pending = append(pending, p)
		}
	}

	if len(committed) > 0 {
		// Torn commit: a sibling already committed, so the transaction must
		// be rolled FORWARD — the committed root cannot be undone (its
		// backups are gone). Every pending participant is fully prepared
		// (the commit loop only runs once all roots prepared), so its
		// forward payload was persisted; load and replay it. If any pending
		// participant has no payload — an old or hand-built transaction
		// recovery cannot complete — refuse rather than leave it half-done.
		for _, p := range pending {
			payload, found, err := p.env.DB.CommitPayload(ctx, p.txn.ID)
			if err != nil {
				return false, err
			}
			if !found {
				return false, fmt.Errorf("peipkg/install: cross-root transaction %s is torn and "+
					"root %q carries no commit payload to roll forward; resolve it manually",
					crossRootID, p.root)
			}
			cp, err := unmarshalCommitPayload(payload)
			if err != nil {
				return false, err
			}
			if err := rollForwardTxn(ctx, p.env, p.txn, cp); err != nil {
				return false, err
			}
		}
		return len(pending) > 0, nil
	}

	// No root committed: roll every pending participant back.
	for _, p := range pending {
		if err := rollbackTxn(ctx, p.env, p.txn,
			"rolled back: interrupted cross-root transaction, no root committed"); err != nil {
			return false, err
		}
	}
	return len(pending) > 0, nil
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

// allCreatedDirs flattens the directories a transaction may have
// created during staging.
func allCreatedDirs(staged []stagedOp) []string {
	var dirs []string
	for _, s := range staged {
		dirs = append(dirs, s.createdDirs...)
	}
	return dirs
}
