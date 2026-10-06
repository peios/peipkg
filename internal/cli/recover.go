package cli

import (
	"context"
	"sort"

	"github.com/peios/peipkg/internal/audit"
	"github.com/peios/peipkg/internal/db"
	"github.com/peios/peipkg/internal/install"
)

// cmdRecover rolls back a transaction left pending by an interrupted run
// (§7.4.7), reconciling cross-root transactions across the roots they
// touched (DESIGN-named-roots.md). It walks the registry from the current
// root, so running it from the system anchor reaches every root.
func cmdRecover(app *App, args []string) error {
	fs := flags("recover")
	if err := fs.Parse(args); err != nil {
		return err
	}
	// Every run is recorded, including one with nothing to recover and
	// one that failed part-way, with the transactions rolled back so far.
	recovered, err := recoverAll(app)
	ev := audit.New(audit.TypeTransactionRecovered).
		Uint(audit.FieldOperationSucceeded, uint64(recovered))
	if err != nil {
		ev = ev.Failed("", err.Error())
	} else {
		ev = ev.Succeeded()
	}
	app.emit(ev)
	return err
}

// recoverAll does cmdRecover's work, reporting how many interrupted
// transactions it rolled back, including on failure.
func recoverAll(app *App) (int, error) {
	ctx := context.Background()

	// The reachable roots: the current root plus every named root under it.
	refs, err := gatherRootRefs(ctx, app.paths.root)
	if err != nil {
		return 0, err
	}
	rootPaths := map[string]bool{app.paths.root: true}
	for _, path := range refs {
		rootPaths[path] = true
	}

	// Open each reachable root that has a database, and classify what is
	// pending: ordinary single-root transactions, and the cross-root
	// transaction ids that need reconciling as a unit.
	envs := map[string]install.Env{}
	var opened []*db.DB
	defer func() {
		for _, d := range opened {
			_ = d.Close()
		}
	}()
	var singleRoot []string
	crossIDs := map[string]bool{}
	for path := range rootPaths {
		store, exists, err := openRootDBForRecover(ctx, app, path)
		if err != nil {
			return 0, err
		}
		if !exists {
			continue
		}
		opened = append(opened, store)
		p := newPaths(path)
		envs[path] = install.Env{Root: path, DB: store, LockPath: p.lockPath, PeipkgVersion: peipkgVersion}

		txn, pending, err := store.PendingTxn(ctx)
		if err != nil {
			return 0, err
		}
		if !pending {
			continue
		}
		if txn.CrossRootID != "" {
			crossIDs[txn.CrossRootID] = true
		} else {
			singleRoot = append(singleRoot, path)
		}
	}

	if len(singleRoot) == 0 && len(crossIDs) == 0 {
		app.printf("no interrupted transaction to recover\n")
		return 0, nil
	}

	recovered := 0
	// Single-root pending transactions: each is rolled back independently.
	sort.Strings(singleRoot)
	for _, path := range singleRoot {
		if err := install.Recover(ctx, envs[path]); err != nil {
			return recovered, err
		}
		app.printf("recovered: rolled back the interrupted transaction in %s\n", path)
		recovered++
	}
	// Cross-root pending transactions: reconcile each across its roots.
	ids := make([]string, 0, len(crossIDs))
	for id := range crossIDs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		rolledBack, err := install.RecoverCrossRoot(ctx, envs, id)
		if err != nil {
			return recovered, err
		}
		if rolledBack {
			app.printf("recovered: rolled back cross-root transaction %s\n", id)
			recovered++
		}
	}
	return recovered, nil
}

// openRootDBForRecover opens the database of a reachable root: the current
// root is created if absent (it is where recovery was invoked), other
// roots are opened only if their database already exists.
func openRootDBForRecover(ctx context.Context, app *App, path string) (*db.DB, bool, error) {
	if sameRoot(path, app.paths.root) {
		store, err := app.openDBAt(ctx, path)
		return store, err == nil, err
	}
	return openRootDB(ctx, path)
}
