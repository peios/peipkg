package cli

import (
	"context"

	"github.com/peios/peipkg/internal/audit"
	"github.com/peios/peipkg/internal/install"
)

// cmdRecover rolls back a transaction left pending by an interrupted
// run (§7.4.7).
func cmdRecover(app *App, args []string) error {
	fs := flags("recover")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx := context.Background()
	store, err := app.openDB(ctx)
	if err != nil {
		return err
	}
	defer store.Close()

	_, pending, err := store.PendingTxn(ctx)
	if err != nil {
		return err
	}
	if !pending {
		app.printf("no interrupted transaction to recover\n")
		return nil
	}
	env := install.Env{
		Root:          app.paths.root,
		DB:            store,
		LockPath:      app.paths.lockPath,
		PeipkgVersion: peipkgVersion,
	}
	if err := install.Recover(ctx, env); err != nil {
		return err
	}
	app.emit(audit.Event{Type: audit.TypeRecovery, Outcome: audit.OutcomeSuccess,
		Detail: "an interrupted transaction was rolled back"})
	app.printf("recovered: the interrupted transaction was rolled back\n")
	return nil
}
