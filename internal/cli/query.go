package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/peios/peipkg/internal/db"
	"github.com/peios/peipkg/internal/manifest"
)

// flags builds a command's flag set, with errors suppressed so a parse
// failure is reported once, by Run.
func flags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

// parseArgs parses fs against args and returns the positional
// arguments. Unlike a plain flag.Parse, it accepts flags and
// positionals in any order — `install nginx --yes` works as well as
// `install --yes nginx`.
func parseArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	var positionals []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return positionals, nil
		}
		positionals = append(positionals, rest[0])
		args = rest[1:]
	}
}

// emitJSON writes v to standard output as indented JSON.
func (app *App) emitJSON(v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding JSON: %w", err)
	}
	app.printf("%s\n", data)
	return nil
}

// cmdList prints the installed packages.
func cmdList(app *App, args []string) error {
	fs := flags("list")
	asJSON := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx := context.Background()
	store, err := app.openDB(ctx)
	if err != nil {
		return err
	}
	defer store.Close()

	pkgs, err := store.ListPackages(ctx)
	if err != nil {
		return err
	}
	if *asJSON {
		type view struct {
			Name, Version, Architecture, Origin string
		}
		views := make([]view, len(pkgs))
		for i, p := range pkgs {
			views[i] = view{p.Name, p.Version, p.Architecture, p.OriginRepo}
		}
		return app.emitJSON(views)
	}
	if len(pkgs) == 0 {
		app.printf("no packages are installed\n")
		return nil
	}
	for _, p := range pkgs {
		app.printf("%s  %s  %s\n", p.Name, p.Version, p.Architecture)
	}
	return nil
}

// cmdInfo prints the details of one installed package.
func cmdInfo(app *App, args []string) error {
	fs := flags("info")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("info: exactly one package name is required")
	}
	name := pos[0]

	ctx := context.Background()
	store, err := app.openDB(ctx)
	if err != nil {
		return err
	}
	defer store.Close()

	pkg, found, err := store.GetPackage(ctx, name)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("info: %q is not installed", name)
	}
	app.printf("name:         %s\n", pkg.Name)
	app.printf("version:      %s\n", pkg.Version)
	app.printf("architecture: %s\n", pkg.Architecture)
	if pkg.OriginRepo != "" {
		app.printf("origin:       %s\n", pkg.OriginRepo)
	} else {
		app.printf("origin:       (local file)\n")
	}
	app.printf("installed:    %s\n", pkg.InstalledAt.Format(time.RFC3339))
	if m, err := manifest.Decode([]byte(pkg.Manifest)); err == nil {
		if m.Description != "" {
			app.printf("description:  %s\n", m.Description)
		}
		if m.License != "" {
			app.printf("license:      %s\n", m.License)
		}
		if m.Homepage != "" {
			app.printf("homepage:     %s\n", m.Homepage)
		}
	}
	return nil
}

// cmdFiles prints the filesystem objects a package owns.
func cmdFiles(app *App, args []string) error {
	fs := flags("files")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("files: exactly one package name is required")
	}
	name := pos[0]

	ctx := context.Background()
	store, err := app.openDB(ctx)
	if err != nil {
		return err
	}
	defer store.Close()

	if _, found, err := store.GetPackage(ctx, name); err != nil {
		return err
	} else if !found {
		return fmt.Errorf("files: %q is not installed", name)
	}
	files, err := store.PackageFiles(ctx, name)
	if err != nil {
		return err
	}
	for _, f := range files {
		app.printf("%s\n", f.Path)
	}
	return nil
}

// cmdOwns reports which package owns a path.
func cmdOwns(app *App, args []string) error {
	fs := flags("owns")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("owns: exactly one path is required")
	}
	path := pos[0]

	ctx := context.Background()
	store, err := app.openDB(ctx)
	if err != nil {
		return err
	}
	defer store.Close()

	owners, err := store.FileOwners(ctx, path)
	if err != nil {
		return err
	}
	if len(owners) == 0 {
		return fmt.Errorf("owns: no package owns %q", path)
	}
	for _, o := range owners {
		app.printf("%s\n", o.PackageName)
	}
	return nil
}

// cmdHistory prints the transaction history, most recent first.
func cmdHistory(app *App, args []string) error {
	fs := flags("history")
	limit := fs.Int("n", 20, "show at most this many transactions (0 for all)")
	asJSON := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx := context.Background()
	store, err := app.openDB(ctx)
	if err != nil {
		return err
	}
	defer store.Close()

	txns, err := store.ListTxns(ctx, *limit)
	if err != nil {
		return err
	}
	if *asJSON {
		type view struct {
			ID        int64  `json:"id"`
			State     string `json:"state"`
			StartedAt string `json:"started_at"`
			Summary   string `json:"summary"`
		}
		views := make([]view, len(txns))
		for i, t := range txns {
			views[i] = view{t.ID, string(t.State), t.StartedAt.Format(time.RFC3339), t.OpSummary}
		}
		return app.emitJSON(views)
	}
	if len(txns) == 0 {
		app.printf("no transactions recorded\n")
		return nil
	}
	for _, t := range txns {
		app.printf("%d  %s  %s  %s\n", t.ID, t.StartedAt.Format(time.RFC3339),
			t.State, txnDescription(t))
	}
	return nil
}

// txnDescription is a transaction's summary, or a placeholder.
func txnDescription(t db.Txn) string {
	if t.OpSummary == "" {
		return "(no summary)"
	}
	return t.OpSummary
}
