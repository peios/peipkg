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
	orphaned, err := app.orphanedPackages(ctx)
	if err != nil {
		return err
	}
	if *asJSON {
		views := make([]packageJSON, len(pkgs))
		for i, p := range pkgs {
			views[i] = newPackageJSON(p, orphaned[p.Name], false)
		}
		return app.emitJSON(views)
	}
	if len(pkgs) == 0 {
		app.printf("no packages are installed\n")
		return nil
	}
	for _, p := range pkgs {
		// §5.37: an orphan is displayed with a clear indicator. Its
		// repository was removed or revoked, so nothing is refreshing it
		// and no trust state stands behind it any more.
		if orphaned[p.Name] {
			app.printf("%s  %s  %s  [orphaned: %s is no longer configured]\n",
				p.Name, p.Version, p.Architecture, p.OriginRepo)
			continue
		}
		app.printf("%s  %s  %s\n", p.Name, p.Version, p.Architecture)
	}
	return nil
}

// packageJSON is an installed package as list --json and info --json give
// it: one shape, info's with the fields only it carries filled in.
type packageJSON struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	Architecture  string `json:"architecture"`
	Origin        string `json:"origin"` // "" for a package installed from a local file
	Orphaned      bool   `json:"orphaned"`
	InstalledAt   string `json:"installed_at"`
	Description   string `json:"description,omitempty"`
	SizeInstalled int64  `json:"size_installed"`

	License          string   `json:"license,omitempty"`
	LicenseClass     string   `json:"license_class,omitempty"`
	Homepage         string   `json:"homepage,omitempty"`
	AlternateUpgrade string   `json:"alternate_upgrade,omitempty"`
	Dependencies     []string `json:"dependencies,omitempty"`
	Provides         []string `json:"provides,omitempty"`
}

// newPackageJSON builds p's JSON view; detail adds what info gives and
// list does not.
func newPackageJSON(p db.Package, orphaned, detail bool) packageJSON {
	v := packageJSON{Name: p.Name, Version: p.Version, Architecture: p.Architecture,
		Origin: p.OriginRepo, Orphaned: orphaned,
		InstalledAt: p.InstalledAt.UTC().Format(time.RFC3339)}
	m, err := manifest.Decode([]byte(p.Manifest))
	if err != nil {
		return v
	}
	v.Description = m.Description
	v.SizeInstalled = m.SizeInstalled
	if !detail {
		return v
	}
	v.License = m.License
	if m.LicenseClass != manifest.LicenseClassUnknown {
		v.LicenseClass = string(m.LicenseClass)
	}
	v.Homepage = m.Homepage
	if m.AlternateUpgrade != nil {
		v.AlternateUpgrade = m.AlternateUpgrade.Message
	}
	for _, d := range m.Dependencies {
		s := d.Name
		if !d.Constraint.Any() {
			s += " " + d.Constraint.String()
		}
		v.Dependencies = append(v.Dependencies, s)
	}
	for _, pr := range m.Provides {
		s := pr.Name
		if pr.Version != nil {
			s += " " + pr.Version.String()
		}
		v.Provides = append(v.Provides, s)
	}
	return v
}

// orphanedPackages reports, by package name, which installed packages
// have an origin repository that is no longer configured (§5.37).
//
// A package with no origin at all — a raw local-file install — is not
// orphaned: it never had a repository to lose.
func (app *App) orphanedPackages(ctx context.Context) (map[string]bool, error) {
	store, err := app.openDB(ctx)
	if err != nil {
		return nil, err
	}
	defer store.Close()
	pkgs, err := store.ListPackages(ctx)
	if err != nil {
		return nil, err
	}
	repos, err := app.configProvider().Repositories()
	if err != nil {
		return nil, err
	}
	configured := make(map[string]bool, len(repos))
	for _, r := range repos {
		configured[r.Name] = true
	}
	out := map[string]bool{}
	for _, p := range pkgs {
		if p.OriginRepo != "" && !configured[p.OriginRepo] {
			out[p.Name] = true
		}
	}
	return out, nil
}

// cmdInfo prints the details of one installed package.
func cmdInfo(app *App, args []string) error {
	fs := flags("info")
	asJSON := fs.Bool("json", false, "emit JSON")
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
	if *asJSON {
		orphaned, err := app.orphanedPackages(ctx)
		if err != nil {
			return err
		}
		return app.emitJSON(newPackageJSON(pkg, orphaned[pkg.Name], true))
	}
	app.printf("name:         %s\n", pkg.Name)
	app.printf("version:      %s\n", pkg.Version)
	app.printf("architecture: %s\n", pkg.Architecture)
	switch orphaned, err := app.orphanedPackages(ctx); {
	case err != nil:
		return err
	case pkg.OriginRepo == "":
		app.printf("origin:       (local file)\n")
	case orphaned[pkg.Name]:
		// §5.37: the orphan state is surfaced on any operation involving
		// the package, which includes simply asking about it.
		app.printf("origin:       %s (ORPHANED — no longer configured; this package is "+
			"not refreshed and no trust state stands behind it)\n", pkg.OriginRepo)
	default:
		app.printf("origin:       %s\n", pkg.OriginRepo)
	}
	app.printf("installed:    %s\n", pkg.InstalledAt.Format(time.RFC3339))
	if m, err := manifest.Decode([]byte(pkg.Manifest)); err == nil {
		if m.Description != "" {
			app.printf("description:  %s\n", m.Description)
		}
		if m.License != "" {
			app.printf("license:      %s\n", m.License)
		}
		if m.LicenseClass != "" && m.LicenseClass != manifest.LicenseClassUnknown {
			app.printf("license-class: %s\n", m.LicenseClass)
		}
		if m.Homepage != "" {
			app.printf("homepage:     %s\n", m.Homepage)
		}
		if m.AlternateUpgrade != nil {
			app.printf("Alternate upgrade path:\n%s\n", m.AlternateUpgrade.Message)
		}
	}
	return nil
}

// cmdFiles prints the filesystem objects a package owns.
func cmdFiles(app *App, args []string) error {
	fs := flags("files")
	asJSON := fs.Bool("json", false, "emit JSON")
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
	if *asJSON {
		type view struct {
			Path   string `json:"path"`
			Type   string `json:"type"` // file, dir or symlink
			Target string `json:"target,omitempty"`
		}
		views := make([]view, len(files))
		for i, f := range files {
			views[i] = view{f.Path, string(f.Type), f.SymlinkTarget}
		}
		return app.emitJSON(views)
	}
	for _, f := range files {
		app.printf("%s\n", f.Path)
	}
	return nil
}

// cmdOwns reports which package owns a path.
func cmdOwns(app *App, args []string) error {
	fs := flags("owns")
	asJSON := fs.Bool("json", false, "emit JSON")
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
	if *asJSON {
		// An unowned path is an empty list, not an error: the question
		// had an answer.
		names := make([]string, len(owners))
		for i, o := range owners {
			names[i] = o.PackageName
		}
		return app.emitJSON(names)
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
		type op struct {
			Action string `json:"action"` // install, upgrade, downgrade, remove or claim
			Name   string `json:"name"`
			From   string `json:"from,omitempty"`
			To     string `json:"to,omitempty"`
		}
		type view struct {
			ID         int64  `json:"id"`
			State      string `json:"state"`
			StartedAt  string `json:"started_at"`
			Summary    string `json:"summary"`
			Operations []op   `json:"operations"`
		}
		views := make([]view, len(txns))
		for i, t := range txns {
			views[i] = view{t.ID, string(t.State), t.StartedAt.UTC().Format(time.RFC3339), t.OpSummary, []op{}}
			ops, err := store.TxnOps(ctx, t.ID)
			if err != nil {
				return err
			}
			for _, o := range ops {
				views[i].Operations = append(views[i].Operations,
					op{string(o.Action), o.PackageName, o.FromVersion, o.ToVersion})
			}
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
