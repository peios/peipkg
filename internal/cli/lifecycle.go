package cli

import (
	"context"
	"fmt"
	"runtime"

	"github.com/peios/peipkg/internal/config"
	"github.com/peios/peipkg/internal/db"
	"github.com/peios/peipkg/internal/install"
	"github.com/peios/peipkg/internal/manifest"
	"github.com/peios/peipkg/internal/resolver"
	"github.com/peios/peipkg/internal/version"
)

// cmdInstall installs one or more packages and their dependencies.
func cmdInstall(app *App, args []string) error {
	fs := flags("install")
	dryRun := fs.Bool("dry-run", false, "show the plan without applying it")
	yes := fs.Bool("yes", false, "skip the confirmation prompt")
	fs.BoolVar(yes, "y", false, "skip the confirmation prompt")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) == 0 {
		return fmt.Errorf("install: at least one package name is required")
	}
	reqs := make([]resolver.Request, len(pos))
	for i, name := range pos {
		reqs[i] = resolver.Request{Kind: resolver.Install, Name: name}
	}
	return transact(app, reqs, resolver.Options{}, *dryRun, *yes)
}

// cmdUpgrade upgrades the named packages, or every installed package
// when none is named.
func cmdUpgrade(app *App, args []string) error {
	fs := flags("upgrade")
	dryRun := fs.Bool("dry-run", false, "show the plan without applying it")
	yes := fs.Bool("yes", false, "skip the confirmation prompt")
	fs.BoolVar(yes, "y", false, "skip the confirmation prompt")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	var reqs []resolver.Request
	if len(pos) == 0 {
		reqs = []resolver.Request{{Kind: resolver.Upgrade}} // every installed package
	} else {
		for _, name := range pos {
			reqs = append(reqs, resolver.Request{Kind: resolver.Upgrade, Name: name})
		}
	}
	return transact(app, reqs, resolver.Options{}, *dryRun, *yes)
}

// cmdUninstall removes one or more packages.
func cmdUninstall(app *App, args []string) error {
	fs := flags("uninstall")
	dryRun := fs.Bool("dry-run", false, "show the plan without applying it")
	yes := fs.Bool("yes", false, "skip the confirmation prompt")
	fs.BoolVar(yes, "y", false, "skip the confirmation prompt")
	cascade := fs.Bool("cascade", false, "also remove packages that depend on the removed ones")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) == 0 {
		return fmt.Errorf("uninstall: at least one package name is required")
	}
	reqs := make([]resolver.Request, len(pos))
	for i, name := range pos {
		reqs[i] = resolver.Request{Kind: resolver.Remove, Name: name}
	}
	return transact(app, reqs, resolver.Options{CascadeRemovals: *cascade}, *dryRun, *yes)
}

// transact resolves a set of requests into a plan, presents it for
// approval, and — once approved — executes it as one transaction.
func transact(app *App, reqs []resolver.Request, opts resolver.Options, dryRun, yes bool) error {
	ctx := context.Background()
	store, err := app.openDB(ctx)
	if err != nil {
		return err
	}
	defer store.Close()

	opts.PrimaryArch = primaryArch(ctx, store)
	installed, err := installedSet(ctx, store)
	if err != nil {
		return err
	}
	available, configs, err := availableSet(ctx, app, store)
	if err != nil {
		return err
	}

	plan, err := resolver.Resolve(reqs, installed, available, opts)
	if err != nil {
		return err
	}
	app.presentPlan(plan)
	if len(plan.Operations) == 0 {
		return nil
	}
	if dryRun {
		app.printf("(dry run — no changes were made)\n")
		return nil
	}
	// §7.6.6: elevated actions need a deliberate, specific authorisation
	// that the routine confirmation — and --yes — do not supply.
	if !app.authorize(plan.Authorizations) {
		app.printf("cancelled — required authorisation was not given\n")
		return nil
	}
	if !yes && !app.confirm() {
		app.printf("cancelled\n")
		return nil
	}

	env := install.Env{
		Root:           app.paths.root,
		DB:             store,
		LockPath:       app.paths.lockPath,
		PeipkgVersion:  peipkgVersion,
		RunSideEffects: true,
		Provider:       &repoProvider{client: app.repoClient(store), configs: configs},
	}
	result, err := install.Execute(ctx, plan, env)
	if err != nil {
		return err
	}
	for _, w := range result.Warnings {
		fmt.Fprintf(app.errOut, "peipkg: warning: %s\n", w)
	}
	app.printf("done — %s\n", operationCount(plan))
	return nil
}

// installedSet builds the resolver's view of the installed packages
// from the package database.
func installedSet(ctx context.Context, store *db.DB) ([]resolver.Installed, error) {
	pkgs, err := store.ListPackages(ctx)
	if err != nil {
		return nil, err
	}
	installed := make([]resolver.Installed, 0, len(pkgs))
	for _, p := range pkgs {
		v, err := version.Parse(p.Version)
		if err != nil {
			return nil, fmt.Errorf("installed package %q has an invalid version: %w", p.Name, err)
		}
		m, err := manifest.Decode([]byte(p.Manifest))
		if err != nil {
			return nil, fmt.Errorf("installed package %q has an unreadable manifest: %w", p.Name, err)
		}
		installed = append(installed, resolver.Installed{
			Name: p.Name, Version: v, Architecture: p.Architecture,
			Dependencies: m.Dependencies, Conflicts: m.Conflicts, Provides: m.Provides,
		})
	}
	return installed, nil
}

// availableSet builds the resolver's candidate set from the configured
// repositories' cached active indexes. A repository with no usable
// cached index is skipped with a warning.
func availableSet(ctx context.Context, app *App, store *db.DB) (
	[]resolver.Candidate, map[string]config.RepoConfig, error) {

	repos, err := app.configProvider().Repositories()
	if err != nil {
		return nil, nil, err
	}
	client := app.repoClient(store)
	configs := make(map[string]config.RepoConfig, len(repos))
	var candidates []resolver.Candidate
	for _, cfg := range repos {
		configs[cfg.Name] = cfg
		idx, err := client.ActiveIndex(ctx, cfg.Name)
		if err != nil {
			fmt.Fprintf(app.errOut, "peipkg: skipping repository %q: %v\n", cfg.Name, err)
			continue
		}
		for _, e := range idx.Packages {
			candidates = append(candidates, resolver.Candidate{
				Name: e.Name, Version: e.Version, Architecture: e.Architecture,
				Dependencies: e.Dependencies, Conflicts: e.Conflicts, Provides: e.Provides,
				Repo: cfg.Name, RepoPriority: cfg.Priority,
				URL: e.URL, Hash: e.Hash,
				SizeCompressed: e.SizeCompressed, SizeInstalled: e.SizeInstalled,
			})
		}
	}
	return candidates, configs, nil
}

// primaryArch reports the system's primary architecture, from the
// database when recorded and otherwise from the build target.
func primaryArch(ctx context.Context, store *db.DB) string {
	if v, found, err := store.Meta(ctx, "primary_arch"); err == nil && found && v != "" {
		return v
	}
	if runtime.GOARCH == "arm64" {
		return "aarch64"
	}
	return "x86_64"
}

// operationCount summarises how many operations a plan applied.
func operationCount(plan resolver.Plan) string {
	if len(plan.Operations) == 1 {
		return "1 operation applied"
	}
	return fmt.Sprintf("%d operations applied", len(plan.Operations))
}
