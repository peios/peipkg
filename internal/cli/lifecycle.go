package cli

import (
	"context"
	"fmt"
	"runtime"
	"sort"

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
		return fmt.Errorf("install: at least one package name or .peipkg file is required")
	}
	// An argument may name a repository package or a local .peipkg file;
	// a local file is installed raw — the repository trust layer skipped.
	reqs := make([]resolver.Request, 0, len(pos))
	var locals []resolver.Candidate
	for _, arg := range pos {
		if isLocalPeipkg(arg) {
			cand, err := readLocalPackage(arg)
			if err != nil {
				return err
			}
			locals = append(locals, cand)
			reqs = append(reqs, resolver.Request{Kind: resolver.Install, Name: cand.Name})
			continue
		}
		reqs = append(reqs, resolver.Request{Kind: resolver.Install, Name: arg})
	}
	return transact(app, reqs, resolver.Options{}, *dryRun, *yes, locals)
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
	return transact(app, reqs, resolver.Options{}, *dryRun, *yes, nil)
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
	return transact(app, reqs, resolver.Options{CascadeRemovals: *cascade}, *dryRun, *yes, nil)
}

// transact resolves a set of requests into a plan, presents it for
// approval, and — once approved — executes it as one transaction.
// extraCandidates are packages added to the resolver's candidate set
// beyond the repositories' active indexes — raw local-file packages.
// When opts.AllowDowngrade is set the repositories' archive indexes are
// fetched too, so a downgrade or undo can reach historical versions.
func transact(app *App, reqs []resolver.Request, opts resolver.Options, dryRun, yes bool,
	extraCandidates []resolver.Candidate) error {
	ctx := context.Background()
	store, err := app.openDB(ctx)
	if err != nil {
		return err
	}
	defer store.Close()

	opts.PrimaryArch = primaryArch(ctx, store)
	available, configs, err := availableSet(ctx, app, store)
	if err != nil {
		return err
	}
	// Local-file packages join the resolver's candidate set; their
	// dependencies still resolve against the configured repositories.
	available = append(available, extraCandidates...)
	// A downgrade or undo targets historical versions, which live only
	// in the repositories' archive indexes.
	if opts.AllowDowngrade {
		archived, err := archiveCandidates(ctx, app, store, configs)
		if err != nil {
			return err
		}
		available = append(available, archived...)
	}
	installed, err := installedSet(ctx, store, configs)
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
// from the package database. configs supplies the current repository
// priorities so each package can carry its origin repository's trust
// level for the §6.5.7 foreign-replaces gate.
func installedSet(ctx context.Context, store *db.DB,
	configs map[string]config.RepoConfig) ([]resolver.Installed, error) {

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
		inst := resolver.Installed{
			Name: p.Name, Version: v, Architecture: p.Architecture,
			Dependencies: m.Dependencies, Conflicts: m.Conflicts, Provides: m.Provides,
		}
		// Record the origin repository's current priority when that
		// repository is still configured; otherwise the origin is
		// unknown and the §6.5.7 gate cannot apply.
		if cfg, ok := configs[p.OriginRepo]; ok && p.OriginRepo != "" {
			inst.Repo = p.OriginRepo
			inst.RepoPriority = cfg.Priority
		}
		installed = append(installed, inst)
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
		app.warnUnsigned(cfg)
		for _, e := range idx.Packages {
			candidates = append(candidates, resolver.Candidate{
				Name: e.Name, Version: e.Version, Architecture: e.Architecture,
				Dependencies: e.Dependencies, Conflicts: e.Conflicts,
				Provides: e.Provides, Replaces: e.Replaces,
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

// cmdDowngrade installs a specific older version of a package, drawn
// from the repositories' archive indexes. The move backward is an
// elevated action the resolver raises for explicit authorisation.
func cmdDowngrade(app *App, args []string) error {
	fs := flags("downgrade")
	dryRun := fs.Bool("dry-run", false, "show the plan without applying it")
	yes := fs.Bool("yes", false, "skip the confirmation prompt")
	fs.BoolVar(yes, "y", false, "skip the confirmation prompt")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 2 {
		return fmt.Errorf("downgrade: usage: downgrade <package> <version>")
	}
	target, err := version.Parse(pos[1])
	if err != nil {
		return fmt.Errorf("downgrade: invalid version %q: %w", pos[1], err)
	}
	reqs := []resolver.Request{{Kind: resolver.Downgrade, Name: pos[0], Version: target}}
	return transact(app, reqs, resolver.Options{AllowDowngrade: true}, *dryRun, *yes, nil)
}

// cmdUndo reverses the most recent committed transaction: an install is
// undone by a removal, and an upgrade, downgrade, or removal by
// restoring the package to its prior version. The inverse is applied as
// a new transaction — it is not a roll-back of committed state.
func cmdUndo(app *App, args []string) error {
	fs := flags("undo")
	dryRun := fs.Bool("dry-run", false, "show the plan without applying it")
	yes := fs.Bool("yes", false, "skip the confirmation prompt")
	fs.BoolVar(yes, "y", false, "skip the confirmation prompt")
	if _, err := parseArgs(fs, args); err != nil {
		return err
	}

	ctx := context.Background()
	store, err := app.openDB(ctx)
	if err != nil {
		return err
	}
	last, ops, err := lastCommittedTxn(ctx, store)
	store.Close()
	if err != nil {
		return err
	}
	reqs, err := inverseRequests(ops)
	if err != nil {
		return err
	}
	app.printf("undoing transaction %d (%s)\n", last.ID, last.OpSummary)
	return transact(app, reqs, resolver.Options{AllowDowngrade: true}, *dryRun, *yes, nil)
}

// lastCommittedTxn returns the most recent committed transaction and
// its per-package operations.
func lastCommittedTxn(ctx context.Context, store *db.DB) (db.Txn, []db.TxnOp, error) {
	txns, err := store.ListTxns(ctx, 0) // 0 — all, most recent first
	if err != nil {
		return db.Txn{}, nil, err
	}
	for _, t := range txns {
		if t.State != db.TxnCommitted {
			continue
		}
		ops, err := store.TxnOps(ctx, t.ID)
		if err != nil {
			return db.Txn{}, nil, err
		}
		return t, ops, nil
	}
	return db.Txn{}, nil, fmt.Errorf("undo: there is no committed transaction to undo")
}

// inverseRequests builds the requests that reverse a transaction's
// operations.
func inverseRequests(ops []db.TxnOp) ([]resolver.Request, error) {
	var reqs []resolver.Request
	for _, op := range ops {
		switch op.Action {
		case db.OpInstall:
			reqs = append(reqs, resolver.Request{Kind: resolver.Remove, Name: op.PackageName})
		case db.OpUpgrade, db.OpDowngrade, db.OpRemove:
			prior, err := version.Parse(op.FromVersion)
			if err != nil {
				return nil, fmt.Errorf("undo: %s has an unreadable prior version %q: %w",
					op.PackageName, op.FromVersion, err)
			}
			reqs = append(reqs, resolver.Request{
				Kind: resolver.Downgrade, Name: op.PackageName, Version: prior})
		}
	}
	if len(reqs) == 0 {
		return nil, fmt.Errorf("undo: the last transaction made no reversible changes")
	}
	return reqs, nil
}

// archiveCandidates fetches every configured repository's archive index
// and returns its package entries as resolver candidates — the
// historical versions a downgrade or undo may target. A repository
// whose archive index is unavailable is skipped with a warning.
func archiveCandidates(ctx context.Context, app *App, store *db.DB,
	configs map[string]config.RepoConfig) ([]resolver.Candidate, error) {

	names := make([]string, 0, len(configs))
	for name := range configs {
		names = append(names, name)
	}
	sort.Strings(names)

	client := app.repoClient(store)
	var candidates []resolver.Candidate
	for _, name := range names {
		cfg := configs[name]
		idx, err := client.ArchiveIndex(ctx, cfg)
		if err != nil {
			fmt.Fprintf(app.errOut, "peipkg: archive index of %q unavailable: %v\n", name, err)
			continue
		}
		for _, e := range idx.Packages {
			candidates = append(candidates, resolver.Candidate{
				Name: e.Name, Version: e.Version, Architecture: e.Architecture,
				Dependencies: e.Dependencies, Conflicts: e.Conflicts,
				Provides: e.Provides, Replaces: e.Replaces,
				Repo: cfg.Name, RepoPriority: cfg.Priority,
				URL: e.URL, Hash: e.Hash,
				SizeCompressed: e.SizeCompressed, SizeInstalled: e.SizeInstalled,
			})
		}
	}
	return candidates, nil
}
