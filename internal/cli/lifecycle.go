package cli

import (
	"context"
	"fmt"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/peios/peipkg/internal/audit"
	"github.com/peios/peipkg/internal/config"
	"github.com/peios/peipkg/internal/db"
	"github.com/peios/peipkg/internal/install"
	"github.com/peios/peipkg/internal/manifest"
	"github.com/peios/peipkg/internal/repository"
	"github.com/peios/peipkg/internal/resolver"
	"github.com/peios/peipkg/internal/version"
)

// cmdInstall installs one or more packages and their dependencies.
func cmdInstall(app *App, args []string) error {
	fs := flags("install")
	dryRun := fs.Bool("dry-run", false, "show the plan without applying it")
	yes := fs.Bool("yes", false, "skip the confirmation prompt")
	fs.BoolVar(yes, "y", false, "skip the confirmation prompt")
	noClaim := fs.Bool("no-claim", false, "do not auto-claim roles the packages provide")
	claimAll := fs.Bool("claim-all", false,
		"claim every provided role, overriding current holders")
	claimRoles := fs.String("claim", "",
		"comma-separated roles to claim, overriding current holders")
	allowStale := fs.Bool("allow-stale", false,
		"proceed although a repository's trust state exceeds its maximum trusted age (§6.5.4)")
	bypassPaths := fs.Bool("dangerously-bypass-path-restrictions", false,
		"permit packages declaring special_system_package to install outside the §3.4 layout")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) == 0 {
		return fmt.Errorf("install: at least one package name or .peipkg file is required")
	}
	app.bypassPathRestrictions = *bypassPaths
	claimDir, err := claimDirective(*noClaim, *claimAll, *claimRoles)
	if err != nil {
		return err
	}
	if err := ensureFreshTrust(app, *allowStale); err != nil {
		return fmt.Errorf("install: %w", err)
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
	// §3.3.6 top-level placement: with no explicit --root, a package's
	// default_root chooses the target root, exactly as if --root had named
	// it (DESIGN-named-roots.md). An explicit --root always wins, so the
	// re-root only happens when the operator gave none.
	if !app.rootExplicit {
		target, err := app.topLevelTargetRoot(context.Background(), reqs, locals)
		if err != nil {
			return err
		}
		app.setRoot(target)
	}
	return transact(app, reqs, resolver.Options{}, *dryRun, *yes, locals, claimDir,
		audit.TypeInstall, true)
}

// topLevelTargetRoot decides which root a top-level install lands in from
// the requested packages' default_root preferences (§3.3.6). The
// preference is read from the invocation root's candidate set — the
// active indexes and any local files. The rule:
//
//   - no package declares a default_root → the current root, unchanged.
//   - exactly one distinct default_root is declared → that root (other,
//     undeclared packages in the same command ride along into it).
//   - two or more distinct default_roots → rejected: a single transaction
//     installs into one root, so divergent preferences need either
//     separate commands or an explicit --root. (Composing several roots
//     at once is the cross-root dependency graph, not a flat install.)
//
// A requested package with no available candidate contributes no
// preference; the resolver reports its absence later, with the right error.
func (app *App) topLevelTargetRoot(ctx context.Context, reqs []resolver.Request,
	locals []resolver.Candidate) (string, error) {

	store, err := app.openDB(ctx)
	if err != nil {
		return "", err
	}
	available, _, err := availableSet(ctx, app, store)
	store.Close()
	if err != nil {
		return "", err
	}

	// default_root is a per-package fact, identical across a package's
	// versions, so the first candidate matching a name suffices.
	defaultRootOf := func(name string) string {
		for _, c := range locals {
			if c.Name == name {
				return c.DefaultRoot
			}
		}
		for _, c := range available {
			if c.Name == name {
				return c.DefaultRoot
			}
		}
		return ""
	}

	declared := map[string]bool{}
	for _, req := range reqs {
		if req.Kind != resolver.Install {
			continue
		}
		if dr := defaultRootOf(req.Name); dr != "" {
			declared[dr] = true
		}
	}

	switch len(declared) {
	case 0:
		return app.paths.root, nil
	case 1:
		var ref string
		for r := range declared {
			ref = r
		}
		target, err := resolveRootRef(ctx, app.paths.root, ref)
		if err != nil {
			return "", fmt.Errorf("install: default_root %q: %w", ref, err)
		}
		return target, nil
	default:
		refs := make([]string, 0, len(declared))
		for r := range declared {
			refs = append(refs, r)
		}
		sort.Strings(refs)
		return "", fmt.Errorf("install: the requested packages declare different default roots "+
			"(%s); install them separately or pass --root to choose one",
			strings.Join(refs, ", "))
	}
}

// claimDirective builds the install-time claim directive from the flags
// and enforces the §7.7.2 mutual-exclusion rules.
func claimDirective(noClaim, all bool, roleList string) (install.ClaimDirective, error) {
	var roles []string
	for _, r := range strings.Split(roleList, ",") {
		if r = strings.TrimSpace(r); r != "" {
			roles = append(roles, r)
		}
	}
	if all && len(roles) > 0 {
		return install.ClaimDirective{}, fmt.Errorf(
			"install: --claim-all and --claim are mutually exclusive")
	}
	if all && noClaim {
		return install.ClaimDirective{}, fmt.Errorf(
			"install: --claim-all and --no-claim are mutually exclusive")
	}
	return install.ClaimDirective{NoClaim: noClaim, All: all, Roles: roles}, nil
}

// cmdUpgrade upgrades the named packages, or every installed package
// when none is named. By default it cascades: the current root and,
// recursively, its named roots are each upgraded as an independent
// transaction (DESIGN-named-roots.md). --no-recurse confines it to the
// current root.
func cmdUpgrade(app *App, args []string) error {
	fs := flags("upgrade")
	dryRun := fs.Bool("dry-run", false, "show the plan without applying it")
	yes := fs.Bool("yes", false, "skip the confirmation prompt")
	fs.BoolVar(yes, "y", false, "skip the confirmation prompt")
	noRecurse := fs.Bool("no-recurse", false, "confine the upgrade to the current root")
	allowStale := fs.Bool("allow-stale", false,
		"proceed although a repository's trust state exceeds its maximum trusted age (§6.5.4)")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if err := ensureFreshTrust(app, *allowStale); err != nil {
		return fmt.Errorf("upgrade: %w", err)
	}
	var reqs []resolver.Request
	if len(pos) == 0 {
		reqs = []resolver.Request{{Kind: resolver.Upgrade}} // every installed package
	} else {
		for _, name := range pos {
			reqs = append(reqs, resolver.Request{Kind: resolver.Upgrade, Name: name})
		}
	}
	if *noRecurse {
		return transact(app, reqs, resolver.Options{}, *dryRun, *yes, nil,
			install.ClaimDirective{}, audit.TypeUpgrade, false)
	}
	return cascadeUpgrade(app, reqs, *dryRun, *yes)
}

// cascadeUpgrade upgrades the current root and, recursively, its named
// roots — each as its own independent transaction against its own repos.
// Unlike a dependency closure, the roots are independent, so the cascade
// is continue-on-error (DESIGN-named-roots.md): a failure in one root is
// recorded and the walk proceeds, and a per-root success/fail/skip
// summary is printed at the end. A registered root whose tree is gone is
// skipped with a warning.
func cascadeUpgrade(app *App, reqs []resolver.Request, dryRun, yes bool) error {
	ctx := context.Background()
	present, dangling, err := gatherUpgradeRoots(ctx, app.paths.root)
	if err != nil {
		return err
	}
	for _, d := range dangling {
		fmt.Fprintf(app.errOut, "peipkg: skipping registered root %s — its tree does not exist\n", d)
	}

	// The fast path: a system with no named roots behaves exactly as a
	// plain single-root upgrade — no headers, no summary.
	if len(present) == 1 && len(dangling) == 0 {
		return transact(app, reqs, resolver.Options{}, dryRun, yes, nil,
			install.ClaimDirective{}, audit.TypeUpgrade, false)
	}

	var failed, skipped []string
	succeeded := 0
	for _, rootPath := range present {
		sub := *app
		sub.paths = newPaths(rootPath)

		// A named-package upgrade only concerns roots that hold one of the
		// named packages; a root holding none is skipped rather than failed.
		rootReqs, err := confineRequestsToRoot(ctx, &sub, reqs)
		if err != nil {
			fmt.Fprintf(app.errOut, "peipkg: upgrade of %s failed: %v\n", rootPath, err)
			failed = append(failed, rootPath)
			continue
		}
		if len(rootReqs) == 0 {
			skipped = append(skipped, rootPath)
			continue
		}

		app.printf("== %s ==\n", rootPath)
		if err := transact(&sub, rootReqs, resolver.Options{}, dryRun, yes, nil,
			install.ClaimDirective{}, audit.TypeUpgrade, false); err != nil {
			fmt.Fprintf(app.errOut, "peipkg: upgrade of %s failed: %v\n", rootPath, err)
			failed = append(failed, rootPath)
			continue
		}
		succeeded++
	}

	app.printf("cascade: %d upgraded, %d failed, %d skipped\n",
		succeeded, len(failed), len(skipped)+len(dangling))
	if len(failed) > 0 {
		return fmt.Errorf("upgrade: %d root(s) failed: %s", len(failed), strings.Join(failed, ", "))
	}
	return nil
}

// confineRequestsToRoot narrows a set of upgrade requests to those that
// apply to the root sub operates on. The upgrade-everything request (an
// Upgrade with no name) always applies. A named-package request applies
// only when that package is installed in the root; this is what lets the
// cascade skip a root that simply does not hold a named package, instead
// of reporting it as a failure.
func confineRequestsToRoot(ctx context.Context, sub *App, reqs []resolver.Request) ([]resolver.Request, error) {
	named := false
	for _, r := range reqs {
		if r.Kind == resolver.Upgrade && r.Name == "" {
			return reqs, nil // upgrade-everything applies to every root
		}
		if r.Name != "" {
			named = true
		}
	}
	if !named {
		return reqs, nil
	}

	store, err := sub.openDB(ctx)
	if err != nil {
		return nil, err
	}
	pkgs, err := store.ListPackages(ctx)
	store.Close()
	if err != nil {
		return nil, err
	}
	installed := make(map[string]bool, len(pkgs))
	for _, p := range pkgs {
		installed[p.Name] = true
	}
	var out []resolver.Request
	for _, r := range reqs {
		if installed[r.Name] {
			out = append(out, r)
		}
	}
	return out, nil
}

// gatherUpgradeRoots walks the root topology starting at start: the
// starting root, then each present named root, recursively. It returns
// the present roots in visit order (start first) and any dangling roots —
// registered names whose tree no longer exists (D3). A visited-set of
// resolved absolute paths guards cycles and double-visits.
func gatherUpgradeRoots(ctx context.Context, start string) (present, dangling []string, err error) {
	visited := map[string]bool{}
	var walk func(path string) error
	walk = func(path string) error {
		abs, err := filepath.Abs(path)
		if err != nil {
			return err
		}
		if visited[abs] {
			return nil
		}
		visited[abs] = true
		present = append(present, path)

		store, exists, err := openRootDB(ctx, path)
		if err != nil {
			return err
		}
		if !exists {
			return nil // no registry here — no children
		}
		entries, err := store.NamedRoots(ctx)
		_ = store.Close()
		if err != nil {
			return err
		}
		for _, e := range entries {
			child := filepath.Join(path, e.Path)
			if rootStatus(child) != "present" {
				dangling = append(dangling, child)
				continue
			}
			if err := walk(child); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(start); err != nil {
		return nil, nil, err
	}
	return present, dangling, nil
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
	return transact(app, reqs, resolver.Options{CascadeRemovals: *cascade},
		*dryRun, *yes, nil, install.ClaimDirective{}, audit.TypeUninstall, false)
}

// transact resolves a set of requests into a plan, presents it for
// approval, and — once approved — executes it as one transaction. It
// emits the §7.6 audit event for the outcome: eventType on success, or
// peipkg.transaction-failed on a rejection or rollback.
//
// extraCandidates are packages added to the resolver's candidate set
// beyond the repositories' active indexes — raw local-file packages.
// When opts.AllowDowngrade is set the repositories' archive indexes are
// fetched too, so a downgrade or undo can reach historical versions.
func transact(app *App, reqs []resolver.Request, opts resolver.Options, dryRun, yes bool,
	extraCandidates []resolver.Candidate, claimDir install.ClaimDirective, eventType string,
	crossRoot bool) error {
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

	// Resolve. A cross-root-capable operation (install) resolves across
	// every reachable root, so a dependency placed `IN` another root is
	// routed there (DESIGN-named-roots.md); every other verb resolves
	// single-root, exactly as before.
	var plan resolver.Plan
	if crossRoot {
		plan, err = app.resolveCrossRoot(ctx, reqs, store, available, configs, opts)
	} else {
		var installed []resolver.Installed
		if installed, err = installedSet(ctx, store, configs); err == nil {
			plan, err = resolver.Resolve(reqs, installed, available, opts)
		}
	}
	if err != nil {
		app.emit(audit.Event{Type: audit.TypeTxnFailed,
			Outcome: audit.OutcomeRejection, Detail: err.Error()})
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

	provider := &repoProvider{client: app.repoClient(store), configs: configs}

	// A plan that spans more than one root commits as a cross-root
	// two-phase-commit transaction; a single-root plan uses the existing
	// single-root executor against the anchor's environment.
	if len(planRoots(plan, app.paths.root)) > 1 {
		return app.executeCrossRoot(ctx, plan, store, provider, claimDir, eventType)
	}

	env := install.Env{
		Root:                   app.paths.root,
		DB:                     store,
		LockPath:               app.paths.lockPath,
		PeipkgVersion:          peipkgVersion,
		RunSideEffects:         true,
		Claims:                 claimDir,
		Provider:               provider,
		BypassPathRestrictions: app.bypassPathRestrictions,
	}
	result, err := install.Execute(ctx, plan, env)
	if err != nil {
		app.emit(audit.Event{Type: audit.TypeTxnFailed, TxnID: result.TxnID,
			Outcome: audit.OutcomeRollback, Packages: auditPackages(plan),
			Detail: err.Error()})
		return err
	}
	for _, w := range result.Warnings {
		fmt.Fprintf(app.errOut, "peipkg: warning: %s\n", w)
	}
	app.emit(audit.Event{Type: eventType, TxnID: result.TxnID,
		Outcome: audit.OutcomeSuccess, Packages: auditPackages(plan),
		Detail: operationCount(plan)})
	app.printf("done — %s\n", operationCount(plan))
	return nil
}

// resolveCrossRoot resolves reqs (rooted at the anchor) across every
// reachable root, so a dependency's `IN <root>` placement is honoured. It
// builds the named-root reference map and each reachable root's installed
// set, then runs the multi-root resolver. The opened satellite databases
// are closed before it returns — resolution only reads them; execution
// re-opens whatever roots the plan actually touches.
func (app *App) resolveCrossRoot(ctx context.Context, reqs []resolver.Request, store *db.DB,
	available []resolver.Candidate, configs map[string]config.RepoConfig,
	opts resolver.Options) (resolver.Plan, error) {

	refToPath, err := gatherRootRefs(ctx, app.paths.root)
	if err != nil {
		return resolver.Plan{}, err
	}
	installedByRoot, extraDBs, err := app.gatherInstalledByRoot(ctx, store, configs, refToPath)
	if err != nil {
		return resolver.Plan{}, err
	}
	defer func() {
		for _, d := range extraDBs {
			_ = d.Close()
		}
	}()
	// Requests target the anchor (the operating root); cross-root edges in
	// the closure route packages elsewhere.
	rooted := make([]resolver.Request, len(reqs))
	copy(rooted, reqs)
	for i := range rooted {
		rooted[i].Root = app.paths.root
	}
	return resolver.ResolveMultiRoot(rooted, installedByRoot, available, refToPath, opts)
}

// gatherInstalledByRoot reads the installed set of the anchor and every
// reachable named root, keyed by resolved root path, for the multi-root
// resolver. A registered root whose database does not yet exist
// contributes an empty set (it is a root that has received nothing yet).
// It returns the satellite databases it opened so the caller can close
// them.
func (app *App) gatherInstalledByRoot(ctx context.Context, anchorStore *db.DB,
	configs map[string]config.RepoConfig, refToPath map[string]string) (
	map[string][]resolver.Installed, []*db.DB, error) {

	byRoot := map[string][]resolver.Installed{}
	anchorInstalled, err := installedSet(ctx, anchorStore, configs)
	if err != nil {
		return nil, nil, err
	}
	byRoot[app.paths.root] = anchorInstalled

	var extraDBs []*db.DB
	closeAll := func() {
		for _, d := range extraDBs {
			_ = d.Close()
		}
	}
	for _, path := range refToPath {
		if sameRoot(path, app.paths.root) {
			continue
		}
		if _, done := byRoot[path]; done {
			continue
		}
		rootStore, exists, err := openRootDB(ctx, path)
		if err != nil {
			closeAll()
			return nil, nil, err
		}
		if !exists {
			byRoot[path] = nil // registered but not yet created — empty
			continue
		}
		insts, err := installedSet(ctx, rootStore, configs)
		if err != nil {
			_ = rootStore.Close()
			closeAll()
			return nil, nil, err
		}
		extraDBs = append(extraDBs, rootStore)
		byRoot[path] = insts
	}
	return byRoot, extraDBs, nil
}

// executeCrossRoot commits a multi-root plan as one cross-root two-phase-
// commit transaction: it opens (creating if needed) each participating
// root's database, builds a per-root environment sharing the anchor's
// package provider — v1 fetches every root's packages from the anchor's
// repositories — and runs [install.ExecuteCrossRoot].
func (app *App) executeCrossRoot(ctx context.Context, plan resolver.Plan, anchorStore *db.DB,
	provider install.PackageProvider, claimDir install.ClaimDirective, eventType string) error {

	crossRootID, err := newCrossRootID()
	if err != nil {
		return err
	}

	envs := map[string]install.Env{}
	var opened []*db.DB
	defer func() {
		for _, d := range opened {
			_ = d.Close()
		}
	}()
	for _, root := range planRoots(plan, app.paths.root) {
		store := anchorStore
		if !sameRoot(root, app.paths.root) {
			s, err := app.openDBAt(ctx, root)
			if err != nil {
				return err
			}
			opened = append(opened, s)
			store = s
		}
		p := newPaths(root)
		envs[root] = install.Env{
			Root: root, DB: store, LockPath: p.lockPath,
			PeipkgVersion: peipkgVersion, RunSideEffects: true,
			Claims: claimDir, Provider: provider,
			BypassPathRestrictions: app.bypassPathRestrictions,
		}
	}

	results, err := install.ExecuteCrossRoot(ctx, plan, envs, crossRootID)
	if err != nil {
		var txnID int64
		for _, r := range results {
			if r.TxnID != 0 {
				txnID = r.TxnID
				break
			}
		}
		app.emit(audit.Event{Type: audit.TypeTxnFailed, TxnID: txnID,
			Outcome: audit.OutcomeRollback, Packages: auditPackages(plan), Detail: err.Error()})
		return err
	}
	for _, res := range results {
		for _, w := range res.Warnings {
			fmt.Fprintf(app.errOut, "peipkg: warning: %s\n", w)
		}
	}
	app.emit(audit.Event{Type: eventType, Outcome: audit.OutcomeSuccess,
		Packages: auditPackages(plan), Detail: operationCount(plan)})
	app.printf("done — %s across %d roots\n", operationCount(plan), len(envs))
	return nil
}

// planRoots returns the distinct roots a plan's operations target, an
// empty operation root counting as the anchor. A single-root plan yields
// exactly one.
func planRoots(plan resolver.Plan, anchor string) []string {
	seen := map[string]bool{}
	var out []string
	for _, op := range plan.Operations {
		r := op.Root
		if r == "" {
			r = anchor
		}
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	return out
}

// sameRoot reports whether two root paths denote the same directory.
func sameRoot(a, b string) bool {
	aa, err1 := filepath.Abs(a)
	bb, err2 := filepath.Abs(b)
	if err1 != nil || err2 != nil {
		return a == b
	}
	return aa == bb
}

// auditPackages renders a plan's operations as audit package
// references: the version each package ends at, or — for a removal —
// the version removed.
func auditPackages(plan resolver.Plan) []audit.PackageRef {
	refs := make([]audit.PackageRef, 0, len(plan.Operations))
	for _, op := range plan.Operations {
		ref := audit.PackageRef{Name: op.Name}
		if op.Kind == resolver.OpRemove {
			ref.Version = op.FromVersion.String()
		} else {
			ref.Version = op.ToVersion.String()
			if op.Candidate != nil {
				ref.Architecture = op.Candidate.Architecture
			}
		}
		refs = append(refs, ref)
	}
	return refs
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

// ensureFreshTrust applies the §6.5.4 maximum-trusted-age gate before
// an install, upgrade, or downgrade. For each configured repository
// whose last successful refresh is older than its maximum trusted age,
// a refresh is attempted; a repository that is still stale afterwards —
// the refresh failed, or the index is frozen and the refresh time
// deliberately did not advance (§6.2.3) — refuses the operation unless
// the operator passed --allow-stale, which warns and is audited.
//
// Uninstall and undo are deliberately not gated: removal and recovery
// must remain possible offline.
func ensureFreshTrust(app *App, allowStale bool) error {
	repos, err := app.configProvider().Repositories()
	if err != nil {
		return err
	}
	if len(repos) == 0 {
		return nil
	}
	ctx := context.Background()
	store, err := app.openDB(ctx)
	if err != nil {
		return err
	}
	defer store.Close()
	client := app.repoClient(store)
	now := time.Now()

	for _, cfg := range repos {
		if cfg.MaxTrustedAgeDays > repository.WarnMaxTrustedAgeDays {
			fmt.Fprintf(app.errOut, "peipkg: warning: repository %q sets max_trusted_age_days=%d "+
				"(above %d) — the freshness check is effectively disabled (§6.5.4)\n",
				cfg.Name, cfg.MaxTrustedAgeDays, repository.WarnMaxTrustedAgeDays)
		}
		if cfg.MaxIndexStalenessDays > repository.WarnMaxIndexStalenessDays {
			fmt.Fprintf(app.errOut, "peipkg: warning: repository %q sets "+
				"max_index_staleness_days=%d (above %d) — the index-staleness check is "+
				"effectively disabled (§5.34)\n",
				cfg.Name, cfg.MaxIndexStalenessDays, repository.WarnMaxIndexStalenessDays)
		}
		if err := ensureIndexNotStale(ctx, app, client, cfg, now, allowStale); err != nil {
			return err
		}
		age, stale, err := client.TrustAge(ctx, cfg, now)
		if err != nil {
			return err
		}
		if !stale {
			continue
		}
		max := repository.MaxTrustedAge(cfg)
		fmt.Fprintf(app.errOut, "peipkg: repository %q last refreshed %s ago (maximum trusted "+
			"age %s); refreshing\n", cfg.Name, formatAge(age), formatAge(max))
		refreshErr := client.Refresh(ctx, cfg)
		if refreshErr == nil {
			// A refresh that made progress advanced the refresh time; a
			// frozen index deliberately did not (§6.2.3) — re-check rather
			// than assume.
			if _, stale, err = client.TrustAge(ctx, cfg, now); err != nil {
				return err
			}
			if !stale {
				continue
			}
		}
		if !allowStale {
			if refreshErr != nil {
				return fmt.Errorf("repository %q trust state is %s old (maximum %s) and the "+
					"refresh failed: %v\nretry with the repository reachable, or pass "+
					"--allow-stale to proceed with stale trust state (§6.5.4)",
					cfg.Name, formatAge(age), formatAge(max), refreshErr)
			}
			return fmt.Errorf("repository %q is frozen: it refreshes but its index has not "+
				"progressed, and its trust state is %s old (maximum %s)\npass --allow-stale "+
				"to proceed with stale trust state (§6.5.4)",
				cfg.Name, formatAge(age), formatAge(max))
		}
		fmt.Fprintf(app.errOut, "peipkg: warning: proceeding with stale trust state for "+
			"repository %q (%s old) — authorised by --allow-stale (§6.5.4)\n",
			cfg.Name, formatAge(age))
		app.emit(audit.Event{Type: audit.TypeAuthorisation, Outcome: audit.OutcomeSuccess,
			Repo: cfg.Name, Detail: fmt.Sprintf("proceed with stale trust state (age %s)",
				formatAge(age))})
	}
	return nil
}

// ensureIndexNotStale applies the §5.34 maximum-index-staleness gate to
// one repository.
//
// Separate from the maximum-trusted-age gate beside it because they
// measure different things and only both together close the hole:
// trusted age is time since the last successful refresh, staleness is
// the age of the metadata itself. A repository that bumps index_version
// on every publication while stamping an ancient generated_at reads as
// permanently fresh to the trusted-age check — CheckFreshness treats
// the version bump as progress, and Refresh then advances
// LastRefreshAt — while serving metadata of any age.
//
// The 90-day window is independent of max_trusted_age_days, and
// deliberately so: raising the trusted age (permitted up to 180 without
// so much as a warning) must not widen this one.
func ensureIndexNotStale(ctx context.Context, app *App, client *repository.Client,
	cfg config.RepoConfig, now time.Time, allowStale bool) error {

	age, stale, err := client.IndexStaleness(ctx, cfg, now)
	if err != nil {
		return err
	}
	if !stale {
		return nil
	}
	max := repository.MaxIndexStaleness(cfg)
	fmt.Fprintf(app.errOut, "peipkg: repository %q index was generated %s ago (maximum index "+
		"staleness %s); refreshing\n", cfg.Name, formatAge(age), formatAge(max))

	refreshErr := client.Refresh(ctx, cfg)
	if refreshErr == nil {
		// A refresh only clears this if it actually brought a newer
		// index: a repository republishing the same ancient generated_at
		// leaves the floor where it was. Re-measure rather than assume.
		if _, stale, err = client.IndexStaleness(ctx, cfg, now); err != nil {
			return err
		}
		if !stale {
			return nil
		}
	}
	if !allowStale {
		if refreshErr != nil {
			return fmt.Errorf("repository %q index was generated %s ago (maximum %s) and the "+
				"refresh failed: %v\nretry with the repository reachable, or pass "+
				"--allow-stale to proceed with stale metadata (§5.34)",
				cfg.Name, formatAge(age), formatAge(max), refreshErr)
		}
		return fmt.Errorf("repository %q serves stale metadata: its index was generated %s "+
			"ago (maximum %s) and refreshing did not bring a newer one\npass --allow-stale "+
			"to proceed with stale metadata (§5.34)",
			cfg.Name, formatAge(age), formatAge(max))
	}
	fmt.Fprintf(app.errOut, "peipkg: warning: proceeding with stale metadata for repository "+
		"%q (index generated %s ago) — authorised by --allow-stale (§5.34)\n",
		cfg.Name, formatAge(age))
	app.emit(audit.Event{Type: audit.TypeAuthorisation, Outcome: audit.OutcomeSuccess,
		Repo: cfg.Name, Detail: fmt.Sprintf("proceed with stale index metadata (generated %s ago)",
			formatAge(age))})
	return nil
}

// formatAge renders a trust-state age for operator messages: whole days
// once the age reaches a day, whole hours below that.
func formatAge(d time.Duration) string {
	if d >= 24*time.Hour {
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
	return fmt.Sprintf("%dh", int(d.Hours()))
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
				DefaultRoot: e.DefaultRoot,
				URL:         e.URL, Hash: e.Hash,
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
	allowStale := fs.Bool("allow-stale", false,
		"proceed although a repository's trust state exceeds its maximum trusted age (§6.5.4)")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 2 {
		return fmt.Errorf("downgrade: usage: downgrade <package> <version>")
	}
	if err := ensureFreshTrust(app, *allowStale); err != nil {
		return fmt.Errorf("downgrade: %w", err)
	}
	target, err := version.Parse(pos[1])
	if err != nil {
		return fmt.Errorf("downgrade: invalid version %q: %w", pos[1], err)
	}
	reqs := []resolver.Request{{Kind: resolver.Downgrade, Name: pos[0], Version: target}}
	// §7.6 has no `downgrade` event type; a downgrade is audited as an
	// upgrade (a downgrade is an upgrade to an older version, §7.2.5).
	return transact(app, reqs, resolver.Options{AllowDowngrade: true},
		*dryRun, *yes, nil, install.ClaimDirective{}, audit.TypeUpgrade, false)
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
	// A cross-root transaction is undone as a unit: undoing only the
	// anchor's half would tear it, orphaning the packages it placed in
	// other roots (DESIGN-named-roots.md). Reverse every participating
	// root in one cross-root transaction.
	if last.CrossRootID != "" {
		app.printf("undoing cross-root transaction %s (%s)\n", last.CrossRootID, last.OpSummary)
		return app.undoCrossRoot(ctx, last.CrossRootID, *dryRun, *yes)
	}
	reqs, err := inverseRequests(ops)
	if err != nil {
		return err
	}
	app.printf("undoing transaction %d (%s)\n", last.ID, last.OpSummary)
	// An undo is a version-changing transaction; §7.6 has no dedicated
	// type, so it is audited as an upgrade.
	return transact(app, reqs, resolver.Options{AllowDowngrade: true},
		*dryRun, *yes, nil, install.ClaimDirective{}, audit.TypeUpgrade, false)
}

// undoCrossRoot reverses every root of a committed cross-root transaction
// as one new cross-root transaction: it gathers each participating root's
// committed operations, inverts them (an install becomes a removal; an
// upgrade, downgrade, or removal becomes a restore of the prior version),
// and resolves and executes the inverse across all roots together.
func (app *App) undoCrossRoot(ctx context.Context, crossRootID string, dryRun, yes bool) error {
	store, err := app.openDB(ctx)
	if err != nil {
		return err
	}
	defer store.Close()

	opts := resolver.Options{AllowDowngrade: true, PrimaryArch: primaryArch(ctx, store)}
	available, configs, err := availableSet(ctx, app, store)
	if err != nil {
		return err
	}
	// Restoring a prior version draws on the archive indexes, as a
	// single-root undo does; cross-root fetch is anchor-level.
	archived, err := archiveCandidates(ctx, app, store, configs)
	if err != nil {
		return err
	}
	available = append(available, archived...)

	refToPath, err := gatherRootRefs(ctx, app.paths.root)
	if err != nil {
		return err
	}
	reqs, err := app.crossRootInverseRequests(ctx, crossRootID, refToPath)
	if err != nil {
		return err
	}
	installedByRoot, extraDBs, err := app.gatherInstalledByRoot(ctx, store, configs, refToPath)
	if err != nil {
		return err
	}
	defer func() {
		for _, d := range extraDBs {
			_ = d.Close()
		}
	}()

	plan, err := resolver.ResolveMultiRoot(reqs, installedByRoot, available, refToPath, opts)
	if err != nil {
		app.emit(audit.Event{Type: audit.TypeTxnFailed,
			Outcome: audit.OutcomeRejection, Detail: err.Error()})
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
	if !app.authorize(plan.Authorizations) {
		app.printf("cancelled — required authorisation was not given\n")
		return nil
	}
	if !yes && !app.confirm() {
		app.printf("cancelled\n")
		return nil
	}
	provider := &repoProvider{client: app.repoClient(store), configs: configs}
	return app.executeCrossRoot(ctx, plan, store, provider, install.ClaimDirective{}, audit.TypeUpgrade)
}

// crossRootInverseRequests gathers, across every reachable root, the
// committed operations of one cross-root transaction and inverts them
// into resolver requests rooted at the root each ran in.
func (app *App) crossRootInverseRequests(ctx context.Context, crossRootID string,
	refToPath map[string]string) ([]resolver.Request, error) {

	rootPaths := map[string]bool{app.paths.root: true}
	for _, path := range refToPath {
		rootPaths[path] = true
	}
	var reqs []resolver.Request
	for path := range rootPaths {
		store, exists, err := openRootDB(ctx, path)
		if err != nil {
			return nil, err
		}
		if !exists {
			continue
		}
		txns, err := store.TxnsByCrossRootID(ctx, crossRootID)
		if err != nil {
			_ = store.Close()
			return nil, err
		}
		for _, txn := range txns {
			if txn.State != db.TxnCommitted {
				continue
			}
			ops, err := store.TxnOps(ctx, txn.ID)
			if err != nil {
				_ = store.Close()
				return nil, err
			}
			inv, err := inverseRequests(ops)
			if err != nil {
				_ = store.Close()
				return nil, err
			}
			for i := range inv {
				inv[i].Root = path
			}
			reqs = append(reqs, inv...)
		}
		_ = store.Close()
	}
	if len(reqs) == 0 {
		return nil, fmt.Errorf("undo: no committed operations found for cross-root transaction %s",
			crossRootID)
	}
	return reqs, nil
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
