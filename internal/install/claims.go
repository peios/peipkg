package install

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/peios/peipkg/internal/claims"
	"github.com/peios/peipkg/internal/db"
	"github.com/peios/peipkg/internal/manifest"
	"github.com/peios/peipkg/internal/resolver"
	"github.com/peios/peipkg/internal/safepath"
)

// ClaimDirective is the operator's install-time claim intent (§7.7.2).
// The zero value is the default: auto-claim every unheld role the
// installed packages provide, claim nothing already held.
type ClaimDirective struct {
	// NoClaim suppresses auto-claiming (--no-claim).
	NoClaim bool
	// All claims every provided role, overriding existing holders
	// (--claim-all).
	All bool
	// Roles names roles to claim even if already held (--claim x,y).
	Roles []string
}

// claimWork is the claim materialisation a transaction must apply: the
// journalled file operations (created/repointed/removed symlinks), the
// staged symlinks to create on disk, and the database row changes —
// holders to set or clear and links to delete or insert (§4.4.4).
type claimWork struct {
	fileOps        []fileOp
	createdDirs    []string
	stagedSymlinks []stagedSymlink
	setHolders     map[string]string
	delHolders     []string
	delLinks       []string
	insLinks       []db.ClaimLink
}

// stagedSymlink is one claim link awaiting materialisation: the staged
// sibling path to create, and the (absolute, logical) target it points
// at.
type stagedSymlink struct {
	staged string
	target string
	// dir pins the parent the link is created in, and name is the
	// staged link's component within it. §5.26 applies to a claim link
	// exactly as it does to payload: the link is created relative to a
	// verified descriptor, never through a re-walked string (PEI-444).
	dir  *safepath.Dir
	name string
}

func (w claimWork) empty() bool {
	return len(w.fileOps) == 0 && len(w.setHolders) == 0 && len(w.delHolders) == 0 &&
		len(w.delLinks) == 0 && len(w.insLinks) == 0
}

// planClaims computes the claim materialisation for a transaction:
// reconciling the desired link set (from the post-transaction installed
// packages and holders) against what is on disk (§4.4.4). It returns the
// work to apply, any withdrawal warnings (§7.7.6), or an error — a
// path-collision or a forced role the plan does not provide.
func planClaims(ctx context.Context, env Env, pins *pinnedDirs, plan resolver.Plan,
	provided map[string]ProvidedPackage, dir ClaimDirective, txnID int64,
	plannedDirs map[string]bool) (claimWork, []string, error) {

	postInstalled, err := postInstalledManifests(ctx, env, plan, provided)
	if err != nil {
		return claimWork{}, nil, err
	}
	current, post, err := computeHolders(ctx, env, plan, provided, dir)
	if err != nil {
		return claimWork{}, nil, err
	}
	w, err := reconcileClaims(ctx, env, pins, postInstalled, current, post, txnID, plannedDirs)
	if err != nil {
		return claimWork{}, nil, err
	}
	return w, withdrawalWarnings(current, post, postInstalled), nil
}

// reconcileClaims diffs the desired link set (from postInstalled and the
// post-transaction holders) against what is on disk and returns the work
// to make them equal: file operations, staged symlinks, and database row
// changes (§4.4.4). It is shared by install transactions and the
// standalone claim command, which differ only in how post is derived.
func reconcileClaims(ctx context.Context, env Env, pins *pinnedDirs,
	postInstalled []claims.Installed, current, post map[string]string, txnID int64,
	plannedDirs map[string]bool) (claimWork, error) {

	desired, err := claims.Desired(postInstalled, post)
	if err != nil {
		return claimWork{}, err
	}
	// §4.4.4: a claim path must not collide with a package-owned file.
	for _, l := range desired {
		owners, err := env.DB.FileOwners(ctx, l.Path)
		if err != nil {
			return claimWork{}, err
		}
		for _, o := range owners {
			if o.Type != db.FileTypeDir {
				return claimWork{}, fmt.Errorf(
					"peipkg/install: claim path %s (role %s) is owned by package %s",
					l.Path, l.Role, o.PackageName)
			}
		}
	}

	actual, err := env.DB.ClaimLinks(ctx)
	if err != nil {
		return claimWork{}, err
	}
	recPlan := claims.Reconcile(toClaimsLinks(actual), desired)

	w := claimWork{setHolders: post}
	for role := range current {
		if _, ok := post[role]; !ok {
			w.delHolders = append(w.delHolders, role)
		}
	}
	sort.Strings(w.delHolders)

	// Create and repoint both stage a fresh symlink; plannedOp makes the
	// repoint a replace because the old link still occupies the path.
	for _, l := range append(append([]claims.Link{}, recPlan.Create...), recPlan.Repoint...) {
		physical := filepath.Join(env.Root, l.Path)
		staged := tempPath(physical, stagedMarker, txnID)
		rememberCreatedDirs(pins, env.Root, filepath.Dir(staged), plannedDirs, &w.createdDirs)
		// Relative target keeps the link valid under any root prefix (env.Root
		// here, a future mount point, an image build); the DB keeps the
		// absolute logical target. See claims.RelativeTarget.
		target, err := claims.RelativeTarget(l)
		if err != nil {
			return claimWork{}, err
		}
		fo, err := plannedOp(pins, physical, staged, txnID)
		if err != nil {
			return claimWork{}, err
		}
		w.stagedSymlinks = append(w.stagedSymlinks, stagedSymlink{
			staged: staged, target: target, dir: fo.dir, name: filepath.Base(staged)})
		w.fileOps = append(w.fileOps, fo)
	}
	for _, l := range recPlan.Remove {
		physical := filepath.Join(env.Root, l.Path)
		d, err := pins.existingDirFor(physical)
		if err != nil {
			return claimWork{}, err
		}
		w.fileOps = append(w.fileOps, fileOp{
			finalPath: physical, action: actionRemove, dir: d,
			backupPath: tempPath(physical, backupMarker, txnID)})
	}

	// The database link rows are reset to the desired set wholesale: the
	// reconcile already proved this equals on-disk after the file ops.
	for _, l := range actual {
		w.delLinks = append(w.delLinks, l.Path)
	}
	for _, l := range desired {
		w.insLinks = append(w.insLinks, db.ClaimLink{
			Path: l.Path, Role: l.Role, Slot: l.Slot, Target: l.Target})
	}
	return w, nil
}

// postInstalledManifests is the claim-relevant manifest of every package
// installed after the transaction applies: the current installed set,
// minus removals, plus the new manifests of installs and upgrades. The
// in-flight packages' manifests come from the verified payload (the
// authority); the rest from the stored manifest.
func postInstalledManifests(ctx context.Context, env Env, plan resolver.Plan,
	provided map[string]ProvidedPackage) ([]claims.Installed, error) {

	pkgs, err := env.DB.ListPackages(ctx)
	if err != nil {
		return nil, err
	}
	byName := make(map[string]manifest.Manifest, len(pkgs))
	for _, p := range pkgs {
		// A stored manifest that will not decode contributes no claim
		// data: an already-installed package's manifest was validated at
		// install, so this never skips a real package in production; it
		// only tolerates a degraded or fixture row rather than failing an
		// unrelated transaction's claim reconciliation.
		m, err := manifest.Decode([]byte(p.Manifest))
		if err != nil {
			continue
		}
		byName[p.Name] = m
	}
	for _, op := range plan.Operations {
		if op.Kind == resolver.OpRemove {
			delete(byName, op.Name)
			continue
		}
		byName[op.Name] = provided[op.Name].Pkg.Manifest
	}

	out := make([]claims.Installed, 0, len(byName))
	for name, m := range byName {
		out = append(out, claims.Installed{Name: name, Manifest: m})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// computeHolders returns the role holders before and after the
// transaction. A removed package's roles go unheld (§7.7.6); an installed
// eligible provider auto-claims the roles it provides that are unheld,
// and force-claims those named by the directive — overriding the
// incumbent (§7.7.1, §7.7.2).
func computeHolders(ctx context.Context, env Env, plan resolver.Plan,
	provided map[string]ProvidedPackage, dir ClaimDirective) (current, post map[string]string, err error) {

	current = map[string]string{}
	holders, err := env.DB.ClaimHolders(ctx)
	if err != nil {
		return nil, nil, err
	}
	for _, h := range holders {
		current[h.Role] = h.Holder
	}

	post = make(map[string]string, len(current))
	removing := map[string]bool{}
	for _, op := range plan.Operations {
		if op.Kind == resolver.OpRemove {
			removing[op.Name] = true
		}
	}
	for role, holder := range current {
		if !removing[holder] {
			post[role] = holder
		}
	}

	// The roles each in-flight package is an eligible provider of. When
	// two in-flight packages provide the same role, the lexicographically
	// smallest package name wins — a stable choice independent of plan
	// order, so the resulting holder is deterministic (§4.2.8).
	providerOf := map[string]string{}
	for _, op := range plan.Operations {
		if op.Kind == resolver.OpRemove {
			continue
		}
		for _, role := range claims.ProvidedRoles(provided[op.Name].Pkg.Manifest) {
			if cur, ok := providerOf[role]; !ok || op.Name < cur {
				providerOf[role] = op.Name
			}
		}
	}

	// §7.7.2: a forced role must be provided by some in-flight package.
	forced := map[string]bool{}
	for _, role := range dir.Roles {
		if _, ok := providerOf[role]; !ok {
			return nil, nil, fmt.Errorf(
				"peipkg/install: --claim %s: no package being installed provides role %q",
				role, role)
		}
		forced[role] = true
	}

	for role, pkg := range providerOf {
		switch {
		case dir.All || forced[role]:
			post[role] = pkg // force-claim, overriding any incumbent
		case dir.NoClaim:
			// claim nothing automatically
		default:
			if _, held := post[role]; !held {
				post[role] = pkg // auto-claim an unheld role
			}
		}
	}
	return current, post, nil
}

// withdrawalWarnings reports the §7.7.6 notice for each role that became
// unheld in this transaction while other eligible providers remain
// installed.
func withdrawalWarnings(current, post map[string]string, installed []claims.Installed) []string {
	var warnings []string
	roles := make([]string, 0, len(current))
	for role := range current {
		if _, ok := post[role]; !ok {
			roles = append(roles, role)
		}
	}
	sort.Strings(roles)
	for _, role := range roles {
		var providers []string
		for _, p := range installed {
			if claims.EligibleProvider(p.Manifest, role) {
				providers = append(providers, p.Name)
			}
		}
		if len(providers) == 0 {
			continue
		}
		warnings = append(warnings, fmt.Sprintf(
			"claim %q withdrawn — packages %s also provide it; run "+
				"'peipkg claim %s grant %s' to assign a new holder",
			role, strings.Join(providers, ", "), role, providers[0]))
	}
	return warnings
}

// materializeClaims creates the staged claim symlinks after the journal
// exists, mirroring materializePackage for payload entries.
func materializeClaims(w claimWork) error {
	for _, ss := range w.stagedSymlinks {
		// The parent was created and pinned when the link was planned,
		// so there is no directory to make and no path to re-walk here.
		if err := ss.dir.Symlink(ss.target, ss.name); err != nil {
			return fmt.Errorf("peipkg/install: staging claim link %s: %w", ss.staged, err)
		}
	}
	return nil
}

// applyClaimMetadata records the post-transaction holder and link state.
// It runs inside the commit's SQLite transaction (§7.4.5), after
// applyMetadata so every holder package row already exists. Holders are
// set before links are inserted, satisfying the link -> holder foreign
// key; cleared holders cascade their old links away first.
func applyClaimMetadata(ctx context.Context, tx *db.Tx, w claimWork) error {
	for _, role := range w.delHolders {
		if err := tx.DeleteClaimHolder(ctx, role); err != nil {
			return err
		}
	}
	for role, holder := range w.setHolders {
		if err := tx.SetClaimHolder(ctx, role, holder); err != nil {
			return err
		}
	}
	for _, path := range w.delLinks {
		if err := tx.DeleteClaimLink(ctx, path); err != nil {
			return err
		}
	}
	return tx.InsertClaimLinks(ctx, w.insLinks)
}

// ClaimRequest is a standalone grant or revoke of a role's holder
// (§7.7). Holder names the package to grant the role to; an empty Holder
// revokes the current grant, leaving the role unheld.
type ClaimRequest struct {
	Role   string
	Holder string
}

// Claim grants or revokes a role's holder as a standalone transaction
// (§7.7): it changes the holder pointer and reconciles the role's
// symlinks, recorded under a synthetic 'claim' txn_op so it journals,
// commits, and recovers like any other transaction.
func Claim(ctx context.Context, env Env, req ClaimRequest) (Result, error) {
	lock, err := Acquire(env.LockPath)
	if err != nil {
		return Result{}, err
	}
	defer lock.Release()
	if err := recoverPending(ctx, env); err != nil {
		return Result{}, err
	}

	installed, err := postInstalledManifests(ctx, env, resolver.Plan{}, nil)
	if err != nil {
		return Result{}, err
	}
	current := map[string]string{}
	holders, err := env.DB.ClaimHolders(ctx)
	if err != nil {
		return Result{}, err
	}
	for _, h := range holders {
		current[h.Role] = h.Holder
	}

	post := make(map[string]string, len(current))
	for r, h := range current {
		post[r] = h
	}
	if req.Holder != "" {
		var m manifest.Manifest
		found := false
		for _, p := range installed {
			if p.Name == req.Holder {
				m, found = p.Manifest, true
				break
			}
		}
		if !found {
			return Result{}, fmt.Errorf(
				"peipkg/install: claim grant: package %q is not installed", req.Holder)
		}
		if !claims.EligibleProvider(m, req.Role) {
			return Result{}, fmt.Errorf(
				"peipkg/install: claim grant: package %q is not an eligible provider of role %q",
				req.Holder, req.Role)
		}
		post[req.Role] = req.Holder
	} else {
		if _, held := current[req.Role]; !held {
			return Result{}, fmt.Errorf("peipkg/install: claim revoke: role %q is not held", req.Role)
		}
		delete(post, req.Role)
	}

	txnID, err := env.DB.BeginTxn(ctx, env.PeipkgVersion, journalSchemaVersion)
	if err != nil {
		return Result{}, err
	}
	pins, err := newPinnedDirs(env.Root)
	if err != nil {
		_ = env.DB.FinishTxn(ctx, txnID, db.TxnRolledBack, "opening the installation root failed")
		return Result{TxnID: txnID}, err
	}
	defer pins.close()

	plannedDirs := map[string]bool{}
	w, err := reconcileClaims(ctx, env, pins, installed, current, post, txnID, plannedDirs)
	if err != nil {
		_ = env.DB.FinishTxn(ctx, txnID, db.TxnRolledBack, "planning the claim failed")
		return Result{TxnID: txnID}, err
	}

	if err := writeClaimJournal(ctx, env.DB, txnID, req.Role, w); err != nil {
		return Result{TxnID: txnID}, errors.Join(err,
			abandonClaim(ctx, env, pins, txnID, w, "recording the journal failed"))
	}
	if err := materializeClaims(w); err != nil {
		return Result{TxnID: txnID}, errors.Join(err,
			abandonClaim(ctx, env, pins, txnID, w, "staging claim links failed"))
	}
	if err := commitOps(w.fileOps); err != nil {
		return Result{TxnID: txnID}, errors.Join(err,
			finishRolledBack(ctx, env, pins, txnID, w.fileOps, w.createdDirs,
				"applying claim changes failed"))
	}
	err = env.DB.Tx(ctx, func(tx *db.Tx) error {
		if err := applyClaimMetadata(ctx, tx, w); err != nil {
			return err
		}
		return tx.FinishTxn(ctx, txnID, db.TxnCommitted, claimSummary(req))
	})
	if err != nil {
		return Result{TxnID: txnID}, errors.Join(
			fmt.Errorf("peipkg/install: committing claim transaction %d: %w", txnID, err),
			finishRolledBack(ctx, env, pins, txnID, w.fileOps, w.createdDirs,
				"committing the claim failed"))
	}

	result := Result{TxnID: txnID}
	result.Warnings = append(result.Warnings, discardBackups(w.fileOps)...)
	return result, nil
}

// writeClaimJournal records a standalone claim transaction: one 'claim'
// txn_op keyed by the role, and the role's symlink file operations. The
// txn_file rows reference that op through the same foreign key as any
// package's file rows, so crash recovery reverses them identically.
func writeClaimJournal(ctx context.Context, store *db.DB, txnID int64, role string, w claimWork) error {
	ops := []db.TxnOp{{Seq: 0, PackageName: role, Action: db.OpClaim}}
	files := make([]db.TxnFile, 0, len(w.fileOps))
	for i, fo := range w.fileOps {
		files = append(files, db.TxnFile{
			Seq: i, PackageName: role, FinalPath: fo.finalPath,
			Action: txnFileAction(fo.action), StagedPath: fo.stagedPath, BackupPath: fo.backupPath})
	}
	dirs := make([]db.TxnDir, 0, len(w.createdDirs))
	for i, d := range w.createdDirs {
		dirs = append(dirs, db.TxnDir{Seq: i, Path: d})
	}
	if err := store.InsertTxnOps(ctx, txnID, ops); err != nil {
		return err
	}
	if err := store.InsertTxnFiles(ctx, txnID, files); err != nil {
		return err
	}
	return store.InsertTxnDirs(ctx, txnID, dirs)
}

func abandonClaim(ctx context.Context, env Env, pins *pinnedDirs, txnID int64,
	w claimWork, reason string) error {
	return finishRolledBack(ctx, env, pins, txnID, w.fileOps, w.createdDirs, reason)
}

func claimSummary(req ClaimRequest) string {
	if req.Holder == "" {
		return fmt.Sprintf("revoked claim %s", req.Role)
	}
	return fmt.Sprintf("granted claim %s to %s", req.Role, req.Holder)
}

// toClaimsLinks adapts database link rows to the reconciliation type.
func toClaimsLinks(rows []db.ClaimLink) []claims.Link {
	links := make([]claims.Link, len(rows))
	for i, r := range rows {
		links[i] = claims.Link{Path: r.Path, Role: r.Role, Slot: r.Slot, Target: r.Target}
	}
	return links
}
