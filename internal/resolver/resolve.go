package resolver

import (
	"fmt"
	"sort"
	"strings"

	"github.com/peios/peipkg/internal/manifest"
	"github.com/peios/peipkg/internal/version"
)

// maxResolveSteps bounds the resolver's work against a pathological
// dependency graph (§4.2.8). It is generous: a real transaction
// processes a few hundred packages.
const maxResolveSteps = 100_000

// rootSep separates the root and name halves of a world key. It is a NUL
// so it can never occur inside a root path or a package name.
const rootSep = "\x00"

// worldKey is the identity of a package in the resolution working set:
// the pair (root, name), since the same name installed in two roots is
// two independent packages (DESIGN-named-roots.md → "Identity"). In a
// single-root resolution every key shares the empty root, so the key
// orders and behaves exactly as the bare name did.
func worldKey(root, name string) string { return root + rootSep + name }

// nameOf returns the name half of a world key, for error messages.
func nameOf(key string) string {
	if i := strings.Index(key, rootSep); i >= 0 {
		return key[i+len(rootSep):]
	}
	return key
}

// worldPkg is one package in the resolution working set — the set the
// resolver shapes into the desired installed state.
type worldPkg struct {
	// root is the resolved root this package occupies (an opaque key; the
	// empty string in single-root resolution). name is its package name;
	// (root, name) is its identity.
	root         string
	name         string
	version      version.Version
	architecture string
	dependencies []manifest.Dependency
	conflicts    []manifest.Dependency
	provides     []manifest.Provides

	// installedVersion is the version this package is currently
	// installed at in its root, or nil if it is not installed.
	installedVersion *version.Version
	// installedRepo and installedRepoPriority record the repository the
	// package was installed from, for the §6.5.7 foreign-replaces gate;
	// installedRepo is empty when the package is not installed or its
	// origin is unknown.
	installedRepo         string
	installedRepoPriority int
	// candidate is the chosen replacement, or nil if the package is left
	// at its installed version.
	candidate *Candidate
}

// originRepo reports the repository this package came from and that
// repository's priority, for §4.2.4 rule 2. Both are zero only when the
// package is neither installed nor being changed by this resolution.
//
// Rule 2 scopes itself to "when the dependency is being resolved for a
// depending package D", with no restriction to packages being newly
// installed — so an already-installed depender's repository counts.
// Returning zero for it made the same dependency resolve to different
// providers depending on whether the depender happened to be part of the
// transaction, which is precisely the "low-trust depender pulling in
// low-trust transitive dependencies" gate the rule exists for, applied
// inconsistently.
func (p *worldPkg) originRepo() (repo string, priority int) {
	if p.candidate != nil {
		return p.candidate.Repo, p.candidate.RepoPriority
	}
	return p.installedRepo, p.installedRepoPriority
}

// Resolve computes a single-root plan that brings the installed set to a
// state satisfying the requests, or returns a rejection (§4.2). It is the
// unchanged single-root entry point: every package lives in one root, and
// a dependency's placement `root` field is inert (a single-root operation
// has nowhere else to place a dependency). Existing callers are
// unaffected; the resulting plan's operations all carry the empty root.
func Resolve(reqs []Request, installed []Installed, available []Candidate, opts Options) (Plan, error) {
	return resolveCore(reqs, map[string][]Installed{"": installed}, available, nil, opts)
}

// ResolveMultiRoot computes a plan that may span several roots
// (DESIGN-named-roots.md → cross-root dependencies). installed is the
// installed set of each participating root, keyed by the same opaque
// root key the requests use (a resolved filesystem path in practice).
// refToPath maps a dependency's named placement reference (§3.3.6) to the
// root key it resolves to; a dependency whose `root` names a reference
// absent from refToPath is rejected as placed in an unregistered root.
// available is the shared candidate set — v1 fetches every root's
// packages from the anchor's repositories, so one candidate set serves
// all roots.
//
// The caller MUST supply the installed set of every root the closure can
// reach (every value in refToPath, plus each request's root); a root that
// a dependency routes into but whose installed set is absent would look
// empty, and the dependency would be (re)installed spuriously.
func ResolveMultiRoot(reqs []Request, installed map[string][]Installed, available []Candidate,
	refToPath map[string]string, opts Options) (Plan, error) {
	return resolveCore(reqs, installed, available, refToPath, opts)
}

// resolveCore is the shared resolution engine. world keys are (root,
// name) pairs; refToPath routes a dependency's named placement reference
// to a root key, and is nil in single-root resolution — where every
// dependency stays in its depender's root.
func resolveCore(reqs []Request, installedByRoot map[string][]Installed, available []Candidate,
	refToPath map[string]string, opts Options) (Plan, error) {

	idx := buildIndex(available)
	world := make(map[string]*worldPkg)
	for root, insts := range installedByRoot {
		for _, inst := range insts {
			v := inst.Version
			world[worldKey(root, inst.Name)] = &worldPkg{
				root: root, name: inst.Name, version: inst.Version, architecture: inst.Architecture,
				dependencies: inst.Dependencies, conflicts: inst.Conflicts, provides: inst.Provides,
				installedVersion:      &v,
				installedRepo:         inst.Repo,
				installedRepoPriority: inst.RepoPriority,
			}
		}
	}

	// Removals are applied first, subtractively, against the world.
	downgradeAllowed := map[string]bool{}
	var removeTargets []string
	for _, req := range reqs {
		switch req.Kind {
		case Remove:
			removeTargets = append(removeTargets, worldKey(req.Root, req.Name))
		case Downgrade:
			downgradeAllowed[worldKey(req.Root, req.Name)] = true
		}
	}
	if err := applyRemovals(world, removeTargets, refToPath, opts); err != nil {
		return Plan{}, err
	}

	// Install / upgrade / downgrade requests seed the forward resolution.
	var goals []string
	var notices []Notice
	for _, req := range reqs {
		keys, err := applyGoal(req, world, idx, opts, &notices)
		if err != nil {
			return Plan{}, err
		}
		goals = append(goals, keys...)
	}

	var auths []Authorization
	if err := resolveForward(world, idx, goals, refToPath, opts, &auths); err != nil {
		return Plan{}, err
	}
	applyReplaces(world, &auths)
	if err := checkConsistency(world, opts, downgradeAllowed); err != nil {
		return Plan{}, err
	}
	plan, err := buildPlan(world, installedByRoot, refToPath, opts.PrimaryArch)
	if err != nil {
		return Plan{}, err
	}
	// A move backward to an older version is an elevated action the
	// operator must explicitly authorise (§7.2.5, §7.6.6).
	for _, op := range plan.Operations {
		if op.Kind == OpDowngrade {
			auths = append(auths, Authorization{
				Kind: AuthDowngrade,
				Detail: fmt.Sprintf("%s would move backward from %s to %s",
					op.Name, op.FromVersion, op.ToVersion),
			})
		}
	}
	plan.Authorizations = dedupeAuthorizations(auths)
	plan.Notices = notices
	return plan, nil
}

// routeRoot resolves the root a dependency is placed and satisfied in. A
// dependency with no `root` field stays in its depender's root — the
// default that makes a closure flow into the root that needs it. A named
// `root` is resolved through refToPath. In single-root resolution
// refToPath is nil and every dependency stays in the depender's root, so
// the `root` field has no effect. ok is false when a named reference is
// not registered (multi-root only).
func routeRoot(dep manifest.Dependency, dependerRoot string, refToPath map[string]string) (string, bool) {
	if dep.Root == "" || refToPath == nil {
		return dependerRoot, true
	}
	if path, ok := refToPath[dep.Root]; ok {
		return path, true
	}
	return "", false
}

// candidateIndex indexes available candidates for satisfaction queries.
type candidateIndex struct {
	byName     map[string][]Candidate
	byProvides map[string][]Candidate
}

func buildIndex(available []Candidate) candidateIndex {
	idx := candidateIndex{
		byName:     map[string][]Candidate{},
		byProvides: map[string][]Candidate{},
	}
	for _, c := range available {
		idx.byName[c.Name] = append(idx.byName[c.Name], c)
		for _, p := range c.Provides {
			idx.byProvides[p.Name] = append(idx.byProvides[p.Name], c)
		}
	}
	return idx
}

// applyGoal seeds the world from one install/upgrade/downgrade request,
// returning the world keys whose dependencies must be resolved.
func applyGoal(req Request, world map[string]*worldPkg, idx candidateIndex, opts Options,
	notices *[]Notice) ([]string, error) {

	switch req.Kind {
	case Install:
		key := worldKey(req.Root, req.Name)
		if _, ok := world[key]; ok {
			return []string{key}, nil // already present in this root; just resolve its deps
		}
		// An install goal resolves by name or via `provides` (§4.2.3), so a
		// goal may name a role — `sh`, `cc`, `coreutils` — rather than a
		// concrete package.
		cand := bestForGoal(idx, req.Name, version.Constraint{}, opts.PrimaryArch)
		if cand == nil {
			return nil, &Rejection{Reason: ReasonUnsatisfiable,
				Detail: fmt.Sprintf("no candidate is available for package %q", req.Name)}
		}
		if cand.Name != req.Name && notices != nil {
			*notices = append(*notices, Notice{
				Kind: NoticeGoalViaProvides,
				Detail: fmt.Sprintf("goal %q is satisfied by %q %s via `provides`; "+
					"no available package is named %q",
					req.Name, cand.Name, cand.Version, req.Name),
			})
		}
		placeCandidate(world, cand, req.Root)
		return []string{worldKey(req.Root, cand.Name)}, nil

	case Upgrade:
		var targets []string
		if req.Name != "" {
			targets = []string{worldKey(req.Root, req.Name)}
		} else {
			for key := range world {
				targets = append(targets, key)
			}
			sort.Strings(targets)
		}
		var resolved []string
		for _, key := range targets {
			cur, ok := world[key]
			if !ok {
				if req.Name != "" {
					return nil, &Rejection{Reason: ReasonUnsatisfiable,
						Detail: fmt.Sprintf("cannot upgrade %q: it is not installed", req.Name)}
				}
				continue
			}
			cand := bestNamed(idx.byName[cur.name], version.Constraint{}, opts.PrimaryArch)
			if cand != nil && cand.Version.Less(cur.version) == false && !cand.Version.Equal(cur.version) {
				placeCandidate(world, cand, cur.root)
			}
			resolved = append(resolved, key)
		}
		return resolved, nil

	case Downgrade:
		exact, err := version.ParseConstraint("= " + req.Version.String())
		if err != nil {
			return nil, err
		}
		cand := bestNamed(idx.byName[req.Name], exact, opts.PrimaryArch)
		if cand == nil {
			return nil, &Rejection{Reason: ReasonUnsatisfiable,
				Detail: fmt.Sprintf("no candidate of %q at version %s is available",
					req.Name, req.Version)}
		}
		placeCandidate(world, cand, req.Root)
		return []string{worldKey(req.Root, cand.Name)}, nil

	default: // Remove — already applied
		return nil, nil
	}
}

// placeCandidate installs cand into root within the world, preserving any
// record of the package being currently installed in that root.
func placeCandidate(world map[string]*worldPkg, cand *Candidate, root string) {
	key := worldKey(root, cand.Name)
	wp := &worldPkg{
		root: root, name: cand.Name, version: cand.Version, architecture: cand.Architecture,
		dependencies: cand.Dependencies, conflicts: cand.Conflicts, provides: cand.Provides,
		candidate: cand,
	}
	if existing, ok := world[key]; ok {
		wp.installedVersion = existing.installedVersion
		wp.installedRepo = existing.installedRepo
		wp.installedRepoPriority = existing.installedRepoPriority
	}
	world[key] = wp
}

// resolveForward greedily satisfies the dependencies of every package
// reachable from the goals, adding candidates as needed (§4.2). A
// dependency is satisfied and placed in the root routeRoot selects — the
// depender's root by default, or the root its `root` field names.
func resolveForward(world map[string]*worldPkg, idx candidateIndex, goals []string,
	refToPath map[string]string, opts Options, auths *[]Authorization) error {

	worklist := append([]string(nil), goals...)
	steps := 0
	for len(worklist) > 0 {
		if steps++; steps > maxResolveSteps {
			return &Rejection{Reason: ReasonTooComplex,
				Detail: "dependency resolution exceeded the work limit"}
		}
		key := worklist[0]
		worklist = worklist[1:]
		pkg := world[key]
		if pkg == nil {
			continue
		}
		deps := append([]manifest.Dependency(nil), pkg.dependencies...)
		sort.Slice(deps, func(i, j int) bool { return deps[i].Name < deps[j].Name })
		for _, dep := range deps {
			targetRoot, ok := routeRoot(dep, pkg.root, refToPath)
			if !ok {
				return &Rejection{Reason: ReasonUnsatisfiable,
					Detail: fmt.Sprintf("package %q depends on %q placed in root %q, "+
						"which is not a registered root", pkg.name, dep.Name, dep.Root)}
			}
			if worldSatisfiesInRoot(world, dep, pkg.architecture, opts.PrimaryArch, targetRoot) {
				continue
			}
			depRepo, depPriority := pkg.originRepo()
			cand := bestForDependency(idx, dep, pkg.architecture, opts.PrimaryArch, depRepo, depPriority)
			if cand == nil {
				return &Rejection{Reason: ReasonUnsatisfiable,
					Detail: fmt.Sprintf("package %q depends on %q, which no available "+
						"package satisfies", pkg.name, dep.Name)}
			}
			placeCandidate(world, cand, targetRoot)
			if a := lowTrustProvidesAuthorization(idx, dep, cand); a != nil {
				*auths = append(*auths, *a)
			}
			worklist = append(worklist, worldKey(targetRoot, cand.Name))
		}
	}
	return nil
}

// worldSatisfiesInRoot reports whether some package in targetRoot already
// satisfies dep for a depender of architecture dependerArch.
func worldSatisfiesInRoot(world map[string]*worldPkg, dep manifest.Dependency,
	dependerArch, primaryArch, targetRoot string) bool {

	for _, p := range world {
		if p.root != targetRoot {
			continue
		}
		if satisfies(p.name, p.version, p.architecture, p.provides, dep, dependerArch, primaryArch) {
			return true
		}
	}
	return false
}

// effectiveArch is a package's architecture for resolution purposes
// (§5.21): its own when arch-specific, and the system's primary
// architecture when it is noarch. A noarch package's payload is
// architecture-independent, but its resolution context is not.
func effectiveArch(arch, primaryArch string) string {
	if arch == archNoarch && primaryArch != "" {
		return primaryArch
	}
	return arch
}

// satisfies reports whether a package — described by its name, version,
// architecture, and provides — satisfies dep for a depender of
// architecture dependerArch (§4.2.3). The caller restricts the candidate
// to the dependency's target root; satisfaction within that root is what
// this checks.
func satisfies(name string, ver version.Version, arch string, provides []manifest.Provides,
	dep manifest.Dependency, dependerArch, primaryArch string) bool {

	// §4.1.3/§5.21: the satisfier's architecture must be noarch or equal
	// the depender's *effective* architecture — its own when
	// arch-specific, and the system's primary architecture when the
	// depender is noarch.
	//
	// Skipping the test outright for a noarch depender let any
	// architecture satisfy, a foreign one included. That candidate then
	// entered the matching set, could win rules 1-6, was placed, and was
	// caught only by checkConsistency — which rejects the *entire*
	// resolution. §4.2.5(1) permits failure only when no available
	// package satisfies, and §4.2.5(3) is a check on the proposed plan,
	// not a licence to build a bad one and then reject it. A noarch
	// depender with a noarch candidate available was failing outright
	// because a foreign-arch candidate outranked it.
	if arch != archNoarch && effectiveArch(dependerArch, primaryArch) != archNoarch &&
		arch != effectiveArch(dependerArch, primaryArch) {
		return false
	}
	if name == dep.Name && dep.Constraint.Matches(ver) {
		return true
	}
	for _, p := range provides {
		if p.Name != dep.Name {
			continue
		}
		// An unversioned provides satisfies any constraint (§4.1.4).
		if p.Version == nil || dep.Constraint.Matches(*p.Version) {
			return true
		}
	}
	return false
}

// lowTrustProvidesAuthorization reports the §4.2.4 elevated action, if
// any, raised by choosing cand to satisfy dep: cand satisfies dep only
// through a `provides` entry, and a higher-priority repository offers a
// package whose name matches dep but whose version fails dep's
// constraint. The operator must authorise such a substitution (§7.6.6).
func lowTrustProvidesAuthorization(idx candidateIndex, dep manifest.Dependency,
	cand *Candidate) *Authorization {

	if cand.Name == dep.Name && dep.Constraint.Matches(cand.Version) {
		return nil // a direct name match — not a `provides` substitution
	}
	for _, c := range idx.byName[dep.Name] {
		if c.RepoPriority < cand.RepoPriority && !dep.Constraint.Matches(c.Version) {
			return &Authorization{
				Kind: AuthLowTrustProvides,
				Detail: fmt.Sprintf(
					"dependency %q is satisfied by %q %s via `provides` from repository %q, "+
						"shadowing %q %s from higher-priority repository %q whose version "+
						"does not meet the constraint",
					dep.Name, cand.Name, cand.Version, cand.Repo,
					c.Name, c.Version, c.Repo),
			}
		}
	}
	return nil
}

// dedupeAuthorizations drops authorizations with identical detail,
// preserving order, so a package re-placed during resolution does not
// raise the same elevated action twice.
func dedupeAuthorizations(auths []Authorization) []Authorization {
	if len(auths) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(auths))
	out := auths[:0]
	for _, a := range auths {
		if seen[a.Detail] {
			continue
		}
		seen[a.Detail] = true
		out = append(out, a)
	}
	return out
}

// applyReplaces enacts §4.1.5 succession within each root. A package being
// installed or upgraded that declares a `replaces` entry matching a
// package installed in the same root supersedes it: the replaced package
// is dropped from the desired world, so the plan removes it and installs
// the replacer in its place. Succession does not cross roots — a replacer
// in one root has no bearing on a same-named package in another. A
// succession driven by a package from a lower-priority repository than the
// replaced package's origin is an elevated action requiring explicit
// operator authorisation (§6.5.7).
//
// World keys are visited in sorted order so the authorizations are
// produced deterministically (§4.2.7).
func applyReplaces(world map[string]*worldPkg, auths *[]Authorization) {
	var superseded []string
	for _, key := range sortedKeys(world) {
		p := world[key]
		if p.candidate == nil {
			continue // not being installed or upgraded — its replaces is inert
		}
		for _, r := range p.candidate.Replaces {
			victimKey := worldKey(p.root, r.Name)
			victim, ok := world[victimKey]
			if !ok || victim.installedVersion == nil {
				continue // not installed in this root — nothing to supersede
			}
			if !r.Constraint.Matches(*victim.installedVersion) {
				continue
			}
			superseded = append(superseded, victimKey)
			if victim.installedRepo != "" &&
				p.candidate.RepoPriority > victim.installedRepoPriority {
				*auths = append(*auths, Authorization{
					Kind: AuthForeignReplaces,
					Detail: fmt.Sprintf(
						"%q from repository %q (priority %d) replaces %q, which was "+
							"installed from higher-priority repository %q (priority %d)",
						p.name, p.candidate.Repo, p.candidate.RepoPriority,
						r.Name, victim.installedRepo, victim.installedRepoPriority),
				})
			}
		}
	}
	for _, key := range superseded {
		delete(world, key)
	}
}
