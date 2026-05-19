package resolver

import (
	"fmt"
	"sort"

	"github.com/peios/peipkg/internal/manifest"
	"github.com/peios/peipkg/internal/version"
)

// maxResolveSteps bounds the resolver's work against a pathological
// dependency graph (§4.2.8). It is generous: a real transaction
// processes a few hundred packages.
const maxResolveSteps = 100_000

// worldPkg is one package in the resolution working set — the set the
// resolver shapes into the desired installed state.
type worldPkg struct {
	name         string
	version      version.Version
	architecture string
	dependencies []manifest.Dependency
	conflicts    []manifest.Dependency
	provides     []manifest.Provides

	// installedVersion is the version this package is currently
	// installed at, or nil if it is not installed.
	installedVersion *version.Version
	// candidate is the chosen replacement, or nil if the package is left
	// at its installed version.
	candidate *Candidate
}

// originRepo reports the repository this package is being installed from
// and that repository's priority, for §4.2.4 rule 2. Both are zero when
// the package is not being changed by this resolution (it has no chosen
// candidate), in which case rule 2 does not apply.
func (p *worldPkg) originRepo() (repo string, priority int) {
	if p.candidate != nil {
		return p.candidate.Repo, p.candidate.RepoPriority
	}
	return "", 0
}

// Resolve computes a plan that brings the installed set to a state
// satisfying the requests, or returns a rejection (§4.2).
func Resolve(reqs []Request, installed []Installed, available []Candidate, opts Options) (Plan, error) {
	idx := buildIndex(available)
	world := make(map[string]*worldPkg, len(installed))
	for _, inst := range installed {
		v := inst.Version
		world[inst.Name] = &worldPkg{
			name: inst.Name, version: inst.Version, architecture: inst.Architecture,
			dependencies: inst.Dependencies, conflicts: inst.Conflicts, provides: inst.Provides,
			installedVersion: &v,
		}
	}

	// Removals are applied first, subtractively, against the world.
	downgradeAllowed := map[string]bool{}
	var removeRoots []string
	for _, req := range reqs {
		switch req.Kind {
		case Remove:
			removeRoots = append(removeRoots, req.Name)
		case Downgrade:
			downgradeAllowed[req.Name] = true
		}
	}
	if err := applyRemovals(world, removeRoots, opts); err != nil {
		return Plan{}, err
	}

	// Install / upgrade / downgrade requests seed the forward resolution.
	var goals []string
	for _, req := range reqs {
		names, err := applyGoal(req, world, idx, opts)
		if err != nil {
			return Plan{}, err
		}
		goals = append(goals, names...)
	}

	if err := resolveForward(world, idx, goals, opts); err != nil {
		return Plan{}, err
	}
	if err := checkConsistency(world, opts, downgradeAllowed); err != nil {
		return Plan{}, err
	}
	return buildPlan(world, installed)
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
// returning the package names whose dependencies must be resolved.
func applyGoal(req Request, world map[string]*worldPkg, idx candidateIndex, opts Options) ([]string, error) {
	switch req.Kind {
	case Install:
		if _, ok := world[req.Name]; ok {
			return []string{req.Name}, nil // already present; just resolve its deps
		}
		cand := bestNamed(idx.byName[req.Name], version.Constraint{}, opts.PrimaryArch)
		if cand == nil {
			return nil, &Rejection{Reason: ReasonUnsatisfiable,
				Detail: fmt.Sprintf("no candidate is available for package %q", req.Name)}
		}
		placeCandidate(world, cand)
		return []string{cand.Name}, nil

	case Upgrade:
		var targets []string
		if req.Name != "" {
			targets = []string{req.Name}
		} else {
			for name := range world {
				targets = append(targets, name)
			}
			sort.Strings(targets)
		}
		var resolved []string
		for _, name := range targets {
			cur, ok := world[name]
			if !ok {
				if req.Name != "" {
					return nil, &Rejection{Reason: ReasonUnsatisfiable,
						Detail: fmt.Sprintf("cannot upgrade %q: it is not installed", name)}
				}
				continue
			}
			cand := bestNamed(idx.byName[name], version.Constraint{}, opts.PrimaryArch)
			if cand != nil && cand.Version.Less(cur.version) == false && !cand.Version.Equal(cur.version) {
				placeCandidate(world, cand)
			}
			resolved = append(resolved, name)
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
		placeCandidate(world, cand)
		return []string{cand.Name}, nil

	default: // Remove — already applied
		return nil, nil
	}
}

// placeCandidate installs cand into the world, preserving any record of
// the package being currently installed.
func placeCandidate(world map[string]*worldPkg, cand *Candidate) {
	wp := &worldPkg{
		name: cand.Name, version: cand.Version, architecture: cand.Architecture,
		dependencies: cand.Dependencies, conflicts: cand.Conflicts, provides: cand.Provides,
		candidate: cand,
	}
	if existing, ok := world[cand.Name]; ok {
		wp.installedVersion = existing.installedVersion
	}
	world[cand.Name] = wp
}

// resolveForward greedily satisfies the dependencies of every package
// reachable from the goals, adding candidates as needed (§4.2).
func resolveForward(world map[string]*worldPkg, idx candidateIndex, goals []string, opts Options) error {
	worklist := append([]string(nil), goals...)
	steps := 0
	for len(worklist) > 0 {
		if steps++; steps > maxResolveSteps {
			return &Rejection{Reason: ReasonTooComplex,
				Detail: "dependency resolution exceeded the work limit"}
		}
		name := worklist[0]
		worklist = worklist[1:]
		pkg := world[name]
		if pkg == nil {
			continue
		}
		deps := append([]manifest.Dependency(nil), pkg.dependencies...)
		sort.Slice(deps, func(i, j int) bool { return deps[i].Name < deps[j].Name })
		for _, dep := range deps {
			if worldSatisfies(world, dep, pkg.architecture) {
				continue
			}
			depRepo, depPriority := pkg.originRepo()
			cand := bestForDependency(idx, dep, pkg.architecture, opts.PrimaryArch, depRepo, depPriority)
			if cand == nil {
				return &Rejection{Reason: ReasonUnsatisfiable,
					Detail: fmt.Sprintf("package %q depends on %q, which no available "+
						"package satisfies", pkg.name, dep.Name)}
			}
			placeCandidate(world, cand)
			worklist = append(worklist, cand.Name)
		}
	}
	return nil
}

// worldSatisfies reports whether some package already in the world
// satisfies dep for a depender of architecture dependerArch.
func worldSatisfies(world map[string]*worldPkg, dep manifest.Dependency, dependerArch string) bool {
	for _, p := range world {
		if satisfies(p.name, p.version, p.architecture, p.provides, dep, dependerArch) {
			return true
		}
	}
	return false
}

// satisfies reports whether a package — described by its name, version,
// architecture, and provides — satisfies dep for a depender of
// architecture dependerArch (§4.2.3).
func satisfies(name string, ver version.Version, arch string, provides []manifest.Provides,
	dep manifest.Dependency, dependerArch string) bool {

	// §4.1.3: with the v0.22 `any` arch qualifier, the satisfier's
	// architecture must equal the depender's or be noarch.
	if arch != archNoarch && arch != dependerArch {
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
