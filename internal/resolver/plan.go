package resolver

import (
	"fmt"
	"sort"

	"github.com/peios/peipkg/internal/version"
)

// removedPkg is one installed package the plan removes, tagged with the
// root it is removed from.
type removedPkg struct {
	root string
	inst Installed
}

// buildPlan diffs the resolved world against the installed set and
// orders the resulting operations: removals first — dependents before
// their dependencies — then installs, upgrades, and downgrades —
// dependencies before their dependents (§4.2.1). Operations carry their
// target root; dependency ordering follows edges across roots, so a
// cross-root dependency is sequenced before the dependent that needs it.
func buildPlan(world map[string]*worldPkg, installedByRoot map[string][]Installed,
	refToPath map[string]string) (Plan, error) {

	var forward []Operation
	for _, key := range sortedKeys(world) {
		p := world[key]
		if p.candidate == nil {
			continue // installed and unchanged
		}
		op := Operation{Root: p.root, Name: p.name, ToVersion: p.candidate.Version, Candidate: p.candidate}
		if p.installedVersion == nil {
			op.Kind = OpInstall
		} else {
			op.FromVersion = *p.installedVersion
			switch version.Compare(p.candidate.Version, *p.installedVersion) {
			case 1:
				op.Kind = OpUpgrade
			case -1:
				op.Kind = OpDowngrade
			default:
				continue // re-selected at the same version: no operation
			}
		}
		forward = append(forward, op)
	}

	var removed []removedPkg
	for root, insts := range installedByRoot {
		for _, inst := range insts {
			if _, present := world[worldKey(root, inst.Name)]; !present {
				removed = append(removed, removedPkg{root: root, inst: inst})
			}
		}
	}

	removeOps, err := orderRemovals(removed, refToPath)
	if err != nil {
		return Plan{}, err
	}
	forwardOps, err := orderForward(forward, world, refToPath)
	if err != nil {
		return Plan{}, err
	}
	return Plan{Operations: append(removeOps, forwardOps...)}, nil
}

// orderForward sorts install/upgrade/downgrade operations so each
// package follows the in-plan packages it depends on, across roots.
func orderForward(ops []Operation, world map[string]*worldPkg, refToPath map[string]string) ([]Operation, error) {
	byKey := make(map[string]Operation, len(ops))
	inPlan := make(map[string]bool, len(ops))
	keys := make([]string, 0, len(ops))
	for _, op := range ops {
		k := worldKey(op.Root, op.Name)
		byKey[k] = op
		inPlan[k] = true
		keys = append(keys, k)
	}
	ordered, err := topoSort(keys, func(key string) []string {
		return planDependencies(key, world, inPlan, refToPath)
	})
	if err != nil {
		return nil, err
	}
	out := make([]Operation, len(ordered))
	for i, key := range ordered {
		out[i] = byKey[key]
	}
	return out, nil
}

// orderRemovals sorts removal operations so each package precedes the
// packages it depended on (§4.2.1), across roots.
func orderRemovals(removed []removedPkg, refToPath map[string]string) ([]Operation, error) {
	byKey := make(map[string]removedPkg, len(removed))
	keys := make([]string, 0, len(removed))
	for _, rp := range removed {
		k := worldKey(rp.root, rp.inst.Name)
		byKey[k] = rp
		keys = append(keys, k)
	}
	ordered, err := topoSort(keys, func(key string) []string {
		return removedDependencies(byKey[key], byKey, refToPath)
	})
	if err != nil {
		return nil, err
	}
	// topoSort yields dependency-first order; a removal runs in the
	// reverse, so a dependent is removed before what it depended on.
	out := make([]Operation, 0, len(ordered))
	for i := len(ordered) - 1; i >= 0; i-- {
		rp := byKey[ordered[i]]
		out = append(out, Operation{Kind: OpRemove, Root: rp.root, Name: rp.inst.Name,
			FromVersion: rp.inst.Version})
	}
	return out, nil
}

// planDependencies returns the world keys of the in-plan packages that
// key's package depends on, routing each dependency to its target root so
// a cross-root edge orders correctly.
func planDependencies(key string, world map[string]*worldPkg, inPlan map[string]bool,
	refToPath map[string]string) []string {

	p := world[key]
	if p == nil {
		return nil
	}
	seen := map[string]bool{}
	var deps []string
	for _, dep := range p.dependencies {
		targetRoot, ok := routeRoot(dep, p.root, refToPath)
		if !ok {
			continue
		}
		for _, other := range sortedKeys(world) {
			if other == key || !inPlan[other] || seen[other] {
				continue
			}
			s := world[other]
			if s.root != targetRoot {
				continue
			}
			if satisfies(s.name, s.version, s.architecture, s.provides, dep, p.architecture) {
				seen[other] = true
				deps = append(deps, other)
			}
		}
	}
	sort.Strings(deps)
	return deps
}

// removedDependencies returns, among the removed packages, the keys inst
// depended on, routing each dependency to its target root.
func removedDependencies(rp removedPkg, removed map[string]removedPkg,
	refToPath map[string]string) []string {

	others := make([]string, 0, len(removed))
	for key := range removed {
		others = append(others, key)
	}
	sort.Strings(others)

	selfKey := worldKey(rp.root, rp.inst.Name)
	seen := map[string]bool{}
	var deps []string
	for _, dep := range rp.inst.Dependencies {
		targetRoot, ok := routeRoot(dep, rp.root, refToPath)
		if !ok {
			continue
		}
		for _, other := range others {
			if other == selfKey || seen[other] {
				continue
			}
			o := removed[other]
			if o.root != targetRoot {
				continue
			}
			if satisfies(o.inst.Name, o.inst.Version, o.inst.Architecture, o.inst.Provides,
				dep, rp.inst.Architecture) {
				seen[other] = true
				deps = append(deps, other)
			}
		}
	}
	sort.Strings(deps)
	return deps
}

// topoSort orders names dependency-first: a name follows every name
// returned by depsOf for it. It fails on a cycle.
func topoSort(names []string, depsOf func(string) []string) ([]string, error) {
	sorted := append([]string(nil), names...)
	sort.Strings(sorted)

	const (
		unvisited = iota
		active
		done
	)
	state := make(map[string]int, len(sorted))
	var out []string
	var visit func(string) error
	visit = func(n string) error {
		switch state[n] {
		case done:
			return nil
		case active:
			return &Rejection{Reason: ReasonCycle,
				Detail: fmt.Sprintf("dependency cycle through %q cannot be ordered", nameOf(n))}
		}
		state[n] = active
		for _, d := range depsOf(n) {
			if err := visit(d); err != nil {
				return err
			}
		}
		state[n] = done
		out = append(out, n)
		return nil
	}
	for _, n := range sorted {
		if err := visit(n); err != nil {
			return nil, err
		}
	}
	return out, nil
}
