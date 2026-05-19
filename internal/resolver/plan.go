package resolver

import (
	"fmt"
	"sort"

	"github.com/peios/peipkg/internal/version"
)

// buildPlan diffs the resolved world against the installed set and
// orders the resulting operations: removals first — dependents before
// their dependencies — then installs, upgrades, and downgrades —
// dependencies before their dependents (§4.2.1).
func buildPlan(world map[string]*worldPkg, installed []Installed) (Plan, error) {
	var forward []Operation
	for _, name := range sortedNames(world) {
		p := world[name]
		if p.candidate == nil {
			continue // installed and unchanged
		}
		op := Operation{Name: name, ToVersion: p.candidate.Version, Candidate: p.candidate}
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

	var removed []Installed
	for _, inst := range installed {
		if _, present := world[inst.Name]; !present {
			removed = append(removed, inst)
		}
	}

	removeOps, err := orderRemovals(removed)
	if err != nil {
		return Plan{}, err
	}
	forwardOps, err := orderForward(forward, world)
	if err != nil {
		return Plan{}, err
	}
	return Plan{Operations: append(removeOps, forwardOps...)}, nil
}

// orderForward sorts install/upgrade/downgrade operations so each
// package follows the in-plan packages it depends on.
func orderForward(ops []Operation, world map[string]*worldPkg) ([]Operation, error) {
	byName := make(map[string]Operation, len(ops))
	inPlan := make(map[string]bool, len(ops))
	names := make([]string, 0, len(ops))
	for _, op := range ops {
		byName[op.Name] = op
		inPlan[op.Name] = true
		names = append(names, op.Name)
	}
	ordered, err := topoSort(names, func(name string) []string {
		return planDependencies(name, world, inPlan)
	})
	if err != nil {
		return nil, err
	}
	out := make([]Operation, len(ordered))
	for i, name := range ordered {
		out[i] = byName[name]
	}
	return out, nil
}

// orderRemovals sorts removal operations so each package precedes the
// packages it depended on (§4.2.1).
func orderRemovals(removed []Installed) ([]Operation, error) {
	byName := make(map[string]Installed, len(removed))
	names := make([]string, 0, len(removed))
	for _, inst := range removed {
		byName[inst.Name] = inst
		names = append(names, inst.Name)
	}
	ordered, err := topoSort(names, func(name string) []string {
		return removedDependencies(byName[name], byName)
	})
	if err != nil {
		return nil, err
	}
	// topoSort yields dependency-first order; a removal runs in the
	// reverse, so a dependent is removed before what it depended on.
	out := make([]Operation, 0, len(ordered))
	for i := len(ordered) - 1; i >= 0; i-- {
		inst := byName[ordered[i]]
		out = append(out, Operation{Kind: OpRemove, Name: inst.Name, FromVersion: inst.Version})
	}
	return out, nil
}

// planDependencies returns the names of the in-plan packages that name's
// resolved package depends on.
func planDependencies(name string, world map[string]*worldPkg, inPlan map[string]bool) []string {
	p := world[name]
	if p == nil {
		return nil
	}
	seen := map[string]bool{}
	var deps []string
	for _, dep := range p.dependencies {
		for _, other := range sortedNames(world) {
			if other == name || !inPlan[other] || seen[other] {
				continue
			}
			s := world[other]
			if satisfies(s.name, s.version, s.architecture, s.provides, dep, p.architecture) {
				seen[other] = true
				deps = append(deps, other)
			}
		}
	}
	sort.Strings(deps)
	return deps
}

// removedDependencies returns, among the removed packages, the ones inst
// depended on.
func removedDependencies(inst Installed, removed map[string]Installed) []string {
	others := make([]string, 0, len(removed))
	for name := range removed {
		others = append(others, name)
	}
	sort.Strings(others)

	seen := map[string]bool{}
	var deps []string
	for _, dep := range inst.Dependencies {
		for _, other := range others {
			if other == inst.Name || seen[other] {
				continue
			}
			o := removed[other]
			if satisfies(o.Name, o.Version, o.Architecture, o.Provides, dep, inst.Architecture) {
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
				Detail: fmt.Sprintf("dependency cycle through %q cannot be ordered", n)}
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
