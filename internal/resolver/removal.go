package resolver

import (
	"fmt"
	"sort"

	"github.com/peios/peipkg/internal/manifest"
)

// applyRemovals removes the requested packages and — under the cascade
// policy — their now-broken dependents from the world (§4.2.6).
func applyRemovals(world map[string]*worldPkg, roots []string, opts Options) error {
	if len(roots) == 0 {
		return nil
	}
	for _, name := range roots {
		if _, ok := world[name]; !ok {
			return &Rejection{Reason: ReasonRemovalBlocked,
				Detail: fmt.Sprintf("cannot remove %q: it is not installed", name)}
		}
		delete(world, name)
	}
	// A removal can leave a remaining package's dependency unsatisfied.
	// Such a package is itself removed (cascade) or the removal refused.
	for {
		broken, dep := firstBroken(world)
		if broken == "" {
			return nil
		}
		if !opts.CascadeRemovals {
			return &Rejection{Reason: ReasonRemovalBlocked,
				Detail: fmt.Sprintf("removal would leave %q without its dependency %q; "+
					"cascade was not authorised", broken, dep)}
		}
		delete(world, broken)
	}
}

// firstBroken returns the lexicographically-first package in the world
// with a dependency no remaining package satisfies, and that
// dependency's name; it returns empty strings when the world is whole.
func firstBroken(world map[string]*worldPkg) (pkg, dep string) {
	for _, name := range sortedNames(world) {
		p := world[name]
		deps := append([]manifest.Dependency(nil), p.dependencies...)
		sort.Slice(deps, func(i, j int) bool { return deps[i].Name < deps[j].Name })
		for _, d := range deps {
			if !worldSatisfies(world, d, p.architecture) {
				return name, d.Name
			}
		}
	}
	return "", ""
}
