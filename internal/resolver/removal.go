package resolver

import (
	"fmt"
	"sort"

	"github.com/peios/peipkg/internal/manifest"
)

// applyRemovals removes the requested packages and — under the cascade
// policy — their now-broken dependents from the world (§4.2.6). targets
// are world keys (root, name); a removal names one package in one root.
func applyRemovals(world map[string]*worldPkg, targets []string,
	refToPath map[string]string, opts Options) error {

	if len(targets) == 0 {
		return nil
	}
	for _, key := range targets {
		if _, ok := world[key]; !ok {
			return &Rejection{Reason: ReasonRemovalBlocked,
				Detail: fmt.Sprintf("cannot remove %q: it is not installed", nameOf(key))}
		}
		delete(world, key)
	}
	// A removal can leave a remaining package's dependency unsatisfied.
	// Such a package is itself removed (cascade) or the removal refused.
	for {
		brokenKey, dep := firstBroken(world, refToPath, opts.PrimaryArch)
		if brokenKey == "" {
			return nil
		}
		if !opts.CascadeRemovals {
			return &Rejection{Reason: ReasonRemovalBlocked,
				Detail: fmt.Sprintf("removal would leave %q without its dependency %q; "+
					"cascade was not authorised", nameOf(brokenKey), dep)}
		}
		delete(world, brokenKey)
	}
}

// firstBroken returns the lexicographically-first package in the world
// with a dependency no remaining package in that dependency's root
// satisfies, and that dependency's name; it returns empty strings when
// the world is whole. A dependency routed to a root not represented in
// the world (an unregistered reference) is skipped — it is not this
// world's concern to satisfy.
func firstBroken(world map[string]*worldPkg, refToPath map[string]string,
	primaryArch string) (key, dep string) {
	for _, k := range sortedKeys(world) {
		p := world[k]
		deps := append([]manifest.Dependency(nil), p.dependencies...)
		sort.Slice(deps, func(i, j int) bool { return deps[i].Name < deps[j].Name })
		for _, d := range deps {
			targetRoot, ok := routeRoot(d, p.root, refToPath)
			if !ok {
				continue
			}
			if !worldSatisfiesInRoot(world, d, p.architecture, primaryArch, targetRoot) {
				return k, d.Name
			}
		}
	}
	return "", ""
}
