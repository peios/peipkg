package resolver

import (
	"fmt"
	"sort"

	"github.com/peios/peipkg/internal/version"
)

// checkConsistency verifies the resolved world against the §4.2.5
// failure conditions a greedy resolution can still leave: architecture
// mismatch, an active conflict, and an unrequested version regression.
// Conflicts and version checks are per-root: the same name in two roots
// is two independent packages (DESIGN-named-roots.md → "Identity"), so it
// is neither a conflict with itself nor a regression across roots.
func checkConsistency(world map[string]*worldPkg, opts Options, downgradeAllowed map[string]bool) error {
	keys := sortedKeys(world)

	// §4.2.5(3): every planned package must be installable here.
	for _, key := range keys {
		p := world[key]
		if !installableArch(p.architecture, opts.PrimaryArch) {
			return &Rejection{Reason: ReasonArchMismatch,
				Detail: fmt.Sprintf("package %q is built for architecture %q, which this "+
					"system cannot install", p.name, p.architecture)}
		}
	}

	// §4.2.5(2): no two packages in the same root may conflict. A
	// conflicts entry carries no root and so is evaluated against the
	// declaring package's own root — conflicts stay root-local.
	for _, ak := range keys {
		a := world[ak]
		for _, conflict := range a.conflicts {
			for _, bk := range keys {
				if ak == bk {
					continue
				}
				b := world[bk]
				if a.root != b.root {
					continue
				}
				if satisfies(b.name, b.version, b.architecture, b.provides, conflict,
					a.architecture, opts.PrimaryArch) {
					return &Rejection{Reason: ReasonConflict,
						Detail: fmt.Sprintf("packages %q and %q cannot be installed together",
							a.name, b.name)}
				}
			}
		}
	}

	// §4.2.5(4): a package's version must not move backward unless the
	// operator allowed it, transaction-wide or for that package.
	if !opts.AllowDowngrade {
		for _, key := range keys {
			p := world[key]
			if p.candidate == nil || p.installedVersion == nil || downgradeAllowed[key] {
				continue
			}
			if version.Compare(p.candidate.Version, *p.installedVersion) < 0 {
				return &Rejection{Reason: ReasonVersionRegression,
					Detail: fmt.Sprintf("resolving would move %q backward from %s to %s, "+
						"which was not requested", p.name, *p.installedVersion, p.candidate.Version)}
			}
		}
	}
	return nil
}

// sortedKeys returns the world's (root, name) keys in lexicographic
// order, for deterministic iteration. In single-root resolution every key
// shares the empty root, so this orders by name exactly as before.
func sortedKeys(world map[string]*worldPkg) []string {
	keys := make([]string, 0, len(world))
	for key := range world {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
