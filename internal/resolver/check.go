package resolver

import (
	"fmt"
	"sort"

	"github.com/peios/peipkg/internal/version"
)

// checkConsistency verifies the resolved world against the §4.2.5
// failure conditions a greedy resolution can still leave: architecture
// mismatch, an active conflict, and an unrequested version regression.
func checkConsistency(world map[string]*worldPkg, opts Options, downgradeAllowed map[string]bool) error {
	names := sortedNames(world)

	// §4.2.5(3): every planned package must be installable here.
	for _, name := range names {
		p := world[name]
		if !installableArch(p.architecture, opts.PrimaryArch) {
			return &Rejection{Reason: ReasonArchMismatch,
				Detail: fmt.Sprintf("package %q is built for architecture %q, which this "+
					"system cannot install", name, p.architecture)}
		}
	}

	// §4.2.5(2): no two packages in the resulting set may conflict.
	for _, an := range names {
		a := world[an]
		for _, conflict := range a.conflicts {
			for _, bn := range names {
				if an == bn {
					continue
				}
				b := world[bn]
				if satisfies(b.name, b.version, b.architecture, b.provides, conflict, a.architecture) {
					return &Rejection{Reason: ReasonConflict,
						Detail: fmt.Sprintf("packages %q and %q cannot be installed together",
							an, bn)}
				}
			}
		}
	}

	// §4.2.5(4): a package's version must not move backward unless the
	// operator allowed it, transaction-wide or for that package.
	if !opts.AllowDowngrade {
		for _, name := range names {
			p := world[name]
			if p.candidate == nil || p.installedVersion == nil || downgradeAllowed[name] {
				continue
			}
			if version.Compare(p.candidate.Version, *p.installedVersion) < 0 {
				return &Rejection{Reason: ReasonVersionRegression,
					Detail: fmt.Sprintf("resolving would move %q backward from %s to %s, "+
						"which was not requested", name, *p.installedVersion, p.candidate.Version)}
			}
		}
	}
	return nil
}

// sortedNames returns the world's package names in lexicographic order,
// for deterministic iteration.
func sortedNames(world map[string]*worldPkg) []string {
	names := make([]string, 0, len(world))
	for name := range world {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
