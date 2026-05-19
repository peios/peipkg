package resolver

import (
	"github.com/peios/peipkg/internal/manifest"
	"github.com/peios/peipkg/internal/version"
)

// bestNamed returns the preferred candidate of a single package name
// whose version matches constraint and whose architecture is installable
// on the system, or nil if none qualifies. It is used for goal packages,
// which are matched by name only — never via `provides`.
func bestNamed(cands []Candidate, constraint version.Constraint, primaryArch string) *Candidate {
	var matching []Candidate
	for _, c := range cands {
		if !installableArch(c.Architecture, primaryArch) {
			continue
		}
		if constraint.Matches(c.Version) {
			matching = append(matching, c)
		}
	}
	return pickBest(matching, primaryArch)
}

// bestForDependency returns the preferred candidate satisfying dep for a
// depender of architecture dependerArch, or nil if none does. A
// candidate may satisfy dep by name or via a `provides` entry.
func bestForDependency(idx candidateIndex, dep manifest.Dependency,
	dependerArch, primaryArch string) *Candidate {

	var matching []Candidate
	seen := map[string]bool{}
	consider := func(c Candidate) {
		key := c.Name + "\x00" + c.Version.String()
		if seen[key] {
			return
		}
		if satisfies(c.Name, c.Version, c.Architecture, c.Provides, dep, dependerArch) {
			seen[key] = true
			matching = append(matching, c)
		}
	}
	for _, c := range idx.byName[dep.Name] {
		consider(c)
	}
	for _, c := range idx.byProvides[dep.Name] {
		consider(c)
	}
	return pickBest(matching, primaryArch)
}

// pickBest returns the §4.2.4-preferred candidate, or nil for an empty
// slice. Selection is a deterministic total order.
func pickBest(cands []Candidate, primaryArch string) *Candidate {
	if len(cands) == 0 {
		return nil
	}
	best := 0
	for i := 1; i < len(cands); i++ {
		if morePreferred(cands[i], cands[best], primaryArch) {
			best = i
		}
	}
	chosen := cands[best]
	return &chosen
}

// morePreferred reports whether candidate a is preferred over b (§4.2.4):
// an exact architecture match beats noarch; then a higher-priority
// repository; then a higher version; then — purely for determinism — the
// repository name.
//
// §4.2.4 rule 2 (a bounded same-repository `provides` preference) is not
// yet implemented; it refines selection only across multiple
// repositories using virtual packages.
func morePreferred(a, b Candidate, primaryArch string) bool {
	if am, bm := a.Architecture == primaryArch, b.Architecture == primaryArch; am != bm {
		return am
	}
	if a.RepoPriority != b.RepoPriority {
		return a.RepoPriority < b.RepoPriority
	}
	if c := version.Compare(a.Version, b.Version); c != 0 {
		return c > 0
	}
	return a.Repo < b.Repo
}

// installableArch reports whether a package of architecture arch may be
// installed on a system whose primary architecture is primaryArch
// (§2.3.4).
func installableArch(arch, primaryArch string) bool {
	return arch == primaryArch || arch == archNoarch
}
