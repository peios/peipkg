package resolver

import (
	"github.com/peios/peipkg/internal/manifest"
	"github.com/peios/peipkg/internal/version"
)

// bestNamed returns the preferred candidate of a single package name
// whose version matches constraint and whose architecture is installable
// on the system, or nil if none qualifies. It is used for goal packages,
// which are matched by name only — never via `provides` — and have no
// depending package, so §4.2.4 rule 2 does not apply.
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
	return pickBest(matching, primaryArch, "", 0)
}

// bestForDependency returns the preferred candidate satisfying dep for a
// depending package, or nil if none does. A candidate may satisfy dep by
// name or via a `provides` entry. dependerRepo and dependerPriority
// identify the repository the depending package is itself being
// installed from, for §4.2.4 rule 2; dependerRepo is empty when that
// repository is unknown (an already-installed depender).
func bestForDependency(idx candidateIndex, dep manifest.Dependency,
	dependerArch, primaryArch, dependerRepo string, dependerPriority int) *Candidate {

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
	return pickBest(matching, primaryArch, dependerRepo, dependerPriority)
}

// pickBest returns the §4.2.4-preferred candidate, or nil for an empty
// slice. Selection is a deterministic total order.
func pickBest(cands []Candidate, primaryArch, dependerRepo string, dependerPriority int) *Candidate {
	if len(cands) == 0 {
		return nil
	}
	best := 0
	for i := 1; i < len(cands); i++ {
		if morePreferred(cands[i], cands[best], primaryArch, dependerRepo, dependerPriority) {
			best = i
		}
	}
	chosen := cands[best]
	return &chosen
}

// morePreferred reports whether candidate a is preferred over b, applying
// the §4.2.4 candidate-selection rules in order:
//
//   - Rule 1: an exact architecture match beats noarch.
//   - Rule 2: a candidate from the depending package's own repository
//     beats a cross-repository candidate — but only when that repository
//     is at least as high-priority as the cross-repository alternative.
//     This bounds the preference so a low-trust depender cannot shadow a
//     higher-trust alternative with a package from its own repository.
//   - Rule 3: a higher-priority repository (a lower priority number).
//   - Rule 4: a higher version.
//
// Repository name breaks any remaining tie, purely for determinism.
// dependerRepo is empty when there is no depending package or its
// repository is unknown; rule 2 is then inert.
func morePreferred(a, b Candidate, primaryArch, dependerRepo string, dependerPriority int) bool {
	// Rule 1: architecture match.
	if am, bm := a.Architecture == primaryArch, b.Architecture == primaryArch; am != bm {
		return am
	}
	// Rule 2: bounded same-repository preference. It applies only when
	// exactly one candidate is from the depender's repository, and only
	// when that repository is at least as high-priority (priority number
	// no greater) as the cross-repository alternative.
	if dependerRepo != "" {
		aSame, bSame := a.Repo == dependerRepo, b.Repo == dependerRepo
		if aSame && !bSame && dependerPriority <= b.RepoPriority {
			return true
		}
		if bSame && !aSame && dependerPriority <= a.RepoPriority {
			return false
		}
	}
	// Rule 3: repository priority.
	if a.RepoPriority != b.RepoPriority {
		return a.RepoPriority < b.RepoPriority
	}
	// Rule 4: version.
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
