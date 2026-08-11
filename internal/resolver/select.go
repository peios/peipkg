package resolver

import (
	"github.com/peios/peipkg/internal/manifest"
	"github.com/peios/peipkg/internal/version"
)

// match pairs a candidate with the version §4.2.4 rule 4 orders it by —
// the *role* version, i.e. what this candidate offers for the name that
// was asked for.
//
// For a name match that is the candidate's own version. For a `provides`
// match it is the provides entry's version, NOT the package's: a goal or
// dependency naming `coreutils` is asking what coreutils each candidate
// offers, and `coreutils-gnu 9.9` versus `peiosutils 0.4` is not a
// comparison of anything. Ordering by the role version keeps rule 4
// meaningful across distinct providers, and matches how §4.2 already
// evaluates constraints ("the candidate's version, or when matched via
// `provides`, the provides-entry's version").
//
// roleVer is nil when the match came from an unversioned `provides`,
// which satisfies any constraint (§4.1.4) but asserts no version. Such a
// candidate carries no rule-4 information and orders below any candidate
// that states one.
type match struct {
	cand    Candidate
	roleVer *version.Version
}

// matchFor builds the match for a candidate satisfying name, or nil if it
// does not satisfy it. A name match is preferred as the source of the role
// version even when the candidate also provides the name.
func matchFor(c Candidate, name string) *match {
	if c.Name == name {
		v := c.Version
		return &match{cand: c, roleVer: &v}
	}
	for _, p := range c.Provides {
		if p.Name != name {
			continue
		}
		m := match{cand: c}
		if p.Version != nil {
			v := *p.Version
			m.roleVer = &v
		}
		return &m
	}
	return nil
}

// bestNamed returns the preferred candidate of a single package name whose
// version matches constraint and whose architecture is installable on the
// system, or nil if none qualifies.
//
// Name-only, never via `provides`: this serves upgrade and downgrade, which
// act on a concrete already-installed package. Resolving those through
// `provides` would let an upgrade silently swap one package for another.
// Install goals go through [bestForGoal] instead.
func bestNamed(cands []Candidate, constraint version.Constraint, primaryArch string) *Candidate {
	var matching []match
	for _, c := range cands {
		if !installableArch(c.Architecture, primaryArch) {
			continue
		}
		if constraint.Matches(c.Version) {
			v := c.Version
			matching = append(matching, match{cand: c, roleVer: &v})
		}
	}
	return pickBest(matching, primaryArch, "", 0)
}

// bestForGoal returns the preferred candidate satisfying an install goal
// for name, or nil if none does. A goal resolves by name or via a
// `provides` entry, exactly as a dependency does (§4.2.3) — a goal naming
// a role such as `sh` or `coreutils` is asking for whatever fills it.
//
// There is no depending package, so §4.2.4 rule 2 is inert.
func bestForGoal(idx candidateIndex, name string, constraint version.Constraint,
	primaryArch string) *Candidate {

	var matching []match
	seen := map[string]bool{}
	consider := func(c Candidate) {
		if seen[candidateKey(c)] {
			return
		}
		if !installableArch(c.Architecture, primaryArch) {
			return
		}
		m := matchFor(c, name)
		if m == nil {
			return
		}
		// An unversioned `provides` satisfies any constraint (§4.1.4).
		if m.roleVer != nil && !constraint.Matches(*m.roleVer) {
			return
		}
		seen[candidateKey(c)] = true
		matching = append(matching, *m)
	}
	for _, c := range idx.byName[name] {
		consider(c)
	}
	for _, c := range idx.byProvides[name] {
		consider(c)
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

	var matching []match
	seen := map[string]bool{}
	consider := func(c Candidate) {
		if seen[candidateKey(c)] {
			return
		}
		if !satisfies(c.Name, c.Version, c.Architecture, c.Provides, dep, dependerArch) {
			return
		}
		m := matchFor(c, dep.Name)
		if m == nil {
			return
		}
		seen[candidateKey(c)] = true
		matching = append(matching, *m)
	}
	for _, c := range idx.byName[dep.Name] {
		consider(c)
	}
	for _, c := range idx.byProvides[dep.Name] {
		consider(c)
	}
	return pickBest(matching, primaryArch, dependerRepo, dependerPriority)
}

func candidateKey(c Candidate) string {
	return c.Name + "\x00" + c.Version.String() + "\x00" + c.Architecture +
		"\x00" + c.Repo + "\x00" + c.URL + "\x00" + c.Hash
}

// pickBest returns the §4.2.4-preferred candidate, or nil for an empty
// slice. Selection is a deterministic total order.
func pickBest(matches []match, primaryArch, dependerRepo string, dependerPriority int) *Candidate {
	if len(matches) == 0 {
		return nil
	}
	best := 0
	for i := 1; i < len(matches); i++ {
		if morePreferred(matches[i], matches[best], primaryArch, dependerRepo, dependerPriority) {
			best = i
		}
	}
	chosen := matches[best].cand
	return &chosen
}

// morePreferred reports whether match a is preferred over b, applying
// the §4.2.4 candidate-selection rules in order:
//
//   - Rule 1: an exact architecture match beats noarch.
//   - Rule 2: a candidate from the depending package's own repository
//     beats a cross-repository candidate — but only when that repository
//     is at least as high-priority as the cross-repository alternative.
//     This bounds the preference so a low-trust depender cannot shadow a
//     higher-trust alternative with a package from its own repository.
//   - Rule 3: a higher-priority repository (a lower priority number).
//   - Rule 4: a higher role version (see [match]); a candidate stating one
//     beats a candidate that does not.
//
// Package name, then repository name, break any remaining tie. The name
// tiebreak is what makes the order total when the candidates are distinct
// packages filling the same role — without it two providers alike under
// rules 1-4 would be separated only by index order.
//
// dependerRepo is empty when there is no depending package or its
// repository is unknown; rule 2 is then inert.
func morePreferred(a, b match, primaryArch, dependerRepo string, dependerPriority int) bool {
	// Rule 1: architecture match.
	if am, bm := a.cand.Architecture == primaryArch, b.cand.Architecture == primaryArch; am != bm {
		return am
	}
	// Rule 2: bounded same-repository preference. It applies only when
	// exactly one candidate is from the depender's repository, and only
	// when that repository is at least as high-priority (priority number
	// no greater) as the cross-repository alternative.
	if dependerRepo != "" {
		aSame, bSame := a.cand.Repo == dependerRepo, b.cand.Repo == dependerRepo
		if aSame && !bSame && dependerPriority <= b.cand.RepoPriority {
			return true
		}
		if bSame && !aSame && dependerPriority <= a.cand.RepoPriority {
			return false
		}
	}
	// Rule 3: repository priority.
	if a.cand.RepoPriority != b.cand.RepoPriority {
		return a.cand.RepoPriority < b.cand.RepoPriority
	}
	// Rule 4: role version. An unversioned `provides` states none and loses
	// to any candidate that does.
	switch {
	case a.roleVer != nil && b.roleVer == nil:
		return true
	case a.roleVer == nil && b.roleVer != nil:
		return false
	case a.roleVer != nil && b.roleVer != nil:
		if c := version.Compare(*a.roleVer, *b.roleVer); c != 0 {
			return c > 0
		}
	}
	// Total-order tiebreaks.
	if a.cand.Name != b.cand.Name {
		return a.cand.Name < b.cand.Name
	}
	return a.cand.Repo < b.cand.Repo
}

// installableArch reports whether a package of architecture arch may be
// installed on a system whose primary architecture is primaryArch
// (§2.3.4).
func installableArch(arch, primaryArch string) bool {
	return arch == primaryArch || arch == archNoarch
}
