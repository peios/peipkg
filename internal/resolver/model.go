// Package resolver computes a dependency-resolution plan: given a set of
// requested operations, the currently-installed packages, and the
// packages available from configured repositories, it produces an
// ordered plan of installs, upgrades, downgrades, and removals — or a
// rejection explaining why none exists (PSD-009 §4.2).
//
// Resolve is a pure function: identical inputs yield an identical plan,
// so a dry run matches the operation that would be applied (§4.2.7).
// The algorithm is greedy and non-backtracking — it picks the §4.2.4
// best candidate for each dependency and never reconsiders. This is the
// acceptable bootstrap resolver; the constraint model (real packages
// plus virtual `provides` packages) is shaped so a backtracking solver
// can replace the algorithm without changing the inputs or outputs.
package resolver

import (
	"github.com/peios/peipkg/internal/manifest"
	"github.com/peios/peipkg/internal/version"
)

// archNoarch is the architecture identifier of an architecture-
// independent package (§2.3.3).
const archNoarch = "noarch"

// RequestKind is the kind of operation an operator requested.
type RequestKind uint8

const (
	// Install requests that a package be present.
	Install RequestKind = iota
	// Upgrade requests that a package — or, with an empty name, every
	// installed package — move to its newest available version.
	Upgrade
	// Downgrade requests that a package move to a specific older version.
	Downgrade
	// Remove requests that a package be absent.
	Remove
)

// Request is one operator-requested operation.
type Request struct {
	Kind RequestKind
	// Name is the package the request targets. For Upgrade it may be
	// empty, meaning every installed package.
	Name string
	// Version is the target version of a Downgrade request.
	Version version.Version
}

// Candidate is one installable package version: a repository index
// entry annotated with its repository's identity and priority.
type Candidate struct {
	Name         string
	Version      version.Version
	Architecture string
	Dependencies []manifest.Dependency
	Conflicts    []manifest.Dependency
	Provides     []manifest.Provides
	Replaces     []manifest.Replaces

	Repo string
	// RepoPriority orders repositories; a lower number is higher
	// priority (§6.5.5).
	RepoPriority int

	URL            string
	Hash           string
	SizeCompressed int64
	SizeInstalled  int64
}

// Installed is one currently-installed package.
type Installed struct {
	Name         string
	Version      version.Version
	Architecture string
	Dependencies []manifest.Dependency
	Conflicts    []manifest.Dependency
	Provides     []manifest.Provides

	// Repo is the repository the package was installed from, and
	// RepoPriority that repository's current priority — used to gate a
	// §6.5.7 foreign `replaces`. Repo is empty when the origin is
	// unknown (a local-file install, or a repository since removed).
	Repo         string
	RepoPriority int
}

// Options carries the system facts and per-transaction policy a
// resolution depends on.
type Options struct {
	// PrimaryArch is the system's primary architecture (§2.3.4); a
	// planned package must be of this architecture or noarch.
	PrimaryArch string
	// AllowDowngrade permits a plan in which a package's version moves
	// backward (§4.2.5(4)).
	AllowDowngrade bool
	// CascadeRemovals removes the dependents of a removed package; when
	// false a removal blocked by dependents is rejected (§4.2.6).
	CascadeRemovals bool
}

// OpKind is the kind of a planned operation.
type OpKind uint8

const (
	OpInstall OpKind = iota
	OpUpgrade
	OpDowngrade
	OpRemove
)

// Operation is one step of a resolved plan.
type Operation struct {
	Kind OpKind
	Name string
	// FromVersion is the pre-operation version, set for Upgrade,
	// Downgrade, and Remove.
	FromVersion version.Version
	// ToVersion is the post-operation version, set for Install, Upgrade,
	// and Downgrade.
	ToVersion version.Version
	// Candidate is the chosen package for an Install, Upgrade, or
	// Downgrade — the execution layer fetches it by URL and hash. It is
	// nil for a Remove.
	Candidate *Candidate
}

// AuthKind identifies an elevated action that §7.6.6 requires the
// operator to authorise with a deliberate, specific act.
type AuthKind uint8

const (
	// AuthLowTrustProvides marks a dependency satisfied via `provides`
	// by a candidate from a lower-priority repository while a
	// higher-priority repository offers a name-matching package that
	// failed the dependency's version constraint (§4.2.4).
	AuthLowTrustProvides AuthKind = iota
	// AuthForeignReplaces marks a `replaces` succession (§4.1.5)
	// declared by a package from a lower-priority repository against a
	// package installed from a higher-priority one (§6.5.7).
	AuthForeignReplaces
	// AuthDowngrade marks a plan operation that moves a package
	// backward to an older version (§7.2.5, §7.6.6).
	AuthDowngrade
)

// Authorization is an elevated action in a resolved plan that the
// operator MUST authorise with a deliberate, specific act before the
// plan is applied (§7.6.6). The routine proceed-with-this confirmation
// never satisfies it.
type Authorization struct {
	Kind   AuthKind
	Detail string // human-readable, specific to the action
}

// Plan is a resolved, ordered sequence of operations: removals first
// (dependents before their dependencies), then installs and upgrades
// (dependencies before their dependents) — §4.2.1.
type Plan struct {
	Operations []Operation
	// Authorizations are elevated actions the plan contains that the
	// operator must explicitly authorise before it is applied (§7.6.6).
	Authorizations []Authorization
}
