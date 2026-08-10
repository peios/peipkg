// Package manifest decodes and validates a package manifest — the
// .peipkg/manifest.json document inside a .peipkg archive (PSD-009
// §3.3). [Decode] turns the raw JSON bytes into a [Manifest] whose
// every field has been checked against the format rules, or returns a
// precise error naming the offending field.
package manifest

import (
	"time"

	"github.com/peios/peipkg/internal/version"
)

// Manifest is the decoded, validated metadata of a package. Obtain one
// through [Decode]; the zero Manifest is not meaningful.
type Manifest struct {
	Name         string
	Version      version.Version
	Architecture string

	Description string
	License     string
	Homepage    string

	// DefaultRoot is the named root a top-level install of this package
	// lands in when no --root is given (§3.3.6, DESIGN-named-roots.md). ""
	// when absent — the package expresses no top-level placement
	// preference. It is a root reference (a named reference, never a path)
	// and governs top-level placement only, never dependency placement.
	DefaultRoot string

	Dependencies         []Dependency
	OptionalDependencies []Dependency
	Conflicts            []Dependency
	Provides             []Provides
	Replaces             []Replaces

	SideEffects   []SideEffect
	SizeInstalled int64
	SDOverrides   []SDOverride
	Build         Build
}

// Dependency is one entry of the dependencies, optional_dependencies, or
// conflicts arrays (§4.1.1, §4.1.2). The architecture qualifier is not
// retained: v0.22 permits only the value "any", which Decode verifies.
type Dependency struct {
	Name string
	// Constraint restricts the satisfying versions. The zero Constraint
	// — for a dependency with no constraint field — matches any version.
	Constraint version.Constraint
	// Root is the installation root this dependency is placed and
	// satisfied in (§4.1.1, DESIGN-named-roots.md). "" means the
	// depending package's own root (the default — a dependency closure
	// flows into the root the depender occupies); a non-empty value is a
	// root reference naming a different root the dependency crosses into.
	// Carried only on dependencies and optional_dependencies, never
	// conflicts.
	Root string
	// Claims is the claims field (§4.4.2): the role slots this dependency
	// declares a claim path for, keyed by slot name. nil when the entry
	// has no claims. Present only on dependencies and
	// optional_dependencies — never conflicts, where claims are rejected.
	Claims map[string]ClaimSlot
}

// Provides is one entry of the provides array: a virtual name this
// package satisfies (§4.1.4).
type Provides struct {
	Name string
	// Version is the version of the virtual capability, or nil when the
	// provides entry carried no version (it then provides any version).
	Version *version.Version
	// Claims is the claims field (§4.4.2): the role slots this package
	// fills when it holds the named role, keyed by slot name. nil when
	// the entry has no claims.
	Claims map[string]ClaimSlot
}

// ClaimSlot is one slot of a claims field (§4.4.2): the binding of a
// role's named channel to a filesystem location. On a dependency entry
// (the consumer side) a slot carries Path only; on a provides entry (the
// provider side) it carries Target and, optionally, a default Path.
type ClaimSlot struct {
	// Path is the absolute claim path the slot materialises at — the
	// symlink location. Set on a consumer slot; optional on a provider
	// slot, where it is a default used when no consumer declares one. ""
	// when absent.
	Path string
	// Target is the absolute payload path the link points at while this
	// package holds the role. Set on a provider slot; never on a consumer
	// slot. "" when absent.
	Target string
}

// Replaces is one entry of the replaces array: a package this one
// supersedes (§4.1.5).
type Replaces struct {
	Name string
	// Constraint restricts which versions of the named package are
	// replaced. The zero Constraint replaces any version.
	Constraint version.Constraint
}

// SideEffect is a recognised post-install maintenance operation
// (§4.3.4). The set is closed in v0.22.
type SideEffect string

const (
	SideEffectLdconfig SideEffect = "ldconfig"
	SideEffectDepmod   SideEffect = "depmod"
	SideEffectManDB    SideEffect = "man-db"
)

// SDOverride is one entry of sd_overrides: a per-payload-entry security
// descriptor (§3.3.5).
//
// Decode validates the entry structurally — the path is present and the
// sd field is well-formed unpadded base64 within the size limit — but
// does not parse the descriptor bytes against PSD-004, and does not
// check that Path names a real payload entry. Those checks need an SD
// parser and the archive payload respectively; SD overrides are a
// deferred feature (see DESIGN.md appendix B).
type SDOverride struct {
	Path string
	SD   []byte
}

// Build is the build-provenance object of a manifest (§3.3.4).
type Build struct {
	Timestamp time.Time
	FarmID    string
	SourceRef string
	// SourcePackage names the corresponding-source package built from the
	// same recipe and source; empty when the producer declared none.
	SourcePackage string
}
