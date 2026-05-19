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
}

// Provides is one entry of the provides array: a virtual name this
// package satisfies (§4.1.4).
type Provides struct {
	Name string
	// Version is the version of the virtual capability, or nil when the
	// provides entry carried no version (it then provides any version).
	Version *version.Version
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
}
