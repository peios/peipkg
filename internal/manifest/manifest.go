// Package manifest decodes and validates a package manifest — the
// .peipkg/manifest.json document inside a .peipkg archive (PSD-009
// §3.3). [Decode] turns the raw JSON bytes into a [Manifest] whose
// every field has been checked against the format rules, or returns a
// precise error naming the offending field.
package manifest

import (
	"fmt"
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
	// LicenseClass is the package's licence class (§3.3.6): whether its
	// terms make it free software, redistributable device firmware, or
	// proprietary — the machine-readable fact a SPDX expression with a
	// LicenseRef- term cannot convey. LicenseClassUnknown when the
	// manifest declares none.
	LicenseClass LicenseClass
	Homepage     string

	// DefaultRoot is the named root a top-level install of this package
	// lands in when no --root is given (§3.3.6, DESIGN-named-roots.md). ""
	// when absent — the package expresses no top-level placement
	// preference. It is a root reference (a named reference, never a path)
	// and governs top-level placement only, never dependency placement.
	DefaultRoot string

	// SpecialSystemPackage marks a package exempt from the §3.4 payload
	// layout rules — fsbase's mountpoint tree, the kernel, and the few
	// others whose job is to lay down the structure those rules protect.
	//
	// The declaration alone grants nothing at install time: install
	// refuses an out-of-layout payload unless the operator ALSO passes
	// --dangerously-bypass-path-restrictions (or the compose
	// equivalent). A package can propose its own exemption; only the
	// installer can grant it.
	SpecialSystemPackage bool

	// AlternateUpgrade declares that the package is meant to be installed
	// and upgraded by some means other than a routine package operation
	// (§5.18) — an operating-system edition moved by a dedicated tool,
	// for example. nil when absent. Like SpecialSystemPackage it grants
	// nothing: its whole effect is that a consumer refuses a request
	// naming the package and holds it back from an every-package
	// upgrade, unless the operator passes --bypass-alternate-upgrade.
	AlternateUpgrade *AlternateUpgrade

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

// AlternateUpgrade is the alternate_upgrade object (§5.18): the
// declaration that a package has an out-of-band upgrade path.
type AlternateUpgrade struct {
	// Message is the text shown to the operator in place of proceeding:
	// non-empty UTF-8 of at most 1024 bytes, which may contain newlines
	// but no other control characters.
	Message string
}

// LicenseClass is the closed set of licence classes (§3.3.6). Absent in
// a manifest means [LicenseClassUnknown]: nothing has been asserted
// either way, which is the state of every package that predates the
// field.
type LicenseClass string

const (
	// LicenseClassUnknown: no class has been declared.
	LicenseClassUnknown LicenseClass = "unknown"
	// LicenseClassFree: free and open-source software under the usual
	// OSI/FSF sense.
	LicenseClassFree LicenseClass = "free"
	// LicenseClassFirmware: redistributable device firmware — no source,
	// executes on a device rather than the CPU, needed to use hardware
	// the user owns. The class Debian's non-free-firmware and Fedora's
	// firmware exception carve out.
	LicenseClassFirmware LicenseClass = "firmware"
	// LicenseClassProprietary: non-free software that runs on the CPU.
	LicenseClassProprietary LicenseClass = "proprietary"
)

// ParseLicenseClass maps the manifest's license_class string to a
// [LicenseClass]. The empty string is the absent field and yields
// [LicenseClassUnknown]; any string outside the closed set is an error,
// since §5.a2 marks every enumerated set closed.
func ParseLicenseClass(s string) (LicenseClass, error) {
	switch LicenseClass(s) {
	case "", LicenseClassUnknown:
		return LicenseClassUnknown, nil
	case LicenseClassFree, LicenseClassFirmware, LicenseClassProprietary:
		return LicenseClass(s), nil
	}
	return "", fmt.Errorf("license_class %q is not one of unknown, free, firmware, proprietary", s)
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
	SideEffectDepmod SideEffect = "depmod"
	SideEffectManDB  SideEffect = "man-db"
)

// There is deliberately no ldconfig side effect. Peios has no shared
// library cache and needs none: the C library's libdir, slibdir and
// rtlddir are all /usr/lib/<triplet>, and the loader carries that
// compiled in as its default search path. One directory, already
// searched -- nothing for a cache to accelerate and nothing outside the
// path to admit. The rule that replaces it is a layout rule: a package
// shipping a shared library installs it into /usr/lib/<triplet> (§5.24).

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
	// RecipeRef pins the recipe tree the build ran from; empty when the
	// producer recorded none.
	RecipeRef string
	// Builder identifies the producing tool and its revision; empty when
	// the producer recorded none.
	Builder string
}
