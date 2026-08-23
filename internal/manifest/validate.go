package manifest

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"path"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/peios/peipkg/internal/capability"
	"github.com/peios/peipkg/internal/version"
)

// validate checks every field of a decoded wireManifest against the
// §3.3 rules and builds the validated Manifest.
func (wm wireManifest) validate() (Manifest, error) {
	// Required top-level fields must be present (§3.3.2).
	switch {
	case wm.SchemaVersion == nil:
		return Manifest{}, missingField("schema_version")
	case wm.Name == nil:
		return Manifest{}, missingField("name")
	case wm.Version == nil:
		return Manifest{}, missingField("version")
	case wm.Architecture == nil:
		return Manifest{}, missingField("architecture")
	case wm.Dependencies == nil:
		return Manifest{}, missingField("dependencies")
	case wm.Conflicts == nil:
		return Manifest{}, missingField("conflicts")
	case wm.SizeInstalled == nil:
		return Manifest{}, missingField("size_installed")
	case wm.Build == nil:
		return Manifest{}, missingField("build")
	}

	if *wm.SchemaVersion != schemaVersion {
		return Manifest{}, fmt.Errorf(
			"peipkg/manifest: schema_version is %d, want %d", *wm.SchemaVersion, schemaVersion)
	}

	var m Manifest
	var err error

	if err = validateName(*wm.Name); err != nil {
		return Manifest{}, fmt.Errorf("peipkg/manifest: name: %w", err)
	}
	m.Name = *wm.Name

	if m.Version, err = version.Parse(*wm.Version); err != nil {
		return Manifest{}, fmt.Errorf("peipkg/manifest: version: %w", err)
	}

	if err = validateArchitecture(*wm.Architecture); err != nil {
		return Manifest{}, fmt.Errorf("peipkg/manifest: architecture: %w", err)
	}
	m.Architecture = *wm.Architecture

	if err = validateDescription(wm.Description); err != nil {
		return Manifest{}, fmt.Errorf("peipkg/manifest: description: %w", err)
	}
	m.Description = wm.Description

	if err = validateHomepage(wm.Homepage); err != nil {
		return Manifest{}, fmt.Errorf("peipkg/manifest: homepage: %w", err)
	}
	m.Homepage = wm.Homepage
	m.License = wm.License // not validated — §3.3.6 leaves license strings unchecked

	// §3.3.6: default_root, when present, is a root reference — a named
	// reference, never a filesystem path.
	if wm.DefaultRoot != "" {
		if err = ValidateRootRef(wm.DefaultRoot); err != nil {
			return Manifest{}, fmt.Errorf("peipkg/manifest: default_root: %w", err)
		}
		m.DefaultRoot = wm.DefaultRoot
	}

	// special_system_package needs no validation beyond its type: it is a
	// declaration, not a grant. Install refuses an out-of-layout payload
	// unless the operator also passes the bypass flag.
	m.SpecialSystemPackage = wm.SpecialSystemPackage

	if *wm.SizeInstalled < 0 {
		return Manifest{}, fmt.Errorf(
			"peipkg/manifest: size_installed is negative (%d)", *wm.SizeInstalled)
	}
	m.SizeInstalled = *wm.SizeInstalled

	if m.Dependencies, err = validateDependencies(
		"dependencies", *wm.Dependencies, true); err != nil {
		return Manifest{}, err
	}
	if m.OptionalDependencies, err = validateDependencies(
		"optional_dependencies", wm.OptionalDependencies, true); err != nil {
		return Manifest{}, err
	}
	// §4.4.2: claims are permitted on dependencies and
	// optional_dependencies, never conflicts.
	if m.Conflicts, err = validateDependencies("conflicts", *wm.Conflicts, false); err != nil {
		return Manifest{}, err
	}
	if m.Provides, err = validateProvides(wm.Provides); err != nil {
		return Manifest{}, err
	}
	if m.Replaces, err = validateReplaces(wm.Replaces); err != nil {
		return Manifest{}, err
	}
	if m.SideEffects, err = validateSideEffects(wm.SideEffects); err != nil {
		return Manifest{}, err
	}
	if m.SDOverrides, err = validateSDOverrides(wm.SDOverrides); err != nil {
		return Manifest{}, err
	}
	if m.Build, err = validateBuild(*wm.Build); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

// validateName checks a package name against §2.1.
func validateName(s string) error {
	if len(s) < 2 || len(s) > 64 {
		return fmt.Errorf("%q must be 2 to 64 characters", s)
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !isNameChar(c) {
			return fmt.Errorf("%q contains the invalid character %q", s, c)
		}
	}
	if !isLowerOrDigit(s[0]) {
		return fmt.Errorf("%q must start with a lowercase letter or digit", s)
	}
	// A name may end with a plus sign so that C++-style names like
	// `libstdc++` and `g++` are valid (§2.1, and its own informative
	// example).
	if last := s[len(s)-1]; !isLowerOrDigit(last) && last != '+' {
		return fmt.Errorf("%q must end with a lowercase letter, digit, or '+'", s)
	}
	for i := 1; i < len(s); i++ {
		if isNameSeparator(s[i]) && isNameSeparator(s[i-1]) {
			return fmt.Errorf("%q has consecutive separator characters", s)
		}
	}
	return nil
}

// ValidateRootRef checks a root reference against the §3.3.6 grammar: one
// or more dot-separated segments, each [a-z0-9][a-z0-9_-]*. A root
// reference is a named reference and MUST NOT be a filesystem path, so a
// '/' — the very thing that marks a literal path — is rejected here, as is
// an empty segment. The reference's *existence* is a consumer concern
// (§7); this checks only that it is syntactically a name.
func ValidateRootRef(s string) error {
	if strings.ContainsRune(s, '/') {
		return fmt.Errorf("%q must be a named reference, not a filesystem path", s)
	}
	for _, seg := range strings.Split(s, ".") {
		if seg == "" {
			return fmt.Errorf("%q has an empty segment", s)
		}
		for i := 0; i < len(seg); i++ {
			c := seg[i]
			switch {
			case isLowerOrDigit(c):
			case (c == '-' || c == '_') && i > 0:
			default:
				return fmt.Errorf("%q has an invalid segment %q", s, seg)
			}
		}
	}
	return nil
}

// validateArchitecture checks an architecture identifier against the
// §2.3.1 format rules. Membership of the canonical set (§2.3.2) is an
// install-time concern, not a format one, so it is not checked here.
func validateArchitecture(s string) error {
	if s == "" {
		return fmt.Errorf("must not be empty")
	}
	if len(s) > 16 {
		return fmt.Errorf("%q exceeds 16 characters", s)
	}
	if s[0] < 'a' || s[0] > 'z' {
		return fmt.Errorf("%q must start with a lowercase letter", s)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !isLowerOrDigit(c) && c != '_' {
			return fmt.Errorf("%q contains the invalid character %q", s, c)
		}
	}
	return nil
}

// validateDescription accepts printable UTF-8 while rejecting control
// characters, which prevents terminal escape-sequence injection when the
// description is shown to an operator.
func validateDescription(s string) error {
	if !utf8.ValidString(s) {
		return fmt.Errorf("is not valid UTF-8")
	}
	for _, r := range s {
		if r == utf8.RuneError {
			return fmt.Errorf("contains the Unicode replacement character")
		}
		if !unicode.IsPrint(r) {
			return fmt.Errorf("contains a non-printable rune %#U", r)
		}
	}
	return nil
}

// validateHomepage enforces the §3.3.6 URL rules: a homepage, when
// present, must be a syntactically valid http or https URL.
func validateHomepage(s string) error {
	if s == "" {
		return nil
	}
	u, err := url.Parse(s)
	if err != nil {
		return fmt.Errorf("%q is not a valid URL: %w", s, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%q must use the http or https scheme", s)
	}
	return nil
}

// validateDependencies validates a dependencies-shaped array — used for
// dependencies, optional_dependencies, and conflicts, which share the
// §4.1.1 object schema. field names the array for error messages.
// claimsAllowed permits a claims field (§4.4.2): true for dependencies
// and optional_dependencies, false for conflicts, where a claims field
// is rejected.
func validateDependencies(field string, wires []wireDependency, claimsAllowed bool) ([]Dependency, error) {
	if len(wires) > maxDependencies {
		return nil, fmt.Errorf("peipkg/manifest: %s has %d entries, the limit is %d",
			field, len(wires), maxDependencies)
	}
	deps := make([]Dependency, 0, len(wires))
	for i, w := range wires {
		if w.Name == nil {
			return nil, fmt.Errorf("peipkg/manifest: %s[%d]: missing field %q", field, i, "name")
		}
		// §4.1.1: dependencies and optional_dependencies may target a
		// virtual (capability) name; conflicts target a real package name.
		nameErr := capability.ValidateName(*w.Name)
		if field == "conflicts" {
			nameErr = validateName(*w.Name)
		}
		if nameErr != nil {
			return nil, fmt.Errorf("peipkg/manifest: %s[%d]: name: %w", field, i, nameErr)
		}
		// §4.1.3: the only architecture qualifier permitted in v0.22 is
		// "any" (the default when the field is absent).
		if w.Arch != "" && w.Arch != "any" {
			return nil, fmt.Errorf(
				"peipkg/manifest: %s[%d]: arch qualifier %q is not supported (only %q)",
				field, i, w.Arch, "any")
		}
		constraint, err := parseOptionalConstraint(w.Constraint)
		if err != nil {
			return nil, fmt.Errorf("peipkg/manifest: %s[%d]: constraint: %w", field, i, err)
		}
		dep := Dependency{Name: *w.Name, Constraint: constraint}
		// §4.1.1: the placement `root` field is a root reference, carried
		// on dependencies and optional_dependencies only — never conflicts,
		// whose object schema (§4.1.2) has no root and which stay root-local.
		if w.Root != "" {
			if !claimsAllowed { // claimsAllowed is false exactly for conflicts
				return nil, fmt.Errorf(
					"peipkg/manifest: %s[%d]: a root field is not permitted on %s entries",
					field, i, field)
			}
			if err := ValidateRootRef(w.Root); err != nil {
				return nil, fmt.Errorf("peipkg/manifest: %s[%d]: root: %w", field, i, err)
			}
			dep.Root = w.Root
		}
		if len(w.Claims) > 0 {
			if !claimsAllowed {
				return nil, fmt.Errorf(
					"peipkg/manifest: %s[%d]: claims are not permitted on %s entries",
					field, i, field)
			}
			claims, err := validateClaims(
				fmt.Sprintf("%s[%d]", field, i), w.Claims, consumerClaims)
			if err != nil {
				return nil, err
			}
			dep.Claims = claims
		}
		deps = append(deps, dep)
	}
	if err := checkSortedUnique(field, dependencyNames(deps)); err != nil {
		return nil, err
	}
	return deps, nil
}

// claimSide selects which slot fields a claims entry may carry (§4.4.2):
// a consumer slot (on a dependency) carries path only; a provider slot
// (on a provides entry) carries target and an optional default path.
type claimSide int

const (
	consumerClaims claimSide = iota
	providerClaims
)

// validateClaims validates one claims field (§4.4.2). label names the
// enclosing entry for error messages; side selects the permitted slot
// fields. An empty or absent claims field yields a nil map.
func validateClaims(label string, wires map[string]wireClaimSlot, side claimSide) (
	map[string]ClaimSlot, error) {

	if len(wires) > maxClaimSlots {
		return nil, fmt.Errorf("peipkg/manifest: %s: claims has %d slots, the limit is %d",
			label, len(wires), maxClaimSlots)
	}
	claims := make(map[string]ClaimSlot, len(wires))
	for slot, w := range wires {
		// §4.4.2: a slot name conforms to §2.1.
		if err := validateName(slot); err != nil {
			return nil, fmt.Errorf("peipkg/manifest: %s: claims slot name %w", label, err)
		}
		switch side {
		case consumerClaims:
			if w.Target != "" {
				return nil, fmt.Errorf("peipkg/manifest: %s: claims slot %q sets target, "+
					"which only a provides entry may set", label, slot)
			}
			if w.Path == "" {
				return nil, fmt.Errorf(
					"peipkg/manifest: %s: claims slot %q is missing path", label, slot)
			}
			if err := validateClaimPath(w.Path); err != nil {
				return nil, fmt.Errorf(
					"peipkg/manifest: %s: claims slot %q: path: %w", label, slot, err)
			}
		case providerClaims:
			if w.Target == "" {
				return nil, fmt.Errorf(
					"peipkg/manifest: %s: claims slot %q is missing target", label, slot)
			}
			if err := validateClaimPath(w.Target); err != nil {
				return nil, fmt.Errorf(
					"peipkg/manifest: %s: claims slot %q: target: %w", label, slot, err)
			}
			if w.Path != "" {
				if err := validateClaimPath(w.Path); err != nil {
					return nil, fmt.Errorf(
						"peipkg/manifest: %s: claims slot %q: path: %w", label, slot, err)
				}
			}
		}
		claims[slot] = ClaimSlot{Path: w.Path, Target: w.Target}
	}
	if len(claims) == 0 {
		return nil, nil
	}
	return claims, nil
}

// validateClaimPath checks a claim target or path is a clean absolute
// path. Claims deliberately bypass the install-path subdirectory rules
// (§3.4): materialising a link or naming a payload file outside the
// normal layout — e.g. the kernel-mandated /init at the root of an
// initramfs — is a core reason claims exist. So only the structural
// invariants are enforced here: absolute, bounded, clean, non-empty.
func validateClaimPath(p string) error {
	if !strings.HasPrefix(p, "/") {
		return fmt.Errorf("%q must be an absolute path", p)
	}
	if len(p) > maxClaimPath {
		return fmt.Errorf("%q is %d bytes, the limit is %d", p, len(p), maxClaimPath)
	}
	if path.Clean(p) != p {
		return fmt.Errorf("%q is not a clean path", p)
	}
	top, _, _ := strings.Cut(strings.TrimPrefix(p, "/"), "/")
	if top == "" {
		return fmt.Errorf("%q has no path component", p)
	}
	return nil
}

// validateProvides validates the provides array (§4.1.4).
func validateProvides(wires []wireProvides) ([]Provides, error) {
	if len(wires) > maxDependencies {
		return nil, fmt.Errorf("peipkg/manifest: provides has %d entries, the limit is %d",
			len(wires), maxDependencies)
	}
	provides := make([]Provides, 0, len(wires))
	for i, w := range wires {
		if w.Name == nil {
			return nil, fmt.Errorf("peipkg/manifest: provides[%d]: missing field %q", i, "name")
		}
		// §4.1.4: a provides name is a virtual (capability) name.
		if err := capability.ValidateName(*w.Name); err != nil {
			return nil, fmt.Errorf("peipkg/manifest: provides[%d]: name: %w", i, err)
		}
		p := Provides{Name: *w.Name}
		if w.Version != "" {
			// §4.1.4: a provides version expresses a capability level, not
			// a packaging iteration, so the Peios revision may be omitted
			// (e.g. "3.0"). Parse it revision-relaxed, like a constraint
			// operand.
			v, err := version.ParseRelaxed(w.Version)
			if err != nil {
				return nil, fmt.Errorf("peipkg/manifest: provides[%d]: version: %w", i, err)
			}
			p.Version = &v
		}
		if len(w.Claims) > 0 {
			claims, err := validateClaims(
				fmt.Sprintf("provides[%d]", i), w.Claims, providerClaims)
			if err != nil {
				return nil, err
			}
			p.Claims = claims
		}
		provides = append(provides, p)
	}
	names := make([]string, len(provides))
	for i, p := range provides {
		names[i] = p.Name
	}
	if err := checkSortedUnique("provides", names); err != nil {
		return nil, err
	}
	return provides, nil
}

// validateReplaces validates the replaces array (§4.1.5).
func validateReplaces(wires []wireReplaces) ([]Replaces, error) {
	if len(wires) > maxReplaces {
		return nil, fmt.Errorf("peipkg/manifest: replaces has %d entries, the limit is %d",
			len(wires), maxReplaces)
	}
	replaces := make([]Replaces, 0, len(wires))
	for i, w := range wires {
		if w.Name == nil {
			return nil, fmt.Errorf("peipkg/manifest: replaces[%d]: missing field %q", i, "name")
		}
		if err := validateName(*w.Name); err != nil {
			return nil, fmt.Errorf("peipkg/manifest: replaces[%d]: name: %w", i, err)
		}
		constraint, err := parseOptionalConstraint(w.Constraint)
		if err != nil {
			return nil, fmt.Errorf("peipkg/manifest: replaces[%d]: constraint: %w", i, err)
		}
		replaces = append(replaces, Replaces{Name: *w.Name, Constraint: constraint})
	}
	names := make([]string, len(replaces))
	for i, r := range replaces {
		names[i] = r.Name
	}
	if err := checkSortedUnique("replaces", names); err != nil {
		return nil, err
	}
	return replaces, nil
}

// validateSideEffects validates the side_effects array against the
// closed set of §4.3.4 / §9.2 and rejects duplicates (§4.3).
func validateSideEffects(raw []string) ([]SideEffect, error) {
	effects := make([]SideEffect, 0, len(raw))
	seen := make(map[string]bool, len(raw))
	for _, s := range raw {
		switch SideEffect(s) {
		case SideEffectDepmod, SideEffectManDB:
		default:
			return nil, fmt.Errorf("peipkg/manifest: side_effects: %q is not a recognised "+
				"side effect", s)
		}
		if seen[s] {
			return nil, fmt.Errorf("peipkg/manifest: side_effects: %q appears more than once", s)
		}
		seen[s] = true
		effects = append(effects, SideEffect(s))
	}
	return effects, nil
}

// validateSDOverrides validates the sd_overrides array structurally
// (§3.3.5): each entry has a path and a base64 sd field within the size
// limit, and the array is ordered by path.
func validateSDOverrides(wires []wireSDOverride) ([]SDOverride, error) {
	if len(wires) > maxSDOverrides {
		return nil, fmt.Errorf("peipkg/manifest: sd_overrides has %d entries, the limit is %d",
			len(wires), maxSDOverrides)
	}
	overrides := make([]SDOverride, 0, len(wires))
	for i, w := range wires {
		if w.Path == nil {
			return nil, fmt.Errorf("peipkg/manifest: sd_overrides[%d]: missing field %q", i, "path")
		}
		if w.SD == nil {
			return nil, fmt.Errorf("peipkg/manifest: sd_overrides[%d]: missing field %q", i, "sd")
		}
		sd, err := base64.RawStdEncoding.DecodeString(*w.SD)
		if err != nil {
			return nil, fmt.Errorf(
				"peipkg/manifest: sd_overrides[%d]: sd is not valid base64: %w", i, err)
		}
		if len(sd) > maxSDOverride {
			return nil, fmt.Errorf(
				"peipkg/manifest: sd_overrides[%d]: decoded sd is %d bytes, the limit is %d",
				i, len(sd), maxSDOverride)
		}
		overrides = append(overrides, SDOverride{Path: *w.Path, SD: sd})
	}
	paths := make([]string, len(overrides))
	for i, o := range overrides {
		paths[i] = o.Path
	}
	if err := checkSortedUnique("sd_overrides", paths); err != nil {
		return nil, err
	}
	return overrides, nil
}

// validateBuild validates the build-provenance object (§3.3.4).
func validateBuild(w wireBuild) (Build, error) {
	switch {
	case w.Timestamp == nil:
		return Build{}, fmt.Errorf("peipkg/manifest: build: missing field %q", "timestamp")
	case w.FarmID == nil:
		return Build{}, fmt.Errorf("peipkg/manifest: build: missing field %q", "farm_id")
	case w.SourceRef == nil:
		return Build{}, fmt.Errorf("peipkg/manifest: build: missing field %q", "source_ref")
	}
	// §3.3.4: the timestamp is RFC 3339 and must be UTC, ending with Z.
	if !strings.HasSuffix(*w.Timestamp, "Z") {
		return Build{}, fmt.Errorf(
			"peipkg/manifest: build: timestamp %q must be UTC (end with Z)", *w.Timestamp)
	}
	ts, err := time.Parse(time.RFC3339, *w.Timestamp)
	if err != nil {
		return Build{}, fmt.Errorf("peipkg/manifest: build: timestamp: %w", err)
	}
	out := Build{Timestamp: ts, FarmID: *w.FarmID, SourceRef: *w.SourceRef}
	// source_package, recipe_ref, and builder are optional (§3.3.4):
	// absent means the producer recorded nothing for them.
	if w.SourcePackage != nil {
		out.SourcePackage = *w.SourcePackage
	}
	if w.RecipeRef != nil {
		out.RecipeRef = *w.RecipeRef
	}
	if w.Builder != nil {
		out.Builder = *w.Builder
	}
	return out, nil
}

// parseOptionalConstraint parses a constraint string, treating the empty
// string — an absent constraint field — as the unrestricted constraint.
func parseOptionalConstraint(s string) (version.Constraint, error) {
	if s == "" {
		return version.Constraint{}, nil
	}
	return version.ParseConstraint(s)
}

// checkSortedUnique verifies a sequence of names is strictly ascending —
// sorted lexicographically with no duplicates (§4.1.6 for the
// dependency-family fields, §3.3.5 for sd_overrides). field names the
// array for error messages.
func checkSortedUnique(field string, names []string) error {
	for i := 1; i < len(names); i++ {
		switch {
		case names[i] < names[i-1]:
			return fmt.Errorf("peipkg/manifest: %s is not sorted (%q before %q)",
				field, names[i-1], names[i])
		case names[i] == names[i-1]:
			return fmt.Errorf("peipkg/manifest: %s has a duplicate entry %q", field, names[i])
		}
	}
	return nil
}

// dependencyNames extracts the name of each dependency, in order.
func dependencyNames(deps []Dependency) []string {
	names := make([]string, len(deps))
	for i, d := range deps {
		names[i] = d.Name
	}
	return names
}

func isLowerOrDigit(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
}

// isNameSeparator reports whether c is a §2.1 separator. The plus sign is
// deliberately NOT a separator but a regular name character (it is intrinsic
// to names like libstdc++ and g++), so it may repeat and may end a name.
func isNameSeparator(c byte) bool { return c == '-' || c == '.' }

func isNameChar(c byte) bool { return isLowerOrDigit(c) || isNameSeparator(c) || c == '+' }
