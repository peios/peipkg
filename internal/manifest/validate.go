package manifest

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

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

	if *wm.SizeInstalled < 0 {
		return Manifest{}, fmt.Errorf(
			"peipkg/manifest: size_installed is negative (%d)", *wm.SizeInstalled)
	}
	m.SizeInstalled = *wm.SizeInstalled

	if m.Dependencies, err = validateDependencies("dependencies", *wm.Dependencies); err != nil {
		return Manifest{}, err
	}
	if m.OptionalDependencies, err = validateDependencies(
		"optional_dependencies", wm.OptionalDependencies); err != nil {
		return Manifest{}, err
	}
	if m.Conflicts, err = validateDependencies("conflicts", *wm.Conflicts); err != nil {
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
	if !isLowerOrDigit(s[0]) || (!isLowerOrDigit(s[len(s)-1]) && s[len(s)-1] != '+') {
		return fmt.Errorf("%q must start with a lowercase letter or digit and end with one or a plus sign", s)
	}
	for i := 1; i < len(s); i++ {
		if isNameSeparator(s[i]) && isNameSeparator(s[i-1]) {
			return fmt.Errorf("%q has consecutive separator characters", s)
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
func validateDependencies(field string, wires []wireDependency) ([]Dependency, error) {
	if len(wires) > maxDependencies {
		return nil, fmt.Errorf("peipkg/manifest: %s has %d entries, the limit is %d",
			field, len(wires), maxDependencies)
	}
	deps := make([]Dependency, 0, len(wires))
	for i, w := range wires {
		if w.Name == nil {
			return nil, fmt.Errorf("peipkg/manifest: %s[%d]: missing field %q", field, i, "name")
		}
		if err := validateName(*w.Name); err != nil {
			return nil, fmt.Errorf("peipkg/manifest: %s[%d]: name: %w", field, i, err)
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
		deps = append(deps, Dependency{Name: *w.Name, Constraint: constraint})
	}
	if err := checkSortedUnique(field, dependencyNames(deps)); err != nil {
		return nil, err
	}
	return deps, nil
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
		if err := validateName(*w.Name); err != nil {
			return nil, fmt.Errorf("peipkg/manifest: provides[%d]: name: %w", i, err)
		}
		p := Provides{Name: *w.Name}
		if w.Version != "" {
			v, err := version.Parse(w.Version)
			if err != nil {
				return nil, fmt.Errorf("peipkg/manifest: provides[%d]: version: %w", i, err)
			}
			p.Version = &v
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
		case SideEffectLdconfig, SideEffectDepmod, SideEffectManDB:
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
	return Build{Timestamp: ts, FarmID: *w.FarmID, SourceRef: *w.SourceRef}, nil
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

// A plus sign is a regular name character, not a separator: it is intrinsic to
// names like "libstdc++" / "g++" (it may repeat and may end a name), unlike the
// hyphen and dot that join components and may not be adjacent or sit at an edge.
func isNameSeparator(c byte) bool { return c == '-' || c == '.' }

func isNameChar(c byte) bool { return isLowerOrDigit(c) || isNameSeparator(c) || c == '+' }
