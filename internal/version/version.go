// Package version implements the peipkg version-string grammar and
// comparison algorithm (PSD-009 §2.2): parsing a version into its
// epoch / upstream / revision parts, ordering two versions, and
// matching a version against a dependency constraint.
//
// The comparison algorithm is parity-critical — every peipkg-family
// tool must order any pair of valid versions identically (§2.2.9). The
// implementation follows §2.2.7 and is verified against the worked
// examples in §9.3.
package version

import (
	"fmt"
	"strings"
)

// Version is a parsed package version string (§2.2): an optional epoch,
// an upstream version, and a Peios revision. Obtain one through [Parse];
// the zero Version is not meaningful.
//
// A Version must not be compared with ==; use [Compare] or [Version.Equal].
// §2.2.2 and §2.2.4 state no maximum for the epoch or the revision, and
// §2.2.5's stability clause requires two conforming implementations to
// agree on every pair of valid version strings. Holding either in an int
// would make the accept/reject boundary depend on the platform's word
// size, so both are kept as the canonical digit strings they were parsed
// from and ordered by [compareNumeric], exactly as upstream segments are.
type Version struct {
	raw      string
	epoch    string // canonical decimal; empty means the string carried none
	upstream string
	revision string    // canonical decimal; empty when a constraint operand omits it
	segments []segment // tokenised upstream, retained for comparison
}

// Epoch reports the version's epoch as a canonical decimal string —
// "0" if the string carried none.
func (v Version) Epoch() string {
	if v.epoch == "" {
		return "0"
	}
	return v.epoch
}

// Upstream reports the upstream-version portion of the string.
func (v Version) Upstream() string { return v.upstream }

// Revision reports the Peios revision as a canonical decimal string,
// empty when the version omitted one.
func (v Version) Revision() string { return v.revision }

// String returns the version string exactly as it was parsed.
func (v Version) String() string { return v.raw }

// Parse parses and validates a complete version string per §2.2.5: an
// optional `epoch:` prefix, an upstream version, and a required Peios
// revision.
func Parse(s string) (Version, error) {
	return parse(s, false)
}

// ParseRelaxed parses a version whose Peios revision may be omitted — the
// `provides.version` case (§4.1.4), which expresses a capability level
// rather than a packaging iteration, so `3.0` is well-formed. A revision,
// when present, is still parsed; when absent it is left empty. The upstream
// version is validated exactly as for [Parse].
func ParseRelaxed(s string) (Version, error) {
	return parse(s, true)
}

// parse is the shared parser. When revisionOptional is true — the
// constraint-operand case (§2.2.8), where `>= 3.0` is well-formed — a
// string with no trailing `-revision` is accepted and the revision is
// left empty.
func parse(s string, revisionOptional bool) (Version, error) {
	v := Version{raw: s}

	rest := s
	if epochStr, after, found := strings.Cut(s, ":"); found {
		epoch, err := parseDecimal(epochStr)
		if err != nil {
			return Version{}, fmt.Errorf("peipkg/version: invalid epoch in %q: %w", s, err)
		}
		v.epoch = epoch
		rest = after
	}

	upstream := rest
	if idx := strings.LastIndexByte(rest, '-'); idx >= 0 {
		revision, err := parseDecimal(rest[idx+1:])
		switch {
		case err == nil && revision != "0":
			v.revision = revision
			upstream = rest[:idx]
		case revisionOptional:
			// The trailing hyphen group is not a revision; the whole
			// remainder is the upstream version.
		case err != nil:
			return Version{}, fmt.Errorf("peipkg/version: invalid revision in %q: %w", s, err)
		default:
			return Version{}, fmt.Errorf(
				"peipkg/version: revision in %q must be a positive integer", s)
		}
	} else if !revisionOptional {
		return Version{}, fmt.Errorf("peipkg/version: %q has no -revision", s)
	}

	if err := validateUpstream(upstream); err != nil {
		return Version{}, fmt.Errorf("peipkg/version: invalid upstream in %q: %w", s, err)
	}
	v.upstream = upstream
	v.segments = tokenize(upstream)
	return v, nil
}

// parseDecimal parses a non-negative integer in canonical decimal form:
// ASCII digits only, no leading zeros (the value zero is the single
// digit "0"). This is the encoding §2.2.2 and §2.2.4 require of the
// epoch and the revision.
// It returns the digit string itself rather than an integer: §2.2.2 and
// §2.2.4 set no upper bound, so any fixed-width conversion would reject
// values the grammar accepts, and would reject a different set of them on
// a 32-bit build than on a 64-bit one.
func parseDecimal(s string) (string, error) {
	if s == "" {
		return "", fmt.Errorf("empty number")
	}
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) {
			return "", fmt.Errorf("%q is not a decimal number", s)
		}
	}
	if len(s) > 1 && s[0] == '0' {
		return "", fmt.Errorf("%q has a leading zero", s)
	}
	return s, nil
}

// validateUpstream checks the upstream version against the §2.2.3
// character-set and structural rules.
func validateUpstream(s string) error {
	if s == "" {
		return fmt.Errorf("empty upstream version")
	}
	if !isAlphanumeric(s[0]) {
		return fmt.Errorf("must start with a letter or digit")
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !isAlphanumeric(c) && c != '.' && c != '+' && c != '-' && c != '~' {
			return fmt.Errorf("contains the invalid character %q", c)
		}
	}
	return nil
}
