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
	"strconv"
	"strings"
)

// Version is a parsed package version string (§2.2): an optional epoch,
// an upstream version, and a Peios revision. Obtain one through [Parse];
// the zero Version is not meaningful.
//
// A Version must not be compared with ==; use [Compare] or [Version.Equal].
type Version struct {
	raw      string
	epoch    int
	upstream string
	revision int       // a constraint operand that omits the revision leaves this 0
	segments []segment // tokenised upstream, retained for comparison
}

// Epoch reports the version's epoch — 0 if the string carried none.
func (v Version) Epoch() int { return v.epoch }

// Upstream reports the upstream-version portion of the string.
func (v Version) Upstream() string { return v.upstream }

// Revision reports the Peios revision.
func (v Version) Revision() int { return v.revision }

// String returns the version string exactly as it was parsed.
func (v Version) String() string { return v.raw }

// Parse parses and validates a complete version string per §2.2.5: an
// optional `epoch:` prefix, an upstream version, and a required Peios
// revision.
func Parse(s string) (Version, error) {
	return parse(s, false)
}

// parse is the shared parser. When revisionOptional is true — the
// constraint-operand case (§2.2.8), where `>= 3.0` is well-formed — a
// string with no trailing `-revision` is accepted and the revision is
// left as 0.
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
		case err == nil && revision >= 1:
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
func parseDecimal(s string) (int, error) {
	if s == "" {
		return 0, fmt.Errorf("empty number")
	}
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) {
			return 0, fmt.Errorf("%q is not a decimal number", s)
		}
	}
	if len(s) > 1 && s[0] == '0' {
		return 0, fmt.Errorf("%q has a leading zero", s)
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("%q is out of range", s)
	}
	return n, nil
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
