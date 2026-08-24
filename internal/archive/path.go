package archive

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// Payload-path resource limits (§3.2.6, §3.2.7).
const (
	maxPathComponent = 255  // bytes, UTF-8
	maxPathLength    = 4096 // bytes, UTF-8
	maxPathDepth     = 256  // number of components
)

// metadataPrefix is the reserved archive prefix for package metadata
// (§3.2.1); payload entries must not use it.
const metadataPrefix = ".peipkg/"

// checkPathBytes enforces the path-validity constraints that §5.13 sets
// for a payload path and §5.17 then applies unchanged to a symlink
// target: valid UTF-8, no NUL bytes, no ASCII control characters, no
// backslashes, NFC normalisation, and the length limits.
//
// kind names the subject in any error, so the two callers report their
// own vocabulary.
func checkPathBytes(kind, p string) error {
	if len(p) > maxPathLength {
		return fmt.Errorf("%s is %d bytes, the limit is %d", kind, len(p), maxPathLength)
	}
	if !utf8.ValidString(p) {
		return fmt.Errorf("%s is not valid UTF-8", kind)
	}
	if !norm.NFC.IsNormalString(p) {
		return fmt.Errorf("%s %q is not in Unicode NFC", kind, p)
	}
	for i := 0; i < len(p); i++ {
		switch c := p[i]; {
		case c == 0x00:
			return fmt.Errorf("%s contains a NUL byte", kind)
		case c < 0x20 || c == 0x7F:
			return fmt.Errorf("%s contains the control byte %#x", kind, c)
		case c == '\\':
			return fmt.Errorf("%s %q contains a backslash", kind, p)
		}
	}

	components := strings.Split(p, "/")
	if len(components) > maxPathDepth {
		return fmt.Errorf("%s has %d components, the limit is %d",
			kind, len(components), maxPathDepth)
	}
	for _, c := range components {
		if len(c) > maxPathComponent {
			return fmt.Errorf("%s component %q is %d bytes, the limit is %d",
				kind, c, len(c), maxPathComponent)
		}
	}
	return nil
}

// validatePayloadPath checks a payload tar entry's path against every
// §5.13 constraint. A non-conforming path means the package is
// malformed and must be rejected before the entry is processed further.
func validatePayloadPath(p string) error {
	if p == "" {
		return fmt.Errorf("empty payload path")
	}
	if strings.HasPrefix(p, "/") {
		return fmt.Errorf("payload path %q is absolute; it must be relative", p)
	}
	if p == ".peipkg" || strings.HasPrefix(p, metadataPrefix) {
		return fmt.Errorf("payload path %q uses the reserved %q prefix", p, metadataPrefix)
	}
	if err := checkPathBytes("payload path", p); err != nil {
		return err
	}
	for _, c := range strings.Split(p, "/") {
		if c == "" {
			return fmt.Errorf("payload path %q has an empty component", p)
		}
		if c == "." || c == ".." {
			return fmt.Errorf("payload path %q contains a %q component", p, c)
		}
	}
	return nil
}

// ValidateSymlinkTarget checks a symlink's target against §5.17's
// path-validity constraints. The producer side calls it so that a
// non-conforming target is caught at pack time rather than surviving to
// a consumer, and so that both sides enforce one copy of the rules.
func ValidateSymlinkTarget(target string) error { return validateSymlinkTargetPath(target) }

// validateSymlinkTargetPath checks a symlink's target against §5.17,
// which subjects it to the same path-validity constraints as a payload
// path. A target legitimately contains ".." — that is how the
// conventional library split reaches a sibling directory — so the
// component rules a payload path adds do not apply here; whether the
// resolved path lands under a permitted destination is a separate
// question, decided against the symlink's own parent directory.
func validateSymlinkTargetPath(target string) error {
	if target == "" {
		return fmt.Errorf("symlink target is empty")
	}
	if strings.HasPrefix(target, "/") {
		return fmt.Errorf("symlink target %q is absolute; it must be relative", target)
	}
	return checkPathBytes("symlink target", target)
}
