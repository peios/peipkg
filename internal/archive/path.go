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

// validatePayloadPath checks a payload tar entry's path against every
// §3.2.6 constraint. A non-conforming path means the package is
// malformed and must be rejected before the entry is processed further.
func validatePayloadPath(p string) error {
	if p == "" {
		return fmt.Errorf("empty payload path")
	}
	if len(p) > maxPathLength {
		return fmt.Errorf("payload path is %d bytes, the limit is %d", len(p), maxPathLength)
	}
	if strings.HasPrefix(p, "/") {
		return fmt.Errorf("payload path %q is absolute; it must be relative", p)
	}
	if p == ".peipkg" || strings.HasPrefix(p, metadataPrefix) {
		return fmt.Errorf("payload path %q uses the reserved %q prefix", p, metadataPrefix)
	}
	if !utf8.ValidString(p) {
		return fmt.Errorf("payload path is not valid UTF-8")
	}
	if !norm.NFC.IsNormalString(p) {
		return fmt.Errorf("payload path %q is not in Unicode NFC", p)
	}
	for i := 0; i < len(p); i++ {
		switch c := p[i]; {
		case c == 0x00:
			return fmt.Errorf("payload path contains a NUL byte")
		case c < 0x20 || c == 0x7F:
			return fmt.Errorf("payload path contains the control byte %#x", c)
		case c == '\\':
			return fmt.Errorf("payload path %q contains a backslash", p)
		}
	}

	components := strings.Split(p, "/")
	if len(components) > maxPathDepth {
		return fmt.Errorf("payload path has %d components, the limit is %d",
			len(components), maxPathDepth)
	}
	for _, c := range components {
		if c == "" {
			return fmt.Errorf("payload path %q has an empty component", p)
		}
		if c == "." || c == ".." {
			return fmt.Errorf("payload path %q contains a %q component", p, c)
		}
		if len(c) > maxPathComponent {
			return fmt.Errorf("payload path component %q is %d bytes, the limit is %d",
				c, len(c), maxPathComponent)
		}
	}
	return nil
}
