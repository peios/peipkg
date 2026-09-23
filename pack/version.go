package pack

import "github.com/peios/peipkg/internal/version"

// ValidateVersion reports whether s is a complete package version string
// (PSPU §5.5): an optional `epoch:` prefix, an upstream version, and a
// required Peios revision. It is the check [Pack] applies to a manifest's
// version, exposed so a producer can reject a malformed version where it
// renders one rather than when the archive is written.
func ValidateVersion(s string) error {
	_, err := version.Parse(s)
	return err
}
