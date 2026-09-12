package archive

import (
	"archive/tar"
	"fmt"
	"strings"
	"time"

	"github.com/peios/peipkg/internal/layout"
)

// metadataPrefix is the reserved archive prefix for package metadata
// (§3.2.1); payload entries must not use it.
const metadataPrefix = ".peipkg/"

// checkPathBytes enforces the path-validity constraints that §5.13 sets
// for a payload path and §5.17 then applies unchanged to a symlink
// target. The rules live in layout so that a claim path (§5.23), which
// the manifest decoder validates, is held to the same single copy.
func checkPathBytes(kind, p string) error { return layout.CheckPathBytes(kind, p) }

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
	return layout.CheckPathComponents("payload path", p)
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

// checkCanonicalHeader enforces the §5.11 determinism rules that
// constrain a tar header's fields. §5.16 makes the mode rule an explicit
// rejection condition — "Every payload entry's permission bits MUST be
// 0777. Any other value MUST cause the package to be rejected" — and the
// rest are what make the archive's bytes reproducible.
//
// Only entry ordering was checked on read before this, so a hand-built
// .peipkg with mode 04755, uid 1000, uname "attacker" and
// SCHILY.xattr.security.capability records installed cleanly and
// `peipkg verify` reported it clean. There is no escalation on Peios,
// because extraction ignores modes entirely — but the package is
// non-conformant, and a non-Peios consumer extracting the same file with
// GNU tar honours the setuid bit.
//
// It also quietly defeated the reproducibility claim §5.11 exists to
// make: a repacked archive whose per-entry mtimes diverge from
// build.timestamp verified successfully, so a third party re-running the
// build and diffing bytes got a mismatch peipkg itself would accept.
//
// mtime is checked separately by [CheckCanonicalModTime], because it
// needs the manifest.
func checkCanonicalHeader(hdr *tar.Header) error {
	switch {
	case hdr.Mode != 0o777:
		return fmt.Errorf("entry %q has mode %#o, §5.16 requires 0777", hdr.Name, hdr.Mode)
	case hdr.Uid != 0 || hdr.Gid != 0:
		return fmt.Errorf("entry %q has uid/gid %d/%d, §5.11 requires 0/0",
			hdr.Name, hdr.Uid, hdr.Gid)
	case hdr.Uname != "root" || hdr.Gname != "root":
		return fmt.Errorf("entry %q has uname/gname %q/%q, §5.11 requires root/root",
			hdr.Name, hdr.Uname, hdr.Gname)
	case len(hdr.Xattrs) > 0 || len(hdr.PAXRecords) > 0 && hasXattrRecord(hdr):
		return fmt.Errorf("entry %q carries extended attributes, which §5.11 forbids", hdr.Name)
	case hdr.Devmajor != 0 || hdr.Devminor != 0:
		return fmt.Errorf("entry %q has devmajor/devminor %d/%d, §5.11 requires 0/0",
			hdr.Name, hdr.Devmajor, hdr.Devminor)
	case hdr.Format == tar.FormatGNU:
		// A GNU-magic archive uses L/K long-name headers, which are not
		// the ustar/PAX encoding §5.11 pins.
		return fmt.Errorf("entry %q uses GNU tar format, §5.11 requires ustar/PAX", hdr.Name)
	}
	return nil
}

// hasXattrRecord reports whether any PAX record carries an extended
// attribute. Go merges SCHILY.xattr.* into hdr.Xattrs, but a producer
// may also use the newer LIBARCHIVE.xattr.* spelling, which it does not.
func hasXattrRecord(hdr *tar.Header) bool {
	for k := range hdr.PAXRecords {
		if strings.HasPrefix(k, "SCHILY.xattr.") || strings.HasPrefix(k, "LIBARCHIVE.xattr.") {
			return true
		}
	}
	return false
}

// checkCanonicalModTime enforces §5.11 rule 2: every entry's mtime equals
// the manifest's build.timestamp. It is separate from
// [checkCanonicalHeader] only because it needs the manifest, which is
// itself the first entry in the archive.
func checkCanonicalModTime(hdr *tar.Header, buildTimestamp time.Time) error {
	if !hdr.ModTime.Equal(buildTimestamp) {
		return fmt.Errorf("entry %q has mtime %s, §5.11 requires build.timestamp %s",
			hdr.Name, hdr.ModTime.UTC().Format(time.RFC3339),
			buildTimestamp.UTC().Format(time.RFC3339))
	}
	return nil
}
