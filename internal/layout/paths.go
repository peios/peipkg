package layout

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// Path resource limits (PSPU §5.13, §5.A1).
const (
	MaxPathComponent = 255  // bytes, UTF-8
	MaxPathLength    = 4096 // bytes, UTF-8
	MaxPathDepth     = 256  // number of components
)

// PermittedTopLevels enumerates the top-level install destinations PSPU
// §5.14 permits, relative to the installation root with no leading
// slash and a trailing one. A path is under a destination when some
// entry is a prefix of it.
//
// usr/lib/ admits any first-segment-after-lib name so the producer's
// validator can dispatch the per-triplet rule (§5.15): it narrows it to
// "<arch>-linux-peios/", the "debug/" separated-debug-info tree,
// "modules/", "firmware/" or the os-release file, or rejects.
var PermittedTopLevels = []string{
	"usr/bin/",
	"usr/sbin/", // system binaries (daemons, init/boot, service executables)
	"usr/lib/",
	"usr/libexec/", // arch-independent helper executables run by other programs, not on user PATH; no triplet rule
	"usr/share/",
	"usr/include/",
	"usr/etc/",       // vendor config defaults for legacy applications — the bottom layer of the /etc merge
	"usr/conf/",      // vendor defaults for native-application supplementary config — the bottom layer of the /conf merge
	"usr/src/debug/", // separated debug info's source subtree of usr/src
	"usr/src/dist/",  // corresponding-source packages; the rest of usr/src stays admin territory
	"var/",
	"boot/",
	"hooks/", // initramfs boot hooks — mkirf scans /hooks/ when packing the cpio
	"++/",    // initramfs early-cpio segments — mkirf prepends /++/ uncompressed ahead of the main archive
}

// claimOnlyTopLevels are the locations §5.23 admits for a claim path
// over and above §5.14's destinations. Neither is a payload
// destination: /run/ lets a role expose a runtime socket without
// letting packages ship payload there, and /init is the well-known
// initramfs entry point a provider must own directly.
var claimOnlyTopLevels = []string{"run/"}

const claimOnlyRootName = "init"

// UnderPermittedTopLevel reports whether rel — a path relative to the
// installation root, with no leading slash — lies strictly beneath one
// of the §5.14 permitted destinations.
func UnderPermittedTopLevel(rel string) bool {
	for _, top := range PermittedTopLevels {
		if strings.HasPrefix(rel, top) {
			return true
		}
	}
	return false
}

// CheckPathBytes enforces the path-validity constraints that §5.13 sets
// for a payload path and §5.17 then applies unchanged to a symlink
// target: valid UTF-8, no NUL bytes, no ASCII control characters, no
// backslashes, NFC normalisation, and the length limits.
//
// kind names the subject in any error, so each caller reports its own
// vocabulary.
func CheckPathBytes(kind, p string) error {
	if len(p) > MaxPathLength {
		return fmt.Errorf("%s is %d bytes, the limit is %d", kind, len(p), MaxPathLength)
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
	if len(components) > MaxPathDepth {
		return fmt.Errorf("%s has %d components, the limit is %d",
			kind, len(components), MaxPathDepth)
	}
	for _, c := range components {
		if len(c) > MaxPathComponent {
			return fmt.Errorf("%s component %q is %d bytes, the limit is %d",
				kind, c, len(c), MaxPathComponent)
		}
	}
	return nil
}

// CheckPathComponents enforces the component rules §5.13 adds for a
// path that names a location rather than a link body: no empty
// component (so no doubled or trailing slash), and no "." or "..".
func CheckPathComponents(kind, p string) error {
	for _, c := range strings.Split(p, "/") {
		if c == "" {
			return fmt.Errorf("%s %q has an empty component", kind, p)
		}
		if c == "." || c == ".." {
			return fmt.Errorf("%s %q contains a %q component", kind, p, c)
		}
	}
	return nil
}

// checkAbsolute applies the §5.13 syntax and safety rules to an
// absolute path and returns its root-relative form.
func checkAbsolute(kind, p string) (string, error) {
	if !strings.HasPrefix(p, "/") {
		return "", fmt.Errorf("%s %q must be an absolute path", kind, p)
	}
	rel := p[1:]
	if rel == "" {
		return "", fmt.Errorf("%s %q has no path component", kind, p)
	}
	if err := CheckPathBytes(kind, rel); err != nil {
		return "", err
	}
	if err := CheckPathComponents(kind, rel); err != nil {
		return "", err
	}
	return rel, nil
}

// CheckClaimPath enforces PSPU §5.23 on a claim path: it satisfies the
// payload path-syntax and safety constraints of §5.13, and it lies
// under one of §5.14's permitted install destinations, under /run/, or
// at the well-known root-level name /init. Any other location is
// rejected, and /lcl/policy is unreachable whatever else permits it.
func CheckClaimPath(p string) error {
	rel, err := checkAbsolute("claim path", p)
	if err != nil {
		return err
	}
	permitted := UnderPermittedTopLevel(rel) || rel == claimOnlyRootName
	for _, top := range claimOnlyTopLevels {
		permitted = permitted || strings.HasPrefix(rel, top)
	}
	if !permitted {
		return fmt.Errorf("claim path %q is outside every permitted install destination "+
			"(PSPU §5.14), /run/, and /init, which are the only locations a claim path "+
			"may lie in (PSPU §5.23)", p)
	}
	return Check(rel)
}

// CheckClaimTarget enforces the part of PSPU §5.23's target rule that a
// manifest can answer alone: a target names a payload path of the
// declaring package, so it satisfies §5.13 and lies under a §5.14
// destination. Whether the package actually ships that path is checked
// at install time against the payload received.
func CheckClaimTarget(p string) error {
	rel, err := checkAbsolute("claim target", p)
	if err != nil {
		return err
	}
	if !UnderPermittedTopLevel(rel) {
		return fmt.Errorf("claim target %q is outside every permitted install "+
			"destination (PSPU §5.14); a target names a payload path of the declaring "+
			"package (PSPU §5.23)", p)
	}
	return Check(rel)
}
