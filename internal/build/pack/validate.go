package pack

import (
	"fmt"
	"github.com/peios/peipkg/internal/archive"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// permittedTopLevels enumerates the top-level install destinations PSD-009
// §3.4.1 permits. A payload path is acceptable if some entry in this list is
// a prefix of the path (with the trailing slash treated as a directory
// separator, so "etc/foo" matches "etc/" but "etcetera" does not).
//
// usr/lib/ admits any first-segment-after-lib name to allow the per-triplet
// dispatch (validateLibPath narrows it to "<arch>-linux-peios/", the "debug/"
// separated-debug-info tree, "modules/" or "firmware/", or rejects).
var permittedTopLevels = []string{
	"usr/bin/",
	"usr/sbin/", // system binaries (daemons, init/boot, service executables)
	"usr/lib/",
	"usr/libexec/", // arch-independent helper executables run by other programs, not on user PATH (e.g. feature lifecycle scripts); no triplet rule (that is scoped to usr/lib/)
	"usr/share/",
	"usr/include/",
	"usr/etc/",       // vendor config defaults for legacy applications — the bottom layer of the /etc merge. Packages never write /etc directly; the merged view resolves usr/etc < system/retc < lcl/etc
	"usr/conf/",      // vendor defaults for native-application supplementary config — the bottom layer of the /conf merge
	"usr/src/debug/", // separated debug info's source subtree of usr/src
	"usr/src/dist/",  // corresponding-source packages (§3.4.1); the rest of usr/src stays admin territory
	"var/",
	"boot/",
	"hooks/", // initramfs boot hooks — mkirf scans /hooks/ when packing the cpio
	"++/",    // initramfs early-cpio segments — mkirf prepends /++/ uncompressed ahead of the main archive (CPU microcode, ACPI table overrides)
}

// ValidatePayload runs the PSD-009 §3.4 layout checks over the staged tree
// at stagedRoot: permitted top-level destinations (§3.4.1), triplet
// coherence (§3.4.2), the empty-/var/ rule (§3.4.4), and symlink-target
// containment (§3.4.10). architecture is the owning package's manifest
// architecture; it drives the triplet checks.
//
// Validation is deliberately NOT performed by Pack itself: exotic packages
// (the kernel's /boot tree, for one) stage layouts the strict rules reject,
// and their producers skip this call. Errors here mean the payload would
// produce a spec-invalid peipkg; the validator aggregates failures so a
// single run reports every problem, not just the first one.
func ValidatePayload(architecture, stagedRoot string) error {
	leaves, err := walkLeaves(stagedRoot)
	if err != nil {
		return fmt.Errorf("walk staged tree: %w", err)
	}
	return validateEntries(architecture, leaves)
}

// ValidateFiles runs the same §3.4 layout checks over an explicit
// archive-path -> source-path map, the Input.Files counterpart to
// ValidatePayload. Sources are lstat'ed to determine entry kinds and read
// symlink targets, so they must exist.
func ValidateFiles(architecture string, files map[string]string) error {
	leaves, err := mapLeaves(files)
	if err != nil {
		return fmt.Errorf("resolve file map: %w", err)
	}
	return validateEntries(architecture, leaves)
}

// validateEntries is the disk-free core of ValidatePayload, split out so
// tests can drive it with synthetic entries.
func validateEntries(architecture string, leaves []entry) error {
	sorted := append([]entry(nil), leaves...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].path < sorted[j].path })

	var errs []string
	for _, l := range sorted {
		if e := validateEntryPath(architecture, l); e != nil {
			errs = append(errs, e.Error())
		}
		if l.kind == kindSymlink {
			if e := validateSymlinkTarget(l); e != nil {
				errs = append(errs, e.Error())
			}
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("payload validation failed:\n  %s", strings.Join(errs, "\n  "))
	}
	return nil
}

// validateEntryPath verifies a single entry's path against the format-level
// install-destination rules: §3.4.1 permitted top-levels, §3.4.2 triplet
// coherence, §3.4.4 var-must-be-empty.
func validateEntryPath(architecture string, l entry) error {
	if !hasPermittedTopLevel(l.path) {
		if l.kind == kindDir {
			return fmt.Errorf("directory %s is not under any §3.4.1 permitted top-level destination", l.path)
		}
		return fmt.Errorf("%s is not under any §3.4.1 permitted top-level destination", l.path)
	}

	if l.kind == kindDir {
		return nil
	}

	if strings.HasPrefix(l.path, "var/") {
		return fmt.Errorf("%s installs populated content under /var/ (§3.4.4 forbids this; only empty directories are permitted under /var/)", l.path)
	}

	if strings.HasPrefix(l.path, "usr/lib/") {
		if err := validateLibPath(architecture, l.path); err != nil {
			return err
		}
	}
	return nil
}

func hasPermittedTopLevel(p string) bool {
	for _, top := range permittedTopLevels {
		if p == strings.TrimSuffix(top, "/") {
			return true
		}
		if strings.HasPrefix(p, top) {
			return true
		}
	}
	return false
}

// validateLibPath enforces §3.4.2: anything under /usr/lib/ must be under
// /usr/lib/<triplet>/, the triplet must be <architecture>-linux-peios, and
// noarch packages must not have any /usr/lib/<triplet>/ entries at all.
//
// Three subtrees are documented exceptions to the triplet layout:
//
//   - /usr/lib/debug/     separated debug information (§3.4.1) mirrors the
//     install path of the file it describes rather than
//     sitting under <triplet>. Still arch-dependent, so
//     noarch packages must not ship it.
//   - /usr/lib/modules/   kernel modules and the kernel image itself
//     (vmlinuz, System.map, config) live beside their own
//     modules under <ver>/. With UKIs nothing boots from a
//     firmware-visible path, so the kernel is ordinary
//     package content. Arch-dependent.
//   - /usr/lib/firmware/  device firmware blobs, addressed by device rather
//     than by host triplet.
func validateLibPath(architecture, leafPath string) error {
	rest := strings.TrimPrefix(leafPath, "usr/lib/")
	first, _, ok := strings.Cut(rest, "/")
	if !ok {
		// freedesktop os-release: its location (/usr/lib/os-release) is a fixed
		// external contract the ecosystem hard-codes, and the file is
		// arch-independent — so it is exempt from the §3.4.2 triplet layout and
		// permitted directly under /usr/lib/, including in a noarch package
		// (e.g. peios-release-meta, which owns OS identity).
		if rest == "os-release" {
			return nil
		}
		return fmt.Errorf("%s sits directly under /usr/lib/ (§3.4.2 requires /usr/lib/<triplet>/<...>)", leafPath)
	}

	if first == "debug" {
		if architecture == "noarch" {
			return fmt.Errorf("noarch package contains arch-specific debug info %s (§3.4.2 forbids /usr/lib/debug/ entries in noarch packages)", leafPath)
		}
		return nil
	}

	if first == "modules" {
		if architecture == "noarch" {
			return fmt.Errorf("noarch package contains arch-specific kernel content %s (§3.4.2 forbids /usr/lib/modules/ entries in noarch packages)", leafPath)
		}
		return nil
	}

	if first == "firmware" {
		return nil
	}

	if architecture == "noarch" {
		return fmt.Errorf("noarch package contains arch-specific path %s (§3.4.2 forbids /usr/lib/<triplet>/ entries in noarch packages)", leafPath)
	}

	expected := architecture + "-linux-peios"
	if first != expected {
		return fmt.Errorf("%s uses triplet %q, expected %q for architecture %q (§3.4.2)", leafPath, first, expected, architecture)
	}
	return nil
}

// validateSymlinkTarget enforces §3.4 symlink target constraints: relative,
// resolves under §3.4.1, and meets the path-validity rules. The resolved
// target may be in another package's payload (the cross-package case);
// whether the target's owning package is a declared dep is a producer SHOULD
// per §3.4 and outside what pack-time validation can check without a full
// repository index.
func validateSymlinkTarget(l entry) error {
	if l.linkTarget == "" {
		return fmt.Errorf("symlink %s has empty target", l.path)
	}
	if filepath.IsAbs(l.linkTarget) {
		return fmt.Errorf("symlink %s -> %s: absolute targets forbidden (§3.4 requires relative)", l.path, l.linkTarget)
	}
	// §5.17 subjects a target to the same path-validity constraints as a
	// payload path: valid UTF-8, no NUL bytes, no ASCII control
	// characters, no backslashes, NFC normalisation, and the length
	// limits. Shared with the consumer so there is one copy of the rules.
	if err := archive.ValidateSymlinkTarget(l.linkTarget); err != nil {
		return fmt.Errorf("symlink %s -> %q: %w", l.path, l.linkTarget, err)
	}

	parent := path.Dir(l.path)
	if parent == "." {
		parent = ""
	}
	resolved := path.Join(parent, l.linkTarget)

	if resolved == ".." || strings.HasPrefix(resolved, "../") {
		return fmt.Errorf("symlink %s -> %s: target escapes the peipkg-managed tree (§3.4)", l.path, l.linkTarget)
	}
	if !hasPermittedTopLevel(resolved) {
		return fmt.Errorf("symlink %s -> %s resolves to %q, which is not under a §3.4.1 permitted destination", l.path, l.linkTarget, resolved)
	}
	return nil
}

// InstallEntry is one verified payload object as an install-time consumer
// sees it: the archive path, its kind, and a symlink's target. It is the
// decoupled shape of an archive payload entry, so the install path does
// not have to reach into the producer's tar-emission types.
type InstallEntry struct {
	Path       string
	IsDir      bool
	IsSymlink  bool
	LinkTarget string
}

// ValidateInstallPaths runs the same §3.4 layout checks a producer runs at
// pack time, over an already-verified payload at install time.
//
// Pack-time validation is the producer's courtesy to itself: it catches a
// bad layout at build time on the builder's machine. It is not a control,
// because the .peipkg that reaches a target system need not have been
// produced by a cooperating producer. This is the control — the last point
// before bytes land in the filesystem.
//
// The caller decides whether to run it. A Special System Package installed
// with the operator's explicit bypass skips it; nothing else does.
func ValidateInstallPaths(architecture string, entries []InstallEntry) error {
	// An archive carries an explicit entry for every ancestor directory
	// of everything it ships, so a package with one file in
	// usr/bin/ also carries bare "usr" and "usr/bin". Those are
	// structure, not destinations, and the pack-time checks never see
	// them — walkLeaves collects leaves only.
	//
	// A directory entry is therefore checked only when nothing else in
	// the payload sits beneath it: that is the archive shape of an
	// explicit empty directory, which is a real destination claim (a
	// package shipping an empty opt/foo/ is claiming opt/foo/), while a
	// directory with descendants is an ancestor of some leaf that is
	// itself being checked.
	hasDescendant := make(map[string]bool, len(entries))
	for _, e := range entries {
		p := strings.Trim(e.Path, "/")
		for {
			i := strings.LastIndex(p, "/")
			if i < 0 {
				break
			}
			p = p[:i]
			hasDescendant[p] = true
		}
	}

	leaves := make([]entry, 0, len(entries))
	for _, e := range entries {
		path := strings.Trim(e.Path, "/")
		if e.IsDir && hasDescendant[path] {
			continue
		}
		l := entry{path: path, kind: kindFile, linkTarget: e.LinkTarget}
		switch {
		case e.IsDir:
			l.kind = kindDir
		case e.IsSymlink:
			l.kind = kindSymlink
		}
		leaves = append(leaves, l)
	}
	return validateEntries(architecture, leaves)
}
