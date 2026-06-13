package pack

import (
	"fmt"
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
// dispatch (validateLibPath narrows it to "<arch>-linux-peios/" or rejects).
var permittedTopLevels = []string{
	"usr/bin/",
	"usr/lib/",
	"usr/share/",
	"usr/include/",
	"etc/",
	"var/",
	"opt/",
	"boot/",
	"system/",
}

var permittedDirectoryOnlyRoots = map[string]bool{
	"dev":  true,
	"proc": true,
	"run":  true,
	"sys":  true,
	"tmp":  true,
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
	if l.kind == kindDir {
		if hasPermittedTopLevel(l.path) || permittedDirectoryOnlyRoots[l.path] {
			return nil
		}
		return fmt.Errorf("directory %s is not under any §3.4.1 permitted top-level destination or permitted runtime mountpoint root", l.path)
	}

	if !hasPermittedTopLevel(l.path) {
		return fmt.Errorf("%s is not under any §3.4.1 permitted top-level destination", l.path)
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
func validateLibPath(architecture, leafPath string) error {
	rest := strings.TrimPrefix(leafPath, "usr/lib/")
	triplet, _, ok := strings.Cut(rest, "/")
	if !ok {
		return fmt.Errorf("%s sits directly under /usr/lib/ (§3.4.2 requires /usr/lib/<triplet>/<...>)", leafPath)
	}

	if architecture == "noarch" {
		return fmt.Errorf("noarch package contains arch-specific path %s (§3.4.2 forbids /usr/lib/<triplet>/ entries in noarch packages)", leafPath)
	}

	expected := architecture + "-linux-peios"
	if triplet != expected {
		return fmt.Errorf("%s uses triplet %q, expected %q for architecture %q (§3.4.2)", leafPath, triplet, expected, architecture)
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
	if strings.ContainsAny(l.linkTarget, "\x00") || strings.Contains(l.linkTarget, "\\") {
		return fmt.Errorf("symlink %s -> %q: target contains forbidden bytes (§3.4 path-validity)", l.path, l.linkTarget)
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
