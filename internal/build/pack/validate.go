package pack

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/peios/peipkg/internal/archive"
	"github.com/peios/peipkg/internal/pipsig"
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
	errs = append(errs, validateSidecars(sorted)...)

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
		// A directory used to return here, before the var/ and usr/lib/
		// checks below — so a noarch package could ship the empty
		// directory usr/lib/x86_64-linux-peios/foo/, and an x86_64 one
		// usr/lib/aarch64-linux-peios/. Empty directories only, so the
		// severity is low, but it was an unconditional bypass of the rule.
		if strings.HasPrefix(l.path, "usr/lib/") {
			return validateLibPath(architecture, l.path)
		}
		return nil
	}

	// §5.15's positive half: a package whose architecture is not noarch
	// installs *all* shared libraries, static libraries and loadable modules
	// under /usr/lib/<triplet>/, and a noarch package containing any of them
	// is invalid.
	//
	// validateLibPath only ever ran for paths already under usr/lib/, so
	// nothing looked at file *kind* anywhere else in the tree:
	// usr/share/mypkg/libfoo.so, usr/libexec/plugins/bar.so and
	// usr/bin/libbaz.a all passed. Those are exactly the files that collide
	// across architectures, which is what the triplet convention exists to
	// prevent — so the forward-compatibility guarantee of §5.16 was defeated
	// precisely where it matters.
	//
	// A symlink is exempt. §5.17 blesses a link whose target resolves into
	// the triplet directory — that is the conventional library split, and
	// glibc-bin's usr/bin/ld.so -> ../lib/<triplet>/ld-linux-x86-64.so.2 is
	// exactly it. The rule is about where the *file* lives.
	if l.kind != kindSymlink {
		if err := validateArchDependentKind(architecture, l.path); err != nil {
			return err
		}
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
		// (e.g. the edition package peios-experimental, which owns OS identity).
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

// validateSidecars enforces the signature-sidecar rules (pipsig): a
// `<path>.peios.sig` entry must be a regular file whose target is a
// regular-file entry of the same payload, its content must be a
// well-formed signature blob, and its target must not be ELF.
//
// The two content checks need the bytes, which only the producer-side
// callers (ValidatePayload, ValidateFiles) have — their entries carry a
// source path. Install-time entries carry none, so those checks are
// skipped here and performed by the consumer as it materialises the
// payload, which reads the bytes anyway.
func validateSidecars(sorted []entry) []string {
	byPath := make(map[string]entry, len(sorted))
	for _, l := range sorted {
		byPath[l.path] = l
	}
	var errs []string
	for _, l := range sorted {
		if !pipsig.IsSidecar(l.path) {
			continue
		}
		if l.kind != kindFile {
			errs = append(errs, fmt.Sprintf("%s: a signature sidecar must be a regular file", l.path))
			continue
		}
		target, ok := byPath[pipsig.Target(l.path)]
		switch {
		case !ok:
			errs = append(errs, fmt.Sprintf("%s: signature sidecar has no target %s in the payload", l.path, pipsig.Target(l.path)))
			continue
		case target.kind != kindFile:
			errs = append(errs, fmt.Sprintf("%s: signature sidecar target %s is not a regular file", l.path, target.path))
			continue
		}
		if l.source == "" {
			continue
		}
		blob, err := os.ReadFile(l.source)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", l.path, err))
		} else if err := pipsig.ValidateBlob(blob); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", l.path, err))
		}
		if target.source == "" {
			continue
		}
		head, err := pipsig.ReadHead(target.source, 4)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", target.path, err))
		} else if pipsig.IsELF(head) {
			errs = append(errs, fmt.Sprintf("%s: signature sidecar target %s is an ELF file, which carries its signature in a .peios.sig section, not a sidecar", l.path, target.path))
		}
	}
	return errs
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

// archDependentExemptions are the subtrees where an arch-dependent file
// legitimately sits outside /usr/lib/<triplet>/, mirroring the exemptions
// validateLibPath already documents.
var archDependentExemptions = []string{
	"usr/lib/debug/",
	"usr/lib/modules/",
	"usr/lib/firmware/",
}

// validateArchDependentKind rejects a shared library, static library or
// loadable module outside /usr/lib/<triplet>/ — and rejects one anywhere at
// all for a noarch package.
//
// Suffix matching rather than an ELF sniff. An ELF sniff would be stronger,
// and peipkg/pack/derive.go already reads ELF headers for capability
// derivation, so the machinery exists — but suffix matching catches the
// realistic cases and cannot mistake a data file whose contents happen to
// begin with the magic. A producer determined to evade the rule can, and the
// rule is a layout convention rather than a security boundary.
func validateArchDependentKind(architecture, path string) error {
	if !isArchDependentLeaf(path) {
		return nil
	}
	if architecture == "noarch" {
		return fmt.Errorf(
			"%s is a shared or static library, which a noarch package may not ship (§3.4.2)",
			path)
	}
	for _, exempt := range archDependentExemptions {
		if strings.HasPrefix(path, exempt) {
			return nil
		}
	}
	if strings.HasPrefix(path, "usr/lib/") {
		// validateLibPath owns the triplet rule for this subtree and gives a
		// better message than this function could.
		return nil
	}
	return fmt.Errorf(
		"%s is a shared or static library outside /usr/lib/<triplet>/ (§3.4.2)", path)
}

// isArchDependentLeaf reports whether a payload path names a shared library,
// a static library or a loadable module by suffix: `.so`, `.so.<version>` or
// `.a`.
func isArchDependentLeaf(path string) bool {
	name := path
	if index := strings.LastIndexByte(path, '/'); index >= 0 {
		name = path[index+1:]
	}
	if strings.HasSuffix(name, ".so") || strings.HasSuffix(name, ".a") {
		return true
	}
	// libfoo.so.1, libfoo.so.1.2.3 — the test is on the `.so.` infix rather
	// than the suffix, but only where what follows really is a version.
	//
	// Without that qualifier the rule fires on files merely *named after* a
	// library: usr/share/gdb/auto-load/.../libisl.so.23.4.0-gdb.py is a
	// Python script, and two of those ship today.
	index := strings.Index(name, ".so.")
	if index < 0 {
		return false
	}
	return isVersionSuffix(name[index+len(".so."):])
}

// isVersionSuffix reports whether s is a non-empty run of digits separated by
// dots — the tail of a versioned shared library's name.
func isVersionSuffix(s string) bool {
	if s == "" {
		return false
	}
	for _, component := range strings.Split(s, ".") {
		if component == "" {
			return false
		}
		for i := 0; i < len(component); i++ {
			if component[i] < '0' || component[i] > '9' {
				return false
			}
		}
	}
	return true
}
