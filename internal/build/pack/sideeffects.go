package pack

import (
	"fmt"
	"sort"
	"strings"
)

// The two recognised side effects PSPU §5.24 gives a mechanical trigger:
// a file pattern in the payload decides whether the declaration belongs.
const (
	sideEffectDepmod = "depmod"
	sideEffectManDB  = "man-db"
)

// ValidateSideEffectsPayload checks a manifest's side_effects declaration
// against the staged tree at stagedRoot. See validateSideEffectEntries.
func ValidateSideEffectsPayload(sideEffects []string, stagedRoot string) ([]string, error) {
	leaves, err := walkLeaves(stagedRoot)
	if err != nil {
		return nil, fmt.Errorf("walk staged tree: %w", err)
	}
	return validateSideEffectEntries(sideEffects, leaves)
}

// ValidateSideEffectsFiles is the archive-path -> source-path counterpart
// of ValidateSideEffectsPayload.
func ValidateSideEffectsFiles(sideEffects []string, files map[string]string) ([]string, error) {
	leaves, err := mapLeaves(files)
	if err != nil {
		return nil, fmt.Errorf("resolve file map: %w", err)
	}
	return validateSideEffectEntries(sideEffects, leaves)
}

// validateSideEffectEntries enforces PSPU §5.24 in both directions for the
// side effects whose trigger is a payload file pattern.
//
// Both directions matter and they fail differently. A package that ships
// kernel modules without declaring depmod leaves modules.dep stale, so
// modprobe resolves a dependency chain and then cannot find a file — a
// silent failure at load time, far from the package that caused it. A
// package that declares depmod while shipping no modules spends an
// invocation on nothing, which is only waste, but it also means the
// declaration no longer says anything true about the payload.
//
// depmod is normative (MUST / MUST NOT) and returns an error. man-db is a
// recommendation (SHOULD) — a stale man index degrades to a filesystem
// scan rather than breaking anything — so it returns a warning and the
// caller decides. Returning a warning rather than nothing still puts it
// in front of the author at build time, which is the point.
//
// A side effect whose trigger is NOT a payload pattern simply is not
// checked here. The rule is "where the trigger is mechanical, pack
// enforces it", which leaves room for an effect that depends on what a
// package means rather than on what it contains.
func validateSideEffectEntries(sideEffects []string, leaves []entry) ([]string, error) {
	declared := make(map[string]bool, len(sideEffects))
	for _, s := range sideEffects {
		declared[s] = true
	}

	var modules, manPages []string
	for _, l := range leaves {
		if l.kind == kindDir {
			continue
		}
		if isKernelModulePath(l.path) {
			modules = append(modules, l.path)
		}
		if isManPagePath(l.path) {
			manPages = append(manPages, l.path)
		}
	}
	sort.Strings(modules)
	sort.Strings(manPages)

	var errs []string
	if len(modules) > 0 && !declared[sideEffectDepmod] {
		errs = append(errs, fmt.Sprintf(
			"payload contains %d kernel module(s) under usr/lib/modules/ but side_effects does not "+
				"declare %q (§5.24); without it modules.dep is stale and modprobe cannot resolve a "+
				"dependency chain. First: %s",
			len(modules), sideEffectDepmod, modules[0]))
	}
	if len(modules) == 0 && declared[sideEffectDepmod] {
		errs = append(errs, fmt.Sprintf(
			"side_effects declares %q but the payload contains no kernel module under "+
				"usr/lib/modules/ (§5.24)", sideEffectDepmod))
	}

	var warnings []string
	if len(manPages) > 0 && !declared[sideEffectManDB] {
		warnings = append(warnings, fmt.Sprintf(
			"payload contains %d file(s) under usr/share/man/ but side_effects does not declare %q "+
				"(§5.24, SHOULD); man page lookup falls back to a filesystem scan without it. "+
				"First: %s",
			len(manPages), sideEffectManDB, manPages[0]))
	}
	if len(manPages) == 0 && declared[sideEffectManDB] {
		warnings = append(warnings, fmt.Sprintf(
			"side_effects declares %q but the payload contains no file under usr/share/man/ (§5.24)",
			sideEffectManDB))
	}

	if len(errs) > 0 {
		return warnings, fmt.Errorf("side-effect validation failed:\n  %s", strings.Join(errs, "\n  "))
	}
	return warnings, nil
}

// isKernelModulePath reports whether an archive path is a kernel module
// under usr/lib/modules/: `.ko` or `.ko.<compression>` (§5.24).
func isKernelModulePath(p string) bool {
	if !strings.HasPrefix(p, "usr/lib/modules/") {
		return false
	}
	base := p[strings.LastIndexByte(p, '/')+1:]
	if strings.HasSuffix(base, ".ko") {
		return true
	}
	// `.ko.*`: a compressed module, `.ko.zst` and friends. Anchored on
	// ".ko." rather than a suffix list so a new compressor needs no change
	// here, and required to be a real extension rather than anywhere in
	// the name so "not-a.ko.backup" is the author's problem, not a false
	// negative -- it would be a module by the spec's wording too.
	return strings.Contains(base, ".ko.")
}

// isManPagePath reports whether an archive path is a man page (§5.24).
func isManPagePath(p string) bool {
	return strings.HasPrefix(p, "usr/share/man/")
}
