package pack

import (
	"debug/elf"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/peios/peipkg/internal/capability"
	"github.com/peios/peipkg/internal/version"
)

// ValidateCapabilityName reports whether name is a well-formed virtual
// (capability) name — the grammar shared by provides and dependencies
// entries (PSD-009 §4.1). Exposed so build tools can validate
// recipe-declared and derived names against the same rule the manifest
// decoder enforces.
func ValidateCapabilityName(name string) error { return capability.ValidateName(name) }

// SymbolVersionPolicy maps a shared-library soname to the symbol-version
// token prefix whose tokens are commensurable with the providing package's
// version — e.g. {"libc.so.6": "GLIBC_"}. It is the distro-wide assertion
// that a library both versions its symbols and numbers those versions on
// the same scale as its package version, so a consumer referencing
// GLIBC_2.34 may be turned into a `>= 2.34` dependency. A soname absent from
// the policy is derived at soname granularity only (exact-name match, no
// version), which is always safe.
type SymbolVersionPolicy map[string]string

// DerivedDeps is the result of [DeriveELFDeps]: the provides and
// dependencies read out of a staged ELF payload, plus any non-fatal
// warnings the caller should surface. Provides and Dependencies are sorted
// by name. The caller merges these into its hand-declared manifest fields.
type DerivedDeps struct {
	Provides     []Provides
	Dependencies []Dependency
	Warnings     []string
}

// sharedLibName matches a shared-library payload destination by the
// conventional lib*.so / lib*.so.N[.N...] form. Such a file is expected to
// carry a DT_SONAME; one that does not is a packaging bug, since nothing
// can derive a dependency on it.
var sharedLibName = regexp.MustCompile(`(^|/)lib[^/]+\.so(\.\d+)*$`)

// DeriveELFDeps derives shared-library provides and dependencies from a
// staged payload — the automatic-dependency-derivation seam, a sibling to
// [ValidateFiles]. It is opt-in: like validation, it is deliberately not
// part of [Pack], so a producer of an exotic package can decline it.
//
// For every ELF object in files it reads DT_SONAME — the object's own ABI
// name — into provides, and DT_NEEDED — the libraries it loads — into
// dependencies. A soname the package provides itself is subtracted from its
// needs, so a package shipping both a library and a consumer of it does not
// depend on itself. The whole soname (libfoo.so.3) is the capability name:
// ABI-version identity lives in the string and is matched by equality, so
// libfoo.so.3 is never satisfied by libfoo.so.4.
//
// For a soname listed in policy, derivation is refined with symbol
// versioning: on the consumer side the highest matching symbol token (e.g.
// GLIBC_2.34) becomes a `>= 2.34` constraint on that dependency; on the
// provider side the soname's provide is stamped with selfVersion (the
// building package's own version), giving consumers something to match.
//
// files maps payload destination -> on-disk source path. selfVersion is the
// version of the package being built. DeriveELFDeps does not read
// configuration or mutate anything; warnings are returned, not logged.
func DeriveELFDeps(files map[string]string, selfVersion string, policy SymbolVersionPolicy) DerivedDeps {
	provided := map[string]bool{}
	needed := map[string]bool{}
	symFloor := map[string]string{} // soname -> highest required symbol version
	var warnings []string

	for _, dest := range sortedKeys(files) {
		// Skip symlinks: a symlink (e.g. a -devel package's `libfoo.so` ->
		// `libfoo.so.3` dev symlink) merely aliases a real object that is
		// itself a payload entry — usually the versioned `.so.N` in the
		// runtime package. elf.Open would follow the link and read the
		// target's DT_SONAME, mis-attributing the soname provide to whatever
		// package ships the alias. The real object is derived at its own dest.
		if fi, err := os.Lstat(files[dest]); err == nil && fi.Mode()&os.ModeSymlink != 0 {
			continue
		}
		ef, err := elf.Open(files[dest])
		if err != nil {
			continue // not an ELF object (script, data, symlink, ...)
		}
		if soname := dynSoname(ef); soname != "" {
			provided[soname] = true
		} else if sharedLibName.MatchString(dest) {
			warnings = append(warnings, fmt.Sprintf(
				"shared library %s has no DT_SONAME; nothing can depend on it", dest))
		}
		if libs, err := ef.ImportedLibraries(); err == nil {
			for _, lib := range libs {
				needed[lib] = true
			}
		}
		if needs, err := ef.DynamicVersionNeeds(); err == nil {
			for _, n := range needs {
				prefix, ok := policy[n.Name]
				if !ok {
					continue
				}
				tokens := make([]string, 0, len(n.Needs))
				for _, d := range n.Needs {
					tokens = append(tokens, d.Dep)
				}
				if v, ok := pickMaxSymbolVersion(prefix, tokens); ok {
					if cur, seen := symFloor[n.Name]; !seen || versionLess(cur, v) {
						symFloor[n.Name] = v
					}
				}
			}
		}
		ef.Close()
	}

	out := DerivedDeps{Warnings: warnings}
	for name := range provided {
		if err := capability.ValidateName(name); err != nil {
			out.Warnings = append(out.Warnings, fmt.Sprintf("skipping unrepresentable soname provide: %v", err))
			continue
		}
		p := Provides{Name: name}
		if _, ok := policy[name]; ok {
			p.Version = selfVersion // commensurable-scale assertion
		}
		out.Provides = append(out.Provides, p)
	}
	for name := range needed {
		if provided[name] {
			continue // satisfied within this package
		}
		if err := capability.ValidateName(name); err != nil {
			out.Warnings = append(out.Warnings, fmt.Sprintf("skipping unrepresentable soname dependency: %v", err))
			continue
		}
		d := Dependency{Name: name}
		if floor, ok := symFloor[name]; ok {
			d.Constraint = ">= " + floor
		}
		out.Dependencies = append(out.Dependencies, d)
	}
	sort.Slice(out.Provides, func(i, j int) bool { return out.Provides[i].Name < out.Provides[j].Name })
	sort.Slice(out.Dependencies, func(i, j int) bool { return out.Dependencies[i].Name < out.Dependencies[j].Name })
	return out
}

// dynSoname returns the file's DT_SONAME, or "" if it declares none.
func dynSoname(ef *elf.File) string {
	if vals, err := ef.DynString(elf.DT_SONAME); err == nil && len(vals) > 0 {
		return vals[0]
	}
	return ""
}

// pickMaxSymbolVersion returns the highest version among tokens that carry
// the given prefix, with the prefix stripped (e.g. prefix "GLIBC_" over
// {"GLIBC_2.2.5","GLIBC_2.34"} -> "2.34"). Tokens without the prefix, and
// those whose tail is not a version (e.g. GLIBC_PRIVATE), are ignored. The
// bool reports whether any token matched.
func pickMaxSymbolVersion(prefix string, tokens []string) (string, bool) {
	best := ""
	for _, tok := range tokens {
		if !strings.HasPrefix(tok, prefix) {
			continue
		}
		tail := strings.TrimPrefix(tok, prefix)
		// A real symbol-version token is numeric (GLIBC_2.34); reserved
		// tokens like GLIBC_PRIVATE are not floors and must be skipped —
		// and peipkg's grammar would otherwise parse "PRIVATE" as a valid
		// (alphabetic) upstream version.
		if tail == "" || tail[0] < '0' || tail[0] > '9' {
			continue
		}
		if _, err := version.ParseRelaxed(tail); err != nil {
			continue
		}
		if best == "" || versionLess(best, tail) {
			best = tail
		}
	}
	return best, best != ""
}

// versionLess reports whether revision-optional version string a orders
// before b. Unparseable operands sort low so a valid version always wins.
func versionLess(a, b string) bool {
	av, aerr := version.ParseRelaxed(a)
	bv, berr := version.ParseRelaxed(b)
	switch {
	case aerr != nil:
		return berr == nil
	case berr != nil:
		return false
	default:
		return version.Compare(av, bv) < 0
	}
}

// sortedKeys returns the keys of m in sorted order, for deterministic
// iteration over the payload.
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
