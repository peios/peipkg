package pack

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/peios/peipkg/internal/capability"
	"github.com/peios/peipkg/internal/version"
)

// DerivePkgConfigDeps derives pkgconfig(...) provides and dependencies from
// the .pc files in a staged payload — the pkg-config counterpart to
// [DeriveELFDeps], and likewise an opt-in, pure-over-files seam. Each
// foo.pc yields a provides pkgconfig(foo), versioned by its Version: field;
// each module named in its Requires:/Requires.private: yields a dependency
// pkgconfig(<module>) carrying any version constraint. A module the package
// itself provides is self-subtracted. Names that would not survive manifest
// validation, and unparseable versions/constraints, are skipped or dropped
// with a warning rather than producing an uninstallable package.
//
// files maps payload destination -> on-disk source path.
func DerivePkgConfigDeps(files map[string]string) DerivedDeps {
	provided := map[string]string{} // module -> its .pc Version (may be "")
	reqOrder := []string{}          // modules required, first-seen order
	reqConstraints := map[string][]string{}
	var warnings []string

	for _, dest := range sortedKeys(files) {
		if filepath.Ext(dest) != ".pc" {
			continue
		}
		module := strings.TrimSuffix(filepath.Base(dest), ".pc")
		fields, vars, err := parsePC(files[dest])
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("pkgconfig %s: %v", dest, err))
			continue
		}
		provided[module] = expandVars(fields["version"], vars)
		for _, key := range []string{"requires", "requires.private"} {
			for _, r := range parseRequires(expandVars(fields[key], vars)) {
				if _, seen := reqConstraints[r.name]; !seen {
					reqOrder = append(reqOrder, r.name)
				}
				if r.constraint != "" && !contains(reqConstraints[r.name], r.constraint) {
					reqConstraints[r.name] = append(reqConstraints[r.name], r.constraint)
				} else if _, ok := reqConstraints[r.name]; !ok {
					reqConstraints[r.name] = nil
				}
			}
		}
	}

	out := DerivedDeps{Warnings: warnings}
	for module, ver := range provided {
		name := "pkgconfig(" + module + ")"
		if err := capability.ValidateName(name); err != nil {
			out.Warnings = append(out.Warnings, fmt.Sprintf("skipping pkgconfig provide %q: %v", name, err))
			continue
		}
		p := Provides{Name: name}
		if ver != "" {
			if _, err := version.ParseRelaxed(ver); err == nil {
				p.Version = ver
			} else {
				out.Warnings = append(out.Warnings, fmt.Sprintf(
					"pkgconfig(%s): unparseable Version %q, leaving unversioned", module, ver))
			}
		}
		out.Provides = append(out.Provides, p)
	}

	for _, module := range reqOrder {
		if _, self := provided[module]; self {
			continue // satisfied within this package
		}
		name := "pkgconfig(" + module + ")"
		if err := capability.ValidateName(name); err != nil {
			out.Warnings = append(out.Warnings, fmt.Sprintf("skipping pkgconfig dependency %q: %v", name, err))
			continue
		}
		// Combine multiple constraints on the same module with comma-AND,
		// validating the result; drop it (unversioned) if it won't parse.
		constraint := strings.Join(reqConstraints[module], ", ")
		if constraint != "" {
			if _, err := version.ParseConstraint(constraint); err != nil {
				out.Warnings = append(out.Warnings, fmt.Sprintf(
					"pkgconfig(%s): unparseable constraint %q, dropping it", module, constraint))
				constraint = ""
			}
		}
		out.Dependencies = append(out.Dependencies, Dependency{Name: name, Constraint: constraint})
	}

	sort.Slice(out.Provides, func(i, j int) bool { return out.Provides[i].Name < out.Provides[j].Name })
	sort.Slice(out.Dependencies, func(i, j int) bool { return out.Dependencies[i].Name < out.Dependencies[j].Name })
	return out
}

// pcRequire is one parsed Requires entry.
type pcRequire struct {
	name       string
	constraint string // "" or e.g. ">= 2.80"
}

// parsePC reads a .pc file into its lowercased fields (Name, Version,
// Requires, …) and its variable assignments (prefix=…). It is a line
// parser: a line "key=value" is a variable; "Field: value" is a field;
// blank and #-comment lines are ignored.
func parsePC(path string) (fields, vars map[string]string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	fields, vars = map[string]string{}, map[string]string{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if colon := strings.IndexByte(line, ':'); colon >= 0 && isFieldKey(line[:colon]) {
			fields[strings.ToLower(line[:colon])] = strings.TrimSpace(line[colon+1:])
			continue
		}
		if eq := strings.IndexByte(line, '='); eq >= 0 {
			vars[strings.TrimSpace(line[:eq])] = strings.TrimSpace(line[eq+1:])
		}
	}
	return fields, vars, sc.Err()
}

// isFieldKey reports whether s looks like a .pc field keyword (letters and
// dots, e.g. "Requires.private") rather than a variable assignment.
func isFieldKey(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c == '.') {
			return false
		}
	}
	return true
}

// expandVars resolves ${name} references using vars, iterating so nested
// definitions resolve. Unknown references are left as-is.
func expandVars(s string, vars map[string]string) string {
	for i := 0; i < 16 && strings.Contains(s, "${"); i++ {
		changed := false
		for name, val := range vars {
			ref := "${" + name + "}"
			if strings.Contains(s, ref) {
				s = strings.ReplaceAll(s, ref, val)
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	return s
}

// parseRequires parses a pkg-config Requires value: modules separated by
// commas and/or whitespace, each optionally followed by an operator and a
// version (e.g. "glib-2.0 >= 2.80, gobject-2.0").
func parseRequires(value string) []pcRequire {
	fields := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t'
	})
	var out []pcRequire
	for i := 0; i < len(fields); {
		name := fields[i]
		i++
		constraint := ""
		if i < len(fields) && isPkgConfigOp(fields[i]) {
			op := fields[i]
			i++
			if i < len(fields) {
				constraint = op + " " + fields[i]
				i++
			}
		}
		out = append(out, pcRequire{name: name, constraint: constraint})
	}
	return out
}

func isPkgConfigOp(s string) bool {
	switch s {
	case "=", "<", ">", "<=", ">=", "!=":
		return true
	}
	return false
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
