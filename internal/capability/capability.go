// Package capability defines the grammar for virtual (capability) names —
// the names that appear in a manifest's provides and dependencies entries
// (PSD-009 §4.1). It is the single source of truth shared by the manifest
// validator (which gates packages at decode) and the build-time derivers
// (which must emit only names that will later validate).
//
// A capability name is a SUPERSET of the §2.1 package-name grammar. Beyond
// package names it permits:
//
//   - uppercase letters, so a capability can mirror an exact machine
//     identifier such as an ELF soname (libGL.so.1, libICE.so.6) byte for
//     byte — case folding would be unsound on a case-sensitive loader; and
//   - a namespaced form "namespace(argument)" for derived dependency
//     namespaces, e.g. pkgconfig(glib-2.0) or perl(Foo::Bar).
//
// Unlike package names, capability names do NOT forbid consecutive
// separators, because real identifiers contain them (libstdc++.so.6,
// gtk+-3.0).
package capability

import (
	"fmt"
	"strings"
)

// MaxLen bounds a capability name. Larger than a package name (§2.1) to
// accommodate namespaced forms.
const MaxLen = 128

// ValidateName reports whether s is a well-formed capability name.
func ValidateName(s string) error {
	if len(s) < 2 || len(s) > MaxLen {
		return fmt.Errorf("%q must be 2 to %d characters", s, MaxLen)
	}
	if open := strings.IndexByte(s, '('); open >= 0 {
		return validateNamespaced(s, open)
	}
	return validatePlain(s)
}

// validatePlain checks the soname/identifier form: letters (any case),
// digits, the separators - . + , and underscores. It must start with a
// letter or digit and end with a letter, digit, or `+` (real names like
// g++, c++, and libstdc++ end in a plus). No consecutive-separator
// restriction — libstdc++.so.6 is valid.
func validatePlain(s string) error {
	for i := 0; i < len(s); i++ {
		if !isPlainChar(s[i]) {
			return fmt.Errorf("%q contains the invalid character %q", s, rune(s[i]))
		}
	}
	if !isAlnum(s[0]) {
		return fmt.Errorf("%q must start with a letter or digit", s)
	}
	if last := s[len(s)-1]; !isAlnum(last) && last != '+' {
		return fmt.Errorf("%q must end with a letter, digit, or '+'", s)
	}
	return nil
}

// validateNamespaced checks the "namespace(argument)" form: a lowercase
// namespace, then the argument bracketed by parens at the very end.
func validateNamespaced(s string, open int) error {
	ns := s[:open]
	if len(ns) == 0 || !isLower(ns[0]) {
		return fmt.Errorf("%q: namespace must start with a lowercase letter", s)
	}
	for i := 0; i < len(ns); i++ {
		if !isLower(ns[i]) && !isDigit(ns[i]) {
			return fmt.Errorf("%q: namespace must be lowercase letters and digits", s)
		}
	}
	if s[len(s)-1] != ')' {
		return fmt.Errorf("%q: namespaced capability must end with ')'", s)
	}
	arg := s[open+1 : len(s)-1]
	if arg == "" {
		return fmt.Errorf("%q: empty namespace argument", s)
	}
	for i := 0; i < len(arg); i++ {
		if !isArgChar(arg[i]) {
			return fmt.Errorf("%q: argument contains the invalid character %q", s, rune(arg[i]))
		}
	}
	return nil
}

func isLower(c byte) bool     { return c >= 'a' && c <= 'z' }
func isUpper(c byte) bool     { return c >= 'A' && c <= 'Z' }
func isDigit(c byte) bool     { return c >= '0' && c <= '9' }
func isAlnum(c byte) bool     { return isLower(c) || isUpper(c) || isDigit(c) }
func isSeparator(c byte) bool { return c == '-' || c == '.' || c == '+' }

// isPlainChar is the soname/identifier charset: alphanumerics, the
// separators - . + , and the underscore. Underscores are common in real
// sonames (libgcc_s.so.1, libnss_files.so.2) even though §2.1 package names
// exclude them; a capability name mirrors the exact identifier.
func isPlainChar(c byte) bool { return isAlnum(c) || isSeparator(c) || c == '_' }

// isArgChar is the charset inside namespace(...) — identifiers from foreign
// namespaces: the plain charset plus : / (covers perl Foo::Bar, python
// ruamel.yaml, and paths).
func isArgChar(c byte) bool {
	return isPlainChar(c) || c == ':' || c == '/'
}
