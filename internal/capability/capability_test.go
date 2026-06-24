package capability

import "testing"

func TestValidateName(t *testing.T) {
	accept := []string{
		// sonames, including uppercase and trailing-plus identifiers
		"libc.so.6", "libm.so.6", "ld-linux-x86-64.so.2",
		"libBrokenLocale.so.1", "libGL.so.1", "libICE.so.6",
		"libstdc++.so.6", "g++", "c++", "libstdc++",
		// underscores are common in real sonames
		"libgcc_s.so.1", "libnss_files.so.2", "libc_malloc_debug.so.0", "under_score",
		// real package / virtual names
		"openssl", "lib32-foo", "python3.example",
		// namespaced derived capabilities
		"pkgconfig(glib-2.0)", "pkgconfig(gtk+-3.0)", "pkgconfig(Qt5Core)",
		"perl(Foo::Bar)", "python3dist(ruamel.yaml)", "pkgconfig(gstreamer-1.0)",
	}
	reject := []string{
		"", "a", // too short
		"bad name",       // space
		"-leading",       // leading separator
		"trailing-",      // trailing separator (not + )
		"trailing.",      // trailing dot
		"_leading",       // leading underscore (not alnum)
		"UPPER(x)",       // namespace must be lowercase
		"(glib)",         // empty namespace
		"pkgconfig()",    // empty argument
		"pkgconfig(",     // unterminated
		"ns(a)b",         // content after close paren
		"pkgconfig(a b)", // space in argument
	}
	for _, s := range accept {
		if err := ValidateName(s); err != nil {
			t.Errorf("ValidateName(%q) = %v, want accept", s, err)
		}
	}
	for _, s := range reject {
		if err := ValidateName(s); err == nil {
			t.Errorf("ValidateName(%q) = nil, want reject", s)
		}
	}
}
