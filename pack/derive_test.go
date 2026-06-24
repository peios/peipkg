package pack

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/peios/peipkg/internal/version"
)

// buildFixtures compiles a shared library with a soname and a consumer that
// links it (and libc), returning the temp dir holding libfoo.so and app. It
// skips when no C toolchain is available, since the round-trip needs real
// ELF objects.
func buildFixtures(t *testing.T) string {
	t.Helper()
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("no cc in PATH; skipping ELF derivation round-trip")
	}
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	run := func(args ...string) {
		if out, err := exec.Command(cc, args...).CombinedOutput(); err != nil {
			t.Fatalf("cc %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}

	foo := write("foo.c", "int foo(void){return 42;}\n")
	run("-shared", "-fPIC", "-Wl,-soname,libfoo.so.1", "-o", filepath.Join(dir, "libfoo.so"), foo)

	main := write("main.c", "extern int foo(void); int main(void){return foo();}\n")
	run("-o", filepath.Join(dir, "app"), main, "-L"+dir, "-lfoo")

	return dir
}

func depNames(deps []Dependency) map[string]string {
	m := make(map[string]string, len(deps))
	for _, d := range deps {
		m[d.Name] = d.Constraint
	}
	return m
}

func TestDeriveELFDeps(t *testing.T) {
	dir := buildFixtures(t)

	// A non-ELF payload file must be ignored, not error.
	readme := filepath.Join(dir, "README")
	if err := os.WriteFile(readme, []byte("hi\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got := DeriveELFDeps(map[string]string{
		"usr/lib/libfoo.so.1":  filepath.Join(dir, "libfoo.so"),
		"usr/bin/app":          filepath.Join(dir, "app"),
		"usr/share/doc/README": readme,
	}, "1.0-1", nil)

	if len(got.Warnings) != 0 {
		t.Errorf("unexpected warnings: %v", got.Warnings)
	}
	// With no policy, the soname provide is unversioned.
	if len(got.Provides) != 1 || got.Provides[0].Name != "libfoo.so.1" || got.Provides[0].Version != "" {
		t.Fatalf("provides = %+v, want [{libfoo.so.1 <no version>}]", got.Provides)
	}
	deps := depNames(got.Dependencies)
	if _, ok := deps["libfoo.so.1"]; ok {
		t.Errorf("libfoo.so.1 should be self-subtracted, got %v", deps)
	}
	hasLibc := false
	for name := range deps {
		if strings.HasPrefix(name, "libc.so") {
			hasLibc = true
		}
	}
	if !hasLibc {
		t.Errorf("expected a libc.so* dependency, got %v", deps)
	}
}

// TestDeriveELFDepsSkipsSymlinks guards the -devel-package soname leak: a dev
// `.so` symlink aliases the runtime package's real `.so.N`. elf.Open would
// follow it and read the target's DT_SONAME, so a -devel package shipping only
// the symlink would wrongly provide the runtime soname (and contend with the
// runtime package for it). Such a symlink must be skipped — no provide.
func TestDeriveELFDepsSkipsSymlinks(t *testing.T) {
	dir := buildFixtures(t) // builds a real libfoo.so with DT_SONAME libfoo.so.1
	link := filepath.Join(dir, "libfoo.so.devlink")
	if err := os.Symlink(filepath.Join(dir, "libfoo.so"), link); err != nil {
		t.Fatal(err)
	}
	got := DeriveELFDeps(map[string]string{
		"usr/lib/x86_64-linux-peios/libfoo.so": link,
	}, "1.0-1", nil)
	if len(got.Provides) != 0 {
		t.Errorf("a -devel dev symlink must not yield a soname provide, got %+v", got.Provides)
	}
	if len(got.Dependencies) != 0 {
		t.Errorf("a skipped symlink must not contribute dependencies, got %+v", got.Dependencies)
	}
}

func TestDeriveELFDepsSymbolVersions(t *testing.T) {
	dir := buildFixtures(t)
	policy := SymbolVersionPolicy{"libc.so.6": "GLIBC_", "libfoo.so.1": "FOO_"}

	got := DeriveELFDeps(map[string]string{
		"usr/lib/libfoo.so.1": filepath.Join(dir, "libfoo.so"),
		"usr/bin/app":         filepath.Join(dir, "app"),
	}, "2.0-1", policy)

	// Provider side: libfoo.so.1 is in policy, so its provide is stamped
	// with our own version.
	if len(got.Provides) != 1 || got.Provides[0].Name != "libfoo.so.1" {
		t.Fatalf("provides = %+v", got.Provides)
	}
	if got.Provides[0].Version != "2.0-1" {
		t.Errorf("policy soname provide version = %q, want 2.0-1", got.Provides[0].Version)
	}

	// Consumer side: libc.so.6 is in policy, so the dependency carries a
	// `>= N` floor derived from the host glibc's symbol versions.
	c, ok := depNames(got.Dependencies)["libc.so.6"]
	if !ok {
		t.Fatalf("no libc.so.6 dependency in %v", got.Dependencies)
	}
	if !strings.HasPrefix(c, ">= ") {
		t.Fatalf("libc.so.6 constraint = %q, want a `>= N` floor", c)
	}
	if _, err := version.ParseConstraint(c); err != nil {
		t.Errorf("derived constraint %q does not parse: %v", c, err)
	}
}

func TestDeriveELFDepsWarnsOnMissingSoname(t *testing.T) {
	dir := buildFixtures(t)
	cc, _ := exec.LookPath("cc")

	bar := filepath.Join(dir, "bar.c")
	if err := os.WriteFile(bar, []byte("int bar(void){return 1;}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	libbar := filepath.Join(dir, "libbar-raw.so")
	if out, err := exec.Command(cc, "-shared", "-fPIC", "-o", libbar, bar).CombinedOutput(); err != nil {
		t.Fatalf("cc: %v\n%s", err, out)
	}

	got := DeriveELFDeps(map[string]string{"usr/lib/libbar.so.1": libbar}, "1.0-1", nil)
	if len(got.Provides) != 0 {
		t.Errorf("a sonameless object provides nothing, got %+v", got.Provides)
	}
	if len(got.Warnings) != 1 ||
		!strings.Contains(got.Warnings[0], "libbar.so.1") ||
		!strings.Contains(got.Warnings[0], "DT_SONAME") {
		t.Fatalf("warnings = %v, want one mentioning libbar.so.1 and DT_SONAME", got.Warnings)
	}
}

func TestPickMaxSymbolVersion(t *testing.T) {
	cases := []struct {
		name   string
		prefix string
		tokens []string
		want   string
		ok     bool
	}{
		{"numeric not lexical", "GLIBC_", []string{"GLIBC_2.2.5", "GLIBC_2.34", "GLIBC_2.14"}, "2.34", true},
		{"two vs ten", "GLIBC_", []string{"GLIBC_2.9", "GLIBC_2.10"}, "2.10", true},
		{"skips PRIVATE", "GLIBC_", []string{"GLIBC_2.17", "GLIBC_PRIVATE"}, "2.17", true},
		{"ignores other prefix", "GLIBC_", []string{"GCC_4.2.0", "GLIBC_2.3"}, "2.3", true},
		{"no match", "GLIBC_", []string{"GCC_3.0"}, "", false},
		{"empty", "GLIBC_", nil, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := pickMaxSymbolVersion(tc.prefix, tc.tokens)
			if got != tc.want || ok != tc.ok {
				t.Fatalf("pickMaxSymbolVersion(%q, %v) = (%q, %v), want (%q, %v)",
					tc.prefix, tc.tokens, got, ok, tc.want, tc.ok)
			}
		})
	}
}
