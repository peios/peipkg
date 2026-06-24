package pack

import (
	"os"
	"path/filepath"
	"testing"
)

func writePC(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func provMap(ps []Provides) map[string]string {
	m := map[string]string{}
	for _, p := range ps {
		m[p.Name] = p.Version
	}
	return m
}

func depMap(ds []Dependency) map[string]string {
	m := map[string]string{}
	for _, d := range ds {
		m[d.Name] = d.Constraint
	}
	return m
}

func TestDerivePkgConfigDeps(t *testing.T) {
	dir := t.TempDir()
	glib := writePC(t, dir, "glib-2.0.pc", `prefix=/usr
maj=2
min=80
Name: GLib
Version: ${maj}.${min}.0
Requires: gobject-2.0 >= 2.80, libpcre2-8 >= 10.0
Requires.private: libffi
Libs: -lglib-2.0
`)
	gobject := writePC(t, dir, "gobject-2.0.pc", `Name: GObject
Version: 2.80.0
Requires: glib-2.0
`)

	got := DerivePkgConfigDeps(map[string]string{
		"usr/lib/pkgconfig/glib-2.0.pc":    glib,
		"usr/lib/pkgconfig/gobject-2.0.pc": gobject,
	})

	provs := provMap(got.Provides)
	if provs["pkgconfig(glib-2.0)"] != "2.80.0" { // ${maj}.${min}.0 expanded
		t.Errorf("glib provide = %q, want 2.80.0 (var-expanded)", provs["pkgconfig(glib-2.0)"])
	}
	if _, ok := provs["pkgconfig(gobject-2.0)"]; !ok {
		t.Errorf("missing pkgconfig(gobject-2.0) provide; got %v", provs)
	}

	deps := depMap(got.Dependencies)
	// glib-2.0 and gobject-2.0 are self-provided → subtracted.
	for _, self := range []string{"pkgconfig(glib-2.0)", "pkgconfig(gobject-2.0)"} {
		if _, bad := deps[self]; bad {
			t.Errorf("%s should be self-subtracted, got %v", self, deps)
		}
	}
	if deps["pkgconfig(libpcre2-8)"] != ">= 10.0" {
		t.Errorf("libpcre2-8 constraint = %q, want >= 10.0", deps["pkgconfig(libpcre2-8)"])
	}
	if c, ok := deps["pkgconfig(libffi)"]; !ok || c != "" {
		t.Errorf("libffi (Requires.private) = (%q,%v), want unversioned dep", c, ok)
	}
}

func TestDerivePkgConfigRealFiles(t *testing.T) {
	// libthermal.pc: Requires libnl-3.0 libnl-genl-3.0 (space-separated, no constraints).
	matches, _ := filepath.Glob("/home/jack/projects/peios/pkgs/kernel/out/*/build/tools/usr/lib/x86_64-linux-peios/pkgconfig/libthermal.pc")
	if len(matches) == 0 {
		t.Skip("libthermal.pc not staged")
	}
	got := DerivePkgConfigDeps(map[string]string{"usr/lib/pkgconfig/libthermal.pc": matches[0]})
	provs := provMap(got.Provides)
	if provs["pkgconfig(libthermal)"] != "0.0.1" {
		t.Errorf("libthermal provide = %q, want 0.0.1", provs["pkgconfig(libthermal)"])
	}
	deps := depMap(got.Dependencies)
	for _, want := range []string{"pkgconfig(libnl-3.0)", "pkgconfig(libnl-genl-3.0)"} {
		if _, ok := deps[want]; !ok {
			t.Errorf("missing derived dep %s; got %v", want, deps)
		}
	}
}
