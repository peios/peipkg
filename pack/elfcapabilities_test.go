package pack

import (
	"debug/elf"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	buildmanifest "github.com/peios/peipkg/internal/build/manifest"
	"github.com/peios/peipkg/internal/manifest"
	"github.com/peios/peipkg/internal/resolver"
)

const cppSONAME = "libstdc++.so.6"

// Use real GNU version definitions/needs, with C fixtures so testing ABI
// metadata doesn't depend on the host C++ release. Both namespaces are used.
func versionFixtures(t *testing.T) string {
	t.Helper()
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("ELF version integration requires cc")
	}
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	run := func(args ...string) {
		if out, err := exec.Command(cc, args...).CombinedOutput(); err != nil {
			t.Fatalf("cc %v: %v\n%s", args, err, out)
		}
	}
	source := write("lib.c", "int old_api(void){return 1;} int modern_api(void){return 2;} int abi_api(void){return 3;} int future_api(void){return 4;}\n")
	scripts := map[string]string{
		"old":         "GLIBCXX_3.4 {global:old_api; local:*;}; CXXABI_1.3 {};",
		"current":     "GLIBCXX_3.4 {global:old_api; local:*;}; GLIBCXX_3.4.30 {global:modern_api;} GLIBCXX_3.4; CXXABI_1.3.13 {global:abi_api;};",
		"newer":       "GLIBCXX_3.4 {global:old_api; local:*;}; GLIBCXX_3.4.30 {global:modern_api;} GLIBCXX_3.4; GLIBCXX_3.4.99 {global:future_api;} GLIBCXX_3.4.30; CXXABI_1.3.13 {global:abi_api;};",
		"missing-abi": "GLIBCXX_3.4 {global:old_api; local:*;}; GLIBCXX_3.4.30 {global:modern_api;} GLIBCXX_3.4; CXXABI_1.3 {global:abi_api;};",
		"missing-old": "GLIBCXX_3.4.30 {global:modern_api; local:*;}; CXXABI_1.3.13 {global:abi_api;};",
	}
	for name, script := range scripts {
		run("-shared", "-fPIC", "-nostdlib", "-Wl,-soname,"+cppSONAME, "-Wl,--version-script="+write(name+".map", script), "-o", filepath.Join(dir, name+".so"), source)
	}
	run("-shared", "-fPIC", "-nostdlib", "-Wl,-soname,libother.so.6", "-Wl,--version-script="+filepath.Join(dir, "current.map"), "-o", filepath.Join(dir, "other.so"), source)
	main := write("main.c", "extern int old_api(void),modern_api(void),abi_api(void); int main(void){return old_api()+modern_api()+abi_api()==6 ? 0:1;}\n")
	run("-o", filepath.Join(dir, "app"), main, filepath.Join(dir, "current.so"))
	return dir
}

func deriveVersionFixture(dir, file string) DerivedDeps {
	dest := "usr/lib/" + cppSONAME
	if file == "app" {
		dest = "usr/bin/app"
	}
	return DeriveELFDeps(map[string]string{dest: filepath.Join(dir, file)}, "16.1.0-1", nil, cppSONAME)
}

func TestELFVersionCapabilities(t *testing.T) {
	dir := versionFixtures(t)
	consumer := deriveVersionFixture(dir, "app")
	if consumer.Err != nil {
		t.Fatal(consumer.Err)
	}
	deps := depNames(consumer.Dependencies)
	for _, token := range []string{"GLIBCXX_3.4", "GLIBCXX_3.4.30", "CXXABI_1.3.13"} {
		name := "elfver(" + cppSONAME + ":" + token + ")"
		if constraint, ok := deps[name]; !ok || constraint != "" {
			t.Errorf("missing exact requirement %s: %v", name, deps)
		}
	}
	for _, file := range []string{"current.so", "newer.so"} {
		provider := deriveVersionFixture(dir, file)
		if provider.Err != nil {
			t.Fatal(provider.Err)
		}
		provided := map[string]bool{}
		for _, p := range provider.Provides {
			if p.Version != "" {
				t.Errorf("package version leaked into capability %+v", p)
			}
			provided[p.Name] = true
		}
		for name := range deps {
			if strings.HasPrefix(name, "elfver(") && !provided[name] {
				t.Errorf("%s missing %s", file, name)
			}
		}
		if provided["elfver("+cppSONAME+":"+cppSONAME+")"] {
			t.Error("base SONAME node is not an ABI capability")
		}
	}
	// A package's own SONAME is insufficient when its consumer needs newer nodes.
	for _, file := range []string{"old.so", "missing-abi.so", "missing-old.so"} {
		got := DeriveELFDeps(map[string]string{"usr/bin/app": filepath.Join(dir, "app"), "usr/lib/" + cppSONAME: filepath.Join(dir, file)}, "1-1", nil, cppSONAME)
		if got.Err == nil || !strings.Contains(got.Err.Error(), "own payload") {
			t.Errorf("accepted incompatible internal library %s: %+v", file, got)
		}
	}
	got := DeriveELFDeps(map[string]string{"usr/bin/app": filepath.Join(dir, "app"), "usr/lib/" + cppSONAME: filepath.Join(dir, "current.so")}, "1-1", nil, cppSONAME)
	if got.Err != nil {
		t.Fatal(got.Err)
	}
	for _, d := range got.Dependencies {
		if d.Name == cppSONAME || strings.HasPrefix(d.Name, "elfver(") {
			t.Errorf("self-satisfied capability leaked: %+v", d)
		}
	}
	// Reconstructed source fixtures and development symlinks are not providers.
	link := filepath.Join(dir, "link.so")
	if err := os.Symlink(filepath.Join(dir, "current.so"), link); err != nil {
		t.Fatal(err)
	}
	got = DeriveELFDeps(map[string]string{"usr/src/dist/fixture.so": filepath.Join(dir, "current.so"), "usr/lib/libstdc++.so": link}, "1-1", nil, cppSONAME)
	if got.Err != nil || len(got.Provides)+len(got.Dependencies) != 0 {
		t.Fatalf("source or symlink became runtime metadata: %+v", got)
	}
}

func TestELFVersionCapabilityFailures(t *testing.T) {
	dir := versionFixtures(t)
	ef, err := elf.Open(filepath.Join(dir, "app"))
	if err != nil {
		t.Fatal(err)
	}
	section := ef.SectionByType(elf.SHT_GNU_VERNEED)
	data, err := os.ReadFile(filepath.Join(dir, "app"))
	if err != nil {
		t.Fatal(err)
	}
	// Corrupt vn_aux: requirement decoding must fail publication, not downgrade
	// this object to a plain SONAME requirement.
	ef.ByteOrder.PutUint32(data[section.Offset+8:], 0xfffffff0)
	ef.Close()
	if err := os.WriteFile(filepath.Join(dir, "corrupt"), data, 0600); err != nil {
		t.Fatal(err)
	}
	got := deriveVersionFixture(dir, "corrupt")
	if got.Err == nil {
		t.Fatal("malformed version table was silently accepted")
	}
	got = DeriveELFDeps(map[string]string{"usr/lib/a.so": filepath.Join(dir, "old.so"), "usr/lib/b.so": filepath.Join(dir, "current.so")}, "1-1", nil, cppSONAME)
	if got.Err == nil {
		t.Fatal("two different providers of the same SONAME were silently combined")
	}
	for _, pair := range [][2]string{{"libfoo.so.1", "bad:token"}, {"libfoo.so.1", "bad/token"}, {"libfoo.so.1", strings.Repeat("a", 128)}, {"libfoo:bar", "TOKEN_1"}} {
		if _, err := elfVersionCapability(pair[0], pair[1]); err == nil {
			t.Errorf("accepted ambiguous or invalid name %v", pair)
		}
	}
}

func TestELFVersionCapabilitiesResolve(t *testing.T) {
	dir := versionFixtures(t)
	candidate := func(name, v string, d DerivedDeps) resolver.Candidate {
		t.Helper()
		if d.Err != nil {
			t.Fatal(d.Err)
		}
		// Go through the package manifest conversion/validation boundary too.
		built, err := toInternalManifest(Manifest{Name: name, Version: v, Architecture: "x86_64", Description: "ABI fixture", License: "MIT", LicenseClass: "free", Build: BuildInfo{Timestamp: "2026-09-14T00:00:00Z", FarmID: "test", SourceRef: "test://elf-versions"}, Dependencies: d.Dependencies, Provides: d.Provides})
		if err != nil {
			t.Fatal(err)
		}

		built.SchemaVersion = 1
		encoded, err := buildmanifest.Encode(built)
		if err != nil {
			t.Fatal(err)
		}
		m, err := manifest.Decode(encoded)
		if err != nil {
			t.Fatal(err)
		}
		return resolver.Candidate{Name: m.Name, Version: m.Version, Architecture: m.Architecture, Dependencies: m.Dependencies, Provides: m.Provides, Repo: "fixture", RepoPriority: 1}
	}
	app := candidate("app", "1.0-1", deriveVersionFixture(dir, "app"))
	// Nonselected host C-runtime requirements are irrelevant to this fixture.
	var libcProvides []Provides
	for _, d := range app.Dependencies {
		if !strings.HasPrefix(d.Name, "elfver(") && d.Name != cppSONAME {
			libcProvides = append(libcProvides, Provides{Name: d.Name})
		}
	}
	libc := candidate("c-runtime", "1.0-1", DerivedDeps{Provides: libcProvides})
	current := candidate("cpp-runtime", "16.1.0-1", deriveVersionFixture(dir, "current.so"))
	old := candidate("cpp-runtime", "12.1.0-1", deriveVersionFixture(dir, "old.so"))
	opts := resolver.Options{PrimaryArch: "x86_64"}
	request := []resolver.Request{{Kind: resolver.Install, Name: "app"}}
	for _, tc := range []struct {
		name, file string
		ok         bool
	}{{"compatible", "current.so", true}, {"newer compatible", "newer.so", true}, {"too old", "old.so", false}, {"missing CXXABI", "missing-abi.so", false}, {"missing older node", "missing-old.so", false}, {"wrong library", "other.so", false}} {
		t.Run(tc.name, func(t *testing.T) {
			provider := candidate("cpp-runtime", "16.1.0-1", deriveVersionFixture(dir, tc.file))
			_, err := resolver.Resolve(request, nil, []resolver.Candidate{app, libc, provider}, opts)
			if (err == nil) != tc.ok {
				t.Fatalf("Resolve error = %v, want success %v", err, tc.ok)
			}
			if !tc.ok {
				t.Logf("rejected: %v", err)
			}
		})
	}
	installed := []resolver.Installed{{Name: old.Name, Version: old.Version, Architecture: old.Architecture, Provides: old.Provides}}
	plan, err := resolver.Resolve(request, installed, []resolver.Candidate{app, libc, old, current}, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(plan.Operations, func(op resolver.Operation) bool { return op.Name == "cpp-runtime" && op.Kind == resolver.OpUpgrade }) {
		t.Fatalf("old runtime was not upgraded: %+v", plan)
	}
	// A runtime upgrade that drops a capability must not break installed users.
	installed = append([]resolver.Installed{{Name: current.Name, Version: current.Version, Architecture: current.Architecture, Provides: current.Provides}}, resolver.Installed{Name: app.Name, Version: app.Version, Architecture: app.Architecture, Dependencies: app.Dependencies}, resolver.Installed{Name: libc.Name, Version: libc.Version, Architecture: libc.Architecture, Provides: libc.Provides})
	bad := candidate("cpp-runtime", "17.0-1", deriveVersionFixture(dir, "missing-abi.so"))
	_, err = resolver.Resolve([]resolver.Request{{Kind: resolver.Upgrade, Name: "cpp-runtime"}}, installed, []resolver.Candidate{bad}, opts)
	if err == nil {
		t.Fatal("runtime upgrade discarded an installed consumer's ABI requirement")
	}
	// A SONAME-only legacy provider cannot bypass the exact requirement.
	legacy := candidate("cpp-runtime", "99.0-1", DerivedDeps{Provides: []Provides{{Name: cppSONAME}}})
	_, err = resolver.Resolve(request, nil, []resolver.Candidate{app, libc, legacy}, opts)
	if err == nil {
		t.Fatal("legacy metadata bypassed exact ABI requirements")
	}
}
