package pack_test

import (
	"archive/tar"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/peios/libp-go/sddl"

	"github.com/peios/peipkg/pack"
)

// testdataRoot points at internal/build/testdata, shared with the
// internal packing tests.
func testdataRoot(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "internal", "build", "testdata")
}

// helloNoarchManifest mirrors the manifest baked into the hello-noarch
// golden (testdata/cases/hello-noarch/expected/).
func helloNoarchManifest() pack.Manifest {
	return pack.Manifest{
		Name:         "hello",
		Version:      "0.1-1",
		Architecture: "noarch",
		Description:  "Smallest legal peipkg test fixture.",
		License:      "CC0-1.0",
		Homepage:     "https://peios.org",
		Build: pack.BuildInfo{
			Timestamp: "2026-05-06T12:00:00Z",
			FarmID:    "test-farm-1",
			SourceRef: "test://hello-noarch",
		},
	}
}

// TestPackManifestMatchesGolden packs the hello-noarch staged tree
// through the public API and requires the emitted manifest.json to be
// byte-identical to the one inside the hand-verified golden. This pins
// the facade's struct-to-wire conversion to the canonical §3.3 document.
// (The full archives are not byte-compared: the golden's tar headers
// NUL-fill devmajor/devminor where archive/tar writes zero-octal, a
// divergence that predates this package; byte-determinism of the
// archive itself is covered by the internal pack tests.)
func TestPackManifestMatchesGolden(t *testing.T) {
	caseDir := filepath.Join(testdataRoot(t), "cases", "hello-noarch")

	var buf bytes.Buffer
	err := pack.Pack(pack.PackOptions{
		Manifest:   helloNoarchManifest(),
		StagedRoot: filepath.Join(caseDir, "staged"),
		Out:        &buf,
	})
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}

	golden, err := os.ReadFile(filepath.Join(caseDir, "expected", "hello_0.1-1_noarch.peipkg"))
	if err != nil {
		t.Fatal(err)
	}

	got := extractEntry(t, buf.Bytes(), ".peipkg/manifest.json")
	want := extractEntry(t, golden, ".peipkg/manifest.json")
	if !bytes.Equal(got, want) {
		t.Errorf("manifest.json differs from golden:\ngot:  %s\nwant: %s", got, want)
	}
}

// TestPackSortsArrays verifies the facade canonicalizes unsorted
// dependency arrays: the emitted manifest.json must hold them in
// lex-sorted order (§4.1) regardless of input order.
func TestPackSortsArrays(t *testing.T) {
	m := helloNoarchManifest()
	m.Dependencies = []pack.Dependency{
		{Name: "libz"},
		{Name: "libc", Constraint: ">= 2.0"},
	}
	m.Provides = []pack.Provides{
		{Name: "hello-impl"},
		{Name: "greeter", Version: "1.0"},
	}

	caseDir := filepath.Join(testdataRoot(t), "cases", "hello-noarch")
	var buf bytes.Buffer
	err := pack.Pack(pack.PackOptions{
		Manifest:   m,
		StagedRoot: filepath.Join(caseDir, "staged"),
		Out:        &buf,
	})
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}

	var manifest struct {
		Dependencies []struct {
			Name string `json:"name"`
		} `json:"dependencies"`
		Provides []struct {
			Name string `json:"name"`
		} `json:"provides"`
	}
	if err := json.Unmarshal(extractEntry(t, buf.Bytes(), ".peipkg/manifest.json"), &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Dependencies[0].Name != "libc" || manifest.Dependencies[1].Name != "libz" {
		t.Errorf("dependencies not sorted: %+v", manifest.Dependencies)
	}
	if manifest.Provides[0].Name != "greeter" || manifest.Provides[1].Name != "hello-impl" {
		t.Errorf("provides not sorted: %+v", manifest.Provides)
	}
}

// TestPackSDOverrides verifies both supply forms produce the §3.3.5
// wire value: unpadded base64 of the binary self-relative descriptor,
// with SDDL compiled via libp.
func TestPackSDOverrides(t *testing.T) {
	const sddlText = "O:BAG:SY"
	d, err := sddl.Parse(sddlText)
	if err != nil {
		t.Fatal(err)
	}
	wantBinary, err := d.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	m := helloNoarchManifest()
	m.SDOverrides = []pack.SDOverride{
		{Path: "usr/share/hello/MESSAGE", SDDL: sddlText},
		{Path: "usr/share/hello", SD: []byte("raw descriptor bytes")},
	}

	caseDir := filepath.Join(testdataRoot(t), "cases", "hello-noarch")
	var buf bytes.Buffer
	if err := pack.Pack(pack.PackOptions{
		Manifest:   m,
		StagedRoot: filepath.Join(caseDir, "staged"),
		Out:        &buf,
	}); err != nil {
		t.Fatalf("Pack: %v", err)
	}

	var manifest struct {
		SDOverrides []struct {
			Path string `json:"path"`
			SD   string `json:"sd"`
		} `json:"sd_overrides"`
	}
	if err := json.Unmarshal(extractEntry(t, buf.Bytes(), ".peipkg/manifest.json"), &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.SDOverrides) != 2 {
		t.Fatalf("got %d sd_overrides, want 2", len(manifest.SDOverrides))
	}
	// Sorted by path: "usr/share/hello" (raw) before ".../MESSAGE" (SDDL).
	if got, want := manifest.SDOverrides[0].SD, base64.RawStdEncoding.EncodeToString([]byte("raw descriptor bytes")); got != want {
		t.Errorf("raw-form sd = %q, want %q", got, want)
	}
	if got, want := manifest.SDOverrides[1].SD, base64.RawStdEncoding.EncodeToString(wantBinary); got != want {
		t.Errorf("SDDL-form sd = %q, want %q", got, want)
	}
}

// TestPackSDOverrideRequiresOneForm verifies exactly one of SD and SDDL
// must be set, and that SDDL errors surface with the offending path.
func TestPackSDOverrideRequiresOneForm(t *testing.T) {
	caseDir := filepath.Join(testdataRoot(t), "cases", "hello-noarch")
	for name, override := range map[string]pack.SDOverride{
		"both":     {Path: "usr/share/hello/MESSAGE", SD: []byte("x"), SDDL: "O:SY"},
		"neither":  {Path: "usr/share/hello/MESSAGE"},
		"bad sddl": {Path: "usr/share/hello/MESSAGE", SDDL: "not sddl"},
	} {
		m := helloNoarchManifest()
		m.SDOverrides = []pack.SDOverride{override}
		err := pack.Pack(pack.PackOptions{
			Manifest:   m,
			StagedRoot: filepath.Join(caseDir, "staged"),
			Out:        io.Discard,
		})
		if err == nil {
			t.Errorf("%s: expected error, got nil", name)
		} else if !strings.Contains(err.Error(), "usr/share/hello/MESSAGE") {
			t.Errorf("%s: error does not name the override path: %v", name, err)
		}
	}
}

func TestPackRejectsDuplicateNames(t *testing.T) {
	m := helloNoarchManifest()
	m.Dependencies = []pack.Dependency{{Name: "libc"}, {Name: "libc"}}

	caseDir := filepath.Join(testdataRoot(t), "cases", "hello-noarch")
	err := pack.Pack(pack.PackOptions{
		Manifest:   m,
		StagedRoot: filepath.Join(caseDir, "staged"),
		Out:        io.Discard,
	})
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("expected duplicate-name rejection, got %v", err)
	}
}

// TestPackFiles verifies map mode: sources scattered on disk land at
// their mapped archive paths, with ancestor directories synthesized,
// and the integrity manifest hashes the mapped content.
func TestPackFiles(t *testing.T) {
	src := t.TempDir()
	binPath := filepath.Join(src, "build-output", "prelude")
	if err := os.MkdirAll(filepath.Dir(binPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binPath, []byte("elf bytes"), 0o755); err != nil {
		t.Fatal(err)
	}
	emptyDir := filepath.Join(src, "somedir")
	if err := os.Mkdir(emptyDir, 0o755); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	err := pack.Pack(pack.PackOptions{
		Manifest: helloNoarchManifest(),
		Files: map[string]string{
			"system/boot/prelude/init": binPath,
			"var":                      emptyDir,
		},
		Out: &buf,
	})
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}

	want := []string{
		".peipkg/manifest.json",
		".peipkg/files.json",
		"system/",
		"system/boot/",
		"system/boot/prelude/",
		"system/boot/prelude/init",
		"var/",
	}
	got := entryNames(t, buf.Bytes())
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("archive entries = %v, want %v", got, want)
	}

	if body := extractEntry(t, buf.Bytes(), "system/boot/prelude/init"); string(body) != "elf bytes" {
		t.Errorf("mapped file content = %q, want %q", body, "elf bytes")
	}
}

// TestPackFilesRejectsBadDest spot-checks archive-path hygiene in map
// mode; the source files themselves are valid.
func TestPackFilesRejectsBadDest(t *testing.T) {
	src := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(src, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, dest := range []string{
		"/usr/bin/foo",
		"usr/bin/foo/",
		"usr/../etc/passwd",
		"../escape",
		"",
	} {
		err := pack.Pack(pack.PackOptions{
			Manifest: helloNoarchManifest(),
			Files:    map[string]string{dest: src},
			Out:      io.Discard,
		})
		if err == nil {
			t.Errorf("dest %q: expected rejection, got nil", dest)
		}
	}
}

// TestPackRequiresOnePayloadForm verifies StagedRoot and Files are
// mutually exclusive and one is required.
func TestPackRequiresOnePayloadForm(t *testing.T) {
	if err := pack.Pack(pack.PackOptions{
		Manifest: helloNoarchManifest(),
		Out:      io.Discard,
	}); err == nil {
		t.Error("expected error with neither StagedRoot nor Files, got nil")
	}

	src := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(src, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	caseDir := filepath.Join(testdataRoot(t), "cases", "hello-noarch")
	if err := pack.Pack(pack.PackOptions{
		Manifest:   helloNoarchManifest(),
		StagedRoot: filepath.Join(caseDir, "staged"),
		Files:      map[string]string{"usr/bin/foo": src},
		Out:        io.Discard,
	}); err == nil {
		t.Error("expected error with both StagedRoot and Files, got nil")
	}
}

// TestValidatePayload spot-checks the facade passthrough; the rule
// coverage lives with the internal validator's tests.
func TestValidatePayload(t *testing.T) {
	root := t.TempDir()
	bad := filepath.Join(root, "var", "log")
	if err := os.MkdirAll(bad, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bad, "seed.log"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := pack.ValidatePayload("noarch", root); err == nil {
		t.Error("expected /var/ violation, got nil")
	}

	caseDir := filepath.Join(testdataRoot(t), "cases", "hello-noarch")
	if err := pack.ValidatePayload("noarch", filepath.Join(caseDir, "staged")); err != nil {
		t.Errorf("hello-noarch staged tree should validate, got %v", err)
	}

	// The Files counterpart applies the same rules to mapped paths.
	good := filepath.Join(caseDir, "staged", "usr", "share", "hello", "MESSAGE")
	if err := pack.ValidateFiles("noarch", map[string]string{"usr/share/msg": good}); err != nil {
		t.Errorf("mapped file should validate, got %v", err)
	}
	if err := pack.ValidateFiles("noarch", map[string]string{"srv/msg": good}); err == nil {
		t.Error("expected §3.4.1 rejection for srv/ destination, got nil")
	}
}

// entryNames returns the path of every tar entry in archive order.
func entryNames(t *testing.T, compressed []byte) []string {
	t.Helper()
	zr, err := zstd.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	var names []string
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, h.Name)
	}
	return names
}

func extractEntry(t *testing.T, compressed []byte, name string) []byte {
	t.Helper()
	zr, err := zstd.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if h.Name == name {
			body, err := io.ReadAll(tr)
			if err != nil {
				t.Fatal(err)
			}
			return body
		}
	}
	t.Fatalf("entry %q not found in archive", name)
	return nil
}
