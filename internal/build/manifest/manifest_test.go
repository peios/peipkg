package manifest

import (
	"bytes"
	"strings"
	"testing"

	consumer "github.com/peios/peipkg/internal/manifest"
)

// TestEncodeClaimsRoundTrip proves the producer's claims encoding is
// exactly what the consumer's decoder accepts (§4.4.2): a manifest
// emitted with provider and consumer claims decodes back with those
// claims intact.
func TestEncodeClaimsRoundTrip(t *testing.T) {
	m := Manifest{
		SchemaVersion: SchemaVersion,
		Name:          "loregd",
		Version:       "1.0.0-1",
		Architecture:  "x86_64",
		Dependencies: []Dependency{{Name: "logsink",
			Claims: map[string]ClaimSlot{"sink": {Path: "/run/logsink.sock"}}}},
		Provides: []Provides{{Name: "registryd", Claims: map[string]ClaimSlot{
			"binary": {Target: "/usr/sbin/loregd", Path: "/usr/sbin/registryd"}}}},
		SizeInstalled: 1,
		Build:         Build{Timestamp: "2026-05-19T00:00:00Z", FarmID: "f", SourceRef: "s"},
	}
	data, err := Encode(m)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	cm, err := consumer.Decode(data)
	if err != nil {
		t.Fatalf("consumer.Decode rejected the emitted manifest: %v", err)
	}
	if got := cm.Provides[0].Claims["binary"]; got.Target != "/usr/sbin/loregd" ||
		got.Path != "/usr/sbin/registryd" {
		t.Errorf("provider claim round-trip: got %+v", got)
	}
	if got := cm.Dependencies[0].Claims["sink"]; got.Path != "/run/logsink.sock" ||
		got.Target != "" {
		t.Errorf("consumer claim round-trip: got %+v", got)
	}
}

func TestEncodeMinimal(t *testing.T) {
	m := Manifest{
		SchemaVersion: SchemaVersion,
		Name:          "x",
		Version:       "0",
		Architecture:  "noarch",
		SizeInstalled: 0,
		Build: Build{
			Timestamp: "2026-01-01T00:00:00Z",
			FarmID:    "f",
			SourceRef: "r",
		},
	}
	got, err := Encode(m)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"schema_version":1,"name":"x","version":"0","architecture":"noarch","description":"","license":"","homepage":"","dependencies":[],"optional_dependencies":[],"conflicts":[],"provides":[],"replaces":[],"side_effects":[],"size_installed":0,"sd_overrides":[],"build":{"timestamp":"2026-01-01T00:00:00Z","farm_id":"f","source_ref":"r"}}` + "\n"
	if string(got) != want {
		t.Errorf("Encode mismatch:\n got: %s\nwant: %s", got, want)
	}
}

func TestEncodeNilSlicesNormalize(t *testing.T) {
	// Construct a manifest with nil slices: the spec treats absent optional
	// fields as empty arrays, so emission must produce "[]" not "null".
	m := Manifest{
		SchemaVersion: SchemaVersion,
		Name:          "x",
		Version:       "0",
		Architecture:  "noarch",
		Build:         Build{Timestamp: "2026-01-01T00:00:00Z", FarmID: "f", SourceRef: "r"},
	}
	got, err := Encode(m)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{
		`"dependencies":[]`,
		`"optional_dependencies":[]`,
		`"conflicts":[]`,
		`"provides":[]`,
		`"replaces":[]`,
		`"side_effects":[]`,
		`"sd_overrides":[]`,
	} {
		if !bytes.Contains(got, []byte(field)) {
			t.Errorf("missing canonical empty-array form %s in:\n%s", field, got)
		}
	}
	if bytes.Contains(got, []byte(`null`)) {
		t.Errorf("output contains null literal (nil slice not normalized):\n%s", got)
	}
}

func TestEncodeNoHTMLEscape(t *testing.T) {
	// Go's encoding/json defaults to escaping <, >, & as < > &,
	// which would diverge from jq -c output. Encode must disable that.
	m := Manifest{
		Name:        "x",
		Description: "uses <html> & symbols",
		Build:       Build{Timestamp: "2026-01-01T00:00:00Z", FarmID: "f", SourceRef: "r"},
	}
	got, err := Encode(m)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(got, []byte("uses <html> & symbols")) {
		t.Errorf("HTML chars escaped in output:\n%s", got)
	}
}

func TestEncodeTrailingNewline(t *testing.T) {
	m := Manifest{Build: Build{Timestamp: "2026-01-01T00:00:00Z", FarmID: "f", SourceRef: "r"}}
	got, err := Encode(m)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(got, []byte("\n")) {
		t.Error("output missing trailing newline")
	}
	if bytes.HasSuffix(got, []byte("\n\n")) {
		t.Error("output has more than one trailing newline")
	}
}

func TestEncodeFieldOrder(t *testing.T) {
	// Field order in the JSON output must match the struct declaration
	// order (which mirrors PSD-009 §3.3). Reordering fields changes the
	// bytes a producer emits.
	m := Manifest{
		Name:         "n",
		Version:      "v",
		Architecture: "a",
		LicenseClass: "free",
		Build:        Build{Timestamp: "2026-01-01T00:00:00Z", FarmID: "f", SourceRef: "r"},
	}
	got, err := Encode(m)
	if err != nil {
		t.Fatal(err)
	}
	wantOrder := []string{
		`"schema_version"`, `"name"`, `"version"`, `"architecture"`,
		`"description"`, `"license"`, `"license_class"`, `"homepage"`,
		`"dependencies"`, `"optional_dependencies"`, `"conflicts"`,
		`"provides"`, `"replaces"`, `"side_effects"`,
		`"size_installed"`, `"sd_overrides"`, `"build"`,
	}
	out := string(got)
	last := -1
	for _, k := range wantOrder {
		i := strings.Index(out, k)
		if i < 0 {
			t.Errorf("missing field %s in output:\n%s", k, out)
			continue
		}
		if i <= last {
			t.Errorf("field %s appears out of order (at %d, previous %d)", k, i, last)
		}
		last = i
	}
}

func TestDependencyOmitEmpty(t *testing.T) {
	// A bare-name dependency should emit {"name": "..."} without empty
	// constraint or arch fields, matching the spec's canonical example.
	m := Manifest{
		Build:        Build{Timestamp: "2026-01-01T00:00:00Z", FarmID: "f", SourceRef: "r"},
		Dependencies: []Dependency{{Name: "libssl"}},
	}
	got, err := Encode(m)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(got, []byte(`"dependencies":[{"name":"libssl"}]`)) {
		t.Errorf("bare-name dependency did not emit canonical form:\n%s", got)
	}
}

func TestBuildModTime(t *testing.T) {
	b := Build{Timestamp: "2026-05-06T12:00:00Z"}
	tt, err := b.ModTime()
	if err != nil {
		t.Fatal(err)
	}
	if tt.Unix() != 1778068800 {
		t.Errorf("epoch %d, want 1778068800", tt.Unix())
	}
}

func TestEncodeSourcePackage(t *testing.T) {
	m := Manifest{
		SchemaVersion: SchemaVersion,
		Name:          "x",
		Version:       "0",
		Architecture:  "noarch",
		Build: Build{
			Timestamp:     "2026-01-01T00:00:00Z",
			FarmID:        "f",
			SourceRef:     "r",
			SourcePackage: "x-source",
		},
	}
	got, err := Encode(m)
	if err != nil {
		t.Fatal(err)
	}
	want := `"build":{"timestamp":"2026-01-01T00:00:00Z","farm_id":"f","source_ref":"r","source_package":"x-source"}`
	if !strings.Contains(string(got), want) {
		t.Errorf("Encode missing source_package:\n got: %s\nwant substring: %s", got, want)
	}
}

func TestEncodeRecipeRefAndBuilder(t *testing.T) {
	m := Manifest{
		SchemaVersion: SchemaVersion,
		Name:          "x",
		Version:       "0",
		Architecture:  "noarch",
		Build: Build{
			Timestamp: "2026-01-01T00:00:00Z",
			FarmID:    "f",
			SourceRef: "r",
			RecipeRef: "git:0123abcd",
			Builder:   "pekit/2f4c9a1b8d3e",
		},
	}
	got, err := Encode(m)
	if err != nil {
		t.Fatal(err)
	}
	want := `"build":{"timestamp":"2026-01-01T00:00:00Z","farm_id":"f","source_ref":"r","recipe_ref":"git:0123abcd","builder":"pekit/2f4c9a1b8d3e"}`
	if !strings.Contains(string(got), want) {
		t.Errorf("Encode missing recipe_ref/builder:\n got: %s\nwant substring: %s", got, want)
	}

	// Empty fields must vanish entirely — a manifest without them emits
	// bytes identical to a pre-recipe_ref manifest.
	m.Build.RecipeRef, m.Build.Builder = "", ""
	got, err = Encode(m)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), "recipe_ref") || strings.Contains(string(got), "builder") {
		t.Errorf("empty recipe_ref/builder leaked into the wire form: %s", got)
	}
}

// license_class post-dates the format: a package that declares none must
// emit bytes identical to a pre-license_class manifest.
func TestEncodeOmitsAbsentLicenseClass(t *testing.T) {
	m := Manifest{Name: "n", Version: "v", Architecture: "a",
		Build: Build{Timestamp: "2026-01-01T00:00:00Z", FarmID: "f", SourceRef: "r"}}
	got, err := Encode(m)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(got, []byte("license_class")) {
		t.Errorf("absent license_class was emitted: %s", got)
	}
	m.LicenseClass = "firmware"
	if got, err = Encode(m); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(got, []byte(`"license_class":"firmware"`)) {
		t.Errorf("license_class not emitted: %s", got)
	}
}
