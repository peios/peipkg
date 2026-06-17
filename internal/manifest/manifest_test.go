package manifest_test

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/peios/peipkg/internal/manifest"
)

// baseManifest returns a minimal but fully valid manifest as a mutable
// map, so a test can tweak one field and re-encode it.
func baseManifest() map[string]any {
	return map[string]any{
		"schema_version": 1,
		"name":           "nginx",
		"version":        "1.26.2-3",
		"architecture":   "x86_64",
		"description":    "A high-performance web server.",
		"license":        "BSD-2-Clause",
		"homepage":       "https://nginx.org",
		"dependencies": []any{
			map[string]any{"name": "libc", "constraint": ">= 2.39-1"},
			map[string]any{"name": "libssl", "constraint": ">= 3.0"},
		},
		"conflicts":      []any{},
		"size_installed": 4096,
		"build": map[string]any{
			"timestamp":  "2026-05-19T12:00:00Z",
			"farm_id":    "farm-01",
			"source_ref": "git+https://git.peios.org/sources/nginx#refs/tags/v1.26.2-3",
		},
	}
}

// decode marshals a manifest map and decodes it.
func decode(t *testing.T, m map[string]any) (manifest.Manifest, error) {
	t.Helper()
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	return manifest.Decode(data)
}

// mustDecode decodes a manifest the test author asserts is valid.
func mustDecode(t *testing.T, m map[string]any) manifest.Manifest {
	t.Helper()
	got, err := decode(t, m)
	if err != nil {
		t.Fatalf("Decode: unexpected error: %v", err)
	}
	return got
}

// wantReject decodes a manifest the test author asserts is invalid.
func wantReject(t *testing.T, m map[string]any) {
	t.Helper()
	if got, err := decode(t, m); err == nil {
		t.Errorf("Decode should have failed, got %+v", got)
	}
}

func TestDecodeValid(t *testing.T) {
	m := mustDecode(t, baseManifest())

	if m.Name != "nginx" {
		t.Errorf("Name: got %q, want %q", m.Name, "nginx")
	}
	if m.Version.String() != "1.26.2-3" {
		t.Errorf("Version: got %q, want %q", m.Version.String(), "1.26.2-3")
	}
	if m.Architecture != "x86_64" {
		t.Errorf("Architecture: got %q, want %q", m.Architecture, "x86_64")
	}
	if len(m.Dependencies) != 2 || m.Dependencies[0].Name != "libc" {
		t.Errorf("Dependencies: got %+v", m.Dependencies)
	}
	if m.SizeInstalled != 4096 {
		t.Errorf("SizeInstalled: got %d, want 4096", m.SizeInstalled)
	}
	if m.Build.FarmID != "farm-01" {
		t.Errorf("Build.FarmID: got %q", m.Build.FarmID)
	}
	if !m.Build.Timestamp.Equal(time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC)) {
		t.Errorf("Build.Timestamp: got %v", m.Build.Timestamp)
	}
}

func TestDecodeOptionalFields(t *testing.T) {
	m := baseManifest()
	m["optional_dependencies"] = []any{
		map[string]any{"name": "libxml2"},
	}
	m["provides"] = []any{
		map[string]any{"name": "http-server", "version": "1.0-1"},
		map[string]any{"name": "web-server"}, // no version
	}
	m["replaces"] = []any{
		map[string]any{"name": "nginx-core"},
	}
	m["side_effects"] = []any{"ldconfig", "man-db"}
	m["sd_overrides"] = []any{
		map[string]any{
			"path": "usr/bin/nginx",
			"sd":   base64.RawStdEncoding.EncodeToString([]byte("a security descriptor")),
		},
	}

	got := mustDecode(t, m)
	if len(got.OptionalDependencies) != 1 {
		t.Errorf("OptionalDependencies: got %+v", got.OptionalDependencies)
	}
	if len(got.Provides) != 2 {
		t.Fatalf("Provides: got %+v", got.Provides)
	}
	if got.Provides[0].Version == nil || got.Provides[0].Version.String() != "1.0-1" {
		t.Errorf("Provides[0].Version: got %v", got.Provides[0].Version)
	}
	if got.Provides[1].Version != nil {
		t.Errorf("Provides[1].Version: got %v, want nil (unversioned)", got.Provides[1].Version)
	}
	if len(got.SideEffects) != 2 || got.SideEffects[0] != manifest.SideEffectLdconfig {
		t.Errorf("SideEffects: got %v", got.SideEffects)
	}
	if len(got.SDOverrides) != 1 || string(got.SDOverrides[0].SD) != "a security descriptor" {
		t.Errorf("SDOverrides: got %+v", got.SDOverrides)
	}
}

func TestUnknownFieldsIgnored(t *testing.T) {
	m := baseManifest()
	m["future_field"] = "from a newer spec version"
	m["another_one"] = map[string]any{"nested": true}
	// §3.3.3: an unknown field must be ignored, not rejected.
	mustDecode(t, m)
}

func TestMissingRequiredFields(t *testing.T) {
	for _, field := range []string{
		"schema_version", "name", "version", "architecture",
		"dependencies", "conflicts", "size_installed", "build",
	} {
		t.Run(field, func(t *testing.T) {
			m := baseManifest()
			delete(m, field)
			wantReject(t, m)
		})
	}
}

func TestOptionalFieldsMayBeAbsent(t *testing.T) {
	// A manifest with only the required fields must decode.
	mustDecode(t, baseManifest())
}

func TestSchemaVersionMustBeOne(t *testing.T) {
	m := baseManifest()
	m["schema_version"] = 2
	wantReject(t, m)
}

func TestInvalidName(t *testing.T) {
	for _, name := range []string{
		"Nginx",   // uppercase
		"n",       // too short
		"-nginx",  // starts with a separator
		"nginx-",  // ends with a separator
		"ng--inx", // consecutive separators
		"ngin x",  // space
		"nginx_1", // underscore is not permitted
		"++nginx", // starts with a plus (only allowed at the end / interior)
	} {
		t.Run(name, func(t *testing.T) {
			m := baseManifest()
			m["name"] = name
			wantReject(t, m)
		})
	}
}

func TestValidNameWithPlus(t *testing.T) {
	// A plus sign is a regular name character, not a separator: it is intrinsic
	// to names like libstdc++ / g++, so it may repeat and may end a name. §2.1.
	for _, name := range []string{"libstdc++", "g++", "c++", "libstdc++-devel"} {
		t.Run(name, func(t *testing.T) {
			m := baseManifest()
			m["name"] = name
			mustDecode(t, m)
		})
	}
}

func TestInvalidVersion(t *testing.T) {
	m := baseManifest()
	m["version"] = "1.0" // no revision
	wantReject(t, m)
}

func TestInvalidArchitecture(t *testing.T) {
	for _, arch := range []string{
		"X86_64",           // uppercase
		"6502",             // starts with a digit
		"x86-64",           // hyphen is not permitted
		"a-very-long-arch", // hyphen, and over the length limit
		"",                 // empty
	} {
		t.Run(arch, func(t *testing.T) {
			m := baseManifest()
			m["architecture"] = arch
			wantReject(t, m)
		})
	}
}

func TestInvalidDescription(t *testing.T) {
	m := baseManifest()
	m["description"] = "escape \x1b[31m injection" // ASCII control byte
	wantReject(t, m)
}

func TestDescriptionAllowsPrintableUTF8(t *testing.T) {
	m := baseManifest()
	m["description"] = "Swiss army knife — static utilities"
	mustDecode(t, m)
}

func TestInvalidDescriptionUTF8(t *testing.T) {
	m := baseManifest()
	m["description"] = string([]byte{0xff})
	wantReject(t, m)
}

func TestInvalidHomepage(t *testing.T) {
	for _, homepage := range []string{
		"javascript:alert(1)",
		"file:///etc/passwd",
		"ftp://example.org",
	} {
		t.Run(homepage, func(t *testing.T) {
			m := baseManifest()
			m["homepage"] = homepage
			wantReject(t, m)
		})
	}
}

func TestNegativeSizeInstalled(t *testing.T) {
	m := baseManifest()
	m["size_installed"] = -1
	wantReject(t, m)
}

func TestDependencyRules(t *testing.T) {
	cases := map[string][]any{
		"missing name": {
			map[string]any{"constraint": ">= 1.0-1"},
		},
		"invalid name": {
			map[string]any{"name": "BadName"},
		},
		"invalid constraint": {
			map[string]any{"name": "libc", "constraint": "?? 1.0"},
		},
		"unsupported arch qualifier": {
			map[string]any{"name": "libc", "arch": "x86_64"},
		},
		"not sorted": {
			map[string]any{"name": "libssl"},
			map[string]any{"name": "libc"},
		},
		"duplicate name": {
			map[string]any{"name": "libc"},
			map[string]any{"name": "libc"},
		},
	}
	for name, deps := range cases {
		t.Run(name, func(t *testing.T) {
			m := baseManifest()
			m["dependencies"] = deps
			wantReject(t, m)
		})
	}
}

func TestProvidesRules(t *testing.T) {
	cases := map[string][]any{
		"invalid provides version": {
			map[string]any{"name": "smtp-server", "version": "not-a-version"},
		},
		"not sorted": {
			map[string]any{"name": "web-server"},
			map[string]any{"name": "http-server"},
		},
	}
	for name, provides := range cases {
		t.Run(name, func(t *testing.T) {
			m := baseManifest()
			m["provides"] = provides
			wantReject(t, m)
		})
	}
}

func TestSideEffectRules(t *testing.T) {
	t.Run("unknown side effect", func(t *testing.T) {
		m := baseManifest()
		m["side_effects"] = []any{"ldconfig", "rm-rf-slash"}
		wantReject(t, m)
	})
	t.Run("duplicate side effect", func(t *testing.T) {
		m := baseManifest()
		m["side_effects"] = []any{"ldconfig", "ldconfig"}
		wantReject(t, m)
	})
}

func TestSDOverrideRules(t *testing.T) {
	t.Run("invalid base64", func(t *testing.T) {
		m := baseManifest()
		m["sd_overrides"] = []any{
			map[string]any{"path": "usr/bin/x", "sd": "not valid base64!!"},
		}
		wantReject(t, m)
	})
	t.Run("not sorted by path", func(t *testing.T) {
		sd := base64.RawStdEncoding.EncodeToString([]byte("sd"))
		m := baseManifest()
		m["sd_overrides"] = []any{
			map[string]any{"path": "usr/bin/z", "sd": sd},
			map[string]any{"path": "usr/bin/a", "sd": sd},
		}
		wantReject(t, m)
	})
}

func TestBuildRules(t *testing.T) {
	t.Run("missing timestamp", func(t *testing.T) {
		m := baseManifest()
		delete(m["build"].(map[string]any), "timestamp")
		wantReject(t, m)
	})
	t.Run("missing farm_id", func(t *testing.T) {
		m := baseManifest()
		delete(m["build"].(map[string]any), "farm_id")
		wantReject(t, m)
	})
	t.Run("non-UTC timestamp", func(t *testing.T) {
		m := baseManifest()
		m["build"].(map[string]any)["timestamp"] = "2026-05-19T12:00:00+02:00"
		wantReject(t, m)
	})
	t.Run("malformed timestamp", func(t *testing.T) {
		m := baseManifest()
		m["build"].(map[string]any)["timestamp"] = "yesterday"
		wantReject(t, m)
	})
}

func TestMalformedJSON(t *testing.T) {
	if _, err := manifest.Decode([]byte("{not json")); err == nil {
		t.Error("Decode should reject malformed JSON")
	}
}
