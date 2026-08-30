package manifest_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/peios/libp-go/sddl"
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
	m["side_effects"] = []any{"depmod", "man-db"}
	m["sd_overrides"] = []any{
		map[string]any{
			"path": "usr/bin/nginx",
			"sd":   base64.RawStdEncoding.EncodeToString(descriptorBytes(t)),
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
	if len(got.SideEffects) != 2 || got.SideEffects[0] != manifest.SideEffectDepmod {
		t.Errorf("SideEffects: got %v", got.SideEffects)
	}
	if len(got.SDOverrides) != 1 || !bytes.Equal(got.SDOverrides[0].SD, descriptorBytes(t)) {
		t.Errorf("SDOverrides: got %+v", got.SDOverrides)
	}
}

// §3.3.6: license_class is a closed set; absent means unknown, so a
// package that predates the field decodes exactly as before.
func TestLicenseClass(t *testing.T) {
	if got := mustDecode(t, baseManifest()).LicenseClass; got != manifest.LicenseClassUnknown {
		t.Errorf("absent license_class: got %q, want unknown", got)
	}
	for _, want := range []manifest.LicenseClass{
		manifest.LicenseClassUnknown, manifest.LicenseClassFree,
		manifest.LicenseClassFirmware, manifest.LicenseClassProprietary,
	} {
		m := baseManifest()
		m["license_class"] = string(want)
		if got := mustDecode(t, m).LicenseClass; got != want {
			t.Errorf("license_class %q: got %q", want, got)
		}
	}
	for _, bad := range []any{"nonfree", "Free", "FIRMWARE", " free", 1, true} {
		m := baseManifest()
		m["license_class"] = bad
		wantReject(t, m)
	}
}

func TestDefaultRootAndDependencyRoot(t *testing.T) {
	m := baseManifest()
	m["default_root"] = "initramfs"
	m["dependencies"] = []any{
		map[string]any{"name": "libc", "constraint": ">= 2.39-1"},
		// A cross-root placement: peiosutils is required in the initramfs root.
		map[string]any{"name": "peiosutils", "root": "initramfs.sub"},
	}
	got := mustDecode(t, m)
	if got.DefaultRoot != "initramfs" {
		t.Errorf("DefaultRoot: got %q, want %q", got.DefaultRoot, "initramfs")
	}
	// dependencies is sorted by name: libc, peiosutils.
	if len(got.Dependencies) != 2 {
		t.Fatalf("Dependencies: got %+v", got.Dependencies)
	}
	if got.Dependencies[0].Root != "" {
		t.Errorf("libc Root: got %q, want empty (depender's root)", got.Dependencies[0].Root)
	}
	if got.Dependencies[1].Name != "peiosutils" || got.Dependencies[1].Root != "initramfs.sub" {
		t.Errorf("peiosutils placement: got %+v", got.Dependencies[1])
	}
}

func TestDefaultRootRejectsPath(t *testing.T) {
	m := baseManifest()
	m["default_root"] = "./boot/initramfs" // a path, not a named reference
	wantReject(t, m)
}

func TestDependencyRootRejectedOnConflicts(t *testing.T) {
	m := baseManifest()
	m["conflicts"] = []any{
		map[string]any{"name": "apache", "root": "initramfs"},
	}
	wantReject(t, m)
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

func TestValidName(t *testing.T) {
	for _, name := range []string{
		"nginx",           // ordinary
		"lib32-foo",       // hyphenated
		"python3.example", // dotted
		"libstdc++",       // trailing repeated plus (§2.1 informative example)
		"g++",             // trailing plus
		"c++",             // short trailing plus
		"gtk+-3.0",        // plus is not a separator, so +- is allowed
	} {
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

func TestDescriptionAllowsPrintableASCII(t *testing.T) {
	m := baseManifest()
	// The whole of §3.3.5's permitted range, 0x20 through 0x7E.
	var b []byte
	for c := byte(0x20); c <= 0x7E; c++ {
		b = append(b, c)
	}
	m["description"] = string(b)
	mustDecode(t, m)
}

// §3.3.5 restricts the description to printable ASCII 0x20-0x7E. A
// Unicode printability test is not the same rule: it admits letters
// that render as ASCII to an operator reading the description to decide
// whether to install, which is the homoglyph and bidi-confusable
// surface the byte range exists to close.
func TestDescriptionRejectsNonASCII(t *testing.T) {
	for name, desc := range map[string]string{
		"em dash":            "Swiss army knife — static utilities",
		"accented letter":    "caf\u00e9 utilities",
		"emoji":              "utilities \U0001f389",
		"cyrillic homoglyph": "p\u0430ckage tools", // U+0430 renders as "a"
		"fullwidth latin":    "\uff50ackage tools",
		"zero width joiner":  "package\u200dtools",
		"non-breaking space": "package\u00a0tools",
	} {
		t.Run(name, func(t *testing.T) {
			m := baseManifest()
			m["description"] = desc
			wantReject(t, m)
		})
	}
}

// DEL and the C1 range are non-printing but are not caught by a
// "control character" test that only looks below 0x20.
func TestDescriptionRejectsDelAndC1(t *testing.T) {
	for name, desc := range map[string]string{
		"DEL":      "package\x7ftools",
		"C1 NEL":   "package\u0085tools",
		"C1 CSI":   "package\u009btools",
		"NUL byte": "package\x00tools",
	} {
		t.Run(name, func(t *testing.T) {
			m := baseManifest()
			m["description"] = desc
			wantReject(t, m)
		})
	}
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
			map[string]any{"name": "bad name"},
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
			// A space is an invalid upstream character even when the
			// revision is relaxed away (§4.1.4).
			map[string]any{"name": "smtp-server", "version": "not a version"},
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

func TestProvidesVersionRevisionOptional(t *testing.T) {
	// §4.1.4: a provides version expresses a capability level, so the
	// Peios revision may be omitted (e.g. the spec's own "3.0" example).
	m := baseManifest()
	m["provides"] = []any{map[string]any{"name": "smtp-server", "version": "3.0"}}
	got := mustDecode(t, m)
	if got.Provides[0].Version == nil || got.Provides[0].Version.String() != "3.0" {
		t.Errorf("Provides[0].Version: got %v, want 3.0", got.Provides[0].Version)
	}
}

func TestSideEffectRules(t *testing.T) {
	t.Run("unknown side effect", func(t *testing.T) {
		m := baseManifest()
		m["side_effects"] = []any{"depmod", "rm-rf-slash"}
		wantReject(t, m)
	})
	t.Run("duplicate side effect", func(t *testing.T) {
		m := baseManifest()
		m["side_effects"] = []any{"depmod", "depmod"}
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

func TestBuildSourcePackage(t *testing.T) {
	m := baseManifest()
	build := m["build"].(map[string]any)
	build["source_package"] = "nginx-source"
	got := mustDecode(t, m)
	if got.Build.SourcePackage != "nginx-source" {
		t.Errorf("Build.SourcePackage: got %q, want %q", got.Build.SourcePackage, "nginx-source")
	}
}

func TestBuildSourcePackageAbsent(t *testing.T) {
	got := mustDecode(t, baseManifest())
	if got.Build.SourcePackage != "" {
		t.Errorf("Build.SourcePackage: got %q, want empty for an absent field", got.Build.SourcePackage)
	}
}

func TestBuildRecipeRefAndBuilder(t *testing.T) {
	m := baseManifest()
	build := m["build"].(map[string]any)
	build["recipe_ref"] = "git:0123abcd+dirty"
	build["builder"] = "pekit/2f4c9a1b8d3e"
	got := mustDecode(t, m)
	if got.Build.RecipeRef != "git:0123abcd+dirty" {
		t.Errorf("Build.RecipeRef: got %q", got.Build.RecipeRef)
	}
	if got.Build.Builder != "pekit/2f4c9a1b8d3e" {
		t.Errorf("Build.Builder: got %q", got.Build.Builder)
	}

	// Both are optional: absent decodes to empty.
	got = mustDecode(t, baseManifest())
	if got.Build.RecipeRef != "" || got.Build.Builder != "" {
		t.Errorf("absent recipe_ref/builder: got %q / %q, want empty",
			got.Build.RecipeRef, got.Build.Builder)
	}
}

// PSPU §5.9's hardening rules apply to the manifest, and duplicate-key
// rejection is the one that matters most here: size_installed is the
// decompression bound, and name and version are what an operator reads.
// A duplicate-key manifest read one way to a scanner or a third-party
// validator and another way to peipkg, while every signature over the
// bytes still verified.
func TestManifestRejectsDuplicateKeys(t *testing.T) {
	for name, raw := range map[string]string{
		"name": `{"schema_version":1,"name":"nginx","name":"evil","version":"1.26.2-3",` +
			`"architecture":"x86_64","dependencies":[],"conflicts":[],"size_installed":4096,` +
			`"build":{"timestamp":"2026-05-19T12:00:00Z","farm_id":"f","source_ref":"git+https://e.org/s#r"}}`,
		"size_installed": `{"schema_version":1,"name":"nginx","version":"1.26.2-3",` +
			`"architecture":"x86_64","dependencies":[],"conflicts":[],` +
			`"size_installed":0,"size_installed":999999,` +
			`"build":{"timestamp":"2026-05-19T12:00:00Z","farm_id":"f","source_ref":"git+https://e.org/s#r"}}`,
		"inside build": `{"schema_version":1,"name":"nginx","version":"1.26.2-3",` +
			`"architecture":"x86_64","dependencies":[],"conflicts":[],"size_installed":4096,` +
			`"build":{"timestamp":"2026-05-19T12:00:00Z","farm_id":"a","farm_id":"b","source_ref":"git+https://e.org/s#r"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := manifest.Decode([]byte(raw)); err == nil {
				t.Errorf("Decode accepted a duplicate key, got %+v", got)
			}
		})
	}
}

// §5.A caps nesting at 64. The depth is reachable inside an unknown
// field, which §5.9 requires the parser to *ignore* — so the document
// still decodes to a valid manifest unless the depth is checked before
// unmarshalling.
func TestManifestRejectsExcessiveNestingInAnIgnoredField(t *testing.T) {
	m := baseManifest()
	var deep any = 1
	for range 200 {
		deep = []any{deep}
	}
	m["future_field"] = deep
	wantReject(t, m)

	// Well within the cap, the same ignored field must still decode.
	shallow := baseManifest()
	var ok any = 1
	for range 20 {
		ok = []any{ok}
	}
	shallow["future_field"] = ok
	mustDecode(t, shallow)
}

// §5.9 requires a \u escape to resolve to a valid code point.
// encoding/json substitutes U+FFFD instead, so source_ref — which is
// meant to be machine-resolvable — silently became a different string.
func TestManifestRejectsUnpairedSurrogate(t *testing.T) {
	raw := `{"schema_version":1,"name":"nginx","version":"1.26.2-3",` +
		`"architecture":"x86_64","dependencies":[],"conflicts":[],"size_installed":4096,` +
		`"build":{"timestamp":"2026-05-19T12:00:00Z","farm_id":"f",` +
		`"source_ref":"git+https://e.org/s#a\ud800b"}}`
	if got, err := manifest.Decode([]byte(raw)); err == nil {
		t.Errorf("Decode accepted an unpaired surrogate, got %+v", got)
	}
}

// descriptorBytes returns a real self-relative security descriptor.
//
// §5.20 requires `sd` to decode to one, and the consumer checks it now — the
// field used to be free text, so fixtures could carry anything.
func descriptorBytes(t *testing.T) []byte {
	t.Helper()
	d, err := sddl.Parse("O:BAG:SY")
	if err != nil {
		t.Fatalf("sddl.Parse: %v", err)
	}
	raw, err := d.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return raw
}

// §5.20 requires `sd` to decode to a syntactically valid self-relative
// security descriptor. Checking only that it was base64 left the field free
// text: two bytes were accepted, as was an entry with nothing in it.
func TestSDOverrideRejectsSomethingThatIsNotADescriptor(t *testing.T) {
	for name, raw := range map[string][]byte{
		"two bytes":        {0x01, 0x00},
		"plausible text":   []byte("a security descriptor"),
		"empty":            {},
		"truncated header": {0x01, 0x00, 0x80, 0x14},
	} {
		t.Run(name, func(t *testing.T) {
			m := baseManifest()
			m["sd_overrides"] = []any{
				map[string]any{
					"path": "usr/bin/nginx",
					"sd":   base64.RawStdEncoding.EncodeToString(raw),
				},
			}
			wantReject(t, m)
		})
	}
}

// An override with no path names nothing, which the array's own sort order
// cannot catch.
func TestSDOverrideRejectsAnEmptyPath(t *testing.T) {
	m := baseManifest()
	m["sd_overrides"] = []any{
		map[string]any{
			"path": "",
			"sd":   base64.RawStdEncoding.EncodeToString(descriptorBytes(t)),
		},
	}
	wantReject(t, m)
}

// A real descriptor must still decode, or the check would be a refusal of the
// whole feature.
func TestSDOverrideAcceptsARealDescriptor(t *testing.T) {
	m := baseManifest()
	m["sd_overrides"] = []any{
		map[string]any{
			"path": "usr/bin/nginx",
			"sd":   base64.RawStdEncoding.EncodeToString(descriptorBytes(t)),
		},
	}
	mustDecode(t, m)
}

func TestAlternateUpgrade(t *testing.T) {
	m := baseManifest()
	m["alternate_upgrade"] = map[string]any{"message": "Run upgrade-peios instead.\nSee the release notes."}
	got := mustDecode(t, m)
	if got.AlternateUpgrade == nil {
		t.Fatal("AlternateUpgrade: got nil, want the declared object")
	}
	if want := "Run upgrade-peios instead.\nSee the release notes."; got.AlternateUpgrade.Message != want {
		t.Errorf("AlternateUpgrade.Message: got %q, want %q", got.AlternateUpgrade.Message, want)
	}
	// Absent means none — the state of every package that predates the
	// field.
	if got := mustDecode(t, baseManifest()); got.AlternateUpgrade != nil {
		t.Errorf("AlternateUpgrade absent: got %+v, want nil", got.AlternateUpgrade)
	}
}

func TestAlternateUpgradeRejected(t *testing.T) {
	for name, bad := range map[string]any{
		"not an object":     "upgrade-peios",
		"missing message":   map[string]any{},
		"empty message":     map[string]any{"message": ""},
		"non-string":        map[string]any{"message": 1},
		"control character": map[string]any{"message": "a\tb"},
		"too long":          map[string]any{"message": strings.Repeat("x", 1025)},
	} {
		t.Run(name, func(t *testing.T) {
			m := baseManifest()
			m["alternate_upgrade"] = bad
			wantReject(t, m)
		})
	}
	// Exactly the limit is accepted; the newline is the one permitted
	// control character.
	m := baseManifest()
	m["alternate_upgrade"] = map[string]any{"message": strings.Repeat("x", 1023) + "\n"}
	mustDecode(t, m)
}
