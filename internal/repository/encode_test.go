package repository_test

import (
	"strings"
	"testing"
	"time"

	"github.com/peios/peipkg/internal/manifest"
	"github.com/peios/peipkg/internal/repository"
	"github.com/peios/peipkg/internal/version"
)

func mustVersion(t *testing.T, s string) version.Version {
	t.Helper()
	v, err := version.Parse(s)
	if err != nil {
		t.Fatalf("version.Parse(%q): %v", s, err)
	}
	return v
}

func mustConstraint(t *testing.T, s string) version.Constraint {
	t.Helper()
	c, err := version.ParseConstraint(s)
	if err != nil {
		t.Fatalf("version.ParseConstraint(%q): %v", s, err)
	}
	return c
}

func sampleDescriptor(t *testing.T) repository.Descriptor {
	t.Helper()
	return repository.Descriptor{
		RepoName:    "peios-official",
		Description: "Official Peios package repository",
		Keys: []repository.DescriptorKey{
			// Deliberately out of order: §6.1.3 requires the encoder to
			// sort, not the caller.
			{Fingerprint: strings.Repeat("f", 64), URL: "/keys/f.pub",
				Status: repository.KeyActive},
			{Fingerprint: strings.Repeat("a", 64), URL: "/keys/a.pub",
				Status:     repository.KeyTransitioning,
				ValidUntil: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)},
			{Fingerprint: strings.Repeat("0", 64), URL: "/keys/0.pub",
				Status: repository.KeyRevoked},
		},
		ActiveIndex: repository.IndexPointer{
			URL: "/index/active.json", SignatureURL: "/index/active.json.sig"},
		ArchiveIndex: repository.IndexPointer{
			URL: "/index/archive.json", SignatureURL: "/index/archive.json.sig"},
	}
}

// TestDescriptorRoundTrip is the guarantee this package exists to make:
// a descriptor written by the publisher is one the consumer reads back
// unchanged. Encode and Decode share their wire structs, but sharing a
// struct does not prove agreement about which fields are required, how
// timestamps render, or what an absent value means.
func TestDescriptorRoundTrip(t *testing.T) {
	want := sampleDescriptor(t)
	encoded, err := repository.EncodeDescriptor(want)
	if err != nil {
		t.Fatalf("EncodeDescriptor: %v", err)
	}
	got, err := repository.DecodeDescriptor(encoded)
	if err != nil {
		t.Fatalf("DecodeDescriptor of our own output: %v", err)
	}

	if got.RepoName != want.RepoName || got.Description != want.Description {
		t.Errorf("identity changed: %+v", got)
	}
	if got.ActiveIndex != want.ActiveIndex || got.ArchiveIndex != want.ArchiveIndex {
		t.Errorf("index pointers changed: %+v", got)
	}
	if len(got.Keys) != len(want.Keys) {
		t.Fatalf("got %d keys, want %d", len(got.Keys), len(want.Keys))
	}
	// §6.1.3: sorted lexicographically by fingerprint.
	for i := 1; i < len(got.Keys); i++ {
		if got.Keys[i-1].Fingerprint >= got.Keys[i].Fingerprint {
			t.Errorf("keys are not sorted by fingerprint: %v", got.Keys)
		}
	}
	for _, k := range got.Keys {
		if k.Status == repository.KeyTransitioning && k.ValidUntil.IsZero() {
			t.Errorf("transitioning key %s lost its valid_until", k.Fingerprint)
		}
	}
}

// TestEncodeDescriptorIsStable pins the §6.1.7 determinism requirement:
// the same descriptor renders to the same bytes, so a republish that
// changed nothing produces a signature that changed nothing.
func TestEncodeDescriptorIsStable(t *testing.T) {
	d := sampleDescriptor(t)
	first, err := repository.EncodeDescriptor(d)
	if err != nil {
		t.Fatalf("EncodeDescriptor: %v", err)
	}
	decoded, err := repository.DecodeDescriptor(first)
	if err != nil {
		t.Fatalf("DecodeDescriptor: %v", err)
	}
	second, err := repository.EncodeDescriptor(decoded)
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}
	if string(first) != string(second) {
		t.Errorf("encode is not stable across a round trip:\n--- first ---\n%s\n--- second ---\n%s",
			first, second)
	}
}

func TestEncodeDescriptorRejectsMalformedKeySets(t *testing.T) {
	base := sampleDescriptor(t)
	cases := map[string]func(d *repository.Descriptor){
		"no active key": func(d *repository.Descriptor) {
			d.Keys = []repository.DescriptorKey{{
				Fingerprint: strings.Repeat("a", 64), URL: "/keys/a.pub",
				Status: repository.KeyRevoked}}
		},
		"duplicate fingerprint": func(d *repository.Descriptor) {
			d.Keys = append(d.Keys, d.Keys[0])
		},
		"transitioning without valid_until": func(d *repository.Descriptor) {
			d.Keys[1].ValidUntil = time.Time{}
		},
		"active with valid_until": func(d *repository.Descriptor) {
			d.Keys[0].ValidUntil = time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
		},
		"unknown status": func(d *repository.Descriptor) {
			d.Keys[0].Status = "retired"
		},
		"key with no url": func(d *repository.Descriptor) {
			d.Keys[0].URL = ""
		},
		"no keys at all": func(d *repository.Descriptor) {
			d.Keys = nil
		},
		"no name": func(d *repository.Descriptor) {
			d.RepoName = ""
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			d := sampleDescriptor(t)
			d.Description = base.Description
			mutate(&d)
			if _, err := repository.EncodeDescriptor(d); err == nil {
				t.Fatal("encoded a descriptor that should have been refused")
			}
		})
	}
}

func sampleEntry(t *testing.T, name, ver string) repository.IndexEntry {
	t.Helper()
	return repository.IndexEntry{
		Name:         name,
		Version:      mustVersion(t, ver),
		Architecture: "x86_64",
		Description:  "a package",
		License:      "MIT",
		Homepage:     "https://example.org/?a=1&b=2",
		DefaultRoot:  "initramfs",
		Dependencies: []manifest.Dependency{
			{Name: "glibc", Constraint: mustConstraint(t, ">= 2.43-1")},
			// No constraint: the encoder must OMIT the field rather than
			// render the zero constraint's display form, "any".
			{Name: "peiosutils"},
			{Name: "disk-boot-irf", Constraint: mustConstraint(t, ">= 1.0.0"),
				Root: "initramfs"},
		},
		Conflicts:      []manifest.Dependency{{Name: "live-boot-irf"}},
		Provides:       []manifest.Provides{{Name: "root-mounted"}},
		Replaces:       []manifest.Replaces{{Name: "stratafs-base-topo"}},
		SideEffects:    []manifest.SideEffect{manifest.SideEffectDepmod},
		SizeCompressed: 941,
		SizeInstalled:  73,
		Hash:           strings.Repeat("ab", 32),
		URL:            "/p/" + name + "/" + ver + "/" + name + "_" + ver + "_x86_64.peipkg",
		BuildTimestamp: time.Date(2026, 8, 18, 2, 15, 6, 0, time.UTC),
		BuildFarmID:    "local",
	}
}

// TestIndexRoundTrip carries every optional field through the wire and
// back. The dependency arrays are the interesting part: they are the
// only place the index re-serialises structured data rather than
// scalars, and §6.2.5 requires them to match the source manifest
// exactly.
func TestIndexRoundTrip(t *testing.T) {
	want := repository.Index{
		RepoName:     "peios-official",
		Kind:         repository.IndexActive,
		IndexVersion: 7,
		GeneratedAt:  time.Date(2026, 8, 18, 1, 0, 0, 0, time.UTC),
		Packages:     []repository.IndexEntry{sampleEntry(t, "disk-boot", "1.0.0-6")},
	}
	encoded, err := repository.EncodeIndex(want)
	if err != nil {
		t.Fatalf("EncodeIndex: %v", err)
	}
	got, err := repository.DecodeIndex(encoded)
	if err != nil {
		t.Fatalf("DecodeIndex of our own output: %v", err)
	}
	if got.RepoName != want.RepoName || got.Kind != want.Kind ||
		got.IndexVersion != want.IndexVersion || !got.GeneratedAt.Equal(want.GeneratedAt) {
		t.Fatalf("index header changed: %+v", got)
	}
	if len(got.Packages) != 1 {
		t.Fatalf("got %d entries, want 1", len(got.Packages))
	}

	a, b := want.Packages[0], got.Packages[0]
	if a.Name != b.Name || a.Version.String() != b.Version.String() ||
		a.Architecture != b.Architecture || a.Description != b.Description ||
		a.License != b.License || a.Homepage != b.Homepage ||
		a.DefaultRoot != b.DefaultRoot || a.Hash != b.Hash || a.URL != b.URL ||
		a.SizeCompressed != b.SizeCompressed || a.SizeInstalled != b.SizeInstalled ||
		a.BuildFarmID != b.BuildFarmID || !a.BuildTimestamp.Equal(b.BuildTimestamp) {
		t.Errorf("scalar fields changed:\nwant %+v\ngot  %+v", a, b)
	}
	if len(b.Dependencies) != 3 {
		t.Fatalf("got %d dependencies, want 3", len(b.Dependencies))
	}
	// Looked up by name, not position: the encoder sorts the array
	// (§4.1.6), so the input order is deliberately not preserved.
	deps := make(map[string]manifest.Dependency, len(b.Dependencies))
	for _, d := range b.Dependencies {
		deps[d.Name] = d
	}
	if !deps["peiosutils"].Constraint.Any() {
		t.Errorf("an unconstrained dependency came back constrained as %q",
			deps["peiosutils"].Constraint)
	}
	if got := deps["glibc"].Constraint.String(); got != ">= 2.43-1" {
		t.Errorf("constraint changed: got %q, want %q", got, ">= 2.43-1")
	}
	if deps["disk-boot-irf"].Root != "initramfs" {
		t.Errorf("cross-root dependency lost its root: %+v", deps["disk-boot-irf"])
	}
	if len(b.Conflicts) != 1 || len(b.Provides) != 1 ||
		len(b.Replaces) != 1 || len(b.SideEffects) != 1 {
		t.Errorf("an array was dropped: %+v", b)
	}
}

// TestUnconstrainedDependencyOmitsTheField is the specific trap worth
// pinning by inspection rather than by round trip: version.Constraint's
// String renders the zero value as "any", which is a display form with
// no wire meaning. Emitting it would produce an index that this
// package's own decoder rejects.
func TestUnconstrainedDependencyOmitsTheField(t *testing.T) {
	entry := sampleEntry(t, "x", "1.0.0-1")
	entry.Dependencies = []manifest.Dependency{{Name: "peiosutils"}}
	encoded, err := repository.EncodeIndex(repository.Index{
		RepoName: "r", Kind: repository.IndexActive, IndexVersion: 1,
		GeneratedAt: time.Now().UTC(), Packages: []repository.IndexEntry{entry},
	})
	if err != nil {
		t.Fatalf("EncodeIndex: %v", err)
	}
	if strings.Contains(string(encoded), `"constraint"`) {
		t.Errorf("an unconstrained dependency emitted a constraint field:\n%s", encoded)
	}
	if strings.Contains(string(encoded), `"any"`) {
		t.Errorf("the zero constraint leaked its display form into the wire:\n%s", encoded)
	}
}

// TestEncodeIndexDoesNotEscapeHTML keeps a URL readable. encoding/json
// escapes &, < and > into \u0026 and friends by default; such an index
// still parses, but no longer matches byte for byte the manifest §6.2.5
// says it must mirror.
func TestEncodeIndexDoesNotEscapeHTML(t *testing.T) {
	encoded, err := repository.EncodeIndex(repository.Index{
		RepoName: "r", Kind: repository.IndexActive, IndexVersion: 1,
		GeneratedAt: time.Now().UTC(),
		Packages:    []repository.IndexEntry{sampleEntry(t, "x", "1.0.0-1")},
	})
	if err != nil {
		t.Fatalf("EncodeIndex: %v", err)
	}
	if strings.Contains(string(encoded), `\u0026`) {
		t.Errorf("HTML escaping is on:\n%s", encoded)
	}
	if !strings.Contains(string(encoded), "?a=1&b=2") {
		t.Errorf("the homepage URL did not survive verbatim:\n%s", encoded)
	}
}

// TestArchiveOrdersVersionsDescending pins §6.3.6. A consumer scanning
// for the newest version satisfying a constraint is entitled to stop at
// the first match within a name group, which is only sound if the
// group really is highest-first.
func TestArchiveOrdersVersionsDescending(t *testing.T) {
	encoded, err := repository.EncodeIndex(repository.Index{
		RepoName: "r", Kind: repository.IndexArchive, IndexVersion: 1,
		GeneratedAt: time.Now().UTC(),
		Packages: []repository.IndexEntry{
			sampleEntry(t, "b", "1.0.0-1"),
			sampleEntry(t, "a", "1.0.0-2"),
			sampleEntry(t, "a", "2.0.0-1"),
			sampleEntry(t, "a", "1.0.0-10"),
		},
	})
	if err != nil {
		t.Fatalf("EncodeIndex: %v", err)
	}
	idx, err := repository.DecodeIndex(encoded)
	if err != nil {
		t.Fatalf("DecodeIndex: %v", err)
	}
	var got []string
	for _, e := range idx.Packages {
		got = append(got, e.Name+" "+e.Version.String())
	}
	want := []string{"a 2.0.0-1", "a 1.0.0-10", "a 1.0.0-2", "b 1.0.0-1"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

// TestActiveIndexRefusesADuplicateName pins §6.2.9. Per-name uniqueness
// is what makes the active index "active"; two entries would leave a
// consumer choosing between them with no rule to choose by.
func TestActiveIndexRefusesADuplicateName(t *testing.T) {
	_, err := repository.EncodeIndex(repository.Index{
		RepoName: "r", Kind: repository.IndexActive, IndexVersion: 1,
		GeneratedAt: time.Now().UTC(),
		Packages: []repository.IndexEntry{
			sampleEntry(t, "a", "1.0.0-1"),
			sampleEntry(t, "a", "2.0.0-1"),
		},
	})
	if err == nil {
		t.Fatal("the active index accepted the same name twice")
	}
}

func TestEncodeIndexRejectsMalformedHeaders(t *testing.T) {
	valid := repository.Index{
		RepoName: "r", Kind: repository.IndexActive, IndexVersion: 1,
		GeneratedAt: time.Now().UTC(),
	}
	cases := map[string]func(i *repository.Index){
		// §6.2.3 requires a POSITIVE integer, and a consumer's rollback
		// floor starts at zero — so a zeroth index is rejected on the
		// very first refresh.
		"zero index_version":     func(i *repository.Index) { i.IndexVersion = 0 },
		"negative index_version": func(i *repository.Index) { i.IndexVersion = -1 },
		"no repo name":           func(i *repository.Index) { i.RepoName = "" },
		"unknown kind":           func(i *repository.Index) { i.Kind = "current" },
		"no generated_at":        func(i *repository.Index) { i.GeneratedAt = time.Time{} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			idx := valid
			mutate(&idx)
			if _, err := repository.EncodeIndex(idx); err == nil {
				t.Fatal("encoded an index that should have been refused")
			}
		})
	}
}

// TestGeneratedAtIsRenderedInUTC guards a failure that only appears off
// UTC: a timestamp rendered with a numeric offset is valid RFC 3339 and
// is then refused by the decoder, which requires a trailing Z.
func TestGeneratedAtIsRenderedInUTC(t *testing.T) {
	zone := time.FixedZone("UTC+9", 9*60*60)
	encoded, err := repository.EncodeIndex(repository.Index{
		RepoName: "r", Kind: repository.IndexActive, IndexVersion: 1,
		GeneratedAt: time.Date(2026, 8, 18, 12, 0, 0, 0, zone),
	})
	if err != nil {
		t.Fatalf("EncodeIndex: %v", err)
	}
	if !strings.Contains(string(encoded), `"generated_at": "2026-08-18T03:00:00Z"`) {
		t.Errorf("timestamp was not converted to UTC:\n%s", encoded)
	}
	if _, err := repository.DecodeIndex(encoded); err != nil {
		t.Fatalf("our own output does not decode: %v", err)
	}
}
