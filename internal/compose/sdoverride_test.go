package compose

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/peios/libp-go/sddl"

	"github.com/peios/peipkg/internal/sdstamp"
)

// base64Raw is the on-wire encoding of an sd field: RFC 4648 §4 without
// padding (§3.3.5).
func base64Raw(b []byte) string { return base64.RawStdEncoding.EncodeToString(b) }

// realSD compiles an SDDL string the way pack does, so the bytes the
// test carries are the bytes a real package would.
func realSD(t *testing.T, text string) []byte {
	t.Helper()
	d, err := sddl.Parse(text)
	if err != nil {
		t.Fatalf("sddl.Parse(%q): %v", text, err)
	}
	raw, err := d.Marshal()
	if err != nil {
		t.Fatalf("marshal %q: %v", text, err)
	}
	return raw
}

// manifestWithSDOverrides is minimalManifestJSON plus an sd_overrides
// array. The array must be sorted by path, as §3.3.5 requires.
func manifestWithSDOverrides(t *testing.T, name, ver, arch string, sizeInstalled int64,
	overrides []map[string]any) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(minimalManifestJSON(t, name, ver, arch, sizeInstalled), &m); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	m["sd_overrides"] = overrides
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("encode manifest: %v", err)
	}
	return data
}

// TestComposeRecordsSDOverrides: compose hands each override to the
// recorder against its out-relative path and the security.peios.sd
// attribute name, rather than setting it — which is what lets an
// unprivileged image builder carry a descriptor it cannot write, by
// naming it in the tar it streams to mksquashfs.
//
// Both an overridden directory and an overridden regular file are
// covered: unlike a signature sidecar, an override may name either.
func TestComposeRecordsSDOverrides(t *testing.T) {
	homeSD := realSD(t, "O:SYG:SYD:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)(A;;GX;;;WD)")
	toolSD := realSD(t, "O:SYG:SYD:(A;;GA;;;SY)")
	body := []byte("a tool")
	entries := []testEntry{
		{Path: "usr", IsDir: true},
		{Path: "usr/bin", IsDir: true},
		{Path: "usr/bin/tool", Content: body},
		{Path: "usr/share", IsDir: true},
	}
	manifestJSON := manifestWithSDOverrides(t, "fsbase", "1.0-1", "x86_64", int64(len(body)),
		[]map[string]any{
			{"path": "usr/bin/tool", "sd": base64Raw(toolSD)},
			{"path": "usr/share", "sd": base64Raw(homeSD)},
		})
	raw := buildPeipkg(t, manifestJSON, entries)

	orig := sdstamp.Stamp
	sdstamp.Stamp = func(path string, _ []byte) error {
		t.Errorf("Stamp called for %s although a recorder was supplied", path)
		return nil
	}
	t.Cleanup(func() { sdstamp.Stamp = orig })

	sum := sha256.Sum256(raw)
	sourceDate := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	pkgURL := "https://pkgs.peios.org/pool/fsbase.peipkg"
	m := Manifest{Arch: "x86_64", SourceDate: sourceDate, Packages: []PackageRequest{{Name: "fsbase"}}}
	lock := Lock{
		Arch: m.Arch, SourceDate: sourceDate, Manifest: "test.toml",
		Packages: []LockedPackage{{
			Name: "fsbase", Version: "1.0-1", Architecture: "x86_64",
			Source: "official", URL: pkgURL, Hash: hex.EncodeToString(sum[:]),
		}},
	}
	ctx := context.Background()
	fetched, err := fetchAll(ctx, lock, fakeFetcher{pkgURL: raw})
	if err != nil {
		t.Fatalf("fetchAll: %v", err)
	}
	type rec struct {
		name  string
		value []byte
	}
	recorded := map[string]rec{}
	record := func(rel, name string, value []byte) error {
		recorded[rel] = rec{name: name, value: value}
		return nil
	}
	root := filepath.Join(t.TempDir(), "root")
	if err := assemble(ctx, root, m, fetched, false, record); err != nil {
		t.Fatalf("assemble: %v", err)
	}

	for path, want := range map[string][]byte{
		"usr/bin/tool": toolSD,
		"usr/share":    homeSD,
	} {
		got, ok := recorded[path]
		if !ok {
			t.Errorf("%s: no descriptor recorded", path)
			continue
		}
		if got.name != sdstamp.XattrName {
			t.Errorf("%s: recorded attribute %q, want %q", path, got.name, sdstamp.XattrName)
		}
		if !bytes.Equal(got.value, want) {
			t.Errorf("%s: recorded descriptor does not match the declared one", path)
		}
	}
	// An entry with no override is not recorded: inheritance is the
	// default, and it is expressed by the absence of an attribute.
	if _, ok := recorded["usr/bin"]; ok {
		t.Error("usr/bin was recorded although it declared no override")
	}
	if len(recorded) != 2 {
		t.Errorf("recorded %d descriptors, want 2", len(recorded))
	}
	// The payload still composed.
	if got, err := os.ReadFile(filepath.Join(root, "usr/bin/tool")); err != nil ||
		!bytes.Equal(got, body) {
		t.Errorf("composed file: content %q err %v", got, err)
	}
}
