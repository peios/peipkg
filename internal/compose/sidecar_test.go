package compose

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/peios/peipkg/internal/archive"
	"github.com/peios/peipkg/internal/db"
	"github.com/peios/peipkg/internal/pipsig"
)

// sigBlob is a well-formed signature blob: the version byte and 3309
// bytes of (here, zero) signature.
func sigBlob() []byte {
	b := make([]byte, pipsig.BlobLen)
	b[0] = pipsig.Version
	return b
}

// TestAssembleStampsSidecars: a `<file>.peios.sig` entry becomes the
// target's security.peios.sig attribute and is neither written to disk
// nor recorded as a package file. Stamp is replaced by a recorder —
// security.* attributes need CAP_SYS_ADMIN, which the test lacks.
func TestAssembleStampsSidecars(t *testing.T) {
	fw := []byte("firmware bytes")
	entries := []testEntry{
		{Path: "usr", IsDir: true},
		{Path: "usr/lib", IsDir: true},
		{Path: "usr/lib/firmware", IsDir: true},
		{Path: "usr/lib/firmware/fw.bin.zst", Content: fw},
		{Path: "usr/lib/firmware/fw.bin.zst.peios.sig", Content: sigBlob()},
	}
	manifestJSON := minimalManifestJSON(t, "fw", "1.0-1", "x86_64", int64(len(fw)+pipsig.BlobLen))
	raw := buildPeipkg(t, manifestJSON, entries)
	if _, err := archive.VerifyFormat(bytes.NewReader(raw)); err != nil {
		t.Fatalf("archive.VerifyFormat rejected the test .peipkg: %v", err)
	}

	stamped := map[string][]byte{}
	orig := pipsig.Stamp
	pipsig.Stamp = func(path string, b []byte) error { stamped[path] = b; return nil }
	t.Cleanup(func() { pipsig.Stamp = orig })

	sum := sha256.Sum256(raw)
	sourceDate := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	pkgURL := "https://pkgs.peios.org/pool/fw.peipkg"
	m := Manifest{Arch: "x86_64", SourceDate: sourceDate, Packages: []PackageRequest{{Name: "fw"}}}
	lock := Lock{
		Arch: m.Arch, SourceDate: sourceDate, Manifest: "test.toml",
		Packages: []LockedPackage{{
			Name: "fw", Version: "1.0-1", Architecture: "x86_64",
			Source: "official", URL: pkgURL, Hash: hex.EncodeToString(sum[:]),
		}},
	}
	ctx := context.Background()
	fetched, err := fetchAll(ctx, lock, fakeFetcher{pkgURL: raw})
	if err != nil {
		t.Fatalf("fetchAll: %v", err)
	}
	root := filepath.Join(t.TempDir(), "root")
	if err := assemble(ctx, root, m, fetched, false, nil); err != nil {
		t.Fatalf("assemble: %v", err)
	}

	target := filepath.Join(root, "usr/lib/firmware/fw.bin.zst")
	if got, err := os.ReadFile(target); err != nil || !bytes.Equal(got, fw) {
		t.Errorf("target: content %q, err %v", got, err)
	}
	if !bytes.Equal(stamped[target], sigBlob()) {
		t.Errorf("target was not stamped with the blob (stamped: %v)", keysOf(stamped))
	}
	if _, err := os.Lstat(target + pipsig.Suffix); !os.IsNotExist(err) {
		t.Errorf("sidecar was materialised (err %v)", err)
	}

	store, err := db.Open(ctx, filepath.Join(root, "var/state/peipkg/db.sqlite"))
	if err != nil {
		t.Fatalf("opening seeded db: %v", err)
	}
	defer store.Close()
	files, err := store.PackageFiles(ctx, "fw")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f.Path, pipsig.Suffix) {
			t.Errorf("sidecar recorded as a package file: %s", f.Path)
		}
	}
}

// TestComposeRejectsOrphanSidecar: a sidecar without its target fails
// the layout check before anything is written.
func TestComposeRejectsOrphanSidecar(t *testing.T) {
	entries := []testEntry{
		{Path: "usr", IsDir: true},
		{Path: "usr/lib", IsDir: true},
		{Path: "usr/lib/firmware", IsDir: true},
		{Path: "usr/lib/firmware/fw.bin.zst.peios.sig", Content: sigBlob()},
	}
	manifestJSON := minimalManifestJSON(t, "fw", "1.0-1", "x86_64", int64(pipsig.BlobLen))
	raw := buildPeipkg(t, manifestJSON, entries)
	sum := sha256.Sum256(raw)
	sourceDate := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	pkgURL := "https://pkgs.peios.org/pool/fw.peipkg"
	m := Manifest{Arch: "x86_64", SourceDate: sourceDate, Packages: []PackageRequest{{Name: "fw"}}}
	lock := Lock{
		Arch: m.Arch, SourceDate: sourceDate, Manifest: "test.toml",
		Packages: []LockedPackage{{
			Name: "fw", Version: "1.0-1", Architecture: "x86_64",
			Source: "official", URL: pkgURL, Hash: hex.EncodeToString(sum[:]),
		}},
	}
	ctx := context.Background()
	fetched, err := fetchAll(ctx, lock, fakeFetcher{pkgURL: raw})
	if err != nil {
		t.Fatalf("fetchAll: %v", err)
	}
	err = assemble(ctx, filepath.Join(t.TempDir(), "root"), m, fetched, false, nil)
	if err == nil || !strings.Contains(err.Error(), "sidecar") {
		t.Errorf("orphan sidecar: err = %v", err)
	}
}

func keysOf(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestAssembleRecordsSidecars: with a recorder supplied, a sidecar is
// handed to it against the target's out-relative path and Stamp is not
// called — the unprivileged image-builder path.
func TestAssembleRecordsSidecars(t *testing.T) {
	fw := []byte("firmware bytes")
	entries := []testEntry{
		{Path: "usr", IsDir: true},
		{Path: "usr/lib", IsDir: true},
		{Path: "usr/lib/firmware", IsDir: true},
		{Path: "usr/lib/firmware/fw.bin.zst", Content: fw},
		{Path: "usr/lib/firmware/fw.bin.zst.peios.sig", Content: sigBlob()},
	}
	manifestJSON := minimalManifestJSON(t, "fw", "1.0-1", "x86_64", int64(len(fw)+pipsig.BlobLen))
	raw := buildPeipkg(t, manifestJSON, entries)

	orig := pipsig.Stamp
	pipsig.Stamp = func(path string, b []byte) error {
		t.Errorf("Stamp called for %s although a recorder was supplied", path)
		return nil
	}
	t.Cleanup(func() { pipsig.Stamp = orig })

	sum := sha256.Sum256(raw)
	sourceDate := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	pkgURL := "https://pkgs.peios.org/pool/fw.peipkg"
	m := Manifest{Arch: "x86_64", SourceDate: sourceDate, Packages: []PackageRequest{{Name: "fw"}}}
	lock := Lock{
		Arch: m.Arch, SourceDate: sourceDate, Manifest: "test.toml",
		Packages: []LockedPackage{{
			Name: "fw", Version: "1.0-1", Architecture: "x86_64",
			Source: "official", URL: pkgURL, Hash: hex.EncodeToString(sum[:]),
		}},
	}
	ctx := context.Background()
	fetched, err := fetchAll(ctx, lock, fakeFetcher{pkgURL: raw})
	if err != nil {
		t.Fatalf("fetchAll: %v", err)
	}
	recorded := map[string][]byte{}
	record := func(rel string, b []byte) error { recorded[rel] = b; return nil }
	root := filepath.Join(t.TempDir(), "root")
	if err := assemble(ctx, root, m, fetched, false, record); err != nil {
		t.Fatalf("assemble: %v", err)
	}
	if !bytes.Equal(recorded["usr/lib/firmware/fw.bin.zst"], sigBlob()) {
		t.Errorf("sidecar not recorded against its out-relative path (recorded: %v)", keysOf(recorded))
	}
	if _, err := os.Lstat(filepath.Join(root, "usr/lib/firmware/fw.bin.zst"+pipsig.Suffix)); !os.IsNotExist(err) {
		t.Errorf("sidecar was materialised (err %v)", err)
	}
}
