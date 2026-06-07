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
	"github.com/peios/peipkg/internal/config"
	"github.com/peios/peipkg/internal/db"
)

// TestFetchAndAssemble runs the fetch and assemble stages end to end
// against a synthetic .peipkg, verifying that the produced root has the
// expected payload, the .repo configuration, and a populated database.
func TestFetchAndAssemble(t *testing.T) {
	binContent := []byte("#!/bin/sh\necho hi\n")
	cfgContent := []byte("foo = 1\n")
	sizeInstalled := int64(len(binContent) + len(cfgContent))

	entries := []testEntry{
		{Path: "etc", IsDir: true},
		{Path: "etc/foo.conf", Content: cfgContent},
		{Path: "usr", IsDir: true},
		{Path: "usr/bin", IsDir: true},
		{Path: "usr/bin/foo", Content: binContent},
	}
	manifestJSON := minimalManifestJSON(t, "foo", "1.0-1", "x86_64", sizeInstalled)
	raw := buildPeipkg(t, manifestJSON, entries)

	// Sanity-check that peipkg's verifier accepts what the test helper
	// produced — if it does not, the helper is the bug, not assemble.
	if _, err := archive.VerifyFormat(bytes.NewReader(raw)); err != nil {
		t.Fatalf("archive.VerifyFormat rejected the test .peipkg: %v", err)
	}

	sum := sha256.Sum256(raw)
	hash := hex.EncodeToString(sum[:])
	sourceDate := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	pkgURL := "https://pkgs.peios.org/pool/foo.peipkg"

	m := Manifest{
		Arch:       "x86_64",
		SourceDate: sourceDate,
		Repositories: []config.RepoConfig{{
			Name:            "official",
			BaseURL:         "https://pkgs.peios.org",
			Priority:        10,
			SignaturePolicy: config.PolicyRequired,
			TrustAnchors:    []string{strings.Repeat("a", 64)},
		}},
		Packages: []PackageRequest{{Name: "foo"}},
	}
	lock := Lock{
		Arch: m.Arch, SourceDate: sourceDate, Manifest: "test.toml",
		Packages: []LockedPackage{{
			Name: "foo", Version: "1.0-1", Architecture: "x86_64",
			Source: "official", URL: pkgURL, Hash: hash,
		}},
	}
	fetcher := fakeFetcher{pkgURL: raw}
	ctx := context.Background()

	fetched, err := fetchAll(ctx, lock, fetcher)
	if err != nil {
		t.Fatalf("fetchAll: %v", err)
	}
	if len(fetched) != 1 || fetched[0].Locked.Name != "foo" {
		t.Fatalf("fetched = %+v", fetched)
	}

	root := filepath.Join(t.TempDir(), "root")
	if err := assemble(ctx, root, m, fetched); err != nil {
		t.Fatalf("assemble: %v", err)
	}

	// Payload landed at the expected paths with the expected content.
	if got, err := os.ReadFile(filepath.Join(root, "usr/bin/foo")); err != nil {
		t.Errorf("usr/bin/foo: %v", err)
	} else if !bytes.Equal(got, binContent) {
		t.Errorf("usr/bin/foo content mismatch")
	}
	if got, err := os.ReadFile(filepath.Join(root, "etc/foo.conf")); err != nil {
		t.Errorf("etc/foo.conf: %v", err)
	} else if !bytes.Equal(got, cfgContent) {
		t.Errorf("etc/foo.conf content mismatch")
	}

	// The .repo file was written so the booted root inherits the
	// manifest's repository configuration.
	if _, err := os.Stat(filepath.Join(root, "conf/peipkg/official.repo")); err != nil {
		t.Errorf("conf/peipkg/official.repo missing: %v", err)
	}

	// The seeded database has the right meta, package, and file rows.
	store, err := db.Open(ctx, filepath.Join(root, "var/lib/peipkg/db.sqlite"))
	if err != nil {
		t.Fatalf("opening seeded db: %v", err)
	}
	defer store.Close()

	if arch, found, err := store.Meta(ctx, "primary_arch"); err != nil || !found || arch != "x86_64" {
		t.Errorf("primary_arch = %q (found=%v, err=%v)", arch, found, err)
	}

	pkgs, err := store.ListPackages(ctx)
	if err != nil {
		t.Fatalf("listing packages: %v", err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("got %d packages, want 1", len(pkgs))
	}
	p := pkgs[0]
	if p.Name != "foo" || p.Version != "1.0-1" || p.Architecture != "x86_64" {
		t.Errorf("package = %+v", p)
	}
	if p.OriginRepo != "official" {
		t.Errorf("OriginRepo = %q, want official", p.OriginRepo)
	}
	if !p.InstalledAt.Equal(sourceDate) {
		t.Errorf("InstalledAt = %v, want %v", p.InstalledAt, sourceDate)
	}

	pf, err := store.PackageFiles(ctx, "foo")
	if err != nil {
		t.Fatalf("listing package files: %v", err)
	}
	// Three directories and two files.
	if len(pf) != 5 {
		t.Errorf("got %d package files, want 5: %+v", len(pf), pf)
	}
}

// TestFetchHashMismatch confirms the fetch stage rejects a package whose
// bytes do not hash to the lock's recorded value.
func TestFetchHashMismatch(t *testing.T) {
	raw := buildPeipkg(t, minimalManifestJSON(t, "x", "1.0-1", "x86_64", 0), nil)
	pkgURL := "https://example/x.peipkg"
	lock := Lock{
		Arch: "x86_64", SourceDate: time.Now(),
		Packages: []LockedPackage{{
			Name: "x", Version: "1.0-1", Architecture: "x86_64",
			Source: "official", URL: pkgURL, Hash: strings.Repeat("d", 64),
		}},
	}
	fetcher := fakeFetcher{pkgURL: raw}
	_, err := fetchAll(context.Background(), lock, fetcher)
	if err == nil {
		t.Fatal("fetchAll accepted a hash mismatch")
	}
	if !strings.Contains(err.Error(), "hash mismatch") {
		t.Errorf("error %q does not mention hash mismatch", err)
	}
}

// TestBuildFlagConflict confirms --locked and --update are exclusive.
func TestBuildFlagConflict(t *testing.T) {
	err := Build(context.Background(), BuildOptions{
		ManifestPath: "anywhere",
		OutDir:       "anywhere",
		Locked:       true,
		Update:       true,
	})
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("got %v, want a mutual-exclusion error", err)
	}
}

func TestBuildWithResultUsesExplicitLockPath(t *testing.T) {
	payload := []byte("#!/bin/sh\n")
	raw := buildPeipkg(t,
		minimalManifestJSON(t, "foo", "1.0-1", "x86_64", int64(len(payload))),
		[]testEntry{{Path: "usr/bin/foo", Content: payload}})
	sum := sha256.Sum256(raw)

	dir := t.TempDir()
	pkgPath := filepath.Join(dir, "foo.peipkg")
	if err := os.WriteFile(pkgPath, raw, 0o644); err != nil {
		t.Fatalf("writing package: %v", err)
	}
	manifestPath := filepath.Join(dir, "manifest.toml")
	if err := os.WriteFile(manifestPath, []byte(`
schema = 1
arch = "x86_64"
source_date = "2026-06-01T00:00:00Z"

[[package]]
name = "foo"
`), 0o644); err != nil {
		t.Fatalf("writing manifest: %v", err)
	}
	lockPath := filepath.Join(dir, "locks", "root.lock.toml")
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o755); err != nil {
		t.Fatalf("creating lock dir: %v", err)
	}
	lock := Lock{
		Arch:       "x86_64",
		SourceDate: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
		Manifest:   filepath.Base(manifestPath),
		Packages: []LockedPackage{{
			Name:         "foo",
			Version:      "1.0-1",
			Architecture: "x86_64",
			Source:       LocalSource,
			URL:          pkgPath,
			Hash:         hex.EncodeToString(sum[:]),
		}},
	}
	encoded, err := lock.Encode()
	if err != nil {
		t.Fatalf("encoding lock: %v", err)
	}
	if err := os.WriteFile(lockPath, encoded, 0o644); err != nil {
		t.Fatalf("writing lock: %v", err)
	}

	outDir := filepath.Join(dir, "root")
	result, err := BuildWithResult(context.Background(), BuildOptions{
		ManifestPath: manifestPath,
		OutDir:       outDir,
		LockPath:     lockPath,
		Locked:       true,
	})
	if err != nil {
		t.Fatalf("BuildWithResult: %v", err)
	}
	if result.RootDir != outDir || result.LockPath != lockPath || result.PackageCount != 1 {
		t.Fatalf("result = %+v", result)
	}
	if _, err := os.Stat(filepath.Join(outDir, "var/lib/peipkg/db.sqlite")); err != nil {
		t.Fatalf("seeded database missing: %v", err)
	}
}
