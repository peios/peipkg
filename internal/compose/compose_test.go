package compose

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/peios/peipkg/internal/archive"
	"github.com/peios/peipkg/internal/config"
	"github.com/peios/peipkg/internal/db"
	"github.com/peios/peipkg/internal/resolver"
)

// TestFetchAndAssemble runs the fetch and assemble stages end to end
// against a synthetic .peipkg, verifying that the produced root has the
// expected payload, the .repo configuration, and a populated database.
func TestFetchAndAssemble(t *testing.T) {
	binContent := []byte("#!/bin/sh\necho hi\n")
	cfgContent := []byte("foo = 1\n")
	sizeInstalled := int64(len(binContent) + len(cfgContent))

	entries := []testEntry{
		{Path: "usr/etc", IsDir: true},
		{Path: "usr/etc/foo.conf", Content: cfgContent},
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
	if err := assemble(ctx, root, m, fetched, false); err != nil {
		t.Fatalf("assemble: %v", err)
	}

	// Payload landed at the expected paths with the expected content.
	if got, err := os.ReadFile(filepath.Join(root, "usr/bin/foo")); err != nil {
		t.Errorf("usr/bin/foo: %v", err)
	} else if !bytes.Equal(got, binContent) {
		t.Errorf("usr/bin/foo content mismatch")
	}
	if got, err := os.ReadFile(filepath.Join(root, "usr/etc/foo.conf")); err != nil {
		t.Errorf("usr/etc/foo.conf: %v", err)
	} else if !bytes.Equal(got, cfgContent) {
		t.Errorf("usr/etc/foo.conf content mismatch")
	}

	// The .repo file was written so the booted root inherits the
	// manifest's repository configuration.
	if _, err := os.Stat(filepath.Join(root, "conf/peipkg/official.repo")); err != nil {
		t.Errorf("conf/peipkg/official.repo missing: %v", err)
	}

	// The aggregate license inventory covers the composed package set.
	var inventory struct {
		SchemaVersion int    `json:"schema_version"`
		SourceDate    string `json:"source_date"`
		Packages      []struct {
			Name      string `json:"name"`
			Version   string `json:"version"`
			SourceRef string `json:"source_ref"`
			Root      string `json:"root"`
		} `json:"packages"`
	}
	invData, err := os.ReadFile(filepath.Join(root, "usr/share/licenses.json"))
	if err != nil {
		t.Fatalf("usr/share/licenses.json: %v", err)
	}
	if err := json.Unmarshal(invData, &inventory); err != nil {
		t.Fatalf("decoding licenses.json: %v", err)
	}
	if inventory.SchemaVersion != 1 || inventory.SourceDate != "2026-06-01T00:00:00Z" {
		t.Errorf("licenses.json header = %+v", inventory)
	}
	if len(inventory.Packages) != 1 || inventory.Packages[0].Name != "foo" ||
		inventory.Packages[0].Version != "1.0-1" || inventory.Packages[0].SourceRef != "test" ||
		inventory.Packages[0].Root != "" {
		t.Errorf("licenses.json packages = %+v", inventory.Packages)
	}

	// The seeded database has the right meta, package, and file rows.
	store, err := db.Open(ctx, filepath.Join(root, "var/state/peipkg/db.sqlite"))
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

// TestAssembleMaterializesClaims composes a root from a single claim-holding
// package (a prelude-shaped provider of the `init` role) and verifies the
// claim is reconciled: the holder and link rows are recorded, and the symlink
// is materialised in the root. peipkg-compose has no prior state, so the
// holder is auto-claimed and the provider's default path becomes the link.
func TestAssembleMaterializesClaims(t *testing.T) {
	bin := []byte("\x7fELF prelude\n")
	entries := []testEntry{
		{Path: "usr", IsDir: true},
		{Path: "usr/sbin", IsDir: true},
		{Path: "usr/sbin/prelude", Content: bin},
	}
	manifestJSON := providerManifestJSON(t, "prelude", "0.0.1-1", "x86_64",
		int64(len(bin)), "init", "bin", "/usr/sbin/prelude", "/init")
	raw := buildPeipkg(t, manifestJSON, entries)
	if _, err := archive.VerifyFormat(bytes.NewReader(raw)); err != nil {
		t.Fatalf("archive.VerifyFormat rejected the test .peipkg: %v", err)
	}

	sum := sha256.Sum256(raw)
	hash := hex.EncodeToString(sum[:])
	sourceDate := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	pkgURL := "https://pkgs.peios.org/pool/prelude.peipkg"

	m := Manifest{Arch: "x86_64", SourceDate: sourceDate, Packages: []PackageRequest{{Name: "prelude"}}}
	lock := Lock{
		Arch: m.Arch, SourceDate: sourceDate, Manifest: "test.toml",
		Packages: []LockedPackage{{
			Name: "prelude", Version: "0.0.1-1", Architecture: "x86_64",
			Source: "official", URL: pkgURL, Hash: hash,
		}},
	}
	ctx := context.Background()
	fetched, err := fetchAll(ctx, lock, fakeFetcher{pkgURL: raw})
	if err != nil {
		t.Fatalf("fetchAll: %v", err)
	}

	root := filepath.Join(t.TempDir(), "root")
	if err := assemble(ctx, root, m, fetched, false); err != nil {
		t.Fatalf("assemble: %v", err)
	}

	// The claim symlink /init -> /usr/sbin/prelude is materialised.
	info, err := os.Lstat(filepath.Join(root, "init"))
	if err != nil {
		t.Fatalf("/init not materialised: %v", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Errorf("/init is not a symlink (mode %v)", info.Mode())
	}
	// The on-disk link is relative (self-contained root); the DB keeps the
	// absolute logical target (asserted below).
	if target, err := os.Readlink(filepath.Join(root, "init")); err != nil {
		t.Errorf("readlink /init: %v", err)
	} else if target != "usr/sbin/prelude" {
		t.Errorf("/init -> %q, want usr/sbin/prelude", target)
	}

	// The holder and link rows were recorded in the seed transaction.
	store, err := db.Open(ctx, filepath.Join(root, "var/state/peipkg/db.sqlite"))
	if err != nil {
		t.Fatalf("opening seeded db: %v", err)
	}
	defer store.Close()

	holders, err := store.ClaimHolders(ctx)
	if err != nil {
		t.Fatalf("claim holders: %v", err)
	}
	if len(holders) != 1 || holders[0].Role != "init" || holders[0].Holder != "prelude" {
		t.Errorf("claim holders = %+v, want init -> prelude", holders)
	}
	links, err := store.ClaimLinks(ctx)
	if err != nil {
		t.Fatalf("claim links: %v", err)
	}
	if len(links) != 1 || links[0].Path != "/init" || links[0].Target != "/usr/sbin/prelude" {
		t.Errorf("claim links = %+v, want /init -> /usr/sbin/prelude", links)
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

func TestEnsureLockMatchesManifestDigest(t *testing.T) {
	sourceDate := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	first := Manifest{
		Arch: "x86_64", SourceDate: sourceDate,
		Packages: []PackageRequest{{Name: "foo"}},
	}
	second := first
	second.Packages = []PackageRequest{{Name: "bar"}}
	lock := Lock{
		Arch: first.Arch, SourceDate: first.SourceDate,
		ManifestDigest: manifestDigest(first),
		Packages: []LockedPackage{{
			Name: "foo", Version: "1.0-1", Architecture: "x86_64",
			Source: LocalSource, URL: "/tmp/foo.peipkg", Hash: strings.Repeat("a", 64),
		}},
	}
	if err := ensureLockMatches(lock, first); err != nil {
		t.Fatalf("ensureLockMatches(first): %v", err)
	}
	if err := ensureLockMatches(lock, second); err == nil ||
		!strings.Contains(err.Error(), "manifest_digest") {
		t.Fatalf("ensureLockMatches(second) = %v, want manifest_digest mismatch", err)
	}
}

func TestLocalCandidatesResolveRelativeToManifestDir(t *testing.T) {
	dir := t.TempDir()
	pkgDir := filepath.Join(dir, "pkgs")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatalf("mkdir pkgs: %v", err)
	}
	payload := []byte("x")
	raw := buildPeipkg(t,
		minimalManifestJSON(t, "foo", "1.0-1", "x86_64", int64(len(payload))),
		[]testEntry{{Path: "usr/bin/foo", Content: payload}})
	pkgPath := filepath.Join(pkgDir, "foo.peipkg")
	if err := os.WriteFile(pkgPath, raw, 0o644); err != nil {
		t.Fatalf("write package: %v", err)
	}

	oldwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	other := t.TempDir()
	if err := os.Chdir(other); err != nil {
		t.Fatalf("Chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldwd) })

	candidates, err := localCandidates([]string{"pkgs/*.peipkg"}, dir)
	if err != nil {
		t.Fatalf("localCandidates: %v", err)
	}
	if len(candidates) != 1 || candidates[0].URL != pkgPath {
		t.Fatalf("candidates = %+v, want one candidate at %s", candidates, pkgPath)
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
	m, err := LoadManifest(manifestPath)
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}
	lock.ManifestDigest = manifestDigest(m)
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
	if _, err := os.Stat(filepath.Join(outDir, "var/state/peipkg/db.sqlite")); err != nil {
		t.Fatalf("seeded database missing: %v", err)
	}
}

// TestAssembleMultiRoot builds an image spanning two roots: foo into the
// anchor and bar into a declared initramfs root. Each package must land in
// its own root with its own seeded database, and the anchor's database
// must carry the named-root registry so the booted image resolves
// `--root initramfs`.
func TestAssembleMultiRoot(t *testing.T) {
	ctx := context.Background()
	sourceDate := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	fooRaw := buildPeipkg(t, minimalManifestJSON(t, "foo", "1.0-1", "x86_64", 4),
		[]testEntry{{Path: "usr", IsDir: true}, {Path: "usr/bin", IsDir: true},
			{Path: "usr/bin/foo", Content: []byte("fooo")}})
	barRaw := buildPeipkg(t, minimalManifestJSON(t, "bar", "1.0-1", "x86_64", 4),
		[]testEntry{{Path: "usr", IsDir: true}, {Path: "usr/bin", IsDir: true},
			{Path: "usr/bin/bar", Content: []byte("barr")}})
	fooSum, barSum := sha256.Sum256(fooRaw), sha256.Sum256(barRaw)
	fooURL, barURL := "https://r/foo.peipkg", "https://r/bar.peipkg"

	m := Manifest{
		Arch: "x86_64", SourceDate: sourceDate,
		Repositories: []config.RepoConfig{{
			Name: "official", BaseURL: "https://r", Priority: 10,
			SignaturePolicy: config.PolicyRequired, TrustAnchors: []string{strings.Repeat("a", 64)},
		}},
		Roots:    []Root{{Name: "initramfs", Path: "boot/initramfs"}},
		Packages: []PackageRequest{{Name: "foo"}, {Name: "bar", Root: "initramfs"}},
	}
	lock := Lock{
		Arch: m.Arch, SourceDate: sourceDate,
		Packages: []LockedPackage{
			{Name: "foo", Version: "1.0-1", Architecture: "x86_64", Source: "official",
				URL: fooURL, Hash: hex.EncodeToString(fooSum[:])}, // Root "" → anchor
			{Name: "bar", Version: "1.0-1", Architecture: "x86_64", Source: "official",
				URL: barURL, Hash: hex.EncodeToString(barSum[:]), Root: "boot/initramfs"},
		},
	}
	fetched, err := fetchAll(ctx, lock, fakeFetcher{fooURL: fooRaw, barURL: barRaw})
	if err != nil {
		t.Fatalf("fetchAll: %v", err)
	}

	out := filepath.Join(t.TempDir(), "image")
	if err := assemble(ctx, out, m, fetched, false); err != nil {
		t.Fatalf("assemble: %v", err)
	}

	irf := filepath.Join(out, "boot/initramfs")
	// Payloads landed in their respective roots, and nowhere else.
	if _, err := os.Stat(filepath.Join(out, "usr/bin/foo")); err != nil {
		t.Errorf("foo not in anchor: %v", err)
	}
	// Compose installs package storage paths and claims only. Runtime filesystem
	// topology (including PFSL merged views and the x86-64 /lib64 ABI mapping)
	// belongs to the image/bootstrap layer, so compose must not mint legacy-root
	// symlinks in either the anchor or a named root.
	for _, root := range []string{out, irf} {
		for _, name := range []string{"bin", "sbin", "lib", "lib64"} {
			if _, err := os.Lstat(filepath.Join(root, name)); !os.IsNotExist(err) {
				t.Errorf("compose unexpectedly materialised %s/%s: %v", root, name, err)
			}
		}
	}
	if _, err := os.Stat(filepath.Join(out, "bin/bar")); !os.IsNotExist(err) {
		t.Errorf("bar should not be in the anchor: %v", err)
	}
	if _, err := os.Stat(filepath.Join(irf, "usr/bin/foo")); !os.IsNotExist(err) {
		t.Errorf("foo should not be in the initramfs: %v", err)
	}

	// The license inventory is anchor-level, image-wide, and sorted
	// (root, name): the anchor's foo first, then the initramfs' bar with
	// its root recorded. The nested root gets no inventory of its own.
	var inventory struct {
		Packages []struct {
			Name string `json:"name"`
			Root string `json:"root"`
		} `json:"packages"`
	}
	invData, err := os.ReadFile(filepath.Join(out, "usr/share/licenses.json"))
	if err != nil {
		t.Fatalf("usr/share/licenses.json: %v", err)
	}
	if err := json.Unmarshal(invData, &inventory); err != nil {
		t.Fatalf("decoding licenses.json: %v", err)
	}
	if len(inventory.Packages) != 2 ||
		inventory.Packages[0].Name != "foo" || inventory.Packages[0].Root != "" ||
		inventory.Packages[1].Name != "bar" || inventory.Packages[1].Root != "boot/initramfs" {
		t.Errorf("licenses.json packages = %+v", inventory.Packages)
	}
	if _, err := os.Stat(filepath.Join(irf, "usr/share/licenses.json")); !os.IsNotExist(err) {
		t.Errorf("nested root should not carry its own license inventory: %v", err)
	}

	// Anchor DB: records foo and the named-root registry entry.
	anchorDB, err := db.Open(ctx, filepath.Join(out, "var/state/peipkg/db.sqlite"))
	if err != nil {
		t.Fatalf("open anchor db: %v", err)
	}
	defer anchorDB.Close()
	if _, found, _ := anchorDB.GetPackage(ctx, "foo"); !found {
		t.Error("anchor db missing foo")
	}
	if _, found, _ := anchorDB.GetPackage(ctx, "bar"); found {
		t.Error("anchor db should not record bar")
	}
	if path, found, _ := anchorDB.NamedRoot(ctx, "initramfs"); !found || path != "boot/initramfs" {
		t.Errorf("anchor registry: got %q found=%v, want boot/initramfs", path, found)
	}

	// Initramfs DB: records bar, with its own state directory.
	irfDB, err := db.Open(ctx, filepath.Join(irf, "var/state/peipkg/db.sqlite"))
	if err != nil {
		t.Fatalf("open initramfs db: %v", err)
	}
	defer irfDB.Close()
	if _, found, _ := irfDB.GetPackage(ctx, "bar"); !found {
		t.Error("initramfs db missing bar")
	}
}

// TestPackageRootKey covers the placement precedence a top-level
// [[package]] inherits from `peipkg install`: explicit root wins, else
// default_root, else the anchor; an undeclared default_root is an error.
func TestPackageRootKey(t *testing.T) {
	refs := map[string]string{"initramfs": "boot/initramfs"}
	cands := []resolver.Candidate{
		{Name: "live-boot", DefaultRoot: "initramfs"},
		{Name: "ordinary"},
		{Name: "stray", DefaultRoot: "ghost"},
	}
	cases := []struct {
		req  PackageRequest
		want string
		err  bool
	}{
		{PackageRequest{Name: "ordinary", Root: "initramfs"}, "boot/initramfs", false}, // explicit wins
		{PackageRequest{Name: "live-boot"}, "boot/initramfs", false},                   // default_root
		{PackageRequest{Name: "ordinary"}, "", false},                                  // anchor
		{PackageRequest{Name: "stray"}, "", true},                                      // undeclared default_root
	}
	for _, tc := range cases {
		got, err := packageRootKey(tc.req, cands, refs)
		if tc.err {
			if err == nil {
				t.Errorf("%+v: expected an error", tc.req)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("%+v: got %q err %v, want %q", tc.req, got, err, tc.want)
		}
	}
}
