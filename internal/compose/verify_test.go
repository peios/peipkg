package compose

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/peios/peipkg/internal/archive"
	"github.com/peios/peipkg/internal/config"
	"github.com/peios/peipkg/internal/manifest"
	"github.com/peios/peipkg/internal/repository"
	"github.com/peios/peipkg/internal/signature"
)

// signedTestPackage builds a small signed .peipkg and returns its bytes,
// content hash and declared installed size.
func signedTestPackage(t *testing.T, priv ed25519.PrivateKey) (raw []byte, hash string, size int64) {
	t.Helper()
	content := []byte("#!/bin/sh\necho hi\n")
	entries := []testEntry{
		{Path: "usr", IsDir: true},
		{Path: "usr/bin", IsDir: true},
		{Path: "usr/bin/foo", Content: content},
	}
	size = int64(len(content))
	raw = buildPeipkgSigned(t, minimalManifestJSON(t, "foo", "1.0-1", "x86_64", size), entries, priv)
	sum := sha256.Sum256(raw)
	return raw, hex.EncodeToString(sum[:]), size
}

// trustJSON renders a one-key trust set in the encoding the package
// database — and now the lock — stores.
func trustJSON(t *testing.T, pub ed25519.PublicKey, status string, validUntil time.Time) string {
	t.Helper()
	k := map[string]any{
		"fingerprint": signature.Fingerprint(pub),
		"public_key":  base64.RawStdEncoding.EncodeToString(pub),
		"status":      status,
	}
	if status == "transitioning" {
		k["valid_until"] = validUntil.UTC().Format(time.RFC3339)
	}
	data, err := json.Marshal([]any{k})
	if err != nil {
		t.Fatalf("encode trust set: %v", err)
	}
	// Parsing it here keeps a broken helper from looking like a broken fix.
	if _, err := repository.ParseTrustSet(string(data)); err != nil {
		t.Fatalf("the test trust set does not parse: %v", err)
	}
	return string(data)
}

func lockFor(t *testing.T, hash string, size int64, src LockedSource) Lock {
	t.Helper()
	return Lock{
		Arch:       "x86_64",
		SourceDate: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
		Manifest:   "test.toml",
		Sources:    []LockedSource{src},
		Packages: []LockedPackage{{
			Name: "foo", Version: "1.0-1", Architecture: "x86_64",
			Source: src.Name, URL: "https://pkgs.peios.org/pool/foo.peipkg",
			Hash: hash, SizeInstalled: size,
		}},
	}
}

// §5.30: the build phase verifies each package's signature against the
// trust set of its originating repository. Before PEI-373 compose called
// VerifyFormat, which checks everything except the signature's trust, so
// no composed image ever consulted a key.
func TestComposeBuildVerifiesPackageSignatures(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	raw, hash, size := signedTestPackage(t, priv)
	url := "https://pkgs.peios.org/pool/foo.peipkg"
	fetcher := fakeFetcher{url: raw}
	ctx := context.Background()

	t.Run("active key is accepted", func(t *testing.T) {
		lock := lockFor(t, hash, size, LockedSource{
			Name: "official", SignaturePolicy: string(config.PolicyRequired),
			TrustKeys: trustJSON(t, pub, "active", time.Time{}),
		})
		fetched, err := fetchAll(ctx, lock, fetcher)
		if err != nil {
			t.Fatalf("fetchAll: %v", err)
		}
		if len(fetched) != 1 || !fetched[0].Pkg.Signed {
			t.Fatalf("fetched = %+v, want one signed package", fetched)
		}
	})

	// The revoked status is the format's in-band compromise response. It
	// was inert for every composed image: the bytes still match the hash
	// the (signed, still-valid) index advertised, which is exactly the
	// compromised-key case.
	t.Run("revoked key is refused", func(t *testing.T) {
		lock := lockFor(t, hash, size, LockedSource{
			Name: "official", SignaturePolicy: string(config.PolicyRequired),
			TrustKeys: trustJSON(t, pub, "revoked", time.Time{}),
		})
		_, err := fetchAll(ctx, lock, fetcher)
		if err == nil {
			t.Fatal("fetchAll accepted a package signed by a revoked key")
		}
		if !strings.Contains(err.Error(), "not in the trust set") {
			t.Errorf("error = %v, want the key refused as untrusted", err)
		}
	})

	// §6.1.4: a transitioning key verifies until valid_until and not after.
	t.Run("expired transitioning key is refused", func(t *testing.T) {
		lock := lockFor(t, hash, size, LockedSource{
			Name: "official", SignaturePolicy: string(config.PolicyRequired),
			TrustKeys: trustJSON(t, pub, "transitioning", time.Now().Add(-24*time.Hour)),
		})
		if _, err := fetchAll(ctx, lock, fetcher); err == nil {
			t.Fatal("fetchAll accepted a package signed by an expired transitioning key")
		}
	})

	t.Run("unexpired transitioning key is accepted", func(t *testing.T) {
		lock := lockFor(t, hash, size, LockedSource{
			Name: "official", SignaturePolicy: string(config.PolicyRequired),
			TrustKeys: trustJSON(t, pub, "transitioning", time.Now().Add(24*time.Hour)),
		})
		if _, err := fetchAll(ctx, lock, fetcher); err != nil {
			t.Fatalf("fetchAll: %v", err)
		}
	})

	// §5.29 forbids cross-repository signature acceptance; with no trust
	// set consulted at all it could not be enforced here.
	t.Run("another repository's key is refused", func(t *testing.T) {
		otherPub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		lock := lockFor(t, hash, size, LockedSource{
			Name: "official", SignaturePolicy: string(config.PolicyRequired),
			TrustKeys: trustJSON(t, otherPub, "active", time.Time{}),
		})
		if _, err := fetchAll(ctx, lock, fetcher); err == nil {
			t.Fatal("fetchAll accepted a package signed by a key of a different repository")
		}
	})
}

// The `required` policy the compose manifest defaults to (§5.30) has to
// reach the build, or an unsigned package composes into an image the
// operator asked to be signed.
func TestComposeBuildAppliesTheSignaturePolicy(t *testing.T) {
	content := []byte("#!/bin/sh\necho hi\n")
	entries := []testEntry{
		{Path: "usr", IsDir: true},
		{Path: "usr/bin", IsDir: true},
		{Path: "usr/bin/foo", Content: content},
	}
	size := int64(len(content))
	raw := buildPeipkg(t, minimalManifestJSON(t, "foo", "1.0-1", "x86_64", size), entries)
	sum := sha256.Sum256(raw)
	hash := hex.EncodeToString(sum[:])
	url := "https://pkgs.peios.org/pool/foo.peipkg"
	fetcher := fakeFetcher{url: raw}
	ctx := context.Background()

	required := lockFor(t, hash, size, LockedSource{
		Name: "official", SignaturePolicy: string(config.PolicyRequired),
	})
	_, err := fetchAll(ctx, required, fetcher)
	if err == nil {
		t.Fatal("fetchAll accepted an unsigned package from a `required` source")
	}
	if !strings.Contains(err.Error(), "unsigned") {
		t.Errorf("error = %v, want it to say the package is unsigned", err)
	}

	optional := lockFor(t, hash, size, LockedSource{
		Name: "official", SignaturePolicy: string(config.PolicyOptional),
	})
	if _, err := fetchAll(ctx, optional, fetcher); err != nil {
		t.Fatalf("fetchAll of an unsigned package from an `optional` source: %v", err)
	}
}

// §5.27, at the compose layer: the lock carries the index's declared
// installed size forward, so the build bounds decompression by it rather
// than by the manifest inside the archive it is bounding.
func TestComposeBuildBoundsDecompressionByTheLock(t *testing.T) {
	content := []byte("#!/bin/sh\necho hi\n")
	entries := []testEntry{
		{Path: "usr", IsDir: true},
		{Path: "usr/bin", IsDir: true},
		{Path: "usr/bin/foo", Content: content},
	}
	raw := buildPeipkg(t,
		minimalManifestJSON(t, "foo", "1.0-1", "x86_64", int64(len(content))), entries)
	sum := sha256.Sum256(raw)
	url := "https://pkgs.peios.org/pool/foo.peipkg"

	lock := lockFor(t, hex.EncodeToString(sum[:]), 1<<20, LockedSource{
		Name: "official", SignaturePolicy: string(config.PolicyOptional),
	})
	_, err := fetchAll(context.Background(), lock, fakeFetcher{url: raw})
	if err == nil {
		t.Fatal("fetchAll accepted an archive disagreeing with the lock's size_installed")
	}
	if !strings.Contains(err.Error(), "size_installed") {
		t.Errorf("error = %v, want it to name size_installed", err)
	}
}

// publishFakeRepo builds the URL→bytes map of a single-package
// repository signed by priv, plus the manifest repository stanza that
// anchors it.
func publishFakeRepo(t *testing.T, pub ed25519.PublicKey, priv ed25519.PrivateKey,
	pkgRaw []byte, pkgHash string, sizeInstalled int64) (fakeFetcher, config.RepoConfig) {

	t.Helper()
	const base = "https://pkgs.peios.test"
	fp := signature.Fingerprint(pub)
	// A detached repository signature is an envelope over the content's
	// SHA-256, not a raw Ed25519 signature over the bytes.
	sign := func(b []byte) []byte {
		digest := sha256.Sum256(b)
		env, err := json.Marshal(map[string]any{
			"schema_version":  1,
			"algorithm":       "ed25519",
			"key_fingerprint": fp,
			"signature":       base64.RawStdEncoding.EncodeToString(ed25519.Sign(priv, digest[:])),
		})
		if err != nil {
			t.Fatalf("marshal signature envelope: %v", err)
		}
		return env
	}
	enc := func(v any) []byte {
		data, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return data
	}

	desc := enc(map[string]any{
		"schema_version": 1,
		"repo": map[string]any{
			"name": "official",
			"signing": map[string]any{
				"algorithm": "ed25519",
				"keys": []any{map[string]any{
					"fingerprint": fp, "url": "/keys/" + fp + ".pub", "status": "active",
				}},
			},
		},
		"indexes": map[string]any{
			"active": map[string]any{
				"url": "/index/active.json", "signature_url": "/index/active.json.sig",
			},
			"archive": map[string]any{
				"url": "/index/archive.json", "signature_url": "/index/archive.json.sig",
			},
		},
	})
	entry := map[string]any{
		"name": "foo", "version": "1.0-1", "architecture": "x86_64",
		"dependencies": []any{}, "conflicts": []any{},
		"size_compressed": len(pkgRaw), "size_installed": sizeInstalled,
		"hash": map[string]any{"algorithm": "sha256", "value": pkgHash},
		"url":  "/pool/foo.peipkg",
	}
	index := enc(map[string]any{
		"schema_version": 1, "repo": "official", "kind": "active",
		"index_version": 7,
		"generated_at":  time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339),
		"packages":      []any{entry},
	})

	return fakeFetcher{
			base + "/repo.json":             desc,
			base + "/repo.json.sig":         sign(desc),
			base + "/keys/" + fp + ".pub":   []byte(pub),
			base + "/index/active.json":     index,
			base + "/index/active.json.sig": sign(index),
			base + "/pool/foo.peipkg":       pkgRaw,
		}, config.RepoConfig{
			Name: "official", BaseURL: base, Priority: 10,
			SignaturePolicy: config.PolicyRequired, TrustAnchors: []string{fp},
		}
}

// The whole loop: Resolve establishes trust and records it in the lock,
// and Build verifies each package's signature against what the lock
// recorded. Before PEI-373 the trust state died with the scratch
// database Resolve built it in, so the build phase had hashes and no
// keys.
func TestResolveCarriesTrustIntoTheBuild(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	raw, hash, size := signedTestPackage(t, priv)
	fetcher, repoCfg := publishFakeRepo(t, pub, priv, raw, hash, size)

	m := Manifest{
		Arch:         "x86_64",
		SourceDate:   time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
		Repositories: []config.RepoConfig{repoCfg},
		Packages:     []PackageRequest{{Name: "foo"}},
	}
	ctx := context.Background()
	lock, err := Resolve(ctx, m, "test.toml", fetcher, nil)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if len(lock.Sources) != 1 || lock.Sources[0].Name != "official" {
		t.Fatalf("lock.Sources = %+v, want the one repository the closure drew from", lock.Sources)
	}
	src := lock.Sources[0]
	if src.SignaturePolicy != string(config.PolicyRequired) {
		t.Errorf("recorded signature policy = %q, want %q",
			src.SignaturePolicy, config.PolicyRequired)
	}
	ts, err := repository.ParseTrustSet(src.TrustKeys)
	if err != nil {
		t.Fatalf("recorded trust set does not parse: %v", err)
	}
	if len(ts.Keys) != 1 || ts.Keys[0].Fingerprint != signature.Fingerprint(pub) {
		t.Fatalf("recorded trust set = %+v, want the repository's signing key", ts.Keys)
	}
	if len(lock.Packages) != 1 || lock.Packages[0].SizeInstalled != size {
		t.Fatalf("lock.Packages = %+v, want one entry carrying size_installed %d",
			lock.Packages, size)
	}

	// A lock round-trips through TOML on the way to the build.
	encoded, err := lock.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	decoded, err := DecodeLock(encoded)
	if err != nil {
		t.Fatalf("DecodeLock: %v", err)
	}
	fetched, err := fetchAll(ctx, decoded, fetcher)
	if err != nil {
		t.Fatalf("fetchAll from the encoded lock: %v", err)
	}
	if len(fetched) != 1 || !fetched[0].Pkg.Signed {
		t.Fatalf("fetched = %+v, want one signed package", fetched)
	}

	// And the recorded trust is load-bearing: revoke the key in the lock
	// and the same bytes are refused.
	decoded.Sources[0].TrustKeys = trustJSON(t, pub, "revoked", time.Time{})
	if _, err := fetchAll(ctx, decoded, fetcher); err == nil {
		t.Fatal("fetchAll accepted a package whose signing key the lock records as revoked")
	}
}

// The compose half of §5.14's absolute rule: assemble skipped
// ValidateInstallPaths entirely for a special package under
// bypass_path_restrictions, with no residual denylist behind it, so a
// composed image could ship /lcl/policy/autorun.d content (PEI-380).
func TestComposeLayoutRefusesLclPolicyEvenUnderBypass(t *testing.T) {
	fp := fetchedPackage{
		Locked: LockedPackage{Name: "fsbase"},
		Pkg: &archive.Package{
			Manifest: manifest.Manifest{Name: "fsbase", SpecialSystemPackage: true},
			Payload: []archive.PayloadEntry{
				{Path: "lcl/policy/autorun.d/pwn.sh", Type: archive.EntryFile},
			},
		},
	}
	err := checkComposeLayout(fp, true) // bypass enabled: both keys turned
	if err == nil {
		t.Fatal("compose accepted a payload entry under /lcl/policy")
	}
	if !strings.Contains(err.Error(), "/lcl/policy") {
		t.Errorf("error = %v, want it to name the tree it refused", err)
	}

	// The bypass still does what it is for: an out-of-layout path that is
	// not forbidden composes.
	fp.Pkg.Payload = []archive.PayloadEntry{{Path: "opt/vendor/agent", Type: archive.EntryFile}}
	if err := checkComposeLayout(fp, true); err != nil {
		t.Errorf("the bypass no longer waives an ordinary layout violation: %v", err)
	}

	// And the empty skeleton fsbase mints is not content, so it composes.
	fp.Pkg.Payload = []archive.PayloadEntry{
		{Path: "lcl/policy", Type: archive.EntryDir},
		{Path: "lcl/policy/autorun.d", Type: archive.EntryDir},
	}
	if err := checkComposeLayout(fp, true); err != nil {
		t.Errorf("minting the empty /lcl/policy skeleton was refused: %v", err)
	}
}

// A [[root]] no package is placed in was registered in the anchor's
// named-root table and never created, so the registry entry pointed at a
// directory that did not exist and `peipkg --root <name>` on the booted
// image failed opening its database. A declared empty root is a
// reasonable thing to want — somewhere to install into later — so it is
// assembled like any other (PEI-436).
func TestAssembleCreatesADeclaredRootWithNoPackages(t *testing.T) {
	content := []byte("#!/bin/sh\necho hi\n")
	entries := []testEntry{
		{Path: "usr", IsDir: true},
		{Path: "usr/bin", IsDir: true},
		{Path: "usr/bin/foo", Content: content},
	}
	size := int64(len(content))
	raw := buildPeipkg(t, minimalManifestJSON(t, "foo", "1.0-1", "x86_64", size), entries)
	sum := sha256.Sum256(raw)
	url := "https://pkgs.peios.org/pool/foo.peipkg"

	m := Manifest{
		Arch:       "x86_64",
		SourceDate: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
		// Two roots declared; only the anchor gets a package.
		Roots:    []Root{{Name: "initramfs", Path: "boot/initramfs"}},
		Packages: []PackageRequest{{Name: "foo"}},
	}
	lock := lockFor(t, hex.EncodeToString(sum[:]), size, LockedSource{
		Name: "official", SignaturePolicy: string(config.PolicyOptional),
	})
	ctx := context.Background()
	fetched, err := fetchAll(ctx, lock, fakeFetcher{url: raw})
	if err != nil {
		t.Fatalf("fetchAll: %v", err)
	}

	out := filepath.Join(t.TempDir(), "root")
	if err := assemble(ctx, out, m, fetched, false, nil); err != nil {
		t.Fatalf("assemble: %v", err)
	}

	// The declared root exists, and carries its own database — which is
	// what `peipkg --root initramfs` opens.
	empty := filepath.Join(out, "boot/initramfs")
	if fi, err := os.Stat(empty); err != nil || !fi.IsDir() {
		t.Fatalf("the declared empty root was not created: %v", err)
	}
	if _, err := os.Stat(filepath.Join(empty, "var/state/peipkg/db.sqlite")); err != nil {
		t.Errorf("the declared empty root has no database: %v", err)
	}
}

// §: the manifest digest exists so a build refuses a lock that no longer
// describes the manifest. Roots influence resolution as surely as a
// constraint does — the multi-root resolver routes every request and
// every cross-root dependency through them — and the digest covered
// none of it, so a plain build with no --update accepted the stale lock
// and silently rebuilt the previous placement (PEI-412).
func TestManifestDigestCoversRootInformation(t *testing.T) {
	base := Manifest{
		Arch:       "x86_64",
		SourceDate: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
		Roots:      []Root{{Name: "initramfs", Path: "boot/initramfs"}},
		Packages:   []PackageRequest{{Name: "foo"}, {Name: "bar", Root: "initramfs"}},
	}
	want := manifestDigest(base)

	for name, mutate := range map[string]func(*Manifest){
		"a root's path changes": func(m *Manifest) {
			m.Roots = []Root{{Name: "initramfs", Path: "boot/irf"}}
		},
		"a root is added": func(m *Manifest) {
			m.Roots = append(append([]Root(nil), m.Roots...), Root{Name: "spare", Path: "spare"})
		},
		"a root is removed": func(m *Manifest) {
			m.Roots = nil
			m.Packages = []PackageRequest{{Name: "foo"}, {Name: "bar"}}
		},
		"a package moves between roots": func(m *Manifest) {
			m.Packages = []PackageRequest{{Name: "foo", Root: "initramfs"}, {Name: "bar"}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			m := base
			m.Roots = append([]Root(nil), base.Roots...)
			m.Packages = append([]PackageRequest(nil), base.Packages...)
			mutate(&m)
			if got := manifestDigest(m); got == want {
				t.Errorf("the digest did not change, so a stale lock would be accepted")
			}
		})
	}

	// And an unrelated edit still leaves it alone, or every build would
	// demand --update.
	same := base
	same.Roots = append([]Root(nil), base.Roots...)
	same.Packages = append([]PackageRequest(nil), base.Packages...)
	if got := manifestDigest(same); got != want {
		t.Errorf("the digest is not stable across an identical manifest")
	}
}
