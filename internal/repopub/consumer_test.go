package repopub_test

import (
	"crypto/ed25519"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/peios/peipkg/internal/config"
	"github.com/peios/peipkg/internal/db"
	"github.com/peios/peipkg/internal/repository"
	"github.com/peios/peipkg/internal/signature"
)

// The tests in this file are the ones that actually matter. Everything
// else here checks that the publisher does what its own author
// intended; these check the only thing a repository is for — that the
// CLIENT can use it.
//
// They drive internal/repository, the same code the peipkg command
// runs, over a file:// URL pointing at a freshly published state. §6.4.1
// makes file:// a first-class scheme precisely because trust comes from
// the signed index rather than the transport, so nothing is weakened by
// testing over it.

func fileURL(t *testing.T, dir string) string {
	t.Helper()
	abs, err := filepath.Abs(dir)
	if err != nil {
		t.Fatalf("Abs: %v", err)
	}
	return (&url.URL{Scheme: "file", Path: abs}).String()
}

func newClient(t *testing.T) *repository.Client {
	t.Helper()
	store, err := db.Open(t.Context(), filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return repository.NewClient(repository.NewHTTPFetcher(), store, t.TempDir())
}

func repoConfig(t *testing.T, dir string, key ed25519.PrivateKey) config.RepoConfig {
	t.Helper()
	return config.RepoConfig{
		Name:            "test-repo",
		BaseURL:         fileURL(t, dir),
		Priority:        50,
		SignaturePolicy: config.PolicyRequired,
		TrustAnchors: []string{
			signature.Fingerprint(key.Public().(ed25519.PublicKey)),
		},
	}
}

// TestAConsumerCanAddAPublishedRepository walks the §6.5.2 trust
// ceremony against real output: fetch the descriptor, fetch the key it
// names, verify the descriptor's detached signature against the
// operator-supplied anchor, and record the trust state.
//
// This is the check that a descriptor is not merely well-formed but
// correctly signed over its own exact bytes — the one thing no amount
// of encoder round-tripping can establish.
func TestAConsumerCanAddAPublishedRepository(t *testing.T) {
	dir, key := newRepo(t)
	p := writePackage(t, t.TempDir(), key, pkgSpec{name: "dash", version: "0.5.12-2"})
	publish(t, dir, key, at.Add(time.Hour), p)

	client := newClient(t)
	if err := client.Add(t.Context(), repoConfig(t, dir, key)); err != nil {
		t.Fatalf("a consumer could not add the repository we published: %v", err)
	}

	idx, err := client.ActiveIndex(t.Context(), "test-repo")
	if err != nil {
		t.Fatalf("ActiveIndex: %v", err)
	}
	if len(idx.Packages) != 1 || idx.Packages[0].Name != "dash" {
		t.Fatalf("the consumer read %d packages: %+v", len(idx.Packages), idx.Packages)
	}
	if got := idx.Packages[0].Version.String(); got != "0.5.12-2" {
		t.Errorf("consumer sees dash %s, want 0.5.12-2", got)
	}
}

// TestAConsumerRejectsTheWrongAnchor is the negative half of the trust
// ceremony, and it is what makes the positive half meaningful: if any
// anchor were accepted, TestAConsumerCanAdd... would pass against an
// unsigned repository.
func TestAConsumerRejectsTheWrongAnchor(t *testing.T) {
	dir, key := newRepo(t)
	p := writePackage(t, t.TempDir(), key, pkgSpec{name: "dash", version: "0.5.12-2"})
	publish(t, dir, key, at.Add(time.Hour), p)

	_, stranger := keypair(t)
	cfg := repoConfig(t, dir, key)
	cfg.TrustAnchors = []string{
		signature.Fingerprint(stranger.Public().(ed25519.PublicKey)),
	}
	if err := newClient(t).Add(t.Context(), cfg); err == nil {
		t.Fatal("a consumer added a repository against an anchor it does not publish")
	}
}

// TestAConsumerCanRefreshAcrossPublishes exercises the rollback floor
// (§6.2.3) from the consumer's side: each publish must advance
// index_version and generated_at enough for the next refresh to count
// as progress. A publisher that reused either would leave consumers
// stuck at the first revision they ever saw, with no error to show for
// it — the freeze attack, self-inflicted.
func TestAConsumerCanRefreshAcrossPublishes(t *testing.T) {
	dir, key := newRepo(t)
	src := t.TempDir()
	first := writePackage(t, src, key, pkgSpec{name: "pkg", version: "1.0-1"})
	publish(t, dir, key, at.Add(time.Hour), first)

	client := newClient(t)
	cfg := repoConfig(t, dir, key)
	if err := client.Add(t.Context(), cfg); err != nil {
		t.Fatalf("Add: %v", err)
	}

	for i, ver := range []string{"1.0-2", "1.0-3", "2.0-1"} {
		p := writePackage(t, src, key, pkgSpec{name: "pkg", version: ver})
		publish(t, dir, key, at.Add(time.Duration(i+2)*time.Hour), p)

		if err := client.Refresh(t.Context(), cfg); err != nil {
			t.Fatalf("refresh after publishing %s: %v", ver, err)
		}
		idx, err := client.ActiveIndex(t.Context(), "test-repo")
		if err != nil {
			t.Fatalf("ActiveIndex: %v", err)
		}
		if len(idx.Packages) != 1 {
			t.Fatalf("active holds %d entries, want 1", len(idx.Packages))
		}
		if got := idx.Packages[0].Version.String(); got != ver {
			t.Errorf("after publishing %s the consumer still sees %s", ver, got)
		}
	}
}

// TestAConsumerCanFetchAPublishedPackage closes the last link: the URL
// the index advertises resolves, and the bytes behind it hash to what
// the entry claims. FetchPackage performs that check itself, so a
// mismatch between the recorded hash and the served file fails here.
func TestAConsumerCanFetchAPublishedPackage(t *testing.T) {
	dir, key := newRepo(t)
	p := writePackage(t, t.TempDir(), key, pkgSpec{name: "dash", version: "0.5.12-2"})
	publish(t, dir, key, at.Add(time.Hour), p)

	client := newClient(t)
	cfg := repoConfig(t, dir, key)
	if err := client.Add(t.Context(), cfg); err != nil {
		t.Fatalf("Add: %v", err)
	}
	idx, err := client.ActiveIndex(t.Context(), "test-repo")
	if err != nil {
		t.Fatalf("ActiveIndex: %v", err)
	}
	entry := idx.Packages[0]
	// FetchPackage checks the fetched bytes against the hash and size
	// the index advertises, so a publisher that recorded either wrongly
	// fails right here rather than at install time.
	pkg, data, err := client.FetchPackage(
		t.Context(), cfg, entry.URL, entry.Hash, entry.SizeCompressed)
	if err != nil {
		t.Fatalf("a consumer could not fetch the package we published: %v", err)
	}
	if int64(len(data)) != entry.SizeCompressed {
		t.Errorf("fetched %d bytes, index says %d", len(data), entry.SizeCompressed)
	}
	// §6.2.5: the index entry is a derived view of the manifest, so the
	// two must agree about what the package actually is.
	if pkg.Manifest.Name != entry.Name ||
		pkg.Manifest.Version.String() != entry.Version.String() ||
		pkg.Manifest.Architecture != entry.Architecture {
		t.Errorf("index entry %s disagrees with the manifest inside the package (%s %s %s)",
			entry.Name, pkg.Manifest.Name, pkg.Manifest.Version, pkg.Manifest.Architecture)
	}
}

// TestAConsumerReadsTheArchiveIndex covers the half of the contract the
// active index does not: downgrade, pinning and forensics all read the
// archive, and it is signed and floored under the same rules (§6.3).
func TestAConsumerReadsTheArchiveIndex(t *testing.T) {
	dir, key := newRepo(t)
	src := t.TempDir()
	old := writePackage(t, src, key, pkgSpec{name: "pkg", version: "1.0-1"})
	cur := writePackage(t, src, key, pkgSpec{name: "pkg", version: "2.0-1"})
	publish(t, dir, key, at.Add(time.Hour), old, cur)

	client := newClient(t)
	cfg := repoConfig(t, dir, key)
	if err := client.Add(t.Context(), cfg); err != nil {
		t.Fatalf("Add: %v", err)
	}
	idx, err := client.ArchiveIndex(t.Context(), cfg)
	if err != nil {
		t.Fatalf("ArchiveIndex: %v", err)
	}
	if len(idx.Packages) != 2 {
		t.Fatalf("archive holds %d entries, want 2", len(idx.Packages))
	}
	// §6.3.6: highest version first within a name group.
	if idx.Packages[0].Version.String() != "2.0-1" {
		t.Errorf("archive is not highest-first: %s leads",
			idx.Packages[0].Version)
	}
}

// TestAConsumerRejectsATamperedIndex proves the signature is load
// bearing rather than decorative: an index edited after publication —
// still valid JSON, still a valid index — must not be accepted.
func TestAConsumerRejectsATamperedIndex(t *testing.T) {
	dir, key := newRepo(t)
	src := t.TempDir()
	p := writePackage(t, src, key, pkgSpec{name: "pkg", version: "1.0-1"})
	publish(t, dir, key, at.Add(time.Hour), p)

	// Re-sign nothing: rewrite the active index with a different but
	// entirely well-formed body.
	evil := writePackage(t, src, key, pkgSpec{name: "pkg", version: "9.9-9"})
	_ = evil
	active := filepath.Join(dir, "index", "active.json")
	raw, err := readFile(active)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	edited := replaceOnce(string(raw), `"version": "1.0-1"`, `"version": "1.0-2"`)
	if edited == string(raw) {
		t.Fatal("fixture did not modify the index")
	}
	if err := writeFile(active, []byte(edited)); err != nil {
		t.Fatalf("write: %v", err)
	}

	if err := newClient(t).Add(t.Context(), repoConfig(t, dir, key)); err == nil {
		t.Fatal("a consumer accepted an index that was edited after signing")
	}
}
