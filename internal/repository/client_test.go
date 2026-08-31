package repository_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/peios/peipkg/internal/config"
	"github.com/peios/peipkg/internal/db"
	"github.com/peios/peipkg/internal/repository"
	"github.com/peios/peipkg/internal/signature"
)

const (
	testRepoBase = "https://repo.example.test"
	testRepoName = "test-repo"
)

// memFetcher is an in-memory Fetcher serving a fixed URL→bytes map.
type memFetcher map[string][]byte

func (m memFetcher) Fetch(_ context.Context, url string, limit int64) ([]byte, error) {
	data, ok := m[url]
	if !ok {
		return nil, fmt.Errorf("memFetcher: no such URL %q", url)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("memFetcher: %q exceeds the %d-byte limit", url, limit)
	}
	return data, nil
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return data
}

// publishRepo builds the URL→bytes map of a repository signed by priv,
// whose active index carries the given version and generated-at stamp.
// Index generated_at values for tests, expressed relative to now.
//
// These used to be hardcoded absolute dates. That is a latent trap once any
// check measures the index's own age: peipkg enforces a 90-day maximum index
// staleness (PSPU 5.34), so a fixture stamped with a fixed date starts failing
// on a specific calendar day for a reason that has nothing to do with what the
// test is checking. Five CLI e2e tests did exactly that when the staleness gate
// landed (PEI-406).
//
// The three ages below stand in for the three roles the old dates played, and
// keep their ordering: older < baseline < newer.
const (
	generatedOlder    = 11
	generatedBaseline = 2
	generatedNewer    = 1
)

// indexGeneratedAt renders a generated_at n days in the past.
func indexGeneratedAt(daysAgo int) string {
	return time.Now().UTC().Add(-time.Duration(daysAgo) * 24 * time.Hour).Format(time.RFC3339)
}

func publishRepo(t *testing.T, pub ed25519.PublicKey, priv ed25519.PrivateKey,
	indexVersion int, generatedAt string) memFetcher {
	t.Helper()
	fingerprint := signature.Fingerprint(pub)

	descriptor := map[string]any{
		"schema_version": 1,
		"repo": map[string]any{
			"name": testRepoName,
			"signing": map[string]any{
				"algorithm": "ed25519",
				"keys": []any{map[string]any{
					"fingerprint": fingerprint,
					"url":         "/keys/" + fingerprint + ".pub",
					"status":      "active",
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
	}
	index := map[string]any{
		"schema_version": 1,
		"repo":           testRepoName,
		"kind":           "active",
		"index_version":  indexVersion,
		"generated_at":   generatedAt,
		"packages": []any{map[string]any{
			"name": "nginx", "version": "1.26.2-3", "architecture": "x86_64",
			"dependencies": []any{}, "conflicts": []any{},
			"size_compressed": 1024, "size_installed": 4096,
			"hash": map[string]any{"algorithm": "sha256", "value": hashHex},
			"url":  "/p/nginx/1.26.2-3/nginx_1.26.2-3_x86_64.peipkg",
		}},
	}
	archive := map[string]any{
		"schema_version": 1,
		"repo":           testRepoName,
		"kind":           "archive",
		"index_version":  indexVersion,
		"generated_at":   generatedAt,
		"packages": []any{map[string]any{
			"name": "nginx", "version": "1.26.2-3", "architecture": "x86_64",
			"dependencies": []any{}, "conflicts": []any{},
			"size_compressed": 1024, "size_installed": 4096,
			"hash": map[string]any{"algorithm": "sha256", "value": hashHex},
			"url":  "/p/nginx/1.26.2-3/nginx_1.26.2-3_x86_64.peipkg",
		}},
	}
	descBytes := mustJSON(t, descriptor)
	indexBytes := mustJSON(t, index)
	archiveBytes := mustJSON(t, archive)
	sign := func(b []byte) []byte {
		return detachedSig(priv, b)
	}
	return memFetcher{
		testRepoBase + "/repo.json":                    descBytes,
		testRepoBase + "/repo.json.sig":                sign(descBytes),
		testRepoBase + "/keys/" + fingerprint + ".pub": []byte(pub),
		testRepoBase + "/index/active.json":            indexBytes,
		testRepoBase + "/index/active.json.sig":        sign(indexBytes),
		testRepoBase + "/index/archive.json":           archiveBytes,
		testRepoBase + "/index/archive.json.sig":       sign(archiveBytes),
	}
}

func testConfig(pub ed25519.PublicKey) config.RepoConfig {
	return config.RepoConfig{
		Name:            testRepoName,
		BaseURL:         testRepoBase,
		Priority:        10,
		SignaturePolicy: config.PolicyRequired,
		TrustAnchors:    []string{signature.Fingerprint(pub)},
	}
}

func newTestStore(t *testing.T) *db.DB {
	t.Helper()
	store, err := db.Open(t.Context(), filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestClientAdd(t *testing.T) {
	pub, priv := keypair(t)
	client := repository.NewClient(
		publishRepo(t, pub, priv, 5, indexGeneratedAt(generatedBaseline)), newTestStore(t), t.TempDir())

	if err := client.Add(t.Context(), testConfig(pub)); err != nil {
		t.Fatalf("Add: %v", err)
	}
	// The cached active index loads and re-verifies.
	idx, err := client.ActiveIndex(t.Context(), testRepoName)
	if err != nil {
		t.Fatalf("ActiveIndex: %v", err)
	}
	if idx.IndexVersion != 5 || len(idx.Packages) != 1 || idx.Packages[0].Name != "nginx" {
		t.Errorf("active index: version=%d, packages=%+v", idx.IndexVersion, idx.Packages)
	}
}

func TestClientAddCacheFailureDoesNotRecordRepository(t *testing.T) {
	pub, priv := keypair(t)
	store := newTestStore(t)
	cachePath := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(cachePath, []byte("x"), 0o644); err != nil {
		t.Fatalf("write cache blocker: %v", err)
	}
	client := repository.NewClient(
		publishRepo(t, pub, priv, 5, indexGeneratedAt(generatedBaseline)), store, cachePath)

	if err := client.Add(t.Context(), testConfig(pub)); err == nil {
		t.Fatal("Add should fail when the cache path is not a directory")
	}
	if _, found, err := store.GetRepository(t.Context(), testRepoName); err != nil {
		t.Fatalf("GetRepository: %v", err)
	} else if found {
		t.Fatal("repository state was recorded despite cache failure")
	}
}

func TestClientAddRejectsUntrustedAnchor(t *testing.T) {
	pub, priv := keypair(t)
	wrongAnchor, _ := keypair(t)
	client := repository.NewClient(
		publishRepo(t, pub, priv, 5, indexGeneratedAt(generatedBaseline)), newTestStore(t), t.TempDir())

	cfg := testConfig(pub)
	cfg.TrustAnchors = []string{signature.Fingerprint(wrongAnchor)}
	if err := client.Add(t.Context(), cfg); err == nil {
		t.Error("Add should fail when no signing key matches a trust anchor")
	}
}

func TestClientRefreshProgress(t *testing.T) {
	pub, priv := keypair(t)
	store, cache, cfg := newTestStore(t), t.TempDir(), testConfig(pub)

	add := repository.NewClient(publishRepo(t, pub, priv, 5, indexGeneratedAt(generatedBaseline)), store, cache)
	if err := add.Add(t.Context(), cfg); err != nil {
		t.Fatalf("Add: %v", err)
	}
	// Republished at a higher index version: the refresh accepts it.
	refresh := repository.NewClient(publishRepo(t, pub, priv, 6, indexGeneratedAt(generatedNewer)), store, cache)
	if err := refresh.Refresh(t.Context(), cfg); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	idx, err := refresh.ActiveIndex(t.Context(), testRepoName)
	if err != nil {
		t.Fatalf("ActiveIndex: %v", err)
	}
	if idx.IndexVersion != 6 {
		t.Errorf("after refresh: index version %d, want 6", idx.IndexVersion)
	}
}

func TestActiveIndexRejectsCacheAheadOfTrustState(t *testing.T) {
	pub, priv := keypair(t)
	store, cache, cfg := newTestStore(t), t.TempDir(), testConfig(pub)

	add := repository.NewClient(publishRepo(t, pub, priv, 5, indexGeneratedAt(generatedBaseline)), store, cache)
	if err := add.Add(t.Context(), cfg); err != nil {
		t.Fatalf("Add: %v", err)
	}
	oldRow, found, err := store.GetRepository(t.Context(), testRepoName)
	if err != nil {
		t.Fatalf("GetRepository: %v", err)
	}
	if !found {
		t.Fatal("repository state was not recorded")
	}

	refresh := repository.NewClient(publishRepo(t, pub, priv, 6, indexGeneratedAt(generatedNewer)), store, cache)
	if err := refresh.Refresh(t.Context(), cfg); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if err := store.UpsertRepository(t.Context(), oldRow); err != nil {
		t.Fatalf("restore old repository state: %v", err)
	}

	_, err = refresh.ActiveIndex(t.Context(), testRepoName)
	if err == nil || !strings.Contains(err.Error(), "recorded trust state has version 5") {
		t.Fatalf("ActiveIndex error = %v, want cached/recorded version mismatch", err)
	}
}

func TestClientRefreshRejectsRollback(t *testing.T) {
	pub, priv := keypair(t)
	store, cache, cfg := newTestStore(t), t.TempDir(), testConfig(pub)

	add := repository.NewClient(publishRepo(t, pub, priv, 5, indexGeneratedAt(generatedBaseline)), store, cache)
	if err := add.Add(t.Context(), cfg); err != nil {
		t.Fatalf("Add: %v", err)
	}
	// Republished at a lower index version: a rollback, refused (§6.2.3).
	rollback := repository.NewClient(publishRepo(t, pub, priv, 3, indexGeneratedAt(generatedOlder)), store, cache)
	if err := rollback.Refresh(t.Context(), cfg); err == nil {
		t.Error("Refresh should reject a rolled-back index")
	}
}

func TestClientRefreshRejectsUntrustedDescriptor(t *testing.T) {
	pub, priv := keypair(t)
	store, cache, cfg := newTestStore(t), t.TempDir(), testConfig(pub)

	add := repository.NewClient(publishRepo(t, pub, priv, 5, indexGeneratedAt(generatedBaseline)), store, cache)
	if err := add.Add(t.Context(), cfg); err != nil {
		t.Fatalf("Add: %v", err)
	}
	// Republished signed by a key the consumer never trusted.
	otherPub, otherPriv := keypair(t)
	rotated := repository.NewClient(
		publishRepo(t, otherPub, otherPriv, 6, indexGeneratedAt(generatedNewer)), store, cache)
	if err := rotated.Refresh(t.Context(), cfg); err == nil {
		t.Error("Refresh should reject a descriptor signed by an unknown key")
	}
}

func TestClientRefreshNeedsPriorState(t *testing.T) {
	pub, priv := keypair(t)
	client := repository.NewClient(
		publishRepo(t, pub, priv, 5, indexGeneratedAt(generatedBaseline)), newTestStore(t), t.TempDir())
	if err := client.Refresh(t.Context(), testConfig(pub)); err == nil {
		t.Error("Refresh should fail for a repository that was never added")
	}
}

func TestClientArchiveIndex(t *testing.T) {
	pub, priv := keypair(t)
	cfg := testConfig(pub)
	client := repository.NewClient(
		publishRepo(t, pub, priv, 5, indexGeneratedAt(generatedBaseline)), newTestStore(t), t.TempDir())
	if err := client.Add(t.Context(), cfg); err != nil {
		t.Fatalf("Add: %v", err)
	}
	idx, err := client.ArchiveIndex(t.Context(), cfg)
	if err != nil {
		t.Fatalf("ArchiveIndex: %v", err)
	}
	if idx.Kind != repository.IndexArchive {
		t.Errorf("archive index kind: got %q, want %q", idx.Kind, repository.IndexArchive)
	}
	if len(idx.Packages) != 1 || idx.Packages[0].Name != "nginx" {
		t.Errorf("archive index packages: %+v", idx.Packages)
	}
}

func TestClientAddRejectsBelowMinIndexVersion(t *testing.T) {
	pub, priv := keypair(t)

	// The served active index is version 5; a minimum of 10 refuses it.
	cfg := testConfig(pub)
	cfg.MinIndexVersion = 10
	below := repository.NewClient(
		publishRepo(t, pub, priv, 5, indexGeneratedAt(generatedBaseline)), newTestStore(t), t.TempDir())
	if err := below.Add(t.Context(), cfg); err == nil {
		t.Error("Add should refuse an index below the configured minimum (§6.2.3)")
	}

	// At the minimum, the add succeeds.
	cfg.MinIndexVersion = 5
	atFloor := repository.NewClient(
		publishRepo(t, pub, priv, 5, indexGeneratedAt(generatedBaseline)), newTestStore(t), t.TempDir())
	if err := atFloor.Add(t.Context(), cfg); err != nil {
		t.Errorf("Add should accept an index at the minimum: %v", err)
	}
}

func TestClientAddUnsigned(t *testing.T) {
	pub, priv := keypair(t)
	// An unsigned-mode repository publishes no detached signatures.
	fetcher := publishRepo(t, pub, priv, 5, indexGeneratedAt(generatedBaseline))
	delete(fetcher, testRepoBase+"/repo.json.sig")
	delete(fetcher, testRepoBase+"/index/active.json.sig")
	delete(fetcher, testRepoBase+"/index/archive.json.sig")

	// The `optional` policy with no trust anchors selects unsigned mode.
	cfg := config.RepoConfig{
		Name: testRepoName, BaseURL: testRepoBase,
		Priority: 10, SignaturePolicy: config.PolicyOptional,
	}
	if !repository.UnsignedMode(cfg) {
		t.Fatal("config should select unsigned mode")
	}
	client := repository.NewClient(fetcher, newTestStore(t), t.TempDir())
	if err := client.Add(t.Context(), cfg); err != nil {
		t.Fatalf("Add (unsigned): %v", err)
	}
	idx, err := client.ActiveIndex(t.Context(), testRepoName)
	if err != nil {
		t.Fatalf("ActiveIndex (unsigned): %v", err)
	}
	if idx.IndexVersion != 5 || len(idx.Packages) != 1 {
		t.Errorf("unsigned index: version=%d, packages=%d", idx.IndexVersion, len(idx.Packages))
	}
}

func TestClientAddRequiredRejectsMissingSignature(t *testing.T) {
	pub, priv := keypair(t)
	// A required-policy repository must serve a descriptor signature.
	fetcher := publishRepo(t, pub, priv, 5, indexGeneratedAt(generatedBaseline))
	delete(fetcher, testRepoBase+"/repo.json.sig")
	client := repository.NewClient(fetcher, newTestStore(t), t.TempDir())
	if err := client.Add(t.Context(), testConfig(pub)); err == nil {
		t.Error("Add should fail for a required-policy repository with no descriptor signature")
	}
}

// §5.34 says a consumer never resets a recorded freshness floor as a
// side effect of any operation other than removing the repository —
// and `peipkg repo add <name>` on an already-configured repository
// reads as idempotent, so a convergence loop runs it routinely (PEI-378).
func TestClientAddDoesNotResetTheFreshnessFloor(t *testing.T) {
	pub, priv := keypair(t)
	store, cache, cfg := newTestStore(t), t.TempDir(), testConfig(pub)

	add := repository.NewClient(publishRepo(t, pub, priv, 97, indexGeneratedAt(generatedBaseline)), store, cache)
	if err := add.Add(t.Context(), cfg); err != nil {
		t.Fatalf("Add: %v", err)
	}
	// A stale-but-correctly-signed index replayed at the add. Refresh
	// refuses this; so must a re-add, or the rollback becomes permanent.
	rollback := repository.NewClient(publishRepo(t, pub, priv, 40, indexGeneratedAt(generatedOlder)), store, cache)
	if err := rollback.Add(t.Context(), cfg); err == nil {
		t.Fatal("a re-add serving a rolled-back index should be refused")
	}
	row, found, err := store.GetRepository(t.Context(), testRepoName)
	if err != nil || !found {
		t.Fatalf("GetRepository: %v (found=%v)", err, found)
	}
	if row.HighestIndexVersion != 97 {
		t.Errorf("recorded floor = %d, want it held at 97", row.HighestIndexVersion)
	}
}

// A re-add that serves exactly the recorded index is a frozen
// repository, not a fresh one: it may be used, but it must not advance
// the last-refresh time, or a freeze defeats the maximum-trusted-age
// gate (§6.2.3).
func TestClientAddOnAFrozenRepositoryDoesNotAdvanceLastRefresh(t *testing.T) {
	pub, priv := keypair(t)
	store, cache, cfg := newTestStore(t), t.TempDir(), testConfig(pub)
	repo := publishRepo(t, pub, priv, 5, indexGeneratedAt(generatedBaseline))

	client := repository.NewClient(repo, store, cache)
	if err := client.Add(t.Context(), cfg); err != nil {
		t.Fatalf("Add: %v", err)
	}
	first, _, err := store.GetRepository(t.Context(), testRepoName)
	if err != nil {
		t.Fatalf("GetRepository: %v", err)
	}
	// Roll the recorded refresh time back, so an advance is visible.
	first.LastRefreshAt = first.LastRefreshAt.Add(-48 * time.Hour)
	if err := store.UpsertRepository(t.Context(), first); err != nil {
		t.Fatalf("UpsertRepository: %v", err)
	}

	if err := client.Add(t.Context(), cfg); err != nil {
		t.Fatalf("re-Add of an unchanged repository: %v", err)
	}
	second, _, err := store.GetRepository(t.Context(), testRepoName)
	if err != nil {
		t.Fatalf("GetRepository: %v", err)
	}
	if !second.LastRefreshAt.Equal(first.LastRefreshAt) {
		t.Errorf("last refresh advanced from %s to %s on a frozen index",
			first.LastRefreshAt, second.LastRefreshAt)
	}
}

// `repo remove` then `repo add` is the sanctioned way to clear a floor:
// removing the repository discards its whole trust state, which is what
// makes the reset an explicit operator act rather than a side effect.
func TestClientAddAfterRemoveStartsFromNoFloor(t *testing.T) {
	pub, priv := keypair(t)
	store, cache, cfg := newTestStore(t), t.TempDir(), testConfig(pub)

	add := repository.NewClient(publishRepo(t, pub, priv, 97, indexGeneratedAt(generatedBaseline)), store, cache)
	if err := add.Add(t.Context(), cfg); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := store.DeleteRepository(t.Context(), testRepoName); err != nil {
		t.Fatalf("DeleteRepository: %v", err)
	}
	readd := repository.NewClient(publishRepo(t, pub, priv, 40, indexGeneratedAt(generatedOlder)), store, cache)
	if err := readd.Add(t.Context(), cfg); err != nil {
		t.Fatalf("Add after remove: %v", err)
	}
	row, _, err := store.GetRepository(t.Context(), testRepoName)
	if err != nil {
		t.Fatalf("GetRepository: %v", err)
	}
	if row.HighestIndexVersion != 40 {
		t.Errorf("recorded floor = %d, want 40 after a remove/add", row.HighestIndexVersion)
	}
}

// §5.34's freshness requirements apply to both indexes, and §5.35 gives
// the archive index identical index_version semantics. The archive
// index is the candidate source for every downgrade and pin, so a
// replayed one steers an operator back onto a withdrawn version (PEI-386).
func TestArchiveIndexRejectsRollback(t *testing.T) {
	pub, priv := keypair(t)
	store, cache, cfg := newTestStore(t), t.TempDir(), testConfig(pub)

	add := repository.NewClient(publishRepo(t, pub, priv, 6, indexGeneratedAt(generatedNewer)), store, cache)
	if err := add.Add(t.Context(), cfg); err != nil {
		t.Fatalf("Add: %v", err)
	}
	// An old, still validly signed archive index substituted at fetch.
	replay := repository.NewClient(publishRepo(t, pub, priv, 3, indexGeneratedAt(generatedOlder)), store, cache)
	if _, err := replay.ArchiveIndex(t.Context(), cfg); err == nil {
		t.Fatal("ArchiveIndex should reject a rolled-back archive index")
	} else if !strings.Contains(err.Error(), "rolled-back archive index") {
		t.Errorf("ArchiveIndex error = %v, want a rollback rejection", err)
	}
}

// The archive index sits at the recorded floor in the ordinary case —
// repopub publishes both indexes at one version — so the floor must not
// turn a current archive into a rejection.
func TestArchiveIndexAcceptsTheRecordedVersion(t *testing.T) {
	pub, priv := keypair(t)
	store, cache, cfg := newTestStore(t), t.TempDir(), testConfig(pub)
	repo := publishRepo(t, pub, priv, 6, indexGeneratedAt(generatedNewer))

	client := repository.NewClient(repo, store, cache)
	if err := client.Add(t.Context(), cfg); err != nil {
		t.Fatalf("Add: %v", err)
	}
	idx, err := client.ArchiveIndex(t.Context(), cfg)
	if err != nil {
		t.Fatalf("ArchiveIndex at the recorded version: %v", err)
	}
	if idx.IndexVersion != 6 {
		t.Errorf("archive index version = %d, want 6", idx.IndexVersion)
	}
}
