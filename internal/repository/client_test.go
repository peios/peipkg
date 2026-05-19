package repository_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"

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
		return []byte(base64.RawStdEncoding.EncodeToString(ed25519.Sign(priv, b)))
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
		publishRepo(t, pub, priv, 5, "2026-05-19T00:00:00Z"), newTestStore(t), t.TempDir())

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

func TestClientAddRejectsUntrustedAnchor(t *testing.T) {
	pub, priv := keypair(t)
	wrongAnchor, _ := keypair(t)
	client := repository.NewClient(
		publishRepo(t, pub, priv, 5, "2026-05-19T00:00:00Z"), newTestStore(t), t.TempDir())

	cfg := testConfig(pub)
	cfg.TrustAnchors = []string{signature.Fingerprint(wrongAnchor)}
	if err := client.Add(t.Context(), cfg); err == nil {
		t.Error("Add should fail when no signing key matches a trust anchor")
	}
}

func TestClientRefreshProgress(t *testing.T) {
	pub, priv := keypair(t)
	store, cache, cfg := newTestStore(t), t.TempDir(), testConfig(pub)

	add := repository.NewClient(publishRepo(t, pub, priv, 5, "2026-05-19T00:00:00Z"), store, cache)
	if err := add.Add(t.Context(), cfg); err != nil {
		t.Fatalf("Add: %v", err)
	}
	// Republished at a higher index version: the refresh accepts it.
	refresh := repository.NewClient(publishRepo(t, pub, priv, 6, "2026-05-20T00:00:00Z"), store, cache)
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

func TestClientRefreshRejectsRollback(t *testing.T) {
	pub, priv := keypair(t)
	store, cache, cfg := newTestStore(t), t.TempDir(), testConfig(pub)

	add := repository.NewClient(publishRepo(t, pub, priv, 5, "2026-05-19T00:00:00Z"), store, cache)
	if err := add.Add(t.Context(), cfg); err != nil {
		t.Fatalf("Add: %v", err)
	}
	// Republished at a lower index version: a rollback, refused (§6.2.3).
	rollback := repository.NewClient(publishRepo(t, pub, priv, 3, "2026-05-10T00:00:00Z"), store, cache)
	if err := rollback.Refresh(t.Context(), cfg); err == nil {
		t.Error("Refresh should reject a rolled-back index")
	}
}

func TestClientRefreshRejectsUntrustedDescriptor(t *testing.T) {
	pub, priv := keypair(t)
	store, cache, cfg := newTestStore(t), t.TempDir(), testConfig(pub)

	add := repository.NewClient(publishRepo(t, pub, priv, 5, "2026-05-19T00:00:00Z"), store, cache)
	if err := add.Add(t.Context(), cfg); err != nil {
		t.Fatalf("Add: %v", err)
	}
	// Republished signed by a key the consumer never trusted.
	otherPub, otherPriv := keypair(t)
	rotated := repository.NewClient(
		publishRepo(t, otherPub, otherPriv, 6, "2026-05-20T00:00:00Z"), store, cache)
	if err := rotated.Refresh(t.Context(), cfg); err == nil {
		t.Error("Refresh should reject a descriptor signed by an unknown key")
	}
}

func TestClientRefreshNeedsPriorState(t *testing.T) {
	pub, priv := keypair(t)
	client := repository.NewClient(
		publishRepo(t, pub, priv, 5, "2026-05-19T00:00:00Z"), newTestStore(t), t.TempDir())
	if err := client.Refresh(t.Context(), testConfig(pub)); err == nil {
		t.Error("Refresh should fail for a repository that was never added")
	}
}

func TestClientArchiveIndex(t *testing.T) {
	pub, priv := keypair(t)
	cfg := testConfig(pub)
	client := repository.NewClient(
		publishRepo(t, pub, priv, 5, "2026-05-19T00:00:00Z"), newTestStore(t), t.TempDir())
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
		publishRepo(t, pub, priv, 5, "2026-05-19T00:00:00Z"), newTestStore(t), t.TempDir())
	if err := below.Add(t.Context(), cfg); err == nil {
		t.Error("Add should refuse an index below the configured minimum (§6.2.3)")
	}

	// At the minimum, the add succeeds.
	cfg.MinIndexVersion = 5
	atFloor := repository.NewClient(
		publishRepo(t, pub, priv, 5, "2026-05-19T00:00:00Z"), newTestStore(t), t.TempDir())
	if err := atFloor.Add(t.Context(), cfg); err != nil {
		t.Errorf("Add should accept an index at the minimum: %v", err)
	}
}

func TestClientAddUnsigned(t *testing.T) {
	pub, priv := keypair(t)
	// An unsigned-mode repository publishes no detached signatures.
	fetcher := publishRepo(t, pub, priv, 5, "2026-05-19T00:00:00Z")
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
	fetcher := publishRepo(t, pub, priv, 5, "2026-05-19T00:00:00Z")
	delete(fetcher, testRepoBase+"/repo.json.sig")
	client := repository.NewClient(fetcher, newTestStore(t), t.TempDir())
	if err := client.Add(t.Context(), testConfig(pub)); err == nil {
		t.Error("Add should fail for a required-policy repository with no descriptor signature")
	}
}
