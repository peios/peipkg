package repository

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/peios/peipkg/internal/config"
	"github.com/peios/peipkg/internal/db"
	"github.com/peios/peipkg/internal/signature"
)

// Client orchestrates the repository operations that span the network,
// the package database, and the on-disk index cache: adding a
// repository, refreshing its metadata, and loading its verified active
// index.
//
// A repository configured with the `optional` signature policy and no
// trust anchors is operated in unsigned mode (§6.5.3): its descriptor
// and index are fetched and decoded but not verified, it records an
// empty trust set, and the caller is expected to warn the operator on
// every operation that touches it. UnsignedMode reports this.
type Client struct {
	fetcher  Fetcher
	store    *db.DB
	cacheDir string
}

// NewClient returns a Client that fetches through fetcher, records
// repository state in store, and caches indexes under cacheDir.
func NewClient(fetcher Fetcher, store *db.DB, cacheDir string) *Client {
	return &Client{fetcher: fetcher, store: store, cacheDir: cacheDir}
}

// UnsignedMode reports whether cfg selects unverified (unsigned-mode)
// operation: the `optional` signature policy with no trust anchors to
// bootstrap verification against (§6.5.3). Choosing `optional` without
// anchors is the operator's deliberate opt-in; callers MUST warn on
// every operation that touches such a repository.
func UnsignedMode(cfg config.RepoConfig) bool {
	return cfg.SignaturePolicy == config.PolicyOptional && len(cfg.TrustAnchors) == 0
}

// Add performs the first-add trust ceremony (§6.5.2): it fetches the
// descriptor and verifies it against the operator-supplied trust
// anchors, fetches and verifies the active index, and records the
// repository's initial trust state and freshness floor.
func (c *Client) Add(ctx context.Context, cfg config.RepoConfig) error {
	now := time.Now()
	descriptorURL := cfg.BaseURL + "/repo.json"

	if UnsignedMode(cfg) {
		return c.addUnsigned(ctx, cfg, now)
	}

	desc, descBytes, descSig, err := c.fetchDescriptor(ctx, cfg)
	if err != nil {
		return err
	}
	keys, err := c.fetchKeys(ctx, cfg, desc, descriptorURL)
	if err != nil {
		return err
	}
	// The descriptor must be signed by a key the operator anchored
	// out-of-band — this is the trust bootstrap (§6.5.2).
	anchorKeys := keysMatchingAnchors(keys, cfg.TrustAnchors)
	if len(anchorKeys) == 0 {
		return fmt.Errorf("peipkg/repository: no signing key of %q matches a configured "+
			"trust anchor", cfg.Name)
	}
	if err := VerifyDetached(descBytes, descSig, anchorKeys); err != nil {
		return fmt.Errorf("peipkg/repository: descriptor for %q: %w", cfg.Name, err)
	}

	trust, err := NewTrustSet(desc, keys)
	if err != nil {
		return err
	}
	idx, idxBytes, idxSig, err := c.fetchActiveIndex(ctx, cfg, desc, descriptorURL, trust, now)
	if err != nil {
		return err
	}
	// §6.2.3: refuse the first-add when the served index is below the
	// operator-supplied minimum — an out-of-band rollback floor that
	// defends against a stale-but-signed index at the trust bootstrap.
	if cfg.MinIndexVersion > 0 && idx.IndexVersion < cfg.MinIndexVersion {
		return fmt.Errorf("peipkg/repository: %q served active index version %d, below the "+
			"configured minimum %d; repo-add refused (§6.2.3)",
			cfg.Name, idx.IndexVersion, cfg.MinIndexVersion)
	}
	trustJSON, err := trust.Marshal()
	if err != nil {
		return err
	}
	return c.record(ctx, db.Repository{
		Name:                cfg.Name,
		HighestIndexVersion: idx.IndexVersion,
		GeneratedAtFloor:    idx.GeneratedAt.Unix(),
		LastRefreshAt:       now,
		TrustKeys:           trustJSON,
	}, idxBytes, idxSig)
}

// Refresh re-fetches a repository's descriptor and active index,
// verifies them against the previously-recorded trust state, applies
// the §6.2.3 freshness gate, and — on progress — adopts the new trust
// state and advances the freshness floor (§6.5.4).
//
// A refresh that cannot be verified, or whose index is a rollback,
// leaves the recorded state untouched and returns an error.
func (c *Client) Refresh(ctx context.Context, cfg config.RepoConfig) error {
	now := time.Now()
	descriptorURL := cfg.BaseURL + "/repo.json"

	if UnsignedMode(cfg) {
		return c.refreshUnsigned(ctx, cfg, now)
	}

	prev, found, err := c.store.GetRepository(ctx, cfg.Name)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("peipkg/repository: %q has no recorded trust state; add it first", cfg.Name)
	}
	prevTrust, err := ParseTrustSet(prev.TrustKeys)
	if err != nil {
		return err
	}

	desc, descBytes, descSig, err := c.fetchDescriptor(ctx, cfg)
	if err != nil {
		return err
	}
	// §6.5.4 step 2: the new descriptor is verified against keys that
	// were trusted in the previously-recorded descriptor.
	if err := VerifyDetached(descBytes, descSig, prevTrust.VerificationKeys(now)); err != nil {
		return fmt.Errorf("peipkg/repository: descriptor for %q: %w", cfg.Name, err)
	}
	keys, err := c.fetchKeys(ctx, cfg, desc, descriptorURL)
	if err != nil {
		return err
	}
	newTrust, err := NewTrustSet(desc, keys)
	if err != nil {
		return err
	}
	idx, idxBytes, idxSig, err := c.fetchActiveIndex(ctx, cfg, desc, descriptorURL, newTrust, now)
	if err != nil {
		return err
	}
	trustJSON, err := newTrust.Marshal()
	if err != nil {
		return err
	}

	row := db.Repository{Name: cfg.Name, TrustKeys: trustJSON}
	switch CheckFreshness(idx, prev.HighestIndexVersion, time.Unix(prev.GeneratedAtFloor, 0)) {
	case FreshnessRejected:
		return fmt.Errorf("peipkg/repository: %q served a rolled-back index "+
			"(version %d, recorded floor %d); refresh refused",
			cfg.Name, idx.IndexVersion, prev.HighestIndexVersion)
	case FreshnessNoProgress:
		// §6.2.3: the descriptor's trust state is adopted, but the
		// freshness floor and last-refresh time do not advance — a
		// frozen index must not satisfy the maximum-trusted-age check.
		row.HighestIndexVersion = prev.HighestIndexVersion
		row.GeneratedAtFloor = prev.GeneratedAtFloor
		row.LastRefreshAt = prev.LastRefreshAt
	default: // FreshnessProgress
		row.HighestIndexVersion = idx.IndexVersion
		row.GeneratedAtFloor = idx.GeneratedAt.Unix()
		row.LastRefreshAt = now
	}
	return c.record(ctx, row, idxBytes, idxSig)
}

// ActiveIndex loads, re-verifies, and decodes a repository's cached
// active index. Per §6.2.10 the cached index's signature is verified on
// every use rather than trusted across operations.
func (c *Client) ActiveIndex(ctx context.Context, repoName string) (Index, error) {
	row, found, err := c.store.GetRepository(ctx, repoName)
	if err != nil {
		return Index{}, err
	}
	if !found {
		return Index{}, fmt.Errorf("peipkg/repository: %q has no recorded trust state", repoName)
	}
	trust, err := ParseTrustSet(row.TrustKeys)
	if err != nil {
		return Index{}, err
	}
	idxBytes, idxSig, err := c.loadCachedIndex(repoName)
	if err != nil {
		return Index{}, err
	}
	// A signed repository records signing keys; its cached index is
	// re-verified on every use (§6.2.10). An unsigned-mode repository
	// records an empty trust set and caches no signature — there is
	// nothing to verify against (§6.5.3).
	if len(trust.Keys) > 0 {
		if idxSig == nil {
			return Index{}, fmt.Errorf(
				"peipkg/repository: cached index for %q has no signature", repoName)
		}
		if err := VerifyDetached(idxBytes, idxSig, trust.VerificationKeys(time.Now())); err != nil {
			return Index{}, fmt.Errorf("peipkg/repository: cached index for %q: %w", repoName, err)
		}
	}
	return DecodeIndex(idxBytes)
}

// addUnsigned performs the first-add of a repository in unsigned mode
// (§6.5.3): its descriptor and active index are fetched and decoded but
// not verified, and the recorded trust set is left empty.
func (c *Client) addUnsigned(ctx context.Context, cfg config.RepoConfig, now time.Time) error {
	desc, err := c.fetchDescriptorDocument(ctx, cfg)
	if err != nil {
		return err
	}
	idx, idxBytes, err := c.fetchIndexDocument(ctx, cfg, desc, desc.ActiveIndex, IndexActive)
	if err != nil {
		return err
	}
	if cfg.MinIndexVersion > 0 && idx.IndexVersion < cfg.MinIndexVersion {
		return fmt.Errorf("peipkg/repository: %q served active index version %d, below the "+
			"configured minimum %d; repo-add refused (§6.2.3)",
			cfg.Name, idx.IndexVersion, cfg.MinIndexVersion)
	}
	return c.record(ctx, db.Repository{
		Name:                cfg.Name,
		HighestIndexVersion: idx.IndexVersion,
		GeneratedAtFloor:    idx.GeneratedAt.Unix(),
		LastRefreshAt:       now,
		TrustKeys:           "", // an empty trust set marks unsigned mode
	}, idxBytes, nil)
}

// refreshUnsigned re-fetches an unsigned-mode repository's descriptor
// and active index and applies the §6.2.3 freshness gate. Nothing is
// verified; the recorded trust set stays empty.
func (c *Client) refreshUnsigned(ctx context.Context, cfg config.RepoConfig, now time.Time) error {
	prev, found, err := c.store.GetRepository(ctx, cfg.Name)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("peipkg/repository: %q has no recorded state; add it first", cfg.Name)
	}
	desc, err := c.fetchDescriptorDocument(ctx, cfg)
	if err != nil {
		return err
	}
	idx, idxBytes, err := c.fetchIndexDocument(ctx, cfg, desc, desc.ActiveIndex, IndexActive)
	if err != nil {
		return err
	}

	row := db.Repository{Name: cfg.Name, TrustKeys: ""}
	switch CheckFreshness(idx, prev.HighestIndexVersion, time.Unix(prev.GeneratedAtFloor, 0)) {
	case FreshnessRejected:
		return fmt.Errorf("peipkg/repository: %q served a rolled-back index "+
			"(version %d, recorded floor %d); refresh refused",
			cfg.Name, idx.IndexVersion, prev.HighestIndexVersion)
	case FreshnessNoProgress:
		row.HighestIndexVersion = prev.HighestIndexVersion
		row.GeneratedAtFloor = prev.GeneratedAtFloor
		row.LastRefreshAt = prev.LastRefreshAt
	default: // FreshnessProgress
		row.HighestIndexVersion = idx.IndexVersion
		row.GeneratedAtFloor = idx.GeneratedAt.Unix()
		row.LastRefreshAt = now
	}
	return c.record(ctx, row, idxBytes, nil)
}

// ArchiveIndex fetches, verifies, and decodes a repository's archive
// index (§6.3) — the full version history, used for downgrades and
// historical queries. Unlike the active index it is not cached: it is
// large and consulted rarely (§6.3), so it is fetched fresh each time.
//
// The descriptor is re-fetched and verified against the trust state
// recorded at the last add or refresh; the archive index is then
// verified against the descriptor's current keys.
func (c *Client) ArchiveIndex(ctx context.Context, cfg config.RepoConfig) (Index, error) {
	now := time.Now()
	descriptorURL := cfg.BaseURL + "/repo.json"

	row, found, err := c.store.GetRepository(ctx, cfg.Name)
	if err != nil {
		return Index{}, err
	}
	if !found {
		return Index{}, fmt.Errorf(
			"peipkg/repository: %q has no recorded trust state; add it first", cfg.Name)
	}
	prevTrust, err := ParseTrustSet(row.TrustKeys)
	if err != nil {
		return Index{}, err
	}
	desc, descBytes, descSig, err := c.fetchDescriptor(ctx, cfg)
	if err != nil {
		return Index{}, err
	}
	if err := VerifyDetached(descBytes, descSig, prevTrust.VerificationKeys(now)); err != nil {
		return Index{}, fmt.Errorf("peipkg/repository: descriptor for %q: %w", cfg.Name, err)
	}
	keys, err := c.fetchKeys(ctx, cfg, desc, descriptorURL)
	if err != nil {
		return Index{}, err
	}
	trust, err := NewTrustSet(desc, keys)
	if err != nil {
		return Index{}, err
	}
	return c.fetchArchiveIndex(ctx, cfg, desc, descriptorURL, trust, now)
}

// fetchDescriptor fetches and decodes a repository's descriptor and its
// detached signature.
func (c *Client) fetchDescriptor(ctx context.Context, cfg config.RepoConfig) (
	Descriptor, []byte, []byte, error) {

	descBytes, err := c.fetcher.Fetch(ctx, cfg.BaseURL+"/repo.json", maxDescriptorFetch)
	if err != nil {
		return Descriptor{}, nil, nil, err
	}
	descSig, err := c.fetcher.Fetch(ctx, cfg.BaseURL+"/repo.json.sig", maxSignatureFetch)
	if err != nil {
		return Descriptor{}, nil, nil, err
	}
	desc, err := DecodeDescriptor(descBytes)
	if err != nil {
		return Descriptor{}, nil, nil, err
	}
	if desc.RepoName == "" {
		return Descriptor{}, nil, nil, fmt.Errorf("peipkg/repository: descriptor has no repo name")
	}
	return desc, descBytes, descSig, nil
}

// fetchDescriptorDocument fetches and decodes a repository's descriptor
// without its detached signature — the unsigned-mode path (§6.5.3).
func (c *Client) fetchDescriptorDocument(ctx context.Context, cfg config.RepoConfig) (
	Descriptor, error) {

	descBytes, err := c.fetcher.Fetch(ctx, cfg.BaseURL+"/repo.json", maxDescriptorFetch)
	if err != nil {
		return Descriptor{}, err
	}
	return DecodeDescriptor(descBytes)
}

// fetchIndexDocument fetches and decodes an index without its detached
// signature — the unsigned-mode path (§6.5.3). It still checks the
// index kind and that the index names the descriptor's repository.
func (c *Client) fetchIndexDocument(ctx context.Context, cfg config.RepoConfig, desc Descriptor,
	ptr IndexPointer, expectKind IndexKind) (Index, []byte, error) {

	idxURL, err := resolveURL(cfg.BaseURL, cfg.BaseURL+"/repo.json", ptr.URL,
		cfg.AllowInsecureTransport)
	if err != nil {
		return Index{}, nil, err
	}
	idxBytes, err := c.fetcher.Fetch(ctx, idxURL, maxIndexFetch)
	if err != nil {
		return Index{}, nil, err
	}
	idx, err := DecodeIndex(idxBytes)
	if err != nil {
		return Index{}, nil, err
	}
	if idx.Kind != expectKind {
		return Index{}, nil, fmt.Errorf(
			"peipkg/repository: %q served a %q index where the %q index was expected",
			cfg.Name, idx.Kind, expectKind)
	}
	if idx.RepoName != desc.RepoName {
		return Index{}, nil, fmt.Errorf(
			"peipkg/repository: index names repository %q but the descriptor names %q",
			idx.RepoName, desc.RepoName)
	}
	return idx, idxBytes, nil
}

// fetchKeys fetches every signing key file the descriptor declares and
// confirms each hashes to its declared fingerprint (§5.2.3).
func (c *Client) fetchKeys(ctx context.Context, cfg config.RepoConfig, desc Descriptor,
	descriptorURL string) (map[string]ed25519.PublicKey, error) {

	keys := make(map[string]ed25519.PublicKey, len(desc.Keys))
	for _, dk := range desc.Keys {
		keyURL, err := resolveURL(cfg.BaseURL, descriptorURL, dk.URL, cfg.AllowInsecureTransport)
		if err != nil {
			return nil, err
		}
		data, err := c.fetcher.Fetch(ctx, keyURL, maxKeyFetch)
		if err != nil {
			return nil, err
		}
		pub, err := signature.ParsePublicKey(data)
		if err != nil {
			return nil, fmt.Errorf("peipkg/repository: signing key %s: %w", dk.Fingerprint, err)
		}
		if signature.Fingerprint(pub) != dk.Fingerprint {
			return nil, fmt.Errorf(
				"peipkg/repository: fetched key does not hash to declared fingerprint %s",
				dk.Fingerprint)
		}
		keys[dk.Fingerprint] = pub
	}
	return keys, nil
}

// fetchActiveIndex fetches, verifies, and decodes a repository's active
// index against a trust set.
func (c *Client) fetchActiveIndex(ctx context.Context, cfg config.RepoConfig, desc Descriptor,
	descriptorURL string, trust TrustSet, now time.Time) (Index, []byte, []byte, error) {

	idxURL, err := resolveURL(cfg.BaseURL, descriptorURL, desc.ActiveIndex.URL,
		cfg.AllowInsecureTransport)
	if err != nil {
		return Index{}, nil, nil, err
	}
	sigURL, err := resolveURL(cfg.BaseURL, descriptorURL, desc.ActiveIndex.SignatureURL,
		cfg.AllowInsecureTransport)
	if err != nil {
		return Index{}, nil, nil, err
	}
	idxBytes, err := c.fetcher.Fetch(ctx, idxURL, maxIndexFetch)
	if err != nil {
		return Index{}, nil, nil, err
	}
	idxSig, err := c.fetcher.Fetch(ctx, sigURL, maxSignatureFetch)
	if err != nil {
		return Index{}, nil, nil, err
	}
	if err := VerifyDetached(idxBytes, idxSig, trust.VerificationKeys(now)); err != nil {
		return Index{}, nil, nil, fmt.Errorf("peipkg/repository: active index for %q: %w",
			cfg.Name, err)
	}
	idx, err := DecodeIndex(idxBytes)
	if err != nil {
		return Index{}, nil, nil, err
	}
	if idx.Kind != IndexActive {
		return Index{}, nil, nil, fmt.Errorf(
			"peipkg/repository: %q served a %q index where the active index was expected",
			cfg.Name, idx.Kind)
	}
	if idx.RepoName != desc.RepoName {
		return Index{}, nil, nil, fmt.Errorf(
			"peipkg/repository: index names repository %q but the descriptor names %q",
			idx.RepoName, desc.RepoName)
	}
	return idx, idxBytes, idxSig, nil
}

// fetchArchiveIndex fetches, verifies, and decodes a repository's
// archive index against a trust set.
func (c *Client) fetchArchiveIndex(ctx context.Context, cfg config.RepoConfig, desc Descriptor,
	descriptorURL string, trust TrustSet, now time.Time) (Index, error) {

	idxURL, err := resolveURL(cfg.BaseURL, descriptorURL, desc.ArchiveIndex.URL,
		cfg.AllowInsecureTransport)
	if err != nil {
		return Index{}, err
	}
	sigURL, err := resolveURL(cfg.BaseURL, descriptorURL, desc.ArchiveIndex.SignatureURL,
		cfg.AllowInsecureTransport)
	if err != nil {
		return Index{}, err
	}
	idxBytes, err := c.fetcher.Fetch(ctx, idxURL, maxIndexFetch)
	if err != nil {
		return Index{}, err
	}
	idxSig, err := c.fetcher.Fetch(ctx, sigURL, maxSignatureFetch)
	if err != nil {
		return Index{}, err
	}
	if err := VerifyDetached(idxBytes, idxSig, trust.VerificationKeys(now)); err != nil {
		return Index{}, fmt.Errorf("peipkg/repository: archive index for %q: %w", cfg.Name, err)
	}
	idx, err := DecodeIndex(idxBytes)
	if err != nil {
		return Index{}, err
	}
	if idx.Kind != IndexArchive {
		return Index{}, fmt.Errorf(
			"peipkg/repository: %q served a %q index where the archive index was expected",
			cfg.Name, idx.Kind)
	}
	if idx.RepoName != desc.RepoName {
		return Index{}, fmt.Errorf(
			"peipkg/repository: archive index names repository %q but the descriptor names %q",
			idx.RepoName, desc.RepoName)
	}
	return idx, nil
}

// record persists a repository's updated state: the database row and
// the cached active index.
func (c *Client) record(ctx context.Context, row db.Repository, idxBytes, idxSig []byte) error {
	if err := c.store.UpsertRepository(ctx, row); err != nil {
		return err
	}
	return c.cacheIndex(row.Name, idxBytes, idxSig)
}

// cacheIndex writes a repository's active index and its signature to the
// on-disk cache.
func (c *Client) cacheIndex(repoName string, idxBytes, idxSig []byte) error {
	if err := os.MkdirAll(c.cacheDir, 0o755); err != nil {
		return fmt.Errorf("peipkg/repository: creating cache directory: %w", err)
	}
	idxPath := filepath.Join(c.cacheDir, repoName+".active.json")
	if err := os.WriteFile(idxPath, idxBytes, 0o644); err != nil {
		return fmt.Errorf("peipkg/repository: caching index for %q: %w", repoName, err)
	}
	sigPath := idxPath + ".sig"
	if idxSig == nil {
		// Unsigned-mode repository: drop any signature left from an
		// earlier signed state so it cannot be verified against later.
		if err := os.Remove(sigPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("peipkg/repository: clearing index signature for %q: %w",
				repoName, err)
		}
		return nil
	}
	if err := os.WriteFile(sigPath, idxSig, 0o644); err != nil {
		return fmt.Errorf("peipkg/repository: caching index signature for %q: %w", repoName, err)
	}
	return nil
}

// loadCachedIndex reads a repository's cached active index and signature.
func (c *Client) loadCachedIndex(repoName string) ([]byte, []byte, error) {
	idxPath := filepath.Join(c.cacheDir, repoName+".active.json")
	idxBytes, err := os.ReadFile(idxPath)
	if err != nil {
		return nil, nil, fmt.Errorf("peipkg/repository: reading cached index for %q: %w",
			repoName, err)
	}
	idxSig, err := os.ReadFile(idxPath + ".sig")
	if errors.Is(err, fs.ErrNotExist) {
		return idxBytes, nil, nil // an unsigned-mode repository caches no signature
	}
	if err != nil {
		return nil, nil, fmt.Errorf("peipkg/repository: reading cached index signature for %q: %w",
			repoName, err)
	}
	return idxBytes, idxSig, nil
}

// keysMatchingAnchors returns the public keys whose fingerprint appears
// among the operator-supplied trust anchors.
func keysMatchingAnchors(keys map[string]ed25519.PublicKey, anchors []string) []ed25519.PublicKey {
	var matched []ed25519.PublicKey
	for _, anchor := range anchors {
		if pub, ok := keys[anchor]; ok {
			matched = append(matched, pub)
		}
	}
	return matched
}
