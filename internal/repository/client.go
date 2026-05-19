package repository

import (
	"context"
	"crypto/ed25519"
	"fmt"
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
// Note: v0.22 of this client requires a repository's descriptor and
// indexes to be signed. Fully-unsigned repositories — permitted under
// the `optional` signature policy (§6.1.6) — are a deferred case; the
// `optional` policy still governs unsigned package acceptance.
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

// Add performs the first-add trust ceremony (§6.5.2): it fetches the
// descriptor and verifies it against the operator-supplied trust
// anchors, fetches and verifies the active index, and records the
// repository's initial trust state and freshness floor.
func (c *Client) Add(ctx context.Context, cfg config.RepoConfig) error {
	now := time.Now()
	descriptorURL := cfg.BaseURL + "/repo.json"

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
	if err := VerifyDetached(idxBytes, idxSig, trust.VerificationKeys(time.Now())); err != nil {
		return Index{}, fmt.Errorf("peipkg/repository: cached index for %q: %w", repoName, err)
	}
	return DecodeIndex(idxBytes)
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
	if err := os.WriteFile(idxPath+".sig", idxSig, 0o644); err != nil {
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
