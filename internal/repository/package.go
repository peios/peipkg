package repository

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/peios/peipkg/internal/archive"
	"github.com/peios/peipkg/internal/config"
)

// packageFetchAllowance is the slack permitted above a package's
// advertised compressed size when downloading it (§3.5.4).
const packageFetchAllowance = 16 << 20

// FetchPackage downloads, hash-checks, and signature-verifies a package
// file. packageURL is the candidate's URL, resolved against cfg's base;
// expectedHash is the lowercase-hex SHA-256 the index advertises
// (§6.2.8); sizeCompressed bounds the download (§3.5.4).
//
// It returns the verified package and the raw archive bytes — performing
// §3.5.3 steps 1-3. A package that fails the hash check, fails
// signature verification, or — under a `required` policy — is unsigned
// is rejected.
func (c *Client) FetchPackage(ctx context.Context, cfg config.RepoConfig,
	packageURL, expectedHash string, sizeCompressed int64) (*archive.Package, []byte, error) {

	url, err := resolveURL(cfg.BaseURL, cfg.BaseURL+"/repo.json", packageURL,
		cfg.AllowInsecureTransport)
	if err != nil {
		return nil, nil, err
	}
	data, err := c.fetcher.Fetch(ctx, url, sizeCompressed+packageFetchAllowance)
	if err != nil {
		return nil, nil, err
	}

	// §3.5.3 step 2: the download must match the hash the index advertises.
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != expectedHash {
		return nil, nil, fmt.Errorf(
			"peipkg/repository: package %s hash mismatch (got %s, want %s)",
			packageURL, got, expectedHash)
	}

	row, found, err := c.store.GetRepository(ctx, cfg.Name)
	if err != nil {
		return nil, nil, err
	}
	if !found {
		return nil, nil, fmt.Errorf(
			"peipkg/repository: %q has no recorded trust state; refresh it first", cfg.Name)
	}
	trust, err := ParseTrustSet(row.TrustKeys)
	if err != nil {
		return nil, nil, err
	}
	pkg, err := archive.Verify(bytes.NewReader(data), trust.Resolver(time.Now()))
	if err != nil {
		return nil, nil, err
	}
	if cfg.SignaturePolicy == config.PolicyRequired && !pkg.Signed {
		return nil, nil, fmt.Errorf(
			"peipkg/repository: package %s is unsigned, but %q requires signed packages",
			packageURL, cfg.Name)
	}
	return pkg, data, nil
}
