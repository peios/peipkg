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

// maxPackageFetchAllowance caps the slack permitted above a package's
// advertised compressed size when downloading it. §3.5.4 sets the
// allowance at the *lesser* of 1% of the advertised size or this value —
// see [packageFetchAllowance].
const maxPackageFetchAllowance = 16 << 20

// packageFetchAllowance returns the §3.5.4 download allowance for a
// package advertising sizeCompressed bytes: the lesser of 1% of that
// size or 16 MiB.
//
// The 1% half is the one that binds in practice. 1% only exceeds 16 MiB
// above a 1.6 GiB package, so taking the flat 16 MiB gave a 100 MB
// package 16 MB of slack where it is owed 1 MB, and a 1 KB package 16 MB
// where it is owed ten bytes.
func packageFetchAllowance(sizeCompressed int64) int64 {
	if sizeCompressed <= 0 {
		return 0
	}
	return min(sizeCompressed/100, maxPackageFetchAllowance)
}

// PackageFetchLimit is the §5.27 bound on a package download: the
// index-declared size_compressed plus the lesser of 1% or 16 MiB. It is
// exported so peipkg-compose, which downloads from a lock rather than
// straight from an index, applies the same bound rather than a flat
// figure of its own.
func PackageFetchLimit(sizeCompressed int64) int64 {
	return sizeCompressed + packageFetchAllowance(sizeCompressed)
}

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
	packageURL, expectedHash string, sizeCompressed, sizeInstalled int64) (
	*archive.Package, []byte, error) {

	url, err := resolveURL(cfg.BaseURL, cfg.BaseURL+"/repo.json", packageURL,
		cfg.AllowInsecureTransport)
	if err != nil {
		return nil, nil, err
	}
	data, err := c.fetcher.Fetch(ctx, url, PackageFetchLimit(sizeCompressed))
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
	// §5.27: the index's size_installed, not the manifest's, bounds
	// decompression — the manifest is inside the stream being bounded.
	pkg, err := archive.Verify(bytes.NewReader(data), trust.Resolver(time.Now()), sizeInstalled)
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
