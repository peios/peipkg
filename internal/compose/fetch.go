package compose

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/peios/peipkg/internal/archive"
	"github.com/peios/peipkg/internal/repository"
)

// maxPackageFetch caps one .peipkg download. The cap is generous — real
// packages range from kilobytes to a few hundred megabytes — and exists
// to bound a runaway server response.
const maxPackageFetch = 1 << 30 // 1 GiB

// fetchedPackage is one .peipkg fetched, hash-checked against the lock,
// and format-verified. The assemble stage consumes these.
type fetchedPackage struct {
	Locked LockedPackage
	Pkg    *archive.Package
	// Raw is the verified archive's bytes; assemble re-reads them via
	// archive.Extract.
	Raw []byte
}

// fetchAll retrieves, hash-checks, and format-verifies every package in
// the lock. The path serves locked and non-locked builds alike: the
// lock's hash is the carried-forward result of the index signature
// verification done at lock time, and matching it confirms the bytes
// are exactly what the resolver chose.
func fetchAll(ctx context.Context, lock Lock, fetcher repository.Fetcher) ([]fetchedPackage, error) {
	fetched := make([]fetchedPackage, 0, len(lock.Packages))
	for _, lp := range lock.Packages {
		fp, err := fetchOne(ctx, lp, fetcher)
		if err != nil {
			return nil, err
		}
		fetched = append(fetched, fp)
	}
	return fetched, nil
}

// fetchOne retrieves one package by its lock entry. A repository
// package is fetched through fetcher; a local-source package is read
// from disk.
func fetchOne(ctx context.Context, lp LockedPackage,
	fetcher repository.Fetcher) (fetchedPackage, error) {

	data, err := readPackageBytes(ctx, lp, fetcher)
	if err != nil {
		return fetchedPackage{}, err
	}

	sum := sha256.Sum256(data)
	got := hex.EncodeToString(sum[:])
	if got != lp.Hash {
		return fetchedPackage{}, fmt.Errorf("peipkg/compose: %s hash mismatch (got %s, want %s)",
			lp.Name, got, lp.Hash)
	}

	pkg, err := archive.VerifyFormat(bytes.NewReader(data))
	if err != nil {
		return fetchedPackage{}, fmt.Errorf("peipkg/compose: %s: %w", lp.Name, err)
	}

	// The manifest's identity must agree with the lock — a sanity check
	// against a malformed lock or repo index where the entry's name,
	// version, or architecture diverges from the archive it points at.
	if pkg.Manifest.Name != lp.Name {
		return fetchedPackage{}, fmt.Errorf("peipkg/compose: %s carries the manifest for "+
			"package %q", lp.Name, pkg.Manifest.Name)
	}
	if pkg.Manifest.Version.String() != lp.Version {
		return fetchedPackage{}, fmt.Errorf("peipkg/compose: %s carries manifest version %s, "+
			"lock has %s", lp.Name, pkg.Manifest.Version, lp.Version)
	}
	if pkg.Manifest.Architecture != lp.Architecture {
		return fetchedPackage{}, fmt.Errorf("peipkg/compose: %s carries architecture %q, "+
			"lock has %q", lp.Name, pkg.Manifest.Architecture, lp.Architecture)
	}
	return fetchedPackage{Locked: lp, Pkg: pkg, Raw: data}, nil
}

// readPackageBytes loads the raw .peipkg bytes for a lock entry from
// the network or, for a local-source entry, from disk.
func readPackageBytes(ctx context.Context, lp LockedPackage,
	fetcher repository.Fetcher) ([]byte, error) {

	if lp.Source == LocalSource {
		data, err := os.ReadFile(lp.URL)
		if err != nil {
			return nil, fmt.Errorf("peipkg/compose: reading local package %s: %w", lp.URL, err)
		}
		return data, nil
	}
	data, err := fetcher.Fetch(ctx, lp.URL, maxPackageFetch)
	if err != nil {
		return nil, fmt.Errorf("peipkg/compose: fetching %s: %w", lp.URL, err)
	}
	return data, nil
}
