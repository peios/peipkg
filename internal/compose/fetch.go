package compose

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"github.com/peios/peipkg/internal/archive"
	"github.com/peios/peipkg/internal/config"
	"github.com/peios/peipkg/internal/repository"
)

// maxPackageFetch caps a .peipkg download for which the lock records no
// compressed size. §5.27 bounds a download by the index's
// size_compressed, and a lock carries that figure forward; the flat cap
// is the floor under a lock entry that legitimately declares zero.
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
// are exactly what the resolver chose. The packages are independent, so
// they fetch and verify in parallel; the result keeps the lock's order.
func fetchAll(ctx context.Context, lock Lock, fetcher repository.Fetcher) ([]fetchedPackage, error) {
	// §5.30: the signature on each package is checked against the trust
	// set of its originating repository before any payload is extracted.
	// The trust was established at lock time; the lock carries it here.
	now := time.Now()
	trust := make(map[string]lockedTrust, len(lock.Sources))
	for _, src := range lock.Sources {
		ts, err := repository.ParseTrustSet(src.TrustKeys)
		if err != nil {
			return nil, fmt.Errorf("peipkg/compose: trust state of source %q: %w", src.Name, err)
		}
		trust[src.Name] = lockedTrust{set: ts, policy: config.SignaturePolicy(src.SignaturePolicy)}
	}
	return parallelMap(len(lock.Packages), 0, func(i int) (fetchedPackage, error) {
		return fetchOne(ctx, lock.Packages[i], trust, now, fetcher)
	})
}

// lockedTrust is one repository's recorded trust state and signature
// policy, as the build phase applies them.
type lockedTrust struct {
	set    repository.TrustSet
	policy config.SignaturePolicy
}

// fetchOne retrieves one package by its lock entry. A repository
// package is fetched through fetcher; a local-source package is read
// from disk.
func fetchOne(ctx context.Context, lp LockedPackage, trust map[string]lockedTrust,
	now time.Time, fetcher repository.Fetcher) (fetchedPackage, error) {

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

	pkg, err := verifyLocked(data, lp, trust, now)
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

// verifyLocked verifies one fetched archive against the lock: the §5.27
// decompression bound from the lock's carried-forward index figure, and
// — for a repository package — the inline signature against the
// originating repository's recorded trust set (§5.30), under that
// repository's signature policy.
//
// A revoked or expired key fails here, which is the whole point: the
// hash check above proves only that the bytes are the ones the index
// listed, and the compromised-signing-key case is exactly the one where
// they are.
//
// now is the instant key status is evaluated at — the build's, not the
// lock's. A key revoked since the lock was written must not verify, so
// the check deliberately is not reproducible across time.
func verifyLocked(data []byte, lp LockedPackage, trust map[string]lockedTrust,
	now time.Time) (*archive.Package, error) {

	if lp.Source == LocalSource {
		// A local file has no repository and so no trust set. Its
		// size_installed was read from this same manifest at lock time,
		// but the lock pins the bytes by hash, so it is a real bound
		// here: the archive cannot have changed since it was recorded.
		return archive.VerifyFormat(bytes.NewReader(data), lp.SizeInstalled)
	}
	src, ok := trust[lp.Source]
	if !ok {
		// DecodeLock refuses a lock in this shape; a Lock built in
		// memory could still reach here.
		return nil, fmt.Errorf("source %q has no recorded trust state in the lock", lp.Source)
	}
	pkg, err := archive.Verify(bytes.NewReader(data), src.set.Resolver(now), lp.SizeInstalled)
	if err != nil {
		return nil, err
	}
	if src.policy == config.PolicyRequired && !pkg.Signed {
		return nil, fmt.Errorf("package is unsigned, but source %q requires signed packages",
			lp.Source)
	}
	return pkg, nil
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
	// §5.27: the download is bounded by the index's declared compressed
	// size, carried into the lock, plus the lesser of 1% or 16 MiB.
	limit := int64(maxPackageFetch)
	if lp.SizeCompressed > 0 {
		limit = repository.PackageFetchLimit(lp.SizeCompressed)
	}
	data, err := fetcher.Fetch(ctx, lp.URL, limit)
	if err != nil {
		return nil, fmt.Errorf("peipkg/compose: fetching %s: %w", lp.URL, err)
	}
	return data, nil
}
