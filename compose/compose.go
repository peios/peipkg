// Package compose exposes the peipkg root-composition API for external
// image-building tools.
//
// The implementation remains in peipkg's internal packages. This facade
// is intentionally narrow: callers can lock a compose manifest, build a
// populated peipkg root, and inspect compose lock files without depending
// on resolver, repository, archive, or database internals.
package compose

import (
	"context"
	"io"
	"time"

	internalcompose "github.com/peios/peipkg/internal/compose"
	"github.com/peios/peipkg/internal/repository"
)

// Fetcher retrieves bytes from a URL up to limit bytes.
//
// Callers normally leave this unset so peipkg uses its production
// HTTP/file fetcher. Tests and embedding tools may provide their own
// fetcher to route package and repository reads through a controlled
// transport.
type Fetcher interface {
	Fetch(ctx context.Context, url string, limit int64) ([]byte, error)
}

// BuildOptions configures a root composition build.
type BuildOptions struct {
	// ManifestPath is the path to the peipkg-compose manifest TOML.
	ManifestPath string
	// OutDir is where the populated root is written. It must not exist.
	OutDir string
	// LockPath is the lock file to use or write. When empty, the lock is
	// derived from ManifestPath with [LockPath].
	LockPath string
	// Locked requires an existing lock and disables resolution.
	Locked bool
	// Update forces resolution to re-run and overwrite any existing lock.
	Update bool
	// Fetcher retrieves repository documents and package files. When nil,
	// peipkg's production HTTP/file fetcher is used.
	Fetcher Fetcher
	// Warnings receives non-fatal notices and may be nil.
	Warnings io.Writer
	// BypassPathRestrictions permits packages that declare
	// special_system_package to compose payloads outside the §3.4
	// layout — the compose equivalent of `peipkg install
	// --dangerously-bypass-path-restrictions`. It exempts nothing that
	// has not declared itself special.
	BypassPathRestrictions bool
	// RecordXattr, when set, replaces writing the extended attributes a
	// composed payload implies with recording them: it receives the
	// object's path relative to OutDir, the attribute name, and its
	// value. The composed tree then carries NO such attributes.
	//
	// Two attributes reach a payload this way. A package's signature
	// sidecars (`<file>.peios.sig`) become the target's
	// security.peios.sig, and its §3.3.5 sd_overrides become the
	// entry's security.peios.sd. Both live in the security.* namespace,
	// which needs CAP_SYS_ADMIN to set; an unprivileged image builder
	// records them instead and writes them into the image, which needs
	// no privilege at all because a squashfs simply stores whatever
	// attributes its input names.
	//
	// One hook rather than one per attribute: the transport is the same
	// question every time — "this consumer cannot set security.*, hold
	// it for whoever can" — and it is the attribute's name, not the
	// channel, that says what it means.
	RecordXattr func(relPath, name string, value []byte) error
}

// BuildResult describes a completed root composition.
type BuildResult struct {
	ManifestPath string
	RootDir      string
	LockPath     string
	Lock         Lock
	PackageCount int
}

// Build produces a populated peipkg root from a compose manifest and
// returns the lock and output metadata needed for image provenance.
func Build(ctx context.Context, opts BuildOptions) (BuildResult, error) {
	result, err := internalcompose.BuildWithResult(ctx, internalcompose.BuildOptions{
		ManifestPath: opts.ManifestPath,
		OutDir:       opts.OutDir,
		LockPath:     opts.LockPath,
		Locked:       opts.Locked,
		Update:       opts.Update,
		Fetcher:      fetcherOrDefault(opts.Fetcher),
		Warnings:     opts.Warnings,

		BypassPathRestrictions: opts.BypassPathRestrictions,
		RecordXattr:            opts.RecordXattr,
	})
	if err != nil {
		return BuildResult{}, err
	}
	return BuildResult{
		ManifestPath: result.ManifestPath,
		RootDir:      result.RootDir,
		LockPath:     result.LockPath,
		Lock:         fromInternalLock(result.Lock),
		PackageCount: result.PackageCount,
	}, nil
}

// SourceScan is the verified candidate universe of a manifest's
// declared sources — every repository's trust-verified index entries
// and every local pool file's manifest, gathered once. It is a
// snapshot of pure data: no open handles, nothing that goes stale on
// disk, and no content hashes (those are computed per lock, for the
// packages each lock chooses). A tool locking several manifests over
// the same sources scans once and passes the scan to each lock, which
// both halves the work and makes every lock see one universe.
type SourceScan struct {
	scan *internalcompose.SourceScan
}

// ScanOptions configures a source scan.
type ScanOptions struct {
	// ManifestPath is the path to a peipkg-compose manifest TOML whose
	// declared sources are scanned. The scan serves any manifest that
	// declares exactly the same sources.
	ManifestPath string
	// Fetcher retrieves repository documents. When nil, peipkg's
	// production HTTP/file fetcher is used.
	Fetcher Fetcher
	// Warnings receives non-fatal notices and may be nil.
	Warnings io.Writer
}

// ScanSources gathers and verifies the candidate universe of the
// manifest's declared sources, for LockManifest calls to share.
func ScanSources(ctx context.Context, opts ScanOptions) (*SourceScan, error) {
	m, err := internalcompose.LoadManifest(opts.ManifestPath)
	if err != nil {
		return nil, err
	}
	s, err := internalcompose.ScanSources(ctx, m, fetcherOrDefault(opts.Fetcher), opts.Warnings)
	if err != nil {
		return nil, err
	}
	return &SourceScan{scan: s}, nil
}

// LockOptions configures manifest resolution.
type LockOptions struct {
	// ManifestPath is the path to the peipkg-compose manifest TOML.
	ManifestPath string
	// LockPath is where the generated lock is written. When empty, the
	// default sibling lock path is used.
	LockPath string
	// Fetcher retrieves repository documents and package files. When nil,
	// peipkg's production HTTP/file fetcher is used.
	Fetcher Fetcher
	// Warnings receives non-fatal notices and may be nil.
	Warnings io.Writer
	// Sources, when set, reuses an existing scan instead of scanning
	// this manifest's sources. The manifest must declare exactly the
	// sources the scan was taken from — a mismatch is refused, so
	// misuse is an error rather than a subtly different build.
	Sources *SourceScan
}

// LockResult describes the lock written by a manifest-resolution run.
type LockResult struct {
	ManifestPath string
	LockPath     string
	Lock         Lock
}

// LockManifest resolves a compose manifest, writes the resulting lock,
// and returns lock metadata for provenance.
func LockManifest(ctx context.Context, opts LockOptions) (LockResult, error) {
	var scan *internalcompose.SourceScan
	if opts.Sources != nil {
		scan = opts.Sources.scan
	}
	result, err := internalcompose.LockManifestWithResult(ctx, opts.ManifestPath, opts.LockPath,
		fetcherOrDefault(opts.Fetcher), opts.Warnings, scan)
	if err != nil {
		return LockResult{}, err
	}
	return LockResult{
		ManifestPath: result.ManifestPath,
		LockPath:     result.LockPath,
		Lock:         fromInternalLock(result.Lock),
	}, nil
}

// Lock is a resolved package closure.
type Lock struct {
	Arch           string
	SourceDate     time.Time
	Manifest       string
	ManifestDigest string
	Packages       []LockedPackage
	// Sources carries the trust state of every repository the closure
	// draws from. A build verifies each package's signature against the
	// entry for its source, so a lock without them cannot be built.
	Sources []LockedSource
}

// LockedSource is one repository a closure draws from, with the trust
// state established when the lock was resolved.
type LockedSource struct {
	Name string
	// SignaturePolicy is "required" or "optional".
	SignaturePolicy string
	// TrustKeys is the repository's trust set as JSON; empty for a
	// repository in unsigned mode.
	TrustKeys string
}

// LockedPackage is one package in a resolved closure.
type LockedPackage struct {
	Name         string
	Version      string
	Architecture string
	// Root is the path, relative to the output root, of the named root
	// this package is installed into; empty for the output root. A name
	// may appear in more than one root, so a lock is keyed by (Name, Root).
	Root   string
	Source string
	URL    string
	Hash   string
	// SizeCompressed and SizeInstalled are the sizes the source index
	// advertised. They bound the download and the decompression at build
	// time, so they are not hints.
	SizeCompressed int64
	SizeInstalled  int64
}

// LocalSource is the source value used for packages supplied from local
// .peipkg files rather than repositories.
const LocalSource = internalcompose.LocalSource

// LockPath derives the default lock path for manifestPath.
func LockPath(manifestPath string) string {
	return internalcompose.LockPath(manifestPath)
}

// LoadLock reads and decodes a compose lock file.
func LoadLock(path string) (Lock, error) {
	lock, err := internalcompose.LoadLock(path)
	if err != nil {
		return Lock{}, err
	}
	return fromInternalLock(lock), nil
}

// DecodeLock decodes a compose lock from TOML bytes.
func DecodeLock(data []byte) (Lock, error) {
	lock, err := internalcompose.DecodeLock(data)
	if err != nil {
		return Lock{}, err
	}
	return fromInternalLock(lock), nil
}

// Encode renders the lock as TOML.
func (l Lock) Encode() ([]byte, error) {
	return toInternalLock(l).Encode()
}

func fetcherOrDefault(fetcher Fetcher) repository.Fetcher {
	if fetcher != nil {
		return fetcher
	}
	return repository.NewHTTPFetcher()
}

func fromInternalLock(lock internalcompose.Lock) Lock {
	out := Lock{
		Arch:           lock.Arch,
		SourceDate:     lock.SourceDate,
		Manifest:       lock.Manifest,
		ManifestDigest: lock.ManifestDigest,
		Packages:       make([]LockedPackage, 0, len(lock.Packages)),
		Sources:        make([]LockedSource, 0, len(lock.Sources)),
	}
	for _, s := range lock.Sources {
		out.Sources = append(out.Sources, LockedSource{
			Name:            s.Name,
			SignaturePolicy: s.SignaturePolicy,
			TrustKeys:       s.TrustKeys,
		})
	}
	for _, p := range lock.Packages {
		out.Packages = append(out.Packages, LockedPackage{
			Name:           p.Name,
			Version:        p.Version,
			Architecture:   p.Architecture,
			Root:           p.Root,
			Source:         p.Source,
			URL:            p.URL,
			Hash:           p.Hash,
			SizeCompressed: p.SizeCompressed,
			SizeInstalled:  p.SizeInstalled,
		})
	}
	return out
}

func toInternalLock(lock Lock) internalcompose.Lock {
	out := internalcompose.Lock{
		Arch:           lock.Arch,
		SourceDate:     lock.SourceDate,
		Manifest:       lock.Manifest,
		ManifestDigest: lock.ManifestDigest,
		Packages:       make([]internalcompose.LockedPackage, 0, len(lock.Packages)),
		Sources:        make([]internalcompose.LockedSource, 0, len(lock.Sources)),
	}
	for _, s := range lock.Sources {
		out.Sources = append(out.Sources, internalcompose.LockedSource{
			Name:            s.Name,
			SignaturePolicy: s.SignaturePolicy,
			TrustKeys:       s.TrustKeys,
		})
	}
	for _, p := range lock.Packages {
		out.Packages = append(out.Packages, internalcompose.LockedPackage{
			Name:           p.Name,
			Version:        p.Version,
			Architecture:   p.Architecture,
			Root:           p.Root,
			Source:         p.Source,
			URL:            p.URL,
			Hash:           p.Hash,
			SizeCompressed: p.SizeCompressed,
			SizeInstalled:  p.SizeInstalled,
		})
	}
	return out
}
