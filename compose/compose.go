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
	result, err := internalcompose.LockManifestWithResult(ctx, opts.ManifestPath, opts.LockPath,
		fetcherOrDefault(opts.Fetcher), opts.Warnings)
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
	Arch       string
	SourceDate time.Time
	Manifest   string
	Packages   []LockedPackage
}

// LockedPackage is one package in a resolved closure.
type LockedPackage struct {
	Name         string
	Version      string
	Architecture string
	Source       string
	URL          string
	Hash         string
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
		Arch:       lock.Arch,
		SourceDate: lock.SourceDate,
		Manifest:   lock.Manifest,
		Packages:   make([]LockedPackage, 0, len(lock.Packages)),
	}
	for _, p := range lock.Packages {
		out.Packages = append(out.Packages, LockedPackage{
			Name:         p.Name,
			Version:      p.Version,
			Architecture: p.Architecture,
			Source:       p.Source,
			URL:          p.URL,
			Hash:         p.Hash,
		})
	}
	return out
}

func toInternalLock(lock Lock) internalcompose.Lock {
	out := internalcompose.Lock{
		Arch:       lock.Arch,
		SourceDate: lock.SourceDate,
		Manifest:   lock.Manifest,
		Packages:   make([]internalcompose.LockedPackage, 0, len(lock.Packages)),
	}
	for _, p := range lock.Packages {
		out.Packages = append(out.Packages, internalcompose.LockedPackage{
			Name:         p.Name,
			Version:      p.Version,
			Architecture: p.Architecture,
			Source:       p.Source,
			URL:          p.URL,
			Hash:         p.Hash,
		})
	}
	return out
}
