package compose

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/peios/peipkg/internal/repository"
)

// LockManifest resolves a manifest and writes the resulting lock. It is
// the implementation of the `peipkg-compose lock` verb. When lockPath
// is empty, the lock is written to [LockPath]`(manifestPath)`.
func LockManifest(ctx context.Context, manifestPath, lockPath string,
	fetcher repository.Fetcher, warnings io.Writer) error {

	m, err := LoadManifest(manifestPath)
	if err != nil {
		return err
	}
	if lockPath == "" {
		lockPath = LockPath(manifestPath)
	}
	lock, err := Resolve(ctx, m, filepath.Base(manifestPath), fetcher, warnings)
	if err != nil {
		return err
	}
	return writeLock(lockPath, lock)
}

// BuildOptions configures a build.
type BuildOptions struct {
	// ManifestPath is the path to the manifest TOML.
	ManifestPath string
	// OutDir is where the populated root is written. It must not exist;
	// the build creates it atomically by renaming from a sibling
	// staging directory on success.
	OutDir string
	// Locked requires that the lock exist and matches the manifest;
	// resolution is not performed. The air-gapped / CI mode.
	Locked bool
	// Update forces resolution to re-run, overwriting any prior lock.
	Update bool
	// Fetcher retrieves repository documents and package files. Tests
	// pass a double; production passes repository.NewHTTPFetcher().
	Fetcher repository.Fetcher
	// Warnings receives non-fatal notices and may be nil.
	Warnings io.Writer
}

// Build produces a populated peipkg root from a manifest. It runs the
// three stages — resolve (or read the lock), fetch and verify each
// package, assemble into a fresh root — and finalises the output by
// renaming a staging directory into place on success.
func Build(ctx context.Context, opts BuildOptions) error {
	if opts.Locked && opts.Update {
		return fmt.Errorf("peipkg/compose: --locked and --update are mutually exclusive")
	}
	if opts.OutDir == "" {
		return fmt.Errorf("peipkg/compose: an output directory is required")
	}
	if opts.Warnings == nil {
		opts.Warnings = io.Discard
	}

	m, err := LoadManifest(opts.ManifestPath)
	if err != nil {
		return err
	}
	lockPath := LockPath(opts.ManifestPath)
	manifestBase := filepath.Base(opts.ManifestPath)

	lock, err := chooseLock(ctx, m, manifestBase, lockPath, opts)
	if err != nil {
		return err
	}

	fetched, err := fetchAll(ctx, lock, opts.Fetcher)
	if err != nil {
		return err
	}

	// Atomicity is at the granularity of the whole artifact: assemble
	// into a sibling staging directory, then rename it into place. The
	// output path therefore either does not exist or is a complete root.
	// A failed or interrupted build leaves the staging directory for
	// inspection; the next attempt clears it.
	if _, err := os.Stat(opts.OutDir); err == nil {
		return fmt.Errorf("peipkg/compose: output directory %q already exists", opts.OutDir)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("peipkg/compose: checking output directory: %w", err)
	}
	staging := opts.OutDir + ".peipkg-compose-tmp"
	if err := os.RemoveAll(staging); err != nil {
		return fmt.Errorf("peipkg/compose: clearing prior staging directory: %w", err)
	}
	if err := assemble(ctx, staging, m, fetched); err != nil {
		return err
	}
	if err := os.Rename(staging, opts.OutDir); err != nil {
		return fmt.Errorf("peipkg/compose: finalising output: %w", err)
	}
	return nil
}

// chooseLock returns the lock to build from, honouring the --locked and
// --update flags. The default — neither flag — uses a sibling lock if
// one exists, and resolves to write one if not.
func chooseLock(ctx context.Context, m Manifest, manifestBase, lockPath string,
	opts BuildOptions) (Lock, error) {

	switch {
	case opts.Locked:
		lock, err := LoadLock(lockPath)
		if err != nil {
			return Lock{}, fmt.Errorf("peipkg/compose: --locked requires a lock at %s: %w",
				lockPath, err)
		}
		if err := ensureLockMatches(lock, m); err != nil {
			return Lock{}, err
		}
		return lock, nil
	case opts.Update:
		return resolveAndWrite(ctx, m, manifestBase, lockPath, opts)
	}
	if _, err := os.Stat(lockPath); errors.Is(err, fs.ErrNotExist) {
		return resolveAndWrite(ctx, m, manifestBase, lockPath, opts)
	} else if err != nil {
		return Lock{}, fmt.Errorf("peipkg/compose: stat lock: %w", err)
	}
	lock, err := LoadLock(lockPath)
	if err != nil {
		return Lock{}, err
	}
	if err := ensureLockMatches(lock, m); err != nil {
		return Lock{}, fmt.Errorf("%w (re-run with --update to refresh the lock)", err)
	}
	return lock, nil
}

// resolveAndWrite runs the resolve stage and writes the lock.
func resolveAndWrite(ctx context.Context, m Manifest, manifestBase, lockPath string,
	opts BuildOptions) (Lock, error) {

	lock, err := Resolve(ctx, m, manifestBase, opts.Fetcher, opts.Warnings)
	if err != nil {
		return Lock{}, err
	}
	if err := writeLock(lockPath, lock); err != nil {
		return Lock{}, err
	}
	return lock, nil
}

// writeLock encodes a lock and writes it to disk.
func writeLock(path string, lock Lock) error {
	data, err := lock.Encode()
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("peipkg/compose: writing lock: %w", err)
	}
	return nil
}

// ensureLockMatches confirms a stored lock describes the same build as
// the current manifest: same architecture, same source_date. A mismatch
// means the manifest moved on without the lock — the operator must
// regenerate it.
func ensureLockMatches(lock Lock, m Manifest) error {
	if lock.Arch != m.Arch {
		return fmt.Errorf("peipkg/compose: lock arch %q does not match manifest arch %q",
			lock.Arch, m.Arch)
	}
	if !lock.SourceDate.Equal(m.SourceDate) {
		return fmt.Errorf("peipkg/compose: lock source_date %s does not match manifest %s",
			lock.SourceDate.UTC().Format(time.RFC3339),
			m.SourceDate.UTC().Format(time.RFC3339))
	}
	return nil
}
