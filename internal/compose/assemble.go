package compose

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/peios/peipkg/internal/archive"
	"github.com/peios/peipkg/internal/config"
	"github.com/peios/peipkg/internal/db"
)

// assemble builds a populated peipkg root from a manifest's repository
// configuration and the fetched packages. It is the third stage of a
// compose build — Resolve produces the lock, fetchAll fetches and
// verifies it, assemble installs the result into a fresh root.
//
// root must be writable; assemble creates it if it does not exist.
// The caller is responsible for the staging-and-rename atomicity at
// the directory level (the build calls assemble on a staging dir and
// renames it to the final output on success).
func assemble(ctx context.Context, root string, m Manifest, fetched []fetchedPackage) error {
	if err := os.MkdirAll(root, 0o755); err != nil {
		return fmt.Errorf("peipkg/compose: creating output root: %w", err)
	}

	if err := seedDatabase(ctx, root, m, fetched); err != nil {
		return err
	}
	// Payloads are extracted only after the database has accepted the
	// closure, so a cross-package path collision is caught by the
	// package_file UNIQUE constraint before any file is written.
	for _, fp := range fetched {
		if err := extractPayload(root, fp); err != nil {
			return err
		}
	}
	if err := writeRepositoryConfig(root, m.Repositories); err != nil {
		return err
	}
	return nil
}

// seedDatabase creates the root's package database and populates it
// with the meta primary_arch row and one package + its package_file
// rows for every fetched package. The whole seed runs in one SQLite
// transaction so a collision-induced abort leaves nothing committed.
func seedDatabase(ctx context.Context, root string, m Manifest, fetched []fetchedPackage) error {
	stateDir := filepath.Join(root, "var/lib/peipkg")
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		return fmt.Errorf("peipkg/compose: creating state directory: %w", err)
	}
	store, err := db.Open(ctx, filepath.Join(stateDir, "db.sqlite"))
	if err != nil {
		return err
	}
	defer store.Close()

	return store.Tx(ctx, func(tx *db.Tx) error {
		if err := tx.SetMeta(ctx, "primary_arch", m.Arch); err != nil {
			return err
		}
		for _, fp := range fetched {
			origin := fp.Locked.Source
			if origin == LocalSource {
				// peipkg records a local-file install as an empty
				// origin; mirror that convention here.
				origin = ""
			}
			if err := tx.InsertPackage(ctx, db.Package{
				Name:         fp.Locked.Name,
				Version:      fp.Locked.Version,
				Architecture: fp.Locked.Architecture,
				OriginRepo:   origin,
				InstalledAt:  m.SourceDate,
				Manifest:     string(fp.Pkg.ManifestJSON),
			}); err != nil {
				return fmt.Errorf("peipkg/compose: seeding %s: %w", fp.Locked.Name, err)
			}
			if err := tx.InsertPackageFiles(ctx, packageFilesOf(fp)); err != nil {
				return fmt.Errorf("peipkg/compose: seeding %s files: %w", fp.Locked.Name, err)
			}
		}
		return nil
	})
}

// packageFilesOf converts a fetched package's verified payload into the
// package_file rows that record what the package owns. Logical paths
// are absolute (`/usr/bin/foo`), matching peipkg's storage convention.
func packageFilesOf(fp fetchedPackage) []db.PackageFile {
	files := make([]db.PackageFile, 0, len(fp.Pkg.Payload))
	for _, e := range fp.Pkg.Payload {
		logical := "/" + e.Path
		switch e.Type {
		case archive.EntryDir:
			files = append(files, db.PackageFile{
				PackageName: fp.Locked.Name, Path: logical, Type: db.FileTypeDir,
			})
		case archive.EntryFile:
			files = append(files, db.PackageFile{
				PackageName: fp.Locked.Name, Path: logical, Type: db.FileTypeFile,
				Hash: e.Hash,
			})
		case archive.EntrySymlink:
			files = append(files, db.PackageFile{
				PackageName: fp.Locked.Name, Path: logical, Type: db.FileTypeSymlink,
				SymlinkTarget: e.LinkTarget,
			})
		}
	}
	return files
}

// extractPayload writes one package's payload into the root. Directory
// entries are created idempotently — directories are shared across
// packages — while file and symlink entries land at their final paths
// with O_EXCL, so a cross-package collision the database missed would
// surface here too.
func extractPayload(root string, fp fetchedPackage) error {
	err := archive.Extract(bytes.NewReader(fp.Raw),
		func(entry archive.PayloadEntry, content io.Reader) error {
			physical := filepath.Join(root, entry.Path)
			switch entry.Type {
			case archive.EntryDir:
				return os.MkdirAll(physical, 0o755)
			case archive.EntryFile:
				if err := os.MkdirAll(filepath.Dir(physical), 0o755); err != nil {
					return err
				}
				return writeFile(physical, content)
			case archive.EntrySymlink:
				if err := os.MkdirAll(filepath.Dir(physical), 0o755); err != nil {
					return err
				}
				return os.Symlink(entry.LinkTarget, physical)
			}
			return nil
		})
	if err != nil {
		return fmt.Errorf("peipkg/compose: extracting %s: %w", fp.Locked.Name, err)
	}
	return nil
}

// writeFile creates a new file at path with O_EXCL — a cross-package
// path collision missed by the database surfaces here instead of being
// silently resolved by an overwrite.
//
// INTERIM: files are written 0o755. POSIX modes are not the security
// mechanism on Peios (KACS gates access), but the execute bit is still
// load-bearing for execve, and the format does not yet carry per-file
// executability (the tar is canonicalised to 0o777 and files.json has no
// exec field). Until that lands, every extracted file is made executable —
// matching what the old peipkg-bundle did. The correct rule (executable-in
// ⇒ 0o755, else 0o644, recorded in files.json) is deferred.
func writeFile(path string, content io.Reader) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(f, content)
	closeErr := f.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

// writeRepositoryConfig writes a .repo file for every manifest
// repository into <root>/conf/peipkg/. DirProvider.Put validates each
// configuration as it writes, so a malformed repository surfaces here.
func writeRepositoryConfig(root string, repos []config.RepoConfig) error {
	provider := config.NewDirProvider(filepath.Join(root, "conf/peipkg"))
	for _, cfg := range repos {
		if err := provider.Put(cfg); err != nil {
			return fmt.Errorf("peipkg/compose: writing .repo for %q: %w", cfg.Name, err)
		}
	}
	return nil
}
