package compose

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/peios/peipkg/internal/archive"
	packvalidate "github.com/peios/peipkg/internal/build/pack"
	"github.com/peios/peipkg/internal/claims"
	"github.com/peios/peipkg/internal/config"
	"github.com/peios/peipkg/internal/db"
)

// assemble builds a populated peipkg image from a manifest and the
// fetched packages. It is the third stage of a compose build — Resolve
// produces the lock, fetchAll fetches and verifies it, assemble installs
// the result. A multi-root image is several roots nested under one output
// directory (initramfs at <out>/boot/initramfs), so the whole image is
// still one tree the caller renames into place atomically; compose needs
// none of the consumer's cross-root transaction machinery.
//
// out must be writable; assemble creates it if it does not exist. Each
// package is assembled into the root its lock entry names (relative to
// out, "" being out itself). The named roots are registered in the
// anchor's database so the booted system resolves `--root <name>`.
func assemble(ctx context.Context, out string, m Manifest, fetched []fetchedPackage,
	bypassPaths bool) error {
	byRoot := map[string][]fetchedPackage{}
	for _, fp := range fetched {
		byRoot[fp.Locked.Root] = append(byRoot[fp.Locked.Root], fp)
	}
	// The anchor always exists even with no direct packages: it carries
	// the named-root registry and the repository configuration.
	if _, ok := byRoot[""]; !ok {
		byRoot[""] = nil
	}

	rels := make([]string, 0, len(byRoot))
	for rel := range byRoot {
		rels = append(rels, rel)
	}
	sort.Strings(rels)

	for _, rel := range rels {
		var register []Root // only the anchor seeds the registry
		if rel == "" {
			register = m.Roots
		}
		if err := assembleRoot(ctx, filepath.Join(out, rel), m, byRoot[rel], register,
			bypassPaths); err != nil {
			return err
		}
	}
	// The license inventory is anchor-level and image-wide, like the
	// repository configuration below.
	if err := writeLicenseManifest(out, m, fetched); err != nil {
		return err
	}
	// Repositories are anchor-level (the consumer's anchor-fetch model):
	// a composed sub-root receives its packages through the build, not its
	// own repositories.
	return writeRepositoryConfig(out, m.Repositories)
}

// assembleRoot installs one root's packages into rootDir: it resolves the
// root's claims, seeds its database (registering register's named roots
// when non-nil), extracts payloads, and materialises claim links.
func assembleRoot(ctx context.Context, rootDir string, m Manifest,
	fetched []fetchedPackage, register []Root, bypassPaths bool) error {

	for _, fp := range fetched {
		if err := checkComposeLayout(fp, bypassPaths); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(rootDir, 0o755); err != nil {
		return fmt.Errorf("peipkg/compose: creating root %s: %w", rootDir, err)
	}
	// Resolve claims (§4.4 / §7.7) over this root's closed package set: the
	// holders and links are recorded in the seed transaction alongside the
	// packages, and the symlinks are materialised after extraction.
	holders, links, err := composeClaims(fetched)
	if err != nil {
		return err
	}
	if err := seedDatabase(ctx, rootDir, m, fetched, holders, links, register); err != nil {
		return err
	}
	// Payloads are extracted only after the database has accepted the
	// closure, so a cross-package path collision is caught by the
	// package_file UNIQUE constraint before any file is written.
	for _, fp := range fetched {
		if err := extractPayload(rootDir, fp); err != nil {
			return err
		}
	}
	// Claim symlinks land after payloads so a claim contending with a real
	// payload file fails on the already-present path rather than overwriting.
	if err := materializeClaims(rootDir, links); err != nil {
		return err
	}
	return nil
}

// seedDatabase creates the root's package database and populates it
// with the meta primary_arch row and one package + its package_file
// rows for every fetched package. The whole seed runs in one SQLite
// transaction so a collision-induced abort leaves nothing committed.
func seedDatabase(ctx context.Context, root string, m Manifest, fetched []fetchedPackage,
	holders map[string]string, links []claims.Link, register []Root) error {
	stateDir := filepath.Join(root, "var/state/peipkg")
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
		if err := seedClaims(ctx, tx, holders, links); err != nil {
			return err
		}
		// Seed the named-root registry so the booted image resolves
		// `--root <name>` and cascades upgrades into it. Paths are stored
		// relative to this (anchor) root, matching the registry convention.
		for _, r := range register {
			if err := tx.SetNamedRoot(ctx, r.Name, r.Path); err != nil {
				return fmt.Errorf("peipkg/compose: registering root %q: %w", r.Name, err)
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
// repository into <root>/lcl/conf/peipkg/. DirProvider.Put validates each
// configuration as it writes, so a malformed repository surfaces here.
//
// lcl/conf, not conf: /conf is a StrataFS view mounted at boot over
// /lcl/conf and /usr/conf. A composed tree has no views — nothing has
// booted it — so a file written to <root>/conf/ sits underneath a mount
// that will later cover it, invisible to everything on the running
// system. The image would compose cleanly, boot, and report no
// repositories configured, with nothing pointing at why.
func writeRepositoryConfig(root string, repos []config.RepoConfig) error {
	provider := config.NewDirProvider(filepath.Join(root, "lcl/conf/peipkg"))
	for _, cfg := range repos {
		if err := provider.Put(cfg); err != nil {
			return fmt.Errorf("peipkg/compose: writing .repo for %q: %w", cfg.Name, err)
		}
	}
	return nil
}

// checkComposeLayout enforces the §5.14 payload layout rules over one
// fetched package as it is assembled — into whichever root it is placed
// in, not only the anchor.
//
// This is compose's half of the same control `peipkg install` applies:
// a composed image is built from .peipkg files that need not have come
// from a cooperating producer, so pack-time validation proves nothing
// here. A Special System Package composed with BypassPathRestrictions
// is exempt; nothing else is.
func checkComposeLayout(fp fetchedPackage, bypassPaths bool) error {
	if fp.Pkg == nil {
		return nil
	}
	special := fp.Pkg.Manifest.SpecialSystemPackage
	if special && bypassPaths {
		return nil
	}

	entries := make([]packvalidate.InstallEntry, 0, len(fp.Pkg.Payload))
	for _, e := range fp.Pkg.Payload {
		entries = append(entries, packvalidate.InstallEntry{
			Path:       e.Path,
			IsDir:      e.Type == archive.EntryDir,
			IsSymlink:  e.Type == archive.EntrySymlink,
			LinkTarget: e.LinkTarget,
		})
	}

	err := packvalidate.ValidateInstallPaths(fp.Pkg.Manifest.Architecture, entries)
	if err == nil {
		return nil
	}
	if special {
		return fmt.Errorf("peipkg/compose: %s declares special_system_package but this "+
			"compose did not enable bypass_path_restrictions: %w", fp.Locked.Name, err)
	}
	return fmt.Errorf("peipkg/compose: %s: %w", fp.Locked.Name, err)
}
