package install

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/peios/peipkg/internal/archive"
	"github.com/peios/peipkg/internal/db"
	"github.com/peios/peipkg/internal/resolver"
)

// etcNewMarker is the suffix of the file an upgrade writes beside an
// operator-modified /etc file instead of overwriting it (§7.2.2).
const etcNewMarker = ".peipkg-new"

// stagedOp is everything one plan operation contributes to a
// transaction: its staged file operations, the package-database rows it
// will write, and the side effects it declares.
type stagedOp struct {
	op      resolver.Operation
	fileOps []fileOp
	// pkg and files are the package-database rows for an install,
	// upgrade, or downgrade; both are nil for a removal.
	pkg   *db.Package
	files []db.PackageFile
	// sideEffects are the maintenance operations the package declares.
	sideEffects []string
	// warnings are non-fatal divergences the operator should see —
	// chiefly §7.2.2 modified /etc files preserved across an upgrade.
	warnings []string
}

// stageOperation stages one plan operation. On failure it returns the
// partially-staged result so the caller can roll back the file
// operations it did create.
func stageOperation(ctx context.Context, env Env, txnID int64, op resolver.Operation,
	provided map[string]ProvidedPackage) (stagedOp, error) {
	if op.Kind == resolver.OpRemove {
		return stageRemoval(ctx, env, txnID, op)
	}
	return stagePackage(ctx, env, txnID, op, provided[op.Name])
}

// stagePackage extracts a package's verified payload into staging and
// computes the file operations and database rows for installing it.
//
// Content comes from archive.Extract; the per-file metadata — type and
// the verified SHA-256 — comes from the verified payload list, the
// authority for what the package owns.
func stagePackage(ctx context.Context, env Env, txnID int64, op resolver.Operation,
	pp ProvidedPackage) (stagedOp, error) {

	s := stagedOp{op: op}

	// The files the package's previous version owns — empty for a fresh
	// install — diffed against the new payload to find removed files.
	var existing []db.PackageFile
	if op.Kind != resolver.OpInstall {
		var err error
		if existing, err = env.DB.PackageFiles(ctx, op.Name); err != nil {
			return s, err
		}
	}
	existingByPath := make(map[string]db.PackageFile, len(existing))
	for _, f := range existing {
		existingByPath[f.Path] = f
	}

	// Extract: write each payload file's content, each symlink, and each
	// directory into staging. Files and symlinks are staged as siblings;
	// directories are created in place — they are idempotent and shared
	// between packages (§3.4.10).
	stagedAt := map[string]string{} // logical path -> staged sibling path
	err := archive.Extract(pp.Archive, func(entry archive.PayloadEntry, content io.Reader) error {
		physical := filepath.Join(env.Root, entry.Path)
		switch entry.Type {
		case archive.EntryDir:
			return os.MkdirAll(physical, 0o755)
		case archive.EntryFile:
			staged := tempPath(physical, stagedMarker, txnID)
			if err := os.MkdirAll(filepath.Dir(staged), 0o755); err != nil {
				return err
			}
			if err := writeStagedFile(staged, content); err != nil {
				return err
			}
			stagedAt["/"+entry.Path] = staged
		case archive.EntrySymlink:
			staged := tempPath(physical, stagedMarker, txnID)
			if err := os.MkdirAll(filepath.Dir(staged), 0o755); err != nil {
				return err
			}
			if err := os.Symlink(entry.LinkTarget, staged); err != nil {
				return err
			}
			stagedAt["/"+entry.Path] = staged
		}
		return nil
	})
	if err != nil {
		return s, fmt.Errorf("peipkg/install: staging %s: %w", op.Name, err)
	}

	// Build the file operations and database rows from the verified
	// payload list.
	newPaths := map[string]bool{}
	for _, entry := range pp.Pkg.Payload {
		logical := "/" + entry.Path
		physical := filepath.Join(env.Root, entry.Path)
		newPaths[logical] = true

		switch entry.Type {
		case archive.EntryDir:
			s.files = append(s.files, db.PackageFile{
				PackageName: op.Name, Path: logical, Type: db.FileTypeDir})
		case archive.EntryFile:
			dest := physical
			// §7.2.2 modified-detection: an operator-edited /etc file is
			// not clobbered by an upgrade. The new default lands beside
			// it and the divergence is reported; the database still
			// records the path with the new version's hash.
			if old, ok := existingByPath[logical]; ok && old.Type == db.FileTypeFile &&
				isEtcPath(logical) && exists(physical) {
				modified, err := fileModified(physical, old.Hash)
				if err != nil {
					return s, err
				}
				if modified {
					dest = physical + etcNewMarker
					s.warnings = append(s.warnings, fmt.Sprintf(
						"%s has been modified since install — keeping it; the new "+
							"default was written to %s%s", logical, logical, etcNewMarker))
				}
			}
			s.fileOps = append(s.fileOps, plannedOp(dest, stagedAt[logical], txnID))
			s.files = append(s.files, db.PackageFile{
				PackageName: op.Name, Path: logical, Type: db.FileTypeFile, Hash: entry.Hash})
		case archive.EntrySymlink:
			s.fileOps = append(s.fileOps, plannedOp(physical, stagedAt[logical], txnID))
			s.files = append(s.files, db.PackageFile{
				PackageName: op.Name, Path: logical, Type: db.FileTypeSymlink,
				SymlinkTarget: entry.LinkTarget})
		}
	}

	// A file the previous version owned that the new payload does not
	// is removed. Directories are left in place — they may be shared.
	for _, f := range existing {
		if f.Type == db.FileTypeDir || newPaths[f.Path] {
			continue
		}
		physical := filepath.Join(env.Root, f.Path)
		s.fileOps = append(s.fileOps, fileOp{
			finalPath: physical, action: actionRemove,
			backupPath: tempPath(physical, backupMarker, txnID)})
	}

	s.pkg = &db.Package{
		Name:         op.Name,
		Version:      op.ToVersion.String(),
		Architecture: pp.Pkg.Manifest.Architecture,
		OriginRepo:   originRepo(op),
		InstalledAt:  time.Now(),
		Manifest:     string(pp.Pkg.ManifestJSON),
	}
	for _, e := range pp.Pkg.Manifest.SideEffects {
		s.sideEffects = append(s.sideEffects, string(e))
	}
	return s, nil
}

// stageRemoval computes the file operations that remove a package.
func stageRemoval(ctx context.Context, env Env, txnID int64, op resolver.Operation) (stagedOp, error) {
	s := stagedOp{op: op}
	files, err := env.DB.PackageFiles(ctx, op.Name)
	if err != nil {
		return s, err
	}
	for _, f := range files {
		if f.Type == db.FileTypeDir {
			continue // directories are shared; left in place
		}
		physical := filepath.Join(env.Root, f.Path)
		s.fileOps = append(s.fileOps, fileOp{
			finalPath: physical, action: actionRemove,
			backupPath: tempPath(physical, backupMarker, txnID)})
	}
	return s, nil
}

// writeStagedFile writes a payload file's content to its staged sibling.
// O_EXCL ensures a stray staged file from an earlier crash is noticed
// rather than silently reused.
//
// INTERIM: staged files are written 0o755 (carried to the final path by the
// commit rename). POSIX modes are not the security mechanism on Peios (KACS
// gates access), but the execute bit is load-bearing for execve and the
// format does not yet carry per-file executability (tar is canonical 0o777,
// files.json has no exec field). Until that lands, every installed file is
// made executable — mirroring the same interim in compose's assemble.go.
// The correct rule (executable-in => 0o755, else 0o644, recorded in
// files.json) is deferred.
func writeStagedFile(staged string, content io.Reader) error {
	f, err := os.OpenFile(staged, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755)
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

// plannedOp builds the file operation for a staged file or symlink: a
// replace when something already occupies the destination, otherwise a
// create. A displaced file is backed up by rename, never destroyed.
func plannedOp(physical, staged string, txnID int64) fileOp {
	op := fileOp{finalPath: physical, stagedPath: staged}
	if exists(physical) {
		op.action = actionReplace
		op.backupPath = tempPath(physical, backupMarker, txnID)
	} else {
		op.action = actionCreate
	}
	return op
}

// originRepo is the repository a forward operation's package came from,
// or "" for a local-file install.
func originRepo(op resolver.Operation) string {
	if op.Candidate != nil {
		return op.Candidate.Repo
	}
	return ""
}

// isEtcPath reports whether a logical path is configuration under /etc,
// where §7.2.2 modified-detection applies.
func isEtcPath(logical string) bool {
	return strings.HasPrefix(logical, "/etc/")
}

// fileModified reports whether the file at path has content differing
// from recordedHash — the hex SHA-256 the package database recorded for
// it at install.
func fileModified(path, recordedHash string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, fmt.Errorf("peipkg/install: reading %s: %w", path, err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return false, fmt.Errorf("peipkg/install: hashing %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)) != recordedHash, nil
}
