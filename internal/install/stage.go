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
	packvalidate "github.com/peios/peipkg/internal/build/pack"
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
	// createdDirs are directories this transaction may create while
	// staging, ordered parent before child so rollback can remove them
	// in reverse after file operations have been undone.
	createdDirs []string
	// pkg and files are the package-database rows for an install,
	// upgrade, or downgrade; both are nil for a removal.
	pkg   *db.Package
	files []db.PackageFile
	// sideEffects are the maintenance operations the package declares.
	sideEffects []string
	// warnings are non-fatal divergences the operator should see —
	// chiefly §7.2.2 modified /etc files preserved across an upgrade.
	warnings []string
	// stagedAt maps payload logical paths to their incoming staged
	// sibling. It is staging-only state; the journal gets fileOps.
	stagedAt map[string]string
}

// prepareOperation computes one plan operation's journal rows and
// package-database changes without touching the filesystem.
func prepareOperation(ctx context.Context, env Env, txnID int64, op resolver.Operation,
	provided map[string]ProvidedPackage, plannedDirs map[string]bool) (stagedOp, error) {
	if op.Kind == resolver.OpRemove {
		return stageRemoval(ctx, env, txnID, op)
	}
	return preparePackage(ctx, env, txnID, op, provided[op.Name], plannedDirs)
}

// preparePackage computes the file operations and database rows for
// installing a package. No payload bytes are written here: the journal
// is written first, then materializePackage creates the staged siblings.
//
// Per-file metadata — type and the verified SHA-256 — comes from the
// verified payload list, the authority for what the package owns.
func preparePackage(ctx context.Context, env Env, txnID int64, op resolver.Operation,
	pp ProvidedPackage, plannedDirs map[string]bool) (stagedOp, error) {

	s := stagedOp{op: op, stagedAt: map[string]string{}}

	// §3.4 layout enforcement, at the last point before bytes reach the
	// filesystem. Pack-time validation is a producer's courtesy to
	// itself and proves nothing here — the .peipkg on this machine need
	// not have come from a cooperating producer.
	//
	// Every root is held to the same rules, the nested initramfs included.
	// Packages install vendor storage paths under /usr; runtime projections such
	// as /bin are filesystem topology, not package destinations. A package that
	// genuinely must lay down other structure declares itself special like any
	// other.
	//
	// Two keys open this: the package declares special_system_package
	// AND the operator passed --dangerously-bypass-path-restrictions.
	// Either alone leaves the check in force.
	if err := checkPayloadLayout(env, pp); err != nil {
		return s, err
	}

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

	// Build the file operations and database rows from the verified
	// payload list.
	newPaths := map[string]bool{}
	for _, entry := range pp.Pkg.Payload {
		logical := "/" + entry.Path
		physical := filepath.Join(env.Root, entry.Path)
		newPaths[logical] = true

		switch entry.Type {
		case archive.EntryDir:
			rememberCreatedDirs(env.Root, physical, plannedDirs, &s.createdDirs)
			s.files = append(s.files, db.PackageFile{
				PackageName: op.Name, Path: logical, Type: db.FileTypeDir})
		case archive.EntryFile:
			dest := physical
			// §7.2.2 modified-detection: an operator-edited /etc file is
			// not clobbered by an upgrade. The new default lands beside
			// it as <name>.peipkg-new and the divergence is reported.
			//
			// recordedHash is what goes into package_file for the logical
			// path. It must describe the bytes that end up *there*, which
			// on the modified branch are the operator's, not the new
			// version's. Recording the new version's hash made `peipkg
			// verify` report the path as modified forever, on every run,
			// for a file peipkg itself deliberately preserved — poisoning
			// the one signal an operator has for a failed rollback or for
			// tampering.
			recordedHash := entry.Hash
			preserved := false
			if old, ok := existingByPath[logical]; ok && old.Type == db.FileTypeFile &&
				isEtcPath(logical) && exists(physical) {
				modified, err := fileModified(physical, old.Hash)
				if err != nil {
					return s, err
				}
				if modified {
					dest = physical + etcNewMarker
					preserved = true
					if recordedHash, err = fileHash(physical); err != nil {
						return s, err
					}
					s.warnings = append(s.warnings, fmt.Sprintf(
						"%s has been modified since install — keeping it; the new "+
							"default was written to %s%s", logical, logical, etcNewMarker))
				}
			}
			staged := tempPath(dest, stagedMarker, txnID)
			rememberCreatedDirs(env.Root, filepath.Dir(staged), plannedDirs, &s.createdDirs)
			s.stagedAt[logical] = staged
			s.fileOps = append(s.fileOps, plannedOp(dest, staged, txnID))
			s.files = append(s.files, db.PackageFile{
				PackageName: op.Name, Path: logical, Type: db.FileTypeFile, Hash: recordedHash})
			if preserved {
				// The .peipkg-new file is real content on disk. Left
				// unrecorded it is an orphan: uninstall never removes it
				// and `peipkg owns` cannot attribute it.
				newPath := logical + etcNewMarker
				newPaths[newPath] = true
				s.files = append(s.files, db.PackageFile{
					PackageName: op.Name, Path: newPath,
					Type: db.FileTypeFile, Hash: entry.Hash})
			}
		case archive.EntrySymlink:
			staged := tempPath(physical, stagedMarker, txnID)
			rememberCreatedDirs(env.Root, filepath.Dir(staged), plannedDirs, &s.createdDirs)
			s.stagedAt[logical] = staged
			s.fileOps = append(s.fileOps, plannedOp(physical, staged, txnID))
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

// materializePackage writes the package payload to the already-journalled
// staged siblings and creates any directories needed for those siblings.
func materializePackage(env Env, s stagedOp, pp ProvidedPackage) error {
	err := archive.Extract(pp.Archive, func(entry archive.PayloadEntry, content io.Reader) error {
		physical := filepath.Join(env.Root, entry.Path)
		switch entry.Type {
		case archive.EntryDir:
			return os.MkdirAll(physical, 0o755)
		case archive.EntryFile:
			staged := s.stagedAt["/"+entry.Path]
			if staged == "" {
				return fmt.Errorf("no staged path planned for %s", entry.Path)
			}
			if err := os.MkdirAll(filepath.Dir(staged), 0o755); err != nil {
				return err
			}
			if err := writeStagedFile(staged, content); err != nil {
				return err
			}
		case archive.EntrySymlink:
			staged := s.stagedAt["/"+entry.Path]
			if staged == "" {
				return fmt.Errorf("no staged path planned for %s", entry.Path)
			}
			if err := os.MkdirAll(filepath.Dir(staged), 0o755); err != nil {
				return err
			}
			if err := os.Symlink(entry.LinkTarget, staged); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("peipkg/install: staging %s: %w", s.op.Name, err)
	}
	return nil
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

// rememberCreatedDirs records the missing directories from root down to
// dir. The transaction may create them during staging; rollback removes
// them in reverse if they are still empty. planned de-duplicates across
// all operations in the transaction before any of them touch disk.
func rememberCreatedDirs(root, dir string, planned map[string]bool, out *[]string) {
	root = filepath.Clean(root)
	dir = filepath.Clean(dir)
	rel, err := filepath.Rel(root, dir)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return
	}
	cur := root
	for _, part := range strings.Split(rel, string(os.PathSeparator)) {
		if part == "" || part == "." {
			continue
		}
		cur = filepath.Join(cur, part)
		if planned[cur] || exists(cur) {
			continue
		}
		planned[cur] = true
		*out = append(*out, cur)
	}
}

// originRepo is the repository a forward operation's package came from,
// or "" for a local-file install.
func originRepo(op resolver.Operation) string {
	if op.Candidate != nil {
		return op.Candidate.Repo
	}
	return ""
}

// isEtcPath reports whether a logical path is configuration in the /etc
// namespace, where §7.2.2 modified-detection applies.
//
// /usr/etc is where package config now lands: packages no longer write
// /etc directly, which is a merged view resolving usr/etc < system/retc
// < lcl/etc. Bare /etc is still recognised so a package installed before
// the layout change keeps its modified-file protection across the
// upgrade that moves it.
func isEtcPath(logical string) bool {
	return strings.HasPrefix(logical, "/usr/etc/") || strings.HasPrefix(logical, "/etc/")
}

// fileModified reports whether the file at path has content differing
// from recordedHash — the hex SHA-256 the package database recorded for
// it at install.
func fileModified(path, recordedHash string) (bool, error) {
	onDisk, err := fileHash(path)
	if err != nil {
		return false, err
	}
	return onDisk != recordedHash, nil
}

// fileHash returns the lowercase-hex SHA-256 of the file at path.
func fileHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("peipkg/install: reading %s: %w", path, err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("peipkg/install: hashing %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// checkPayloadLayout enforces the §3.4 payload layout rules over a
// verified package immediately before staging.
//
// The exemption needs both keys turned at once. A package that declares
// special_system_package but meets an installer that was not given
// --dangerously-bypass-path-restrictions is still checked, and the error
// says so — the operator is told an exemption was asked for and refused,
// rather than the install silently succeeding or failing obscurely.
func checkPayloadLayout(env Env, pp ProvidedPackage) error {
	if pp.Pkg == nil {
		return nil
	}
	special := pp.Pkg.Manifest.SpecialSystemPackage
	if special && env.BypassPathRestrictions {
		return nil
	}

	entries := make([]packvalidate.InstallEntry, 0, len(pp.Pkg.Payload))
	for _, e := range pp.Pkg.Payload {
		entries = append(entries, packvalidate.InstallEntry{
			Path:       e.Path,
			IsDir:      e.Type == archive.EntryDir,
			IsSymlink:  e.Type == archive.EntrySymlink,
			LinkTarget: e.LinkTarget,
		})
	}

	err := packvalidate.ValidateInstallPaths(pp.Pkg.Manifest.Architecture, entries)
	if err == nil {
		return nil
	}
	if special {
		return fmt.Errorf(
			"%s declares special_system_package but this install did not pass "+
				"--dangerously-bypass-path-restrictions: %w", pp.Pkg.Manifest.Name, err)
	}
	return err
}
