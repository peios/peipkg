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
	"github.com/peios/peipkg/internal/layout"
	"github.com/peios/peipkg/internal/pipsig"
	"github.com/peios/peipkg/internal/resolver"
	"github.com/peios/peipkg/internal/sdstamp"
	"github.com/peios/peipkg/internal/version"
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
	// sdOverrides names each §3.3.5 override this package applied, for
	// the §5.20 rule 2 install report.
	sdOverrides []string
	// stagedAt maps payload logical paths to their incoming staged
	// sibling. It is staging-only state; the journal gets fileOps.
	stagedAt map[string]string
}

// prepareOperation computes one plan operation's journal rows and
// package-database changes without touching the filesystem.
func prepareOperation(ctx context.Context, env Env, txnID int64, op resolver.Operation,
	provided map[string]ProvidedPackage, plannedDirs map[string]bool,
	inTxn map[string]bool) (stagedOp, error) {
	if op.Kind == resolver.OpRemove {
		return stageRemoval(ctx, env, txnID, op)
	}
	return preparePackage(ctx, env, txnID, op, provided[op.Name], plannedDirs, inTxn)
}

// preparePackage computes the file operations and database rows for
// installing a package. No payload bytes are written here: the journal
// is written first, then materializePackage creates the staged siblings.
//
// Per-file metadata — type and the verified SHA-256 — comes from the
// verified payload list, the authority for what the package owns.
func preparePackage(ctx context.Context, env Env, txnID int64, op resolver.Operation,
	pp ProvidedPackage, plannedDirs map[string]bool, inTxn map[string]bool) (stagedOp, error) {

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

	// §5.20 override policy, before anything is staged.
	//
	// The manifest and archive layers have already checked that every
	// override is structurally sound and names a real non-symlink
	// payload entry. What is left is the question the format cannot
	// answer: whether this producer may declare descriptors on this
	// machine at all. §5.20 gives that to the consumer, and requires a
	// package whose overrides the policy rejects to be REFUSED —
	// explicitly not installed with the overrides dropped, because a
	// package silently losing the descriptors it declared is
	// indistinguishable from one that never declared any.
	if err := checkSDOverridePolicy(env, op, pp); err != nil {
		return s, err
	}
	for _, o := range pp.Pkg.Manifest.SDOverrides {
		s.sdOverrides = append(s.sdOverrides,
			fmt.Sprintf("%s: /%s", op.Name, o.Path))
	}

	// §5.21: a provides.version greater than the providing package's own
	// version MUST generate an operator warning at install time, because
	// an inflated provides-version defeats constraint-based resolution.
	//
	// The attack is live rather than theoretical: libfoo 1.0-1 declaring
	// provides libfoo 5.0 satisfies a `>= 4.0` dependency and installs
	// silently. Where a genuine libfoo 4.0-1 is also a candidate it wins
	// on the name match, so this lands exactly where the real package is
	// absent — which is the shadowing case the warning exists for.
	for _, prov := range pp.Pkg.Manifest.Provides {
		if prov.Version != nil && version.Compare(*prov.Version, pp.Pkg.Manifest.Version) > 0 {
			s.warnings = append(s.warnings, fmt.Sprintf(
				"%s provides %s at version %s, above its own version %s — an inflated "+
					"provides-version can shadow a real package in constraint resolution",
				op.Name, prov.Name, prov.Version, pp.Pkg.Manifest.Version))
		}
	}

	// §7.1.2.2 step 3: no payload path may collide with a path already
	// owned by another installed package.
	//
	// The unique index on package_file is the invariant's home, but it
	// fires inside the commit transaction — after a full download,
	// extraction and on-disk clobber, leaving recovery to depend entirely
	// on the rollback succeeding. Diagnosing it here costs one indexed
	// query per payload path and fails before anything is staged.
	if err := checkPayloadCollisions(ctx, env, op, pp, inTxn); err != nil {
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
		// A signature sidecar is never installed: its bytes become the
		// target's security.peios.sig attribute when the payload is
		// materialised (pipsig), so it gets no staged path, no file
		// operation and no package_file row.
		if entry.Type == archive.EntryFile && pipsig.IsSidecar(entry.Path) {
			continue
		}
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
			// §7.1.5, against the path actually written: on the
			// modified-/etc branch that is the .peipkg-new sibling, not
			// the operator's file, which is being deliberately preserved.
			destLogical := logical
			if preserved {
				destLogical = logical + etcNewMarker
			}
			keepBackup, warn, err := unownedPolicy(ctx, env, op.Name, dest, destLogical, entry, inTxn)
			if err != nil {
				return s, err
			}
			if warn != "" {
				s.warnings = append(s.warnings, warn)
			}
			staged := tempPath(dest, stagedMarker, txnID)
			rememberCreatedDirs(env.Root, filepath.Dir(staged), plannedDirs, &s.createdDirs)
			s.stagedAt[logical] = staged
			fo := plannedOp(dest, staged, txnID)
			fo.keepBackup = keepBackup
			s.fileOps = append(s.fileOps, fo)
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
			keepBackup, warn, err := unownedPolicy(ctx, env, op.Name, physical, logical, entry, inTxn)
			if err != nil {
				return s, err
			}
			if warn != "" {
				s.warnings = append(s.warnings, warn)
			}
			staged := tempPath(physical, stagedMarker, txnID)
			rememberCreatedDirs(env.Root, filepath.Dir(staged), plannedDirs, &s.createdDirs)
			s.stagedAt[logical] = staged
			fo := plannedOp(physical, staged, txnID)
			fo.keepBackup = keepBackup
			s.fileOps = append(s.fileOps, fo)
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
	var sidecars pipsig.Sidecars
	written := map[string]string{} // regular files written, archive path -> staged path
	dirs := map[string]string{}    // directories created, archive path -> final path
	err := archive.Extract(pp.Archive, func(entry archive.PayloadEntry, content io.Reader) error {
		physical := filepath.Join(env.Root, entry.Path)
		switch entry.Type {
		case archive.EntryDir:
			dirs[entry.Path] = physical
			return os.MkdirAll(physical, 0o755)
		case archive.EntryFile:
			if pipsig.IsSidecar(entry.Path) {
				return sidecars.Add(entry.Path, content)
			}
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
			written[entry.Path] = staged
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
	// Signatures are stamped on the staged inode, before the commit
	// rename carries it to its final path: the kernel gates mutation of
	// security.peios.sig on signed content, so the attribute has to be
	// set while the file is still an unsigned temporary.
	if err := sidecars.Apply(func(target string) (string, bool) {
		staged, ok := written[target]
		return staged, ok
	}); err != nil {
		return fmt.Errorf("peipkg/install: staging %s: %w", s.op.Name, err)
	}
	// §3.3.5 overrides, last: a descriptor may deny this process the
	// access it needed to write the payload, so nothing may still be
	// waiting to be written when one is applied. Signatures in
	// particular are stamped above, because setting a descriptor that
	// withholds WRITE_DAC from the installer would strand them.
	//
	// A regular file is stamped on its staged inode, before the commit
	// rename carries it to its final path — the same reasoning as the
	// signature stamp, and it makes the entry become visible already
	// carrying its descriptor rather than briefly wearing an inherited
	// one. A directory has no staged sibling: it is created at its final
	// path, so it is stamped there, after the extract loop has put every
	// child inside it.
	if err := sdstamp.New(pp.Pkg.Manifest.SDOverrides).Apply(
		func(path string) (string, bool) {
			if staged, ok := written[path]; ok {
				return staged, true
			}
			dir, ok := dirs[path]
			return dir, ok
		}); err != nil {
		return fmt.Errorf("peipkg/install: staging %s: %w", s.op.Name, err)
	}
	return nil
}

// checkSDOverridePolicy enforces the §5.20 consumer policy: a package
// may carry security-descriptor overrides only from a repository the
// operator has permitted them from.
//
// A package declaring none passes whatever the policy says. The
// question only arises where there is something to authorise, and
// refusing an override-free package from an unvouched repository would
// be refusing every package from it.
func checkSDOverridePolicy(env Env, op resolver.Operation, pp ProvidedPackage) error {
	if len(pp.Pkg.Manifest.SDOverrides) == 0 {
		return nil
	}
	repo := originRepo(op)
	if env.SDOverridePolicy != nil && env.SDOverridePolicy(repo) {
		return nil
	}
	where := fmt.Sprintf("repository %q", repo)
	if repo == "" {
		where = "no repository (a local package file)"
	}
	return fmt.Errorf(
		"peipkg/install: %s declares %d security-descriptor override(s) but comes from %s, "+
			"which is not permitted to declare them; a descriptor grants access to principals "+
			"the package names, and the format cannot check that its producer had authority to. "+
			"Set allow_sd_overrides in that repository's configuration to permit it",
		op.Name, len(pp.Pkg.Manifest.SDOverrides), where)
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

// unownedPolicy applies the §7.1.5 unowned-file rule to a destination
// that may already hold something.
//
// A pre-existing file that no installed package claims is on this
// machine because somebody put it there — a hand-placed binary, or
// filesystem state inherited from a non-Peios installation — and peipkg
// was never asked to manage it. Three outcomes:
//
//   - byte-identical to what would be installed: **adopted**. Installing
//     changes nothing on disk, and refusing would make a re-run of a
//     half-finished install impossible.
//   - different, with no authorisation: the install **fails**. Before
//     this, it was silently overwritten and the backup deleted seconds
//     later at commit, which permanently destroyed the very content the
//     rule exists to protect.
//   - different, authorised by the operator: **displaced**. The
//     original is renamed aside as usual, and keepBackup stops commit
//     from discarding it.
//
// A destination owned by an installed package is not this rule's
// business: the same-package case is an ordinary replace, and the
// other-package case checkPayloadCollisions has already refused.
//
// It reports whether the operation's backup must survive commit, plus a
// warning for the operator when one is due.
func unownedPolicy(ctx context.Context, env Env, pkgName, dest, destLogical string,
	entry archive.PayloadEntry, inTxn map[string]bool) (keepBackup bool, warning string, err error) {

	if !exists(dest) {
		return false, "", nil
	}
	owners, err := env.DB.FileOwners(ctx, destLogical)
	if err != nil {
		return false, "", err
	}
	if len(owners) > 0 {
		return false, "", nil
	}

	same, err := matchesPayload(dest, entry)
	if err != nil {
		return false, "", err
	}
	if same {
		return false, "", nil
	}
	if !env.OverwriteUnowned {
		return false, "", fmt.Errorf(
			"peipkg/install: %s would overwrite %s, which is already on this system and "+
				"belongs to no installed package; its content differs from the package's. "+
				"Move it aside, or pass --overwrite-unowned to displace it (the displaced "+
				"copy is kept)", pkgName, destLogical)
	}
	return true, fmt.Sprintf(
		"%s overwrote %s, which belonged to no package; the previous content is kept at %s",
		pkgName, destLogical, filepath.Base(tempPath(dest, backupMarker, 0))), nil
}

// matchesPayload reports whether what is at dest is already exactly what
// entry would install. The comparison is by kind: content hash for a
// regular file, target for a symlink. A kind mismatch is never a match.
func matchesPayload(dest string, entry archive.PayloadEntry) (bool, error) {
	info, err := os.Lstat(dest)
	if err != nil {
		return false, fmt.Errorf("peipkg/install: examining %s: %w", dest, err)
	}
	switch entry.Type {
	case archive.EntryFile:
		if !info.Mode().IsRegular() {
			return false, nil
		}
		onDisk, err := fileHash(dest)
		if err != nil {
			return false, err
		}
		return onDisk == entry.Hash, nil
	case archive.EntrySymlink:
		if info.Mode()&os.ModeSymlink == 0 {
			return false, nil
		}
		target, err := os.Readlink(dest)
		if err != nil {
			return false, fmt.Errorf("peipkg/install: reading %s: %w", dest, err)
		}
		return target == entry.LinkTarget, nil
	default:
		return false, nil
	}
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
	// §5.14's absolute rule, checked before and independent of the
	// bypass: no waiver reaches /lcl/policy.
	for _, e := range pp.Pkg.Payload {
		if err := layout.CheckEntry(e.Path, e.Type == archive.EntryDir); err != nil {
			return fmt.Errorf("%s: %w", pp.Pkg.Manifest.Name, err)
		}
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

// checkPayloadCollisions reports a planned payload path already owned by
// an installed package that this transaction does not touch (§7.1.2.2
// step 3).
//
// Directories are excluded, as the schema constraint excludes them:
// shared ownership of a directory is normal and expected. A path owned by
// a package inside the transaction is not a collision either — that
// package is being upgraded, downgraded or removed, so the ownership is
// about to change anyway.
func checkPayloadCollisions(ctx context.Context, env Env, op resolver.Operation,
	pp ProvidedPackage, inTxn map[string]bool) error {

	for _, entry := range pp.Pkg.Payload {
		if entry.Type == archive.EntryDir {
			continue
		}
		if entry.Type == archive.EntryFile && pipsig.IsSidecar(entry.Path) {
			continue // never installed, so never owned (pipsig)
		}
		logical := "/" + entry.Path
		owners, err := env.DB.FileOwners(ctx, logical)
		if err != nil {
			return err
		}
		for _, owner := range owners {
			if owner.PackageName == op.Name || inTxn[owner.PackageName] {
				continue
			}
			return fmt.Errorf(
				"peipkg/install: %s payload path %s is already owned by %s",
				op.Name, logical, owner.PackageName)
		}
	}
	return nil
}
