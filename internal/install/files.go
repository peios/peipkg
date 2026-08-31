package install

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/peios/peipkg/internal/safepath"
)

// Temporary-file markers (DESIGN.md "Temporary file naming"). The names
// are visible and explicit — a stray one after a crash is something an
// operator should trip over and understand — and carry the transaction
// id, tying a leftover to a row in `peipkg history`.
const (
	stagedMarker = ".peipkg-staged-"
	backupMarker = ".peipkg-backup-"
)

// maxComponent is the §3.2.7 path-component byte limit.
const maxComponent = 255

// fileAction is what a transaction does to one destination path.
type fileAction uint8

const (
	// actionCreate installs new content where nothing existed.
	actionCreate fileAction = iota
	// actionReplace installs new content over an existing file, which is
	// backed up first.
	actionReplace
	// actionRemove deletes an existing file, which is backed up first.
	actionRemove
)

// fileOp is one file-level step of a transaction — the in-memory form
// of a db.TxnFile row and an entry in the backup map.
type fileOp struct {
	finalPath string
	action    fileAction
	// stagedPath holds the incoming content for a create or replace.
	stagedPath string
	// backupPath holds the displaced old content for a replace or
	// remove — the backup-by-rename target.
	backupPath string
	// keepBackup preserves backupPath past commit. It is set for an
	// authorised overwrite of an unowned file (§7.1.5): the displacement
	// is the whole point of the authorisation, so discarding it at
	// commit would destroy exactly the content the rule exists to save.
	keepBackup bool
	// dir pins the parent directory of all three paths above — they are
	// siblings by construction, which is what lets one descriptor serve
	// the lot. Every effect goes through it, so a rename cannot be
	// redirected by a path component changing between the plan and the
	// commit (§5.26).
	//
	// It is nil only when recovery found the directory already gone, in
	// which case the operation has nothing left to do.
	dir *safepath.Dir
}

// names returns the three sibling component names the operation acts
// on. They are components rather than paths because a Dir operation
// takes one: that is what keeps resolution inside the pinned descriptor.
func (op fileOp) names() (base, staged, backup string) {
	return filepath.Base(op.finalPath), filepath.Base(op.stagedPath),
		filepath.Base(op.backupPath)
}

// tempPath builds a sibling temporary path for finalPath: the same
// directory (so a rename never crosses a filesystem and EXDEV is
// impossible), the base name, the marker, and the transaction id. The
// base name is truncated to keep the result within the 255-byte
// component limit.
func tempPath(finalPath, marker string, txnID int64) string {
	dir, base := filepath.Split(finalPath)
	suffix := marker + strconv.FormatInt(txnID, 10)
	if len(base)+len(suffix) > maxComponent {
		base = base[:maxComponent-len(suffix)]
	}
	return filepath.Join(dir, base+suffix)
}

// commitOps applies file operations in order — the atomic flip of a
// transaction. Each step is a rename within a single directory. A
// failure leaves the operations partially applied; the caller rolls the
// whole set back, which [rollbackOps] does idempotently.
func commitOps(ops []fileOp) error {
	for i := range ops {
		if err := commitOp(ops[i]); err != nil {
			return err
		}
	}
	return nil
}

func commitOp(op fileOp) error {
	if op.dir == nil {
		// Only a removal reaches here without a pinned parent, and only
		// when the directory was already gone when the plan was made —
		// so the file is gone too and there is nothing to remove.
		if op.action == actionRemove {
			return nil
		}
		return fmt.Errorf("peipkg/install: %s has no pinned directory", op.finalPath)
	}
	base, staged, backup := op.names()
	switch op.action {
	case actionCreate:
		if err := op.dir.Rename(staged, base); err != nil {
			return fmt.Errorf("peipkg/install: installing %s: %w", op.finalPath, err)
		}
	case actionReplace:
		if err := op.dir.Rename(base, backup); err != nil {
			return fmt.Errorf("peipkg/install: backing up %s: %w", op.finalPath, err)
		}
		if err := op.dir.Rename(staged, base); err != nil {
			return fmt.Errorf("peipkg/install: installing %s: %w", op.finalPath, err)
		}
	case actionRemove:
		if !op.dir.Exists(base) {
			return nil // already absent — nothing to remove or back up
		}
		if err := op.dir.Rename(base, backup); err != nil {
			return fmt.Errorf("peipkg/install: removing %s: %w", op.finalPath, err)
		}
	}
	return nil
}

// rollbackOps reverses a set of file operations, restoring the
// pre-transaction state. Every step checks the current state before
// acting, so rollback is idempotent: it is correct whether the
// transaction had not started, was partway through, or had fully
// applied its file operations. It attempts every operation and reports
// any failures together.
func rollbackOps(ops []fileOp) error {
	var errs []error
	for i := len(ops) - 1; i >= 0; i-- {
		if err := rollbackOp(ops[i]); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func rollbackOp(op fileOp) error {
	if op.dir == nil {
		// Recovery found the directory gone: nothing under it survives
		// to be undone.
		return nil
	}
	base, staged, backup := op.names()
	switch op.action {
	case actionCreate:
		// Nothing existed before; discard the incoming content wherever
		// it currently sits.
		if err := removeIfExists(op.dir, base); err != nil {
			return err
		}
		return removeIfExists(op.dir, staged)
	case actionReplace, actionRemove:
		// Restore the displaced original from its backup, if the
		// transaction got far enough to make one.
		if op.dir.Exists(backup) {
			if err := removeIfExists(op.dir, base); err != nil {
				return err
			}
			if err := op.dir.Rename(backup, base); err != nil {
				return fmt.Errorf("peipkg/install: restoring %s: %w", op.finalPath, err)
			}
		}
		if op.action == actionReplace {
			return removeIfExists(op.dir, staged)
		}
		return nil
	default:
		return nil
	}
}

// discardBackups removes the displaced-original backups of a committed
// transaction (§7.2.2 step 4.3). Once a transaction has committed its
// backups serve no purpose — recovery only ever rolls back a *pending*
// transaction. A failed removal is reported, not fatal: the
// transaction has already committed.
//
// A backup marked keepBackup is the exception: an authorised overwrite
// of an unowned file displaced content peipkg did not put there, and
// keeping that displacement is what the authorisation bought (§7.1.5).
func discardBackups(ops []fileOp) []string {
	var warnings []string
	for _, op := range ops {
		if op.backupPath == "" || op.keepBackup || op.dir == nil {
			continue
		}
		_, _, backup := op.names()
		if err := op.dir.Remove(backup); err != nil && !os.IsNotExist(err) {
			warnings = append(warnings,
				fmt.Sprintf("could not remove backup %s: %v", op.backupPath, err))
		}
	}
	return warnings
}

// removeIfExists removes name from dir, treating an already-absent name
// as success.
func removeIfExists(dir *safepath.Dir, name string) error {
	if err := dir.Remove(name); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("peipkg/install: removing %s: %w",
			filepath.Join(dir.Path(), name), err)
	}
	return nil
}

// removeCreatedDirs removes transaction-created directories in reverse
// order. Non-empty directories are left alone: another package or an
// operator may have populated them after the transaction began.
func removeCreatedDirs(pins *pinnedDirs, dirs []string) error {
	var errs []error
	for i := len(dirs) - 1; i >= 0; i-- {
		parent, err := pins.existingDirFor(dirs[i])
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if parent == nil {
			continue // the parent is gone, so the child is too
		}
		if err := parent.RemoveDir(filepath.Base(dirs[i])); err != nil {
			if os.IsNotExist(err) || errors.Is(err, syscall.ENOTEMPTY) ||
				errors.Is(err, syscall.EEXIST) {
				continue
			}
			errs = append(errs, fmt.Errorf("peipkg/install: removing directory %s: %w",
				dirs[i], err))
		}
	}
	return errors.Join(errs...)
}
