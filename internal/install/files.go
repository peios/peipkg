package install

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
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
	switch op.action {
	case actionCreate:
		if err := os.Rename(op.stagedPath, op.finalPath); err != nil {
			return fmt.Errorf("peipkg/install: installing %s: %w", op.finalPath, err)
		}
	case actionReplace:
		if err := os.Rename(op.finalPath, op.backupPath); err != nil {
			return fmt.Errorf("peipkg/install: backing up %s: %w", op.finalPath, err)
		}
		if err := os.Rename(op.stagedPath, op.finalPath); err != nil {
			return fmt.Errorf("peipkg/install: installing %s: %w", op.finalPath, err)
		}
	case actionRemove:
		if err := os.Rename(op.finalPath, op.backupPath); err != nil {
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
	switch op.action {
	case actionCreate:
		// Nothing existed before; discard the incoming content wherever
		// it currently sits.
		if err := removeIfExists(op.finalPath); err != nil {
			return err
		}
		return removeIfExists(op.stagedPath)
	case actionReplace, actionRemove:
		// Restore the displaced original from its backup, if the
		// transaction got far enough to make one.
		if exists(op.backupPath) {
			if err := removeIfExists(op.finalPath); err != nil {
				return err
			}
			if err := os.Rename(op.backupPath, op.finalPath); err != nil {
				return fmt.Errorf("peipkg/install: restoring %s: %w", op.finalPath, err)
			}
		}
		if op.action == actionReplace {
			return removeIfExists(op.stagedPath)
		}
		return nil
	default:
		return nil
	}
}

// exists reports whether a filesystem object is present at path. A
// symlink counts as present even if its target is missing.
func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// removeIfExists removes the object at path, treating an already-absent
// path as success.
func removeIfExists(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("peipkg/install: removing %s: %w", path, err)
	}
	return nil
}
