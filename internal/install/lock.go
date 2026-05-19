// Package install executes a resolved plan against the system: it
// stages a transaction's package payloads, commits them atomically, and
// rolls back a transaction that crashed before its durability boundary
// (PSD-009 chapter 7).
package install

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// Lock is the single-writer lock over a package operation (§7.6.7). It
// is an advisory flock on a lock file; the kernel releases it when the
// holding process exits, so a crashed peipkg never leaves it stale. The
// at-most-one-pending-transaction index in the package database is the
// structural backstop should this advisory lock ever be bypassed.
type Lock struct {
	file *os.File
}

// Acquire takes the exclusive lock at path, creating the file if it
// does not exist. It does not block: if another process holds the lock,
// Acquire fails at once.
func Acquire(path string) (*Lock, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return nil, fmt.Errorf("peipkg/install: opening lock file %s: %w", path, err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("peipkg/install: another package operation is already in progress")
	}
	return &Lock{file: f}, nil
}

// Release releases the lock. Closing the descriptor drops the flock.
func (l *Lock) Release() error {
	if err := l.file.Close(); err != nil {
		return fmt.Errorf("peipkg/install: releasing lock: %w", err)
	}
	return nil
}
