// Package safepath resolves paths beneath an installation root without
// ever traversing a symbolic link, and performs every filesystem effect
// against a pinned directory descriptor rather than a re-walked string.
//
// PSPU §5.26 requires a consumer to resolve every path component of an
// install location relative to a verified parent-directory descriptor,
// without traversing any symbolic link — including one it created
// earlier in the same operation.
//
// Two things go wrong without it, and only one of them is a race.
//
// The first needs no race at all. Nothing rejects a payload entry whose
// *ancestor* is a symlink, so a package shipping `usr/share/a -> ../bin`
// and a second package shipping the regular file `usr/share/a/sshd`
// between them write `usr/bin/sshd`. Both payloads are individually
// valid. The database records `/usr/share/a/sshd`, the bytes land on
// another package's binary, the collision index never fires because the
// recorded path and the real path differ, and uninstalling the second
// package renames the victim's file aside as if it were its own.
//
// The second is the ordinary time-of-check/time-of-use window, and it is
// enormous here: existence is checked while the journal is planned and
// the corresponding rename happens after every package in the
// transaction has been downloaded, decompressed and staged.
//
// A well-formed package never has a payload entry whose ancestor is a
// symlink, so refusing to traverse one fires only on a malformed or
// hostile package, where aborting is correct. Symlinks as *leaf* payload
// entries are created normally; they are simply never walked through.
package safepath

import (
	"errors"
	"fmt"
	"os"
	"path"
	"strings"

	"golang.org/x/sys/unix"
)

// Root is an installation root, pinned by an open descriptor. Paths
// resolved through it are resolved component by component relative to a
// descriptor, and a component that is not a real directory — a symlink
// above all — ends the walk.
type Root struct {
	fd   int
	path string
}

// Dir is a directory beneath a [Root], pinned by an open descriptor.
// Operations on it name a single path component, so there is nothing
// left for anyone to redirect: the descriptor is the directory, not a
// name that resolves to one.
type Dir struct {
	fd  int
	rel string // relative to the root, for error messages
	abs string
}

// OpenRoot pins an installation root.
func OpenRoot(rootPath string) (*Root, error) {
	fd, err := unix.Open(rootPath, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("peipkg/safepath: opening root %s: %w", rootPath, err)
	}
	return &Root{fd: fd, path: rootPath}, nil
}

// Close releases the root's descriptor.
func (r *Root) Close() error {
	if r == nil || r.fd < 0 {
		return nil
	}
	err := unix.Close(r.fd)
	r.fd = -1
	return err
}

// Path is the root's own path.
func (r *Root) Path() string { return r.path }

// Dir resolves rel — a slash-separated path relative to the root — to a
// pinned directory. It creates nothing; a missing component is an
// error wrapping [fs.ErrNotExist].
func (r *Root) Dir(rel string) (*Dir, error) { return r.walk(rel, false, 0) }

// MkdirAll resolves rel, creating any missing components with perm, and
// returns the pinned directory. Each component is created and then
// opened relative to the descriptor of its parent, so a component that
// appears between the two — as a symlink, say — is caught by the open
// rather than followed.
func (r *Root) MkdirAll(rel string, perm os.FileMode) (*Dir, error) {
	return r.walk(rel, true, perm)
}

// ErrSymlinkComponent is returned when a path component that must be a
// directory is a symbolic link, or anything else that is not a
// directory. It is the condition §5.26 exists to prevent, and it is
// deliberately distinguishable from an ordinary missing path.
var ErrSymlinkComponent = errors.New("path component is not a directory")

func (r *Root) walk(rel string, create bool, perm os.FileMode) (*Dir, error) {
	comps, err := components(rel)
	if err != nil {
		return nil, err
	}
	cur, err := unix.Dup(r.fd)
	if err != nil {
		return nil, fmt.Errorf("peipkg/safepath: %w", err)
	}
	walked := ""
	for _, comp := range comps {
		walked = path.Join(walked, comp)
		next, err := openDirAt(cur, comp)
		if create && errors.Is(err, unix.ENOENT) {
			if mkErr := unix.Mkdirat(cur, comp, uint32(perm.Perm())); mkErr != nil &&
				!errors.Is(mkErr, unix.EEXIST) {
				unix.Close(cur)
				return nil, fmt.Errorf("peipkg/safepath: creating %s: %w",
					path.Join(r.path, walked), mkErr)
			}
			next, err = openDirAt(cur, comp)
		}
		unix.Close(cur)
		if err != nil {
			return nil, resolveError(path.Join(r.path, walked), err)
		}
		cur = next
	}
	return &Dir{fd: cur, rel: rel, abs: path.Join(r.path, rel)}, nil
}

// openDirAt opens one component as a directory, relative to parent,
// without following it. O_PATH|O_NOFOLLOW alone would open a symlink
// itself; O_DIRECTORY is what turns that into the ENOTDIR this relies
// on.
func openDirAt(parent int, comp string) (int, error) {
	return unix.Openat(parent, comp,
		unix.O_PATH|unix.O_NOFOLLOW|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
}

func resolveError(at string, err error) error {
	if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
		return fmt.Errorf("peipkg/safepath: %s: %w (§5.26 refuses to resolve through one)",
			at, ErrSymlinkComponent)
	}
	if errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("peipkg/safepath: %s: %w", at, os.ErrNotExist)
	}
	return fmt.Errorf("peipkg/safepath: resolving %s: %w", at, err)
}

// components splits a root-relative path, refusing anything that could
// leave the root by name. The archive layer has already rejected such
// paths; this is the second of the two independent checks §5.26 asks
// for, at the point of use.
func components(rel string) ([]string, error) {
	// The raw string is inspected, not path.Clean's output: Clean folds
	// a leading ".." against the root away, so "usr/../.." would arrive
	// here looking like the root itself rather than like an escape
	// attempt. A path that tried to leave is refused whether or not the
	// arithmetic happened to land back inside.
	var out []string
	for _, c := range strings.Split(strings.TrimPrefix(rel, "/"), "/") {
		switch c {
		case "", ".":
			continue
		case "..":
			return nil, fmt.Errorf("peipkg/safepath: %q leaves the root", rel)
		}
		out = append(out, c)
	}
	return out, nil
}

// Close releases the directory's descriptor.
func (d *Dir) Close() error {
	if d == nil || d.fd < 0 {
		return nil
	}
	err := unix.Close(d.fd)
	d.fd = -1
	return err
}

// Path is the directory's absolute path, for error messages only —
// nothing resolves it again.
func (d *Dir) Path() string { return d.abs }

// checkName rejects anything but a single path component. Every Dir
// operation takes one, which is what keeps resolution inside the pinned
// descriptor.
func checkName(name string) error {
	if name == "" || name == "." || name == ".." || strings.Contains(name, "/") {
		return fmt.Errorf("peipkg/safepath: %q is not a single path component", name)
	}
	return nil
}

// Lstat stats name within the directory without following it.
func (d *Dir) Lstat(name string) (os.FileInfo, error) {
	if err := checkName(name); err != nil {
		return nil, err
	}
	var st unix.Stat_t
	if err := unix.Fstatat(d.fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return nil, &os.PathError{Op: "lstat", Path: path.Join(d.abs, name), Err: err}
	}
	return &statInfo{name: name, st: st}, nil
}

// Exists reports whether anything is present at name. A symlink counts
// as present even when its target is missing.
func (d *Dir) Exists(name string) bool {
	_, err := d.Lstat(name)
	return err == nil
}

// Create makes a new file at name and opens it for writing. It fails if
// anything is already there, symlink included: O_EXCL and O_NOFOLLOW
// together mean the file that ends up open is the one this call made.
func (d *Dir) Create(name string, perm os.FileMode) (*os.File, error) {
	if err := checkName(name); err != nil {
		return nil, err
	}
	fd, err := unix.Openat(d.fd, name,
		unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		uint32(perm.Perm()))
	if err != nil {
		return nil, &os.PathError{Op: "create", Path: path.Join(d.abs, name), Err: err}
	}
	return os.NewFile(uintptr(fd), path.Join(d.abs, name)), nil
}

// Open opens name for reading without following it.
func (d *Dir) Open(name string) (*os.File, error) {
	if err := checkName(name); err != nil {
		return nil, err
	}
	fd, err := unix.Openat(d.fd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path.Join(d.abs, name), Err: err}
	}
	return os.NewFile(uintptr(fd), path.Join(d.abs, name)), nil
}

// Symlink creates a symbolic link at name pointing at target. The link
// itself is ordinary payload; what §5.26 forbids is walking through one.
func (d *Dir) Symlink(target, name string) error {
	if err := checkName(name); err != nil {
		return err
	}
	if err := unix.Symlinkat(target, d.fd, name); err != nil {
		return &os.PathError{Op: "symlink", Path: path.Join(d.abs, name), Err: err}
	}
	return nil
}

// Readlink reads the target of the symbolic link at name.
func (d *Dir) Readlink(name string) (string, error) {
	if err := checkName(name); err != nil {
		return "", err
	}
	buf := make([]byte, unix.PathMax)
	n, err := unix.Readlinkat(d.fd, name, buf)
	if err != nil {
		return "", &os.PathError{Op: "readlink", Path: path.Join(d.abs, name), Err: err}
	}
	return string(buf[:n]), nil
}

// Rename renames within the directory. Both names are components of
// this one pinned descriptor, which is what makes the commit
// unredirectable: there is no path left to re-resolve.
func (d *Dir) Rename(from, to string) error {
	if err := checkName(from); err != nil {
		return err
	}
	if err := checkName(to); err != nil {
		return err
	}
	if err := unix.Renameat(d.fd, from, d.fd, to); err != nil {
		return &os.PathError{Op: "rename", Path: path.Join(d.abs, from), Err: err}
	}
	return nil
}

// Remove deletes name, file or directory.
func (d *Dir) Remove(name string) error {
	if err := checkName(name); err != nil {
		return err
	}
	err := unix.Unlinkat(d.fd, name, 0)
	if errors.Is(err, unix.EISDIR) || errors.Is(err, unix.EPERM) {
		if dirErr := unix.Unlinkat(d.fd, name, unix.AT_REMOVEDIR); dirErr == nil {
			return nil
		} else if !errors.Is(err, unix.EPERM) {
			err = dirErr
		}
	}
	if err != nil {
		return &os.PathError{Op: "remove", Path: path.Join(d.abs, name), Err: err}
	}
	return nil
}

// RemoveDir removes the directory name, which must be empty.
func (d *Dir) RemoveDir(name string) error {
	if err := checkName(name); err != nil {
		return err
	}
	if err := unix.Unlinkat(d.fd, name, unix.AT_REMOVEDIR); err != nil {
		return &os.PathError{Op: "rmdir", Path: path.Join(d.abs, name), Err: err}
	}
	return nil
}

// Mkdir creates a subdirectory.
func (d *Dir) Mkdir(name string, perm os.FileMode) error {
	if err := checkName(name); err != nil {
		return err
	}
	if err := unix.Mkdirat(d.fd, name, uint32(perm.Perm())); err != nil {
		return &os.PathError{Op: "mkdir", Path: path.Join(d.abs, name), Err: err}
	}
	return nil
}

// Split separates a root-relative path into its directory part and its
// final component, the two halves every Dir operation needs.
func Split(rel string) (dir, base string) {
	clean := strings.TrimPrefix(path.Clean("/"+rel), "/")
	i := strings.LastIndex(clean, "/")
	if i < 0 {
		return "", clean
	}
	return clean[:i], clean[i+1:]
}
