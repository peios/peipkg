// Package sdstamp applies a package's §3.3.5 security-descriptor
// overrides to the payload entries a consumer has materialised.
//
// Every installed file and directory carries a KACS security
// descriptor. §5.20's default is inheritance: an entry with no override
// is created without an explicit descriptor, so the kernel derives one
// from its parent's inheritable ACEs at creation time. Consumers get
// that for free — they simply do not stamp — and this package exists
// only for the entries a package overrides.
//
// The descriptor's storage is an extended attribute, [XattrName], which
// is what makes an override applicable off Peios: writing it needs
// setxattr and CAP_SYS_ADMIN, not a KACS-aware kernel. `mksquashfs
// -xattrs` carries it into an image, and the kernel prefers a stored
// descriptor to a synthesised one — kacs/file_sd_cache.c reads the
// attribute first and falls through to the mount's synthesis policy
// only on ENODATA. So an entry stamped here keeps its descriptor even
// on a `policy=synth-ephemeral` mount, per inode.
//
// This mirrors [pipsig], which carries PIP signatures into
// security.peios.sig. The shapes are deliberately parallel — a
// collector, a package-level Stamp variable tests can replace, and an
// ApplyWith for a consumer that cannot set security.* attributes
// itself. The two differ in what they may target: a signature sidecar
// names a regular file, while an override may name a directory as well.
//
// Nothing here decides whether an override is *permitted*. §5.20 makes
// that the consumer's policy question, and the consumer answers it
// before calling Apply.
package sdstamp

import (
	"fmt"
	"sort"

	"golang.org/x/sys/unix"

	"github.com/peios/peipkg/internal/manifest"
)

// XattrName is the extended attribute the descriptor lives in, and the
// name the kernel reads it back from (kacs/mount_policy.c).
const XattrName = "security.peios.sd"

// Stamp writes a security descriptor onto the object at path.
//
// It is a variable so tests can observe the stamp without the privilege
// the real one needs: security.* attributes are settable only with
// CAP_SYS_ADMIN, which an ordinary test process lacks. pipsig.Stamp is
// a variable for the same reason.
var Stamp = func(path string, sd []byte) error {
	if err := unix.Setxattr(path, XattrName, sd, 0); err != nil {
		return fmt.Errorf("set %s on %s: %w", XattrName, path, err)
	}
	return nil
}

// Overrides is a package's sd_overrides, indexed by payload path.
type Overrides struct {
	byPath map[string][]byte
}

// New indexes a manifest's overrides. The manifest layer has already
// checked that the list is sorted, free of duplicate paths, and that
// every descriptor parses; the archive layer has already checked that
// each path names a payload entry that is not a symlink. New assumes
// both, because §5.20 requires those checks to have happened before
// anything is installed.
func New(list []manifest.SDOverride) Overrides {
	if len(list) == 0 {
		return Overrides{}
	}
	byPath := make(map[string][]byte, len(list))
	for _, o := range list {
		byPath[o.Path] = o.SD
	}
	return Overrides{byPath: byPath}
}

// Len is the number of overrides held.
func (o Overrides) Len() int { return len(o.byPath) }

// Paths lists the overridden payload paths in lexicographic order.
// §5.20 rule 2 requires a consumer to report every override it applied,
// and this is what it reports.
func (o Overrides) Paths() []string {
	paths := make([]string, 0, len(o.byPath))
	for p := range o.byPath {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	return paths
}

// Apply stamps every override onto its entry, using [Stamp].
func (o Overrides) Apply(locate func(path string) (string, bool)) error {
	return o.ApplyWith(locate, Stamp)
}

// ApplyWith is [Apply] with the stamping step supplied by the caller,
// for a consumer that records the descriptor for someone else to write
// — an image builder handing it to the squashfs writer, say.
//
// locate maps an override's payload path to the on-disk object the
// consumer materialised for it, returning false when it materialised
// none. A miss is an error rather than a skip: the archive layer
// guaranteed the entry exists, so its absence here means the consumer
// and the manifest disagree about what was written, and silently
// leaving an entry with an inherited descriptor is precisely the
// failure §5.20 forbids.
//
// The caller is responsible for ordering: on a consumer that
// materialises a directory before the entries beneath it, ApplyWith
// must run after the whole payload is on disk, or a restrictive
// directory descriptor will deny the consumer its own remaining writes.
func (o Overrides) ApplyWith(locate func(path string) (string, bool),
	stamp func(path string, sd []byte) error) error {
	for _, entry := range o.Paths() {
		path, ok := locate(entry)
		if !ok {
			return fmt.Errorf("sd_override names %q, which the payload did not materialise", entry)
		}
		if err := stamp(path, o.byPath[entry]); err != nil {
			return fmt.Errorf("sd_override %s: %w", entry, err)
		}
	}
	return nil
}
