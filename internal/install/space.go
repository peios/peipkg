package install

import (
	"fmt"
	"path/filepath"

	"github.com/peios/peipkg/internal/archive"
	"github.com/peios/peipkg/internal/resolver"
	"golang.org/x/sys/unix"
)

// spaceMargin is the headroom left free above what a transaction needs.
//
// The figure a transaction computes is the sum of the payload it will
// write, and the filesystem needs a little more than that for the
// metadata it writes on the way — inodes, directory entries, journal
// blocks, and the tail padding of every file that does not end on a
// block boundary. Refusing at 32 MiB of remaining headroom rather than
// at zero keeps a transaction from succeeding at staging and then
// failing in the middle of the commit, which is the expensive place.
const spaceMargin = 32 << 20

// checkDiskSpace verifies that every filesystem the transaction writes
// to has room for what will land on it (§7.1.2.2 step 2).
//
// The check is per filesystem, not against one global figure, because a
// transaction may span several: installation roots can be separate
// mounts, and so can destinations within one root. Grouping by the
// filesystem id rather than by path is what makes that work without
// having to know the mount table.
//
// Only added and replaced content counts. A backup is a rename within
// one directory, so it consumes no space, and a removal frees rather
// than consumes. A replaced file's old bytes are not subtracted: they
// are still on disk under the backup name until the commit succeeds,
// which is precisely the moment the space is needed.
func checkDiskSpace(pins *pinnedDirs, ops []resolver.Operation,
	provided map[string]ProvidedPackage) error {

	type need struct {
		bytes int64
		path  string // a representative path, for the error message
	}
	needed := map[uint64]*need{}

	for _, op := range ops {
		if op.Kind == resolver.OpRemove {
			continue
		}
		pp, ok := provided[op.Name]
		if !ok || pp.Pkg == nil {
			continue
		}
		for _, e := range pp.Pkg.Payload {
			if e.Type != archive.EntryFile || e.Size == 0 {
				continue
			}
			physical := filepath.Join(pins.root.Path(), e.Path)
			dir, err := pins.dirFor(physical)
			if err != nil {
				// A destination that cannot be resolved is a problem for
				// the layout and path checks to report, in their own
				// words. Space is not the interesting failure here.
				continue
			}
			var st unix.Statfs_t
			if err := unix.Statfs(dir.Path(), &st); err != nil {
				continue // an unstattable filesystem is not evidence of a shortage
			}
			id := fsid(st)
			n := needed[id]
			if n == nil {
				n = &need{path: dir.Path()}
				needed[id] = n
			}
			n.bytes += e.Size
		}
	}

	for _, n := range needed {
		var st unix.Statfs_t
		if err := unix.Statfs(n.path, &st); err != nil {
			continue
		}
		// Bavail, not Bfree: the reserved blocks are not ours to spend.
		avail := int64(st.Bavail) * st.Bsize
		if avail < n.bytes+spaceMargin {
			return fmt.Errorf(
				"peipkg/install: the filesystem holding %s has %s free but this transaction "+
					"needs %s plus a %s margin; free some space and retry",
				n.path, humanBytes(avail), humanBytes(n.bytes), humanBytes(spaceMargin))
		}
	}
	return nil
}

// fsid folds a statfs filesystem id into one comparable value. Two
// paths on one filesystem share it; two mounts of the same device do
// not necessarily, which is the safe direction — the worst outcome is
// checking one filesystem's requirement twice.
func fsid(st unix.Statfs_t) uint64 {
	return uint64(uint32(st.Fsid.Val[0]))<<32 | uint64(uint32(st.Fsid.Val[1]))
}

// humanBytes renders a byte count for an operator-facing message.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
