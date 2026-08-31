package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/peios/peipkg/internal/archive"
	"github.com/peios/peipkg/internal/resolver"
	"golang.org/x/sys/unix"
)

// §7.1.2.2 step 2: disk space is verified before staging. There was no
// free-space check at any level — a repo-wide grep for Statfs returned
// nothing — so exhaustion was discovered when a write failed, at worst
// mid-commit with some files renamed into place and some originals at
// their backup paths (PEI-414).
func TestCheckDiskSpaceRefusesAnOversizedTransaction(t *testing.T) {
	root := t.TempDir()
	pins, err := newPinnedDirs(root)
	if err != nil {
		t.Fatalf("newPinnedDirs: %v", err)
	}
	defer pins.close()

	var st unix.Statfs_t
	if err := unix.Statfs(root, &st); err != nil {
		t.Skipf("statfs is unavailable here: %v", err)
	}
	avail := int64(st.Bavail) * st.Bsize

	ops := []resolver.Operation{{Kind: resolver.OpInstall, Name: "huge"}}
	provided := map[string]ProvidedPackage{
		"huge": {Pkg: &archive.Package{Payload: []archive.PayloadEntry{
			{Path: "usr/bin/huge", Type: archive.EntryFile, Size: avail + spaceMargin + 1},
		}}},
	}
	err = checkDiskSpace(pins, ops, provided)
	if err == nil {
		t.Fatal("a transaction larger than the filesystem was accepted")
	}
	if !strings.Contains(err.Error(), "needs") || !strings.Contains(err.Error(), "free") {
		t.Errorf("error %q does not tell the operator what is short", err)
	}

	// Something that comfortably fits is accepted, so the check is not
	// simply refusing everything.
	provided["huge"].Pkg.Payload[0].Size = 1024
	if err := checkDiskSpace(pins, ops, provided); err != nil {
		t.Errorf("a 1 KiB transaction was refused: %v", err)
	}
}

// A removal consumes no space, so it must not be counted — and neither
// must a directory or a symlink, which have no payload bytes.
func TestCheckDiskSpaceCountsOnlyIncomingFileContent(t *testing.T) {
	root := t.TempDir()
	pins, err := newPinnedDirs(root)
	if err != nil {
		t.Fatalf("newPinnedDirs: %v", err)
	}
	defer pins.close()

	var st unix.Statfs_t
	if err := unix.Statfs(root, &st); err != nil {
		t.Skipf("statfs is unavailable here: %v", err)
	}
	huge := int64(st.Bavail)*st.Bsize + spaceMargin + 1

	// The oversized payload belongs to a package being REMOVED, so it is
	// not incoming content and must not be counted.
	ops := []resolver.Operation{{Kind: resolver.OpRemove, Name: "old"}}
	provided := map[string]ProvidedPackage{
		"old": {Pkg: &archive.Package{Payload: []archive.PayloadEntry{
			{Path: "usr/bin/old", Type: archive.EntryFile, Size: huge},
		}}},
	}
	if err := checkDiskSpace(pins, ops, provided); err != nil {
		t.Errorf("a removal was charged for the space it frees: %v", err)
	}

	// Directories and symlinks carry no bytes.
	ops = []resolver.Operation{{Kind: resolver.OpInstall, Name: "links"}}
	provided = map[string]ProvidedPackage{
		"links": {Pkg: &archive.Package{Payload: []archive.PayloadEntry{
			{Path: "usr/share/thing", Type: archive.EntryDir, Size: huge},
			{Path: "usr/bin/link", Type: archive.EntrySymlink, Size: huge},
		}}},
	}
	if err := checkDiskSpace(pins, ops, provided); err != nil {
		t.Errorf("a directory or symlink was charged for payload bytes: %v", err)
	}
}

// The check groups by filesystem rather than summing globally, because a
// transaction may span several — installation roots can be separate
// mounts, and so can destinations within one root. Without a second
// filesystem to hand, the observable is that one root's requirement is
// measured against that root's own filesystem.
func TestCheckDiskSpaceMeasuresTheDestinationsFilesystem(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "usr/bin"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	pins, err := newPinnedDirs(root)
	if err != nil {
		t.Fatalf("newPinnedDirs: %v", err)
	}
	defer pins.close()

	var st unix.Statfs_t
	if err := unix.Statfs(filepath.Join(root, "usr/bin"), &st); err != nil {
		t.Skipf("statfs is unavailable here: %v", err)
	}
	ops := []resolver.Operation{{Kind: resolver.OpInstall, Name: "p"}}
	provided := map[string]ProvidedPackage{
		"p": {Pkg: &archive.Package{Payload: []archive.PayloadEntry{
			{Path: "usr/bin/p", Type: archive.EntryFile,
				Size: int64(st.Bavail)*st.Bsize + spaceMargin + 1},
		}}},
	}
	if err := checkDiskSpace(pins, ops, provided); err == nil {
		t.Fatal("a payload larger than its destination's filesystem was accepted")
	}
}
