package safepath_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/peios/peipkg/internal/safepath"
)

func openRoot(t *testing.T) (*safepath.Root, string) {
	t.Helper()
	dir := t.TempDir()
	r, err := safepath.OpenRoot(dir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r, dir
}

// The condition the whole package exists for: an ancestor that is a
// symlink ends the walk instead of redirecting it.
func TestWalkRefusesASymlinkAncestor(t *testing.T) {
	r, dir := openRoot(t)
	if err := os.MkdirAll(filepath.Join(dir, "usr/bin"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "usr/share"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// The first package's contribution: a valid symlink whose target
	// lexically resolves under a permitted destination.
	if err := os.Symlink("../bin", filepath.Join(dir, "usr/share/a")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	// The second package's: a regular file under usr/share/, also valid.
	// Resolving its parent must refuse rather than land in usr/bin.
	_, err := r.Dir("usr/share/a")
	if !errors.Is(err, safepath.ErrSymlinkComponent) {
		t.Fatalf("Dir through a symlink ancestor = %v, want ErrSymlinkComponent", err)
	}

	// MkdirAll must not paper over it by "creating" the directory either.
	if _, err := r.MkdirAll("usr/share/a", 0o755); !errors.Is(err, safepath.ErrSymlinkComponent) {
		t.Fatalf("MkdirAll through a symlink ancestor = %v, want ErrSymlinkComponent", err)
	}
}

// A symlink to a directory is still a symlink. This is the case that
// looks harmless and is not: it resolves, so a string-based walk sees a
// perfectly good directory.
func TestWalkRefusesASymlinkToARealDirectory(t *testing.T) {
	r, dir := openRoot(t)
	if err := os.MkdirAll(filepath.Join(dir, "real/sub"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Symlink("real", filepath.Join(dir, "link")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if _, err := r.Dir("link/sub"); !errors.Is(err, safepath.ErrSymlinkComponent) {
		t.Fatalf("Dir through a directory symlink = %v, want ErrSymlinkComponent", err)
	}
	if _, err := r.Dir("real/sub"); err != nil {
		t.Fatalf("Dir through real directories: %v", err)
	}
}

func TestWalkRejectsEscapingComponents(t *testing.T) {
	r, _ := openRoot(t)
	for _, rel := range []string{"../etc", "usr/../../etc", "usr/./../.."} {
		if _, err := r.Dir(rel); err == nil {
			t.Errorf("Dir(%q) resolved a path leaving the root", rel)
		}
	}
}

func TestMkdirAllAndFileOperations(t *testing.T) {
	r, root := openRoot(t)
	d, err := r.MkdirAll("usr/bin", 0o755)
	if err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	defer d.Close()

	f, err := d.Create("nginx.staged", 0o755)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := f.WriteString("binary"); err != nil {
		t.Fatalf("write: %v", err)
	}
	f.Close()

	// A second Create over the same name fails: O_EXCL is what makes the
	// file that ends up open the one this call made.
	if _, err := d.Create("nginx.staged", 0o755); err == nil {
		t.Error("Create overwrote an existing name")
	}

	if err := d.Rename("nginx.staged", "nginx"); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(root, "usr/bin/nginx"))
	if err != nil || string(got) != "binary" {
		t.Fatalf("after rename: %q (err %v)", got, err)
	}

	if err := d.Symlink("nginx", "nginx-latest"); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	if target, err := d.Readlink("nginx-latest"); err != nil || target != "nginx" {
		t.Errorf("Readlink = %q (err %v)", target, err)
	}
	if !d.Exists("nginx-latest") {
		t.Error("Exists is false for a symlink that is present")
	}
	if err := d.Remove("nginx-latest"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if d.Exists("nginx-latest") {
		t.Error("Exists is true after Remove")
	}
}

// A pinned descriptor keeps pointing at the directory it opened, even
// after the name that reached it has been made to mean something else.
// That is the whole TOCTOU defence: the plan and the commit act on the
// same directory, not on the same string.
func TestPinnedDirectorySurvivesTheNameBeingRepointed(t *testing.T) {
	r, root := openRoot(t)
	d, err := r.MkdirAll("usr/bin", 0o755)
	if err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	defer d.Close()

	// Between the plan and the commit, the name usr/bin is made to mean
	// the attacker's directory instead. A string-based write would
	// follow it; the pinned descriptor still refers to the directory it
	// opened, which is now reachable as usr/bin.real.
	if err := os.MkdirAll(filepath.Join(root, "attacker"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Rename(filepath.Join(root, "usr/bin"),
		filepath.Join(root, "usr/bin.real")); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if err := os.Symlink("../attacker", filepath.Join(root, "usr/bin")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	f, err := d.Create("nginx", 0o755)
	if err != nil {
		t.Fatalf("Create through the pinned descriptor: %v", err)
	}
	f.Close()

	if _, err := os.Lstat(filepath.Join(root, "attacker/nginx")); err == nil {
		t.Fatal("the write was redirected into the attacker's directory")
	}
	if _, err := os.Lstat(filepath.Join(root, "usr/bin.real/nginx")); err != nil {
		t.Errorf("the write did not land in the pinned directory: %v", err)
	}

	// And a fresh resolution of the repointed name is refused outright,
	// rather than quietly resolving into the attacker's tree.
	if _, err := r.Dir("usr/bin"); !errors.Is(err, safepath.ErrSymlinkComponent) {
		t.Errorf("re-resolving the repointed name = %v, want ErrSymlinkComponent", err)
	}
}

func TestSplit(t *testing.T) {
	for in, want := range map[string][2]string{
		"usr/bin/nginx": {"usr/bin", "nginx"},
		"nginx":         {"", "nginx"},
		"/usr/bin/x":    {"usr/bin", "x"},
	} {
		dir, base := safepath.Split(in)
		if dir != want[0] || base != want[1] {
			t.Errorf("Split(%q) = (%q, %q), want %v", in, dir, base, want)
		}
	}
}
