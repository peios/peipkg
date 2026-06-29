package compose

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMaterializeUsrMergeLinks(t *testing.T) {
	root := t.TempDir()
	if err := materializeUsrMerge(root, "x86_64"); err != nil {
		t.Fatalf("materializeUsrMerge: %v", err)
	}
	want := map[string]string{
		"bin":   "usr/bin",
		"sbin":  "usr/sbin",
		"lib":   "usr/lib",
		"lib64": "usr/lib/x86_64-linux-peios",
	}
	for name, target := range want {
		got, err := os.Readlink(filepath.Join(root, name))
		if err != nil || got != target {
			t.Errorf("/%s -> %q (err %v), want %q", name, got, err, target)
		}
	}

	// Idempotent: a re-compose over an already-merged root is a no-op, not an
	// error (the live image re-composes constantly).
	if err := materializeUsrMerge(root, "x86_64"); err != nil {
		t.Errorf("second materializeUsrMerge should be a no-op, got: %v", err)
	}
}

func TestMaterializeUsrMergeArchGate(t *testing.T) {
	// /lib64 is x86_64-specific; another arch must not get it (its loader root
	// is named differently and would be added explicitly).
	root := t.TempDir()
	if err := materializeUsrMerge(root, "aarch64"); err != nil {
		t.Fatalf("materializeUsrMerge: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "lib64")); !os.IsNotExist(err) {
		t.Errorf("/lib64 should not be minted on aarch64")
	}
	if _, err := os.Readlink(filepath.Join(root, "bin")); err != nil {
		t.Errorf("/bin merge should exist on every arch: %v", err)
	}
}

func TestMaterializeUsrMergeRefusesClobber(t *testing.T) {
	// A real entry already occupying a legacy root is a hard error, never a
	// silent overwrite — that would mean a package wrote outside /usr.
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "bin", "rogue"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := materializeUsrMerge(root, "x86_64"); err == nil {
		t.Error("expected an error when /bin already exists as a real directory")
	}
}
