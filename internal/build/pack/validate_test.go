package pack

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateAcceptsPermittedPaths(t *testing.T) {
	leaves := []entry{
		{path: "usr/bin/foo", kind: kindFile},
		{path: "usr/lib/x86_64-linux-peios/libfoo.so.1", kind: kindFile},
		{path: "usr/share/doc/foo/README", kind: kindFile},
		{path: "usr/include/foo.h", kind: kindFile},
		{path: "etc/foo/foo.conf", kind: kindFile},
		{path: "opt/foo/bin/foo", kind: kindFile},
		{path: "system/boot/prelude/init", kind: kindFile},
		{path: "var", kind: kindDir},
		{path: "proc", kind: kindDir},
		{path: "sys", kind: kindDir},
		{path: "dev", kind: kindDir},
		{path: "run", kind: kindDir},
		{path: "tmp", kind: kindDir},
	}
	if err := validateEntries("x86_64", leaves); err != nil {
		t.Errorf("expected accept, got: %v", err)
	}
}

func TestValidateRejectsPopulatedRuntimeMountpoint(t *testing.T) {
	for _, path := range []string{
		"proc/version",
		"sys/kernel",
		"dev/null",
		"run/service/socket",
		"tmp/file",
	} {
		err := validateEntries("x86_64", []entry{{path: path, kind: kindFile}})
		if err == nil {
			t.Errorf("path %q: expected rejection for populated runtime mountpoint", path)
		}
	}
}

func TestValidateRejectsForbiddenTopLevel(t *testing.T) {
	for _, path := range []string{
		"home/user/foo",
		"tmp/foo",
		"srv/data/foo",
		"usr/local/bin/foo",
		"lib/foo.so",
		"sbin/foo",
	} {
		err := validateEntries("x86_64", []entry{{path: path, kind: kindFile}})
		if err == nil {
			t.Errorf("path %q: expected rejection (not under §3.4.1 destinations)", path)
		}
	}
}

func TestValidateRejectsPopulatedVar(t *testing.T) {
	err := validateEntries("x86_64", []entry{{path: "var/log/foo/seed.log", kind: kindFile}})
	if err == nil || !strings.Contains(err.Error(), "/var/") {
		t.Errorf("expected rejection mentioning /var/, got %v", err)
	}
}

func TestValidateRejectsNoarchTriplet(t *testing.T) {
	err := validateEntries("noarch", []entry{
		{path: "usr/lib/x86_64-linux-peios/libfoo.so.1", kind: kindFile},
	})
	if err == nil || !strings.Contains(err.Error(), "noarch") {
		t.Errorf("expected noarch rejection, got %v", err)
	}
}

func TestValidateRejectsWrongTriplet(t *testing.T) {
	err := validateEntries("x86_64", []entry{
		{path: "usr/lib/aarch64-linux-peios/libfoo.so.1", kind: kindFile},
	})
	if err == nil || !strings.Contains(err.Error(), "triplet") {
		t.Errorf("expected wrong-triplet rejection, got %v", err)
	}
}

func TestValidateRejectsBareUsrLib(t *testing.T) {
	err := validateEntries("x86_64", []entry{
		{path: "usr/lib/foo.so", kind: kindFile},
	})
	if err == nil || !strings.Contains(err.Error(), "directly under /usr/lib/") {
		t.Errorf("expected /usr/lib direct rejection, got %v", err)
	}
}

func TestValidateAcceptsBootSymlinkAndFile(t *testing.T) {
	// /boot/ is a §3.4.1 permitted destination admitting both real files
	// and symlinks. The SHOULD-be-symlinks rule (§3.4.1) is not enforced
	// at format-validation time. The canonical kernel-package pattern:
	// real bzImage under /usr/lib/<triplet>/, /boot/ symlink for
	// bootloader discovery.
	leaves := []entry{
		{path: "usr/lib/x86_64-linux-peios/kernel/vmlinuz", kind: kindFile},
		{path: "boot/vmlinuz", kind: kindSymlink, linkTarget: "../usr/lib/x86_64-linux-peios/kernel/vmlinuz"},
	}
	if err := validateEntries("x86_64", leaves); err != nil {
		t.Errorf("expected accept of boot symlink + canonical file, got: %v", err)
	}
}

func TestValidateAcceptsInTreeSymlink(t *testing.T) {
	leaves := []entry{
		{path: "usr/lib/x86_64-linux-peios/libfoo.so.1.2.3", kind: kindFile},
		{path: "usr/lib/x86_64-linux-peios/libfoo.so.1", kind: kindSymlink, linkTarget: "libfoo.so.1.2.3"},
	}
	if err := validateEntries("x86_64", leaves); err != nil {
		t.Errorf("expected accept, got: %v", err)
	}
}

func TestValidateAcceptsCrossPackageSymlink(t *testing.T) {
	// A -dev package's libfoo.so points at libfoo.so.1 in the runtime
	// package. Resolved target lands under /usr/lib/<triplet>/, which is
	// a §3.4.1 permitted destination — accept.
	leaves := []entry{
		{
			path:       "usr/lib/x86_64-linux-peios/libfoo.so",
			kind:       kindSymlink,
			linkTarget: "libfoo.so.1",
		},
	}
	if err := validateEntries("x86_64", leaves); err != nil {
		t.Errorf("expected accept of cross-package symlink, got: %v", err)
	}
}

func TestValidateRejectsAbsoluteSymlinkTarget(t *testing.T) {
	err := validateEntries("x86_64", []entry{
		{path: "usr/share/bad/link", kind: kindSymlink, linkTarget: "/etc/passwd"},
	})
	if err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Errorf("expected absolute-target rejection, got %v", err)
	}
}

func TestValidateRejectsSymlinkEscapingPeipkgTree(t *testing.T) {
	// Resolved target lands above the peipkg-managed root entirely
	// (path.Join produces "../foo"). This is the strongest escape: not
	// just outside §3.4.1, but outside the entire relative root.
	err := validateEntries("x86_64", []entry{
		{path: "etc/foo", kind: kindSymlink, linkTarget: "../../../bar"},
	})
	if err == nil {
		t.Errorf("expected rejection of target escaping peipkg tree, got nil")
	}
}

// TestValidateAcceptsSymlinkToSystemFileShape documents the format-level
// gap: a symlink whose resolved path lands inside §3.4.1 destinations
// (here, "etc/passwd") passes format-level validation, even though
// /etc/passwd is typically a system-managed file no peipkg owns. The
// install-time consumer is responsible for catching this via collision
// detection. See the §3.4 informative note covering this case.
func TestValidateAcceptsSymlinkToSystemFileShape(t *testing.T) {
	err := validateEntries("x86_64", []entry{
		{path: "usr/share/foo/link", kind: kindSymlink, linkTarget: "../../../etc/passwd"},
	})
	if err != nil {
		t.Errorf("format-level validator should accept syntactically valid /etc/-relative target; got: %v", err)
	}
}

func TestValidateRejectsSymlinkOutsidePermittedDest(t *testing.T) {
	// Resolved target lands at "tmp/whatever" — not under §3.4.1.
	err := validateEntries("x86_64", []entry{
		{path: "usr/share/foo/link", kind: kindSymlink, linkTarget: "../../../tmp/whatever"},
	})
	if err == nil {
		t.Errorf("expected rejection of out-of-tree resolution, got nil")
	}
}

func TestValidateAggregatesErrors(t *testing.T) {
	// Two distinct violations should both appear in the error message,
	// so a producer can fix everything in one pass.
	err := validateEntries("noarch", []entry{
		{path: "var/log/foo.log", kind: kindFile},
		{path: "usr/lib/x86_64-linux-peios/libfoo.so", kind: kindFile},
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "/var/") {
		t.Errorf("aggregate error missing /var/ violation:\n%s", msg)
	}
	if !strings.Contains(msg, "noarch") {
		t.Errorf("aggregate error missing noarch violation:\n%s", msg)
	}
}

// TestValidatePayloadWalksDisk exercises the disk-walking wrapper: the
// staged tree's symlink targets must be read back and validated.
func TestValidatePayloadWalksDisk(t *testing.T) {
	root := t.TempDir()
	libDir := filepath.Join(root, "usr", "lib", "x86_64-linux-peios")
	if err := os.MkdirAll(libDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(libDir, "libfoo.so.1"), []byte("elf"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := ValidatePayload("x86_64", root); err != nil {
		t.Errorf("expected accept, got %v", err)
	}

	if err := os.Symlink("/etc/passwd", filepath.Join(libDir, "evil")); err != nil {
		t.Fatal(err)
	}
	err := ValidatePayload("x86_64", root)
	if err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Errorf("expected absolute-symlink rejection from disk walk, got %v", err)
	}
}

// TestValidateFilesMapsDisk exercises the file-map wrapper: kinds come
// from lstat of the mapped sources, and the §3.4 checks run against the
// archive paths, not the source layout.
func TestValidateFilesMapsDisk(t *testing.T) {
	root := t.TempDir()
	good := filepath.Join(root, "build-output")
	if err := os.WriteFile(good, []byte("elf"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := ValidateFiles("x86_64", map[string]string{
		"usr/bin/foo": good,
	}); err != nil {
		t.Errorf("expected accept, got %v", err)
	}

	// Same source, forbidden destination.
	err := ValidateFiles("x86_64", map[string]string{
		"usr/local/bin/foo": good,
	})
	if err == nil {
		t.Error("expected §3.4.1 rejection for usr/local destination, got nil")
	}
}
