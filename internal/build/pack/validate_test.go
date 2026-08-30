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
		{path: "usr/sbin/food", kind: kindFile},
		{path: "usr/lib/x86_64-linux-peios/libfoo.so.1", kind: kindFile},
		{path: "usr/libexec/features/foo/install.sh", kind: kindFile},
		{path: "usr/lib/modules/6.16.0-peios/kernel/fs/ext4/ext4.ko", kind: kindFile},
		{path: "usr/lib/firmware/amdgpu/aldebaran.bin", kind: kindFile},
		{path: "usr/share/doc/foo/README", kind: kindFile},
		{path: "usr/include/foo.h", kind: kindFile},
		{path: "usr/etc/foo/foo.conf", kind: kindFile},
		{path: "usr/conf/foo/foo.conf", kind: kindFile},
		{path: "hooks/mount-root.sh", kind: kindFile},
		{path: "++/microcode/kernel/x86/microcode/GenuineIntel.bin", kind: kindFile},
		{path: "var", kind: kindDir},
	}
	if err := validateEntries("x86_64", leaves); err != nil {
		t.Errorf("expected accept, got: %v", err)
	}
}

// TestValidateRejectsRuntimeMountpoints covers the kernel-interface and
// runtime roots. They were once admitted as bare directories so fsbase
// could ship the mountpoint tree; that carve-out is gone, and a package
// laying down this structure now declares special_system_package and is
// installed with the operator's explicit bypass. Nothing else may write
// here, as a directory or otherwise.
func TestValidateRejectsRuntimeMountpoints(t *testing.T) {
	for _, l := range []entry{
		{path: "proc/version", kind: kindFile},
		{path: "sys/kernel", kind: kindFile},
		{path: "dev/null", kind: kindFile},
		{path: "run/service/socket", kind: kindFile},
		{path: "tmp/file", kind: kindFile},
		{path: "proc", kind: kindDir},
		{path: "sys", kind: kindDir},
		{path: "dev", kind: kindDir},
		{path: "run", kind: kindDir},
		{path: "tmp", kind: kindDir},
	} {
		if err := validateEntries("x86_64", []entry{l}); err == nil {
			t.Errorf("path %q (dir=%v): expected rejection", l.path, l.kind == kindDir)
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

func TestValidateAcceptsOsRelease(t *testing.T) {
	// /usr/lib/os-release is the freedesktop contract path: arch-independent and
	// exempt from the triplet layout, so it is permitted directly under
	// /usr/lib/ even in a noarch package. The compat symlink ships in the vendor
	// config layer (/usr/etc), not /etc — packages never write /etc directly;
	// the merged view projects usr/etc < system/retc < lcl/etc.
	err := validateEntries("noarch", []entry{
		{path: "usr/lib/os-release", kind: kindFile},
		{path: "usr/etc/os-release", kind: kindSymlink, linkTarget: "../lib/os-release"},
	})
	if err != nil {
		t.Errorf("expected accept of os-release + /usr/etc symlink, got: %v", err)
	}
}

func TestValidateAcceptsDebugTree(t *testing.T) {
	// /usr/lib/debug/ holds separated debug information (§3.4.1) mirroring
	// the install paths of the files it describes, plus the build-id index.
	// It is exempt from the §3.4.2 <triplet> requirement.
	leaves := []entry{
		{path: "usr/lib/debug/usr/bin/foo.debug", kind: kindFile},
		{path: "usr/lib/debug/usr/lib/x86_64-linux-peios/libfoo.so.1.debug", kind: kindFile},
		{path: "usr/lib/debug/.build-id/ab/cdef0123.debug", kind: kindFile},
	}
	if err := validateEntries("x86_64", leaves); err != nil {
		t.Errorf("expected accept of /usr/lib/debug/ tree, got: %v", err)
	}
}

func TestValidateRejectsNoarchDebug(t *testing.T) {
	// Debug information is arch-dependent; a noarch package must not ship it.
	err := validateEntries("noarch", []entry{
		{path: "usr/lib/debug/usr/bin/foo.debug", kind: kindFile},
	})
	if err == nil || !strings.Contains(err.Error(), "noarch") || !strings.Contains(err.Error(), "debug") {
		t.Errorf("expected noarch debug rejection, got %v", err)
	}
}

func TestValidateRejectsBareUsrLibDebugFile(t *testing.T) {
	// A file literally named "debug" directly under /usr/lib/ is not the
	// debug tree; it sits bare under /usr/lib/ and is rejected like any
	// other non-triplet entry.
	err := validateEntries("x86_64", []entry{
		{path: "usr/lib/debug", kind: kindFile},
	})
	if err == nil || !strings.Contains(err.Error(), "directly under /usr/lib/") {
		t.Errorf("expected bare /usr/lib/debug rejection, got %v", err)
	}
}

func TestValidateAcceptsSrcDebugTree(t *testing.T) {
	// /usr/src/debug/ holds the debugger source files the debug info
	// references (§3.4.1). Source is architecture-independent, so it carries
	// no triplet and no noarch restriction — both arch and noarch packages
	// may install there.
	for _, arch := range []string{"x86_64", "noarch"} {
		leaves := []entry{
			{path: "usr/src/debug/foo-1.0/main.c", kind: kindFile},
			{path: "usr/src/debug/foo-1.0/include/foo.h", kind: kindFile},
		}
		if err := validateEntries(arch, leaves); err != nil {
			t.Errorf("arch %q: expected accept of /usr/src/debug/ tree, got: %v", arch, err)
		}
	}
}

func TestValidateRejectsNonDebugUsrSrc(t *testing.T) {
	// Only the debug subtree of /usr/src/ is permitted; the rest of
	// /usr/src/ is not a package destination.
	err := validateEntries("x86_64", []entry{
		{path: "usr/src/linux-headers-6.12/Makefile", kind: kindFile},
	})
	if err == nil || !strings.Contains(err.Error(), "§3.4.1") {
		t.Errorf("expected rejection of non-debug /usr/src/ path, got %v", err)
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
		{path: "usr/etc/foo", kind: kindSymlink, linkTarget: "../../../bar"},
	})
	if err == nil {
		t.Errorf("expected rejection of target escaping peipkg tree, got nil")
	}
}

// TestValidateAcceptsSymlinkToSystemFileShape documents the format-level
// gap: a symlink whose resolved path lands inside §3.4.1 destinations
// (here, "usr/etc/passwd") passes format-level validation, even though that
// is typically a system-managed file no peipkg owns. The install-time
// consumer is responsible for catching this via collision detection. See the
// §3.4 informative note covering this case.
func TestValidateAcceptsSymlinkToSystemFileShape(t *testing.T) {
	err := validateEntries("x86_64", []entry{
		{path: "usr/share/foo/link", kind: kindSymlink, linkTarget: "../../etc/passwd"},
	})
	if err != nil {
		t.Errorf("format-level validator should accept syntactically valid vendor-config target; got: %v", err)
	}
}

// TestValidateRejectsOperatorAndDerivedRoots locks in the two top-level
// destinations withdrawn when the Peios filesystem layout was formalised:
// /opt is operator territory and deliberately off this allowlist, and
// /system holds material derived from the image, registry or platform, so
// nothing a package ships belongs there either.
func TestValidateRejectsOperatorAndDerivedRoots(t *testing.T) {
	for _, path := range []string{
		"opt/foo/bin/foo",
		"system/boot/prelude/init",
		"system/retc/foo.conf",
		"lcl/policy/autorun.d/foo.sh",
		"lcl/etc/foo.conf",
		"etc/foo/foo.conf",
	} {
		if err := validateEntries("x86_64", []entry{{path: path, kind: kindFile}}); err == nil {
			t.Errorf("path %q: expected rejection, got nil", path)
		}
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

func TestValidateAcceptsDistSourceTree(t *testing.T) {
	// /usr/src/dist/ holds corresponding-source packages (§3.4.1); the
	// payload is arch-independent, so a noarch package may ship it.
	leaves := []entry{
		{path: "usr/src/dist/dash-0.5.12-2/upstream/dash-0.5.12.tar.gz", kind: kindFile},
		{path: "usr/src/dist/dash-0.5.12-2/recipe/pekit.toml", kind: kindFile},
	}
	if err := validateEntries("noarch", leaves); err != nil {
		t.Errorf("expected accept of /usr/src/dist/ tree, got: %v", err)
	}
}

func TestValidateRejectsBareUsrSrc(t *testing.T) {
	// Only the debug/ and dist/ subtrees of /usr/src are destinations;
	// anything else under /usr/src stays admin territory.
	err := validateEntries("x86_64", []entry{
		{path: "usr/src/foo-1.0/main.c", kind: kindFile},
	})
	if err == nil || !strings.Contains(err.Error(), "usr/src/foo-1.0/main.c") {
		t.Errorf("expected bare /usr/src rejection, got %v", err)
	}
}

// §5.15's positive half: a package whose architecture is not noarch installs
// *all* shared libraries, static libraries and loadable modules under
// /usr/lib/<triplet>/, and a noarch package containing any of them is invalid.
//
// validateLibPath only ever ran for paths already under usr/lib/, so nothing
// looked at file *kind* anywhere else in the tree. These are exactly the files
// that collide across architectures, which is what the triplet convention
// exists to prevent.
func TestValidateRejectsALibraryOutsideTheTripletDirectory(t *testing.T) {
	for _, path := range []string{
		"usr/share/mypkg/libfoo.so",
		"usr/libexec/plugins/bar.so",
		"usr/bin/libbaz.a",
		"usr/share/mypkg/libfoo.so.1",
		"usr/share/mypkg/libfoo.so.1.2.3",
	} {
		err := validateEntries("x86_64", []entry{{path: path, kind: kindFile}})
		if err == nil {
			t.Errorf("expected rejection of %s", path)
		}
	}
}

// A noarch package may not ship one anywhere at all, including in the
// subtrees an arch package is allowed to use.
func TestValidateRejectsALibraryInANoarchPackage(t *testing.T) {
	for _, path := range []string{
		"usr/share/py/_native.so",
		"usr/lib/debug/usr/bin/foo.so",
		"usr/lib/firmware/thing.so",
	} {
		err := validateEntries("noarch", []entry{{path: path, kind: kindFile}})
		if err == nil {
			t.Errorf("expected noarch rejection of %s", path)
		}
	}
}

// The rule must not fire on files merely *named after* a library. Two ship
// today: usr/share/gdb/auto-load/.../libisl.so.23.4.0-gdb.py and the
// libstdc++ equivalent are Python scripts, and a naive `.so.` test rejects
// them.
func TestValidateAcceptsAFileNamedAfterALibrary(t *testing.T) {
	for _, path := range []string{
		"usr/share/gdb/auto-load/usr/lib/x86_64-linux-peios/libisl.so.23.4.0-gdb.py",
		"usr/share/gdb/auto-load/usr/lib/x86_64-linux-peios/libstdc++.so.6.0.35-gdb.py",
		"usr/share/mypkg/notes.so.txt",
		"usr/share/mypkg/libfoo.sources",
	} {
		if err := validateEntries("x86_64", []entry{{path: path, kind: kindFile}}); err != nil {
			t.Errorf("%s should be accepted: %v", path, err)
		}
	}
}

// A symlink is exempt: §5.17 blesses a link whose target resolves into the
// triplet directory, which is the conventional library split. glibc-bin's
// usr/bin/ld.so -> ../lib/<triplet>/ld-linux-x86-64.so.2 is exactly that, and
// it is the one thing in the whole shipped package set this rule would
// otherwise have rejected.
func TestValidateAcceptsASymlinkNamedLikeALibrary(t *testing.T) {
	leaves := []entry{
		{path: "usr/lib/x86_64-linux-peios/ld-linux-x86-64.so.2", kind: kindFile},
		{
			path:       "usr/bin/ld.so",
			kind:       kindSymlink,
			linkTarget: "../lib/x86_64-linux-peios/ld-linux-x86-64.so.2",
		},
	}
	if err := validateEntries("x86_64", leaves); err != nil {
		t.Errorf("the conventional loader symlink should be accepted: %v", err)
	}
}

// A directory used to return before the usr/lib/ checks ran, so a noarch
// package could ship an empty triplet directory and an x86_64 one could ship
// another architecture's. Empty directories only, so the severity is low —
// but it was an unconditional bypass of the rule.
func TestValidateChecksTheTripletOnDirectoriesToo(t *testing.T) {
	if err := validateEntries("noarch", []entry{
		{path: "usr/lib/x86_64-linux-peios/foo", kind: kindDir},
	}); err == nil {
		t.Error("a noarch package shipping a triplet directory should be rejected")
	}
	if err := validateEntries("x86_64", []entry{
		{path: "usr/lib/aarch64-linux-peios", kind: kindDir},
	}); err == nil {
		t.Error("an x86_64 package shipping another architecture's directory should be rejected")
	}
}

// sigBlob is a well-formed signature blob: the version byte and 3309
// bytes of (here, zero) signature.
func sigBlob() []byte {
	b := make([]byte, 3310)
	b[0] = 0x01
	return b
}

func TestValidateSidecarStructure(t *testing.T) {
	// Structural rules, with no sources: the shape of an install-time check.
	ok := []entry{
		{path: "usr/lib/firmware/fw.bin.zst", kind: kindFile},
		{path: "usr/lib/firmware/fw.bin.zst.peios.sig", kind: kindFile},
	}
	if err := validateEntries("noarch", ok); err != nil {
		t.Errorf("well-formed sidecar rejected: %v", err)
	}
	for name, leaves := range map[string][]entry{
		"missing target": {
			{path: "usr/lib/firmware/fw.bin.zst.peios.sig", kind: kindFile},
		},
		"symlink target": {
			{path: "usr/lib/firmware/fw.bin.zst", kind: kindSymlink, linkTarget: "real.bin.zst"},
			{path: "usr/lib/firmware/real.bin.zst", kind: kindFile},
			{path: "usr/lib/firmware/fw.bin.zst.peios.sig", kind: kindFile},
		},
		"directory target": {
			{path: "usr/lib/firmware/fw", kind: kindDir},
			{path: "usr/lib/firmware/fw.peios.sig", kind: kindFile},
		},
		"sidecar is a symlink": {
			{path: "usr/lib/firmware/fw.bin.zst", kind: kindFile},
			{path: "usr/lib/firmware/fw.bin.zst.peios.sig", kind: kindSymlink, linkTarget: "other.peios.sig"},
			{path: "usr/lib/firmware/other.peios.sig", kind: kindFile},
			{path: "usr/lib/firmware/other", kind: kindFile},
		},
	} {
		if err := validateEntries("noarch", leaves); err == nil {
			t.Errorf("%s: accepted", name)
		} else if !strings.Contains(err.Error(), "sidecar") {
			t.Errorf("%s: wrong error: %v", name, err)
		}
	}
}

func TestValidateSidecarContent(t *testing.T) {
	// Content rules need sources: the pack-time path through ValidatePayload.
	stage := func(t *testing.T, target, sidecar []byte) string {
		dir := t.TempDir()
		fw := filepath.Join(dir, "usr/lib/firmware")
		if err := os.MkdirAll(fw, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(fw, "fw.bin.zst"), target, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(fw, "fw.bin.zst.peios.sig"), sidecar, 0o644); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	if err := ValidatePayload("noarch", stage(t, []byte("blob"), sigBlob())); err != nil {
		t.Errorf("well-formed payload rejected: %v", err)
	}
	if err := ValidatePayload("noarch", stage(t, []byte("blob"), sigBlob()[:100])); err == nil ||
		!strings.Contains(err.Error(), "3310") {
		t.Errorf("short blob: %v", err)
	}
	bad := sigBlob()
	bad[0] = 0x7f
	if err := ValidatePayload("noarch", stage(t, []byte("blob"), bad)); err == nil ||
		!strings.Contains(err.Error(), "version") {
		t.Errorf("wrong version byte: %v", err)
	}
	if err := ValidatePayload("noarch", stage(t, []byte("\x7fELF\x02\x01\x01"), sigBlob())); err == nil ||
		!strings.Contains(err.Error(), "ELF") {
		t.Errorf("ELF target: %v", err)
	}
}
