package install_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/peios/peipkg/internal/install"
	"github.com/peios/peipkg/internal/resolver"
)

// The attack PSPU §5.26 exists to prevent, and it needs no race at all.
//
// Two packages, each individually valid. The first ships a symlink whose
// target lexically resolves under a permitted destination. The second
// ships a regular file under a permitted destination whose *ancestor* is
// that symlink. Nothing rejected either, so the second package's bytes
// landed on /usr/bin/sshd: the collision index never fired because the
// recorded path and the real path differed, and uninstalling the second
// package would have renamed the victim's binary aside as its own
// (PEI-375).
func TestASymlinkAncestorCannotRedirectAWrite(t *testing.T) {
	ctx := t.Context()
	store, root, lock := freshEnv(t)

	// The victim: a package owning /usr/bin/sshd.
	victim := testPkg{name: "openssh", version: "1.0-1",
		files: map[string]string{"usr/bin/sshd": "the real sshd"}}
	// --overwrite-unowned is on throughout so that what is under test is
	// the path resolution and not the §7.1.5 unowned-file policy, which
	// happens to refuse this particular payload for a different reason:
	// through the symlink, the destination looks like an unowned file
	// with differing content. With the authorisation granted, the
	// unfixed code goes ahead and lands the bytes on the victim.
	env := install.Env{Root: root, DB: store, LockPath: lock, PeipkgVersion: "test",
		Provider:         fakeProvider{"openssh": provide(t, victim)},
		OverwriteUnowned: true}
	if _, err := install.Execute(ctx,
		resolver.Plan{Operations: []resolver.Operation{installOp(t, "openssh", "1.0-1")}},
		env); err != nil {
		t.Fatalf("installing the victim: %v", err)
	}

	// P1: the planted ancestor. usr/share/a -> ../bin resolves to
	// usr/bin, which is a permitted destination, so the link is valid.
	planter := testPkg{name: "planter", version: "1.0-1",
		dirs:     []string{"usr/share"},
		symlinks: map[string]string{"usr/share/a": "../bin"}}
	env.Provider = fakeProvider{"planter": provide(t, planter)}
	if _, err := install.Execute(ctx,
		resolver.Plan{Operations: []resolver.Operation{installOp(t, "planter", "1.0-1")}},
		env); err != nil {
		t.Fatalf("installing the planter: %v", err)
	}

	// P2: a regular file under usr/share/, also valid on its face.
	attacker := testPkg{name: "attacker", version: "1.0-1",
		files: map[string]string{"usr/share/a/sshd": "the attacker's sshd"}}
	env.Provider = fakeProvider{"attacker": provide(t, attacker)}
	_, err := install.Execute(ctx,
		resolver.Plan{Operations: []resolver.Operation{installOp(t, "attacker", "1.0-1")}}, env)
	if err == nil {
		t.Fatal("a payload entry whose ancestor is a symlink was installed")
	}
	if !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("error %q does not say the component was refused as a non-directory", err)
	}

	// The victim's binary is untouched, and nothing landed through the link.
	got, err := os.ReadFile(filepath.Join(root, "usr/bin/sshd"))
	if err != nil {
		t.Fatalf("the victim's binary is gone: %v", err)
	}
	if string(got) != "the real sshd" {
		t.Errorf("the victim's binary now holds %q", got)
	}
}

// The same defence, at the leaf rather than the ancestor: a payload
// entry landing exactly where a symlink already sits must not be written
// through it either.
func TestAPayloadFileIsNotWrittenThroughALeafSymlink(t *testing.T) {
	ctx := t.Context()
	store, root, lock := freshEnv(t)

	// An operator-planted symlink at the destination, pointing outside.
	outside := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(outside, []byte("do not clobber"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "usr/bin"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "usr/bin/tool")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	pkg := testPkg{name: "tool", version: "1.0-1",
		files: map[string]string{"usr/bin/tool": "the package's tool"}}
	env := install.Env{Root: root, DB: store, LockPath: lock, PeipkgVersion: "test",
		Provider:         fakeProvider{"tool": provide(t, pkg)},
		OverwriteUnowned: true, // the unowned-file policy is not what is under test
	}
	if _, err := install.Execute(ctx,
		resolver.Plan{Operations: []resolver.Operation{installOp(t, "tool", "1.0-1")}},
		env); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	// The symlink was displaced, not followed: the file outside the root
	// still holds what it held.
	if got, err := os.ReadFile(outside); err != nil || string(got) != "do not clobber" {
		t.Errorf("the symlink's target was written through: %q (err %v)", got, err)
	}
	if got, err := os.ReadFile(filepath.Join(root, "usr/bin/tool")); err != nil ||
		string(got) != "the package's tool" {
		t.Errorf("the package's content did not land: %q (err %v)", got, err)
	}
}
