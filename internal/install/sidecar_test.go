package install_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/peios/peipkg/internal/install"
	"github.com/peios/peipkg/internal/pipsig"
	"github.com/peios/peipkg/internal/resolver"
)

// sigBlob is a well-formed signature blob as a string, for testPkg's
// path -> content map.
func sigBlob() string {
	b := make([]byte, pipsig.BlobLen)
	b[0] = pipsig.Version
	return string(b)
}

// TestExecuteInstallStampsSidecars: a `<file>.peios.sig` payload entry is
// stamped onto its target's security.peios.sig attribute — on the staged
// inode, before the commit rename — and is neither installed nor
// recorded. Stamp is replaced by a recorder because security.* attributes
// need CAP_SYS_ADMIN, which the test process lacks.
func TestExecuteInstallStampsSidecars(t *testing.T) {
	ctx := t.Context()
	store, root, lock := freshEnv(t)
	fw := testPkg{
		name: "fw", version: "1.0-1",
		files: map[string]string{
			"usr/lib/firmware/fw.bin.zst":           "firmware bytes",
			"usr/lib/firmware/fw.bin.zst.peios.sig": sigBlob(),
		},
	}
	stamped := map[string][]byte{}
	orig := pipsig.Stamp
	pipsig.Stamp = func(path string, b []byte) error {
		// Staged sibling, not the final path: the rename comes later.
		if filepath.Base(path) == "fw.bin.zst" {
			t.Errorf("stamped the final path %s rather than the staged file", path)
		}
		if _, err := os.Stat(path); err != nil {
			t.Errorf("stamped path does not exist: %v", err)
		}
		stamped[filepath.Base(path)] = b
		return nil
	}
	t.Cleanup(func() { pipsig.Stamp = orig })

	env := install.Env{
		Root: root, DB: store, LockPath: lock, PeipkgVersion: "0.1.0-test",
		Provider: fakeProvider{"fw": provide(t, fw)},
	}
	plan := resolver.Plan{Operations: []resolver.Operation{installOp(t, "fw", "1.0-1")}}
	if _, err := install.Execute(ctx, plan, env); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	target := filepath.Join(root, "usr/lib/firmware/fw.bin.zst")
	if got, err := os.ReadFile(target); err != nil || string(got) != "firmware bytes" {
		t.Errorf("target: content %q, err %v", got, err)
	}
	if len(stamped) != 1 {
		t.Fatalf("stamped %d files, want 1: %v", len(stamped), stamped)
	}
	for _, b := range stamped {
		if !bytes.Equal(b, []byte(sigBlob())) {
			t.Errorf("stamped bytes are not the blob")
		}
	}
	if _, err := os.Lstat(target + pipsig.Suffix); !os.IsNotExist(err) {
		t.Errorf("sidecar was materialised (err %v)", err)
	}
	files, err := store.PackageFiles(ctx, "fw")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0].Path != "/usr/lib/firmware/fw.bin.zst" {
		t.Errorf("package files = %+v, want only the target", files)
	}
}

// TestExecuteInstallRejectsOrphanSidecar: a sidecar without a target is
// refused at the layout check, before anything is staged.
func TestExecuteInstallRejectsOrphanSidecar(t *testing.T) {
	ctx := t.Context()
	store, root, lock := freshEnv(t)
	fw := testPkg{
		name: "fw", version: "1.0-1",
		files: map[string]string{"usr/lib/firmware/fw.bin.zst.peios.sig": sigBlob()},
	}
	env := install.Env{
		Root: root, DB: store, LockPath: lock, PeipkgVersion: "0.1.0-test",
		Provider: fakeProvider{"fw": provide(t, fw)},
	}
	plan := resolver.Plan{Operations: []resolver.Operation{installOp(t, "fw", "1.0-1")}}
	_, err := install.Execute(ctx, plan, env)
	if err == nil || !strings.Contains(err.Error(), "sidecar") {
		t.Errorf("orphan sidecar: err = %v", err)
	}
}

// TestExecuteInstallRejectsMalformedSidecar: a blob of the wrong shape is
// refused while staging; the transaction rolls back and nothing lands.
func TestExecuteInstallRejectsMalformedSidecar(t *testing.T) {
	ctx := t.Context()
	store, root, lock := freshEnv(t)
	fw := testPkg{
		name: "fw", version: "1.0-1",
		files: map[string]string{
			"usr/lib/firmware/fw.bin.zst":           "firmware bytes",
			"usr/lib/firmware/fw.bin.zst.peios.sig": "not a blob",
		},
	}
	env := install.Env{
		Root: root, DB: store, LockPath: lock, PeipkgVersion: "0.1.0-test",
		Provider: fakeProvider{"fw": provide(t, fw)},
	}
	plan := resolver.Plan{Operations: []resolver.Operation{installOp(t, "fw", "1.0-1")}}
	_, err := install.Execute(ctx, plan, env)
	if err == nil || !strings.Contains(err.Error(), "3310") {
		t.Errorf("malformed sidecar: err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "usr/lib/firmware/fw.bin.zst")); !os.IsNotExist(err) {
		t.Errorf("target landed despite the refusal (err %v)", err)
	}
}
