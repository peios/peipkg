package install_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/peios/peipkg/internal/install"
	"github.com/peios/peipkg/internal/resolver"
	"github.com/peios/peipkg/internal/sdstamp"
)

// allowAll and refuseAll are the two ends of the §5.20 policy.
func allowAll(string) bool  { return true }
func refuseAll(string) bool { return false }

// recordStamps replaces sdstamp.Stamp with a recorder. security.*
// attributes need CAP_SYS_ADMIN, which the test process lacks, so the
// real stamp cannot run here — the same reason pipsig.Stamp is a
// variable.
func recordStamps(t *testing.T) map[string][]byte {
	t.Helper()
	stamped := map[string][]byte{}
	orig := sdstamp.Stamp
	sdstamp.Stamp = func(path string, sd []byte) error {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("stamped a path that does not exist: %v", err)
		}
		stamped[path] = sd
		return nil
	}
	t.Cleanup(func() { sdstamp.Stamp = orig })
	return stamped
}

// TestExecuteInstallAppliesSDOverrides: a declared override reaches the
// object the payload materialised — a regular file on its staged inode
// before the commit rename, a directory at its final path — and an
// entry with no override is not stamped at all, so the kernel derives
// its descriptor by inheritance (§5.20's default).
func TestExecuteInstallAppliesSDOverrides(t *testing.T) {
	ctx := t.Context()
	store, root, lock := freshEnv(t)
	pkg := testPkg{
		name: "fsbase", version: "1.0-1",
		dirs:  []string{"usr/share/scoped", "usr/share/plainly"},
		files: map[string]string{"usr/bin/tool": "a tool", "usr/bin/plain": "no override"},
		sdOverrides: map[string]string{
			"usr/share/scoped": "descriptor for the directory",
			"usr/bin/tool":     "descriptor for the tool",
		},
	}
	stamped := recordStamps(t)

	env := install.Env{
		Root: root, DB: store, LockPath: lock, PeipkgVersion: "0.1.0-test",
		Provider:         fakeProvider{"fsbase": provide(t, pkg)},
		SDOverridePolicy: allowAll,
	}
	plan := resolver.Plan{Operations: []resolver.Operation{installOp(t, "fsbase", "1.0-1")}}
	result, err := install.Execute(ctx, plan, env)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	// A directory has no staged sibling; it is created and stamped at
	// its final path.
	scoped := filepath.Join(root, "usr/share/scoped")
	if got := string(stamped[scoped]); got != "descriptor for the directory" {
		t.Errorf("directory usr/share/scoped: stamped %q, want the declared descriptor", got)
	}

	// A regular file is stamped on the staged inode, so exactly one
	// stamped path must end in the file's name without being it.
	var toolStamp string
	for path, sd := range stamped {
		if strings.Contains(filepath.Base(path), "tool") {
			toolStamp = path
			if string(sd) != "descriptor for the tool" {
				t.Errorf("usr/bin/tool: stamped %q", sd)
			}
		}
	}
	if toolStamp == "" {
		t.Fatal("usr/bin/tool was never stamped")
	}
	if toolStamp == filepath.Join(root, "usr/bin/tool") {
		t.Errorf("stamped the final path %s rather than the staged sibling", toolStamp)
	}

	// The un-overridden entries are untouched: nothing may stamp an
	// entry the package did not declare one for, or inheritance stops
	// being the default.
	for path := range stamped {
		base := filepath.Base(path)
		if strings.Contains(base, "plain") {
			t.Errorf("stamped %s, which declared no override", path)
		}
	}
	if len(stamped) != 2 {
		t.Errorf("stamped %d objects, want 2: %v", len(stamped), stamped)
	}

	// §5.20 rule 2: the install report lists every override applied.
	want := []string{"fsbase: /usr/bin/tool", "fsbase: /usr/share/scoped"}
	if len(result.SDOverrides) != len(want) {
		t.Fatalf("result.SDOverrides = %v, want %v", result.SDOverrides, want)
	}
	for i, w := range want {
		if result.SDOverrides[i] != w {
			t.Errorf("result.SDOverrides[%d] = %q, want %q", i, result.SDOverrides[i], w)
		}
	}

	// The payload still installed normally.
	if got, err := os.ReadFile(filepath.Join(root, "usr/bin/tool")); err != nil ||
		string(got) != "a tool" {
		t.Errorf("installed file: content %q err %v", got, err)
	}
}

// TestExecuteRefusesSDOverridesFromADisallowedRepo: §5.20 requires a
// package whose overrides the policy rejects to be refused outright.
// Installing it with the overrides silently dropped — the behaviour
// before PEI-557 — is the one outcome the spec names and forbids.
func TestExecuteRefusesSDOverridesFromADisallowedRepo(t *testing.T) {
	ctx := t.Context()
	store, root, lock := freshEnv(t)
	pkg := testPkg{
		name: "greedy", version: "1.0-1",
		files:       map[string]string{"usr/bin/greedy": "a binary"},
		sdOverrides: map[string]string{"usr/bin/greedy": "a descriptor"},
	}
	env := install.Env{
		Root: root, DB: store, LockPath: lock, PeipkgVersion: "0.1.0-test",
		Provider:         fakeProvider{"greedy": provide(t, pkg)},
		SDOverridePolicy: refuseAll,
	}
	plan := resolver.Plan{Operations: []resolver.Operation{installOp(t, "greedy", "1.0-1")}}

	_, err := install.Execute(ctx, plan, env)
	if err == nil {
		t.Fatal("Execute succeeded; a package carrying refused overrides must not install")
	}
	if !strings.Contains(err.Error(), "allow_sd_overrides") {
		t.Errorf("error does not tell the operator how to permit it: %v", err)
	}
	// Refused before anything was staged.
	if _, statErr := os.Stat(filepath.Join(root, "usr/bin/greedy")); statErr == nil {
		t.Error("the payload was installed despite the refusal")
	}
}

// TestExecuteRefusesSDOverridesWhenNoPolicyIsSet: a nil policy is not
// "no opinion", it is "no". A caller that never considered the question
// must not thereby let packages set access control.
func TestExecuteRefusesSDOverridesWhenNoPolicyIsSet(t *testing.T) {
	ctx := t.Context()
	store, root, lock := freshEnv(t)
	pkg := testPkg{
		name: "greedy", version: "1.0-1",
		files:       map[string]string{"usr/bin/greedy": "a binary"},
		sdOverrides: map[string]string{"usr/bin/greedy": "a descriptor"},
	}
	env := install.Env{
		Root: root, DB: store, LockPath: lock, PeipkgVersion: "0.1.0-test",
		Provider: fakeProvider{"greedy": provide(t, pkg)},
	}
	plan := resolver.Plan{Operations: []resolver.Operation{installOp(t, "greedy", "1.0-1")}}
	if _, err := install.Execute(ctx, plan, env); err == nil {
		t.Fatal("Execute succeeded with a nil SDOverridePolicy")
	}
}

// TestExecuteAllowsAnOverrideFreePackageFromADisallowedRepo: the policy
// gates declaring descriptors, not installing. Refusing every package
// from a repository that has not been vouched for would be a different
// and much larger rule than §5.20 states.
func TestExecuteAllowsAnOverrideFreePackageFromADisallowedRepo(t *testing.T) {
	ctx := t.Context()
	store, root, lock := freshEnv(t)
	pkg := testPkg{name: "quiet", version: "1.0-1",
		files: map[string]string{"usr/bin/quiet": "a binary"}}
	env := install.Env{
		Root: root, DB: store, LockPath: lock, PeipkgVersion: "0.1.0-test",
		Provider:         fakeProvider{"quiet": provide(t, pkg)},
		SDOverridePolicy: refuseAll,
	}
	plan := resolver.Plan{Operations: []resolver.Operation{installOp(t, "quiet", "1.0-1")}}
	if _, err := install.Execute(ctx, plan, env); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "usr/bin/quiet")); err != nil {
		t.Errorf("the package did not install: %v", err)
	}
}

// TestExecuteRollsBackWhenADescriptorIsRejected: §5.20 — if creation
// fails because the kernel rejects the descriptor, most often because
// it names a principal the system does not know, the install fails and
// partial state is rolled back. It must not be warned past.
func TestExecuteRollsBackWhenADescriptorIsRejected(t *testing.T) {
	ctx := t.Context()
	store, root, lock := freshEnv(t)
	pkg := testPkg{
		name: "stranger", version: "1.0-1",
		files:       map[string]string{"usr/bin/stranger": "a binary"},
		sdOverrides: map[string]string{"usr/bin/stranger": "names an unknown principal"},
	}
	orig := sdstamp.Stamp
	sdstamp.Stamp = func(string, []byte) error { return os.ErrInvalid }
	t.Cleanup(func() { sdstamp.Stamp = orig })

	env := install.Env{
		Root: root, DB: store, LockPath: lock, PeipkgVersion: "0.1.0-test",
		Provider:         fakeProvider{"stranger": provide(t, pkg)},
		SDOverridePolicy: allowAll,
	}
	plan := resolver.Plan{Operations: []resolver.Operation{installOp(t, "stranger", "1.0-1")}}

	if _, err := install.Execute(ctx, plan, env); err == nil {
		t.Fatal("Execute succeeded though the descriptor was rejected")
	}
	if _, err := os.Stat(filepath.Join(root, "usr/bin/stranger")); err == nil {
		t.Error("the payload survived a rejected descriptor; the transaction did not roll back")
	}
	if _, found, _ := store.GetPackage(ctx, "stranger"); found {
		t.Error("the package database recorded the package after a failed install")
	}
}
