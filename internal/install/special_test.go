package install_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/peios/peipkg/internal/install"
	"github.com/peios/peipkg/internal/resolver"
)

// fsbaseLike is a payload no ordinary package may ship: bare mountpoint
// directories and a file outside every §3.4.1 destination. It stands in
// for fsbase and the kernel — the packages whose job is to lay down the
// structure the layout rules exist to protect.
func fsbaseLike(name string) testPkg {
	return testPkg{
		name: name, version: "1.0-1",
		files: map[string]string{"opt/vendor/agent": "agent"},
		dirs:  []string{"srv"},
	}
}

// TestSpecialSystemPackageNeedsBothKeys covers the whole truth table of
// the §3.4 exemption. The declaration and the operator's flag are two
// separate keys and the payload lands only when both are turned: a
// package can propose its own exemption but cannot grant it, and the
// flag cannot exempt a package that never asked.
func TestSpecialSystemPackageNeedsBothKeys(t *testing.T) {
	for _, tc := range []struct {
		name    string
		special bool
		bypass  bool
		wantErr string // "" means the install must succeed
	}{
		{name: "neither", wantErr: "not under any §3.4.1 permitted top-level destination"},
		{name: "declaration alone", special: true,
			wantErr: "did not pass --dangerously-bypass-path-restrictions"},
		{name: "flag alone", bypass: true,
			wantErr: "not under any §3.4.1 permitted top-level destination"},
		{name: "both keys", special: true, bypass: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			store, root, lock := freshEnv(t)
			pkg := fsbaseLike("fsbase")
			pkg.special = tc.special

			env := install.Env{
				Root: root, DB: store, LockPath: lock, PeipkgVersion: "test",
				Provider:               fakeProvider{"fsbase": provide(t, pkg)},
				BypassPathRestrictions: tc.bypass,
			}
			_, err := install.Execute(ctx,
				resolver.Plan{Operations: []resolver.Operation{installOp(t, "fsbase", "1.0-1")}}, env)

			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("both keys turned, install should succeed: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected refusal, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not mention %q", err, tc.wantErr)
			}
		})
	}
}

// TestSpecialSystemPackageDoesNotWaiveOtherRules confirms the exemption
// is scoped to the layout check. A special package installed with the
// bypass is still a normal package in every other respect.
func TestSpecialSystemPackageStillRecordsFiles(t *testing.T) {
	ctx := t.Context()
	store, root, lock := freshEnv(t)
	pkg := fsbaseLike("fsbase")
	pkg.special = true

	env := install.Env{
		Root: root, DB: store, LockPath: lock, PeipkgVersion: "test",
		Provider:               fakeProvider{"fsbase": provide(t, pkg)},
		BypassPathRestrictions: true,
	}
	if _, err := install.Execute(ctx,
		resolver.Plan{Operations: []resolver.Operation{installOp(t, "fsbase", "1.0-1")}}, env); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	files, err := store.PackageFiles(ctx, "fsbase")
	if err != nil {
		t.Fatalf("PackageFiles: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("a bypassed install must still record its files in the database")
	}
}

// §5.14: "/lcl/policy MUST NOT be reachable by this route under any
// circumstance. It is the tree whose contents grant authority, and an
// exemption that could reach it would convert a structural guarantee
// into a policy one."
//
// So the sentence has to hold for the one case that turns both keys —
// which is exactly the case that used to skip the layout check outright,
// with no residual denylist behind it (PEI-380).
//
// What it protects is *content*: an empty directory grants no authority,
// and fsbase mints lcl/policy/autorun.d as one. See
// TestBothKeysMayStillMintTheEmptySkeleton.
func TestBothKeysStillCannotReachLclPolicy(t *testing.T) {
	for _, tc := range []struct {
		name string
		pkg  testPkg
	}{
		{name: "file", pkg: testPkg{name: "fsbase", version: "1.0-1", special: true,
			files: map[string]string{"lcl/policy/autorun.d/pwn.sh": "#!/bin/sh\n"}}},
		{name: "symlink", pkg: testPkg{name: "fsbase", version: "1.0-1", special: true,
			files:    map[string]string{"usr/bin/x": "x"},
			symlinks: map[string]string{"lcl/policy/autorun.d/pwn.sh": "/usr/bin/x"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			store, root, lock := freshEnv(t)
			env := install.Env{
				Root: root, DB: store, LockPath: lock, PeipkgVersion: "test",
				Provider:               fakeProvider{"fsbase": provide(t, tc.pkg)},
				BypassPathRestrictions: true, // both keys turned
			}
			_, err := install.Execute(ctx,
				resolver.Plan{Operations: []resolver.Operation{installOp(t, "fsbase", "1.0-1")}}, env)
			if err == nil {
				t.Fatal("a special system package installed with the bypass reached /lcl/policy")
			}
			if !strings.Contains(err.Error(), "/lcl/policy") {
				t.Errorf("error %q does not name the tree it refused", err)
			}
		})
	}
}

// §7.1.5: an unowned pre-existing file is adopted when it is
// byte-identical to what would be installed, and otherwise the install
// fails rather than overwriting it. Before this the file was overwritten
// silently and its backup deleted seconds later at commit, permanently
// destroying the content the rule exists to protect (PEI-376).
// The other half of the rule: laying down the empty skeleton is what a
// special system package is for, so fsbase's lcl/policy/autorun.d must
// still compose and install.
func TestBothKeysMayStillMintTheEmptySkeleton(t *testing.T) {
	ctx := t.Context()
	store, root, lock := freshEnv(t)
	pkg := testPkg{name: "fsbase", version: "1.0-1", special: true,
		dirs: []string{"lcl/policy", "lcl/policy/autorun.d"}}
	env := install.Env{
		Root: root, DB: store, LockPath: lock, PeipkgVersion: "test",
		Provider:               fakeProvider{"fsbase": provide(t, pkg)},
		BypassPathRestrictions: true,
	}
	if _, err := install.Execute(ctx,
		resolver.Plan{Operations: []resolver.Operation{installOp(t, "fsbase", "1.0-1")}},
		env); err != nil {
		t.Fatalf("minting the empty /lcl/policy skeleton was refused: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "lcl/policy/autorun.d")); err != nil {
		t.Errorf("the skeleton directory was not created: %v", err)
	}
}

func TestUnownedFilePolicy(t *testing.T) {
	pkg := testPkg{name: "nginx", version: "1.0-1",
		files: map[string]string{"usr/bin/nginx": "the packaged binary"}}

	run := func(t *testing.T, onDisk string, authorise bool) (string, install.Result, error) {
		t.Helper()
		ctx := t.Context()
		store, root, lock := freshEnv(t)
		victim := filepath.Join(root, "usr/bin/nginx")
		if err := os.MkdirAll(filepath.Dir(victim), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(victim, []byte(onDisk), 0o755); err != nil {
			t.Fatalf("write: %v", err)
		}
		env := install.Env{
			Root: root, DB: store, LockPath: lock, PeipkgVersion: "test",
			Provider:         fakeProvider{"nginx": provide(t, pkg)},
			OverwriteUnowned: authorise,
		}
		res, err := install.Execute(ctx,
			resolver.Plan{Operations: []resolver.Operation{installOp(t, "nginx", "1.0-1")}}, env)
		return root, res, err
	}

	t.Run("differing content fails", func(t *testing.T) {
		root, _, err := run(t, "a hand-placed binary", false)
		if err == nil {
			t.Fatal("install overwrote an unowned file with different content")
		}
		if !strings.Contains(err.Error(), "belongs to no installed package") {
			t.Errorf("error %q does not explain why it refused", err)
		}
		// And the operator's file is still there, untouched.
		got, readErr := os.ReadFile(filepath.Join(root, "usr/bin/nginx"))
		if readErr != nil {
			t.Fatalf("the unowned file is gone: %v", readErr)
		}
		if string(got) != "a hand-placed binary" {
			t.Errorf("the unowned file now holds %q", got)
		}
	})

	t.Run("identical content is adopted", func(t *testing.T) {
		root, _, err := run(t, "the packaged binary", false)
		if err != nil {
			t.Fatalf("install refused a byte-identical unowned file: %v", err)
		}
		got, err := os.ReadFile(filepath.Join(root, "usr/bin/nginx"))
		if err != nil || string(got) != "the packaged binary" {
			t.Errorf("after adoption the file holds %q (err %v)", got, err)
		}
	})

	t.Run("authorised overwrite keeps the displaced content", func(t *testing.T) {
		root, res, err := run(t, "a hand-placed binary", true)
		if err != nil {
			t.Fatalf("authorised install failed: %v", err)
		}
		got, err := os.ReadFile(filepath.Join(root, "usr/bin/nginx"))
		if err != nil || string(got) != "the packaged binary" {
			t.Errorf("the package's content did not land: %q (err %v)", got, err)
		}
		// The whole point of the authorisation: the displaced content
		// survives the commit that used to delete it.
		entries, err := os.ReadDir(filepath.Join(root, "usr/bin"))
		if err != nil {
			t.Fatalf("readdir: %v", err)
		}
		var backup string
		for _, e := range entries {
			if strings.Contains(e.Name(), "peipkg-backup") {
				backup = filepath.Join(root, "usr/bin", e.Name())
			}
		}
		if backup == "" {
			t.Fatalf("the displaced content was discarded at commit; %s holds %v",
				filepath.Join(root, "usr/bin"), entries)
		}
		kept, err := os.ReadFile(backup)
		if err != nil || string(kept) != "a hand-placed binary" {
			t.Errorf("kept backup holds %q (err %v)", kept, err)
		}
		var told bool
		for _, w := range res.Warnings {
			if strings.Contains(w, "belonged to no package") {
				told = true
			}
		}
		if !told {
			t.Errorf("the operator was not told; warnings were %v", res.Warnings)
		}
	})
}
