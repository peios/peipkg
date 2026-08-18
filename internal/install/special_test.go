package install_test

import (
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
