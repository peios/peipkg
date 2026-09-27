package install_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/peios/libp-go/sd"
	"github.com/peios/libp-go/sddl"
	"github.com/peios/peipkg/internal/install"
	"github.com/peios/peipkg/internal/resolver"
)

// Run in a disposable Peios guest with PEIPKG_NATIVE_SD_ROOT naming a new
// directory. Leave the payload there for independent ordinary-principal opens.
func TestNativeSDCreation(t *testing.T) {
	root := os.Getenv("PEIPKG_NATIVE_SD_ROOT")
	if root == "" {
		t.Skip("requires a disposable Peios guest and PEIPKG_NATIVE_SD_ROOT")
	}
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	raw := func(text string) []byte {
		d, err := sddl.Parse(text)
		if err != nil {
			t.Fatal(err)
		}
		b, err := d.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	public := raw("O:SYG:SYD:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)(A;OICI;GRGX;;;WD)")
	private := raw("O:SYG:SYD:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)")
	if err := sd.SetSD(sd.Path(root), sd.InfoOwner|sd.InfoGroup|sd.InfoDACL, public); err != nil {
		t.Fatal(err)
	}
	// An existing directory must be protected before new children too.
	if err := os.MkdirAll(filepath.Join(root, "usr/share/native/existing"), 0o755); err != nil {
		t.Fatal(err)
	}
	store, _, lock := freshEnv(t)
	consumer := testPkg{name: "consumer", version: "1.0-1",
		files: map[string]string{
			"usr/share/native/existing/child":           "private bytes",
			"usr/share/native/public":                   "public bytes",
			"usr/share/native/explicit":                 "private bytes",
			"usr/share/native/private/nested/inherited": "private bytes",
		}, sdOverrides: map[string]string{"usr/share/native/explicit": string(private)},
	}
	scope := testPkg{name: "scope", version: "1.0-1", dirs: []string{"usr/share/native/private", "usr/share/native/existing"},
		sdOverrides: map[string]string{"usr/share/native/private": string(private), "usr/share/native/existing": string(private)},
	}
	env := install.Env{Root: root, DB: store, LockPath: lock, PeipkgVersion: "native-test",
		Provider: fakeProvider{"consumer": provide(t, consumer), "scope": provide(t, scope)}, SDOverridePolicy: allowAll}
	plan := resolver.Plan{Operations: []resolver.Operation{installOp(t, "consumer", "1.0-1"), installOp(t, "scope", "1.0-1")}}
	if _, err := install.Execute(t.Context(), plan, env); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"explicit", "private/nested/inherited", "existing/child"} {
		b, err := sd.GetSD(sd.Path(filepath.Join(root, "usr/share/native", p)), sd.InfoDACL)
		if err != nil {
			t.Fatal(err)
		}
		d, err := sd.ParseDescriptor(b)
		if err != nil {
			t.Fatal(err)
		}
		if d.DACL == nil {
			t.Fatal("NULL DACL")
		}
		for _, ace := range d.DACL.Entries {
			if ace.SID.String() == "S-1-1-0" {
				t.Fatalf("%s inherited Everyone access", p)
			}
		}
	}
}
