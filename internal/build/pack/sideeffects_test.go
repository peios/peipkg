package pack

import "testing"

func leaf(p string) entry { return entry{path: p, kind: kindFile} }

func TestKernelModulesWithoutDepmodAreRejected(t *testing.T) {
	_, err := validateSideEffectEntries(nil, []entry{
		leaf("usr/lib/modules/7.0.9-peios/kernel/fs/xfs/xfs.ko"),
	})
	if err == nil {
		t.Fatal("a payload with kernel modules and no depmod declaration must be rejected")
	}
}

func TestCompressedKernelModulesCount(t *testing.T) {
	_, err := validateSideEffectEntries(nil, []entry{
		leaf("usr/lib/modules/7.0.9-peios/kernel/fs/xfs/xfs.ko.zst"),
	})
	if err == nil {
		t.Fatal(".ko.<compression> is a kernel module too")
	}
}

func TestDepmodDeclaredWithoutModulesIsRejected(t *testing.T) {
	_, err := validateSideEffectEntries([]string{"depmod"}, []entry{leaf("usr/bin/true")})
	if err == nil {
		t.Fatal("declaring depmod without shipping modules must be rejected")
	}
}

func TestModulesWithDepmodPass(t *testing.T) {
	warnings, err := validateSideEffectEntries([]string{"depmod"}, []entry{
		leaf("usr/lib/modules/7.0.9-peios/kernel/fs/xfs/xfs.ko"),
		leaf("usr/lib/modules/7.0.9-peios/modules.dep"),
	})
	if err != nil {
		t.Fatalf("a correctly declared module package must pass: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("no man pages, so no man-db warning: %v", warnings)
	}
}

// A .ko outside usr/lib/modules/ is not a kernel module for §5.24's
// purposes -- the rule is scoped to the directory depmod indexes.
func TestKoOutsideModulesTreeIsNotAModule(t *testing.T) {
	_, err := validateSideEffectEntries(nil, []entry{leaf("usr/share/examples/hello.ko")})
	if err != nil {
		t.Fatalf("a .ko outside the modules tree must not trigger the rule: %v", err)
	}
}

// man-db is a SHOULD, so a violation is a finding rather than a failure.
// 74 already-published packages ship man pages without declaring it; a
// hard error here would reject the entire distro.
func TestManPagesWithoutManDBWarnRatherThanFail(t *testing.T) {
	warnings, err := validateSideEffectEntries(nil, []entry{leaf("usr/share/man/man1/ls.1")})
	if err != nil {
		t.Fatalf("man-db is a SHOULD, not a MUST: %v", err)
	}
	if len(warnings) != 1 {
		t.Fatalf("expected one man-db warning, got %v", warnings)
	}
}

func TestManDBDeclaredWithoutManPagesWarns(t *testing.T) {
	warnings, err := validateSideEffectEntries([]string{"man-db"}, []entry{leaf("usr/bin/true")})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(warnings) != 1 {
		t.Fatalf("expected one warning, got %v", warnings)
	}
}

// Findings are returned alongside an error so one run reports everything,
// rather than making the author fix depmod to discover the man-db advice.
func TestWarningsAreReturnedAlongsideErrors(t *testing.T) {
	warnings, err := validateSideEffectEntries(nil, []entry{
		leaf("usr/lib/modules/7.0.9-peios/kernel/fs/xfs/xfs.ko"),
		leaf("usr/share/man/man1/xfs.1"),
	})
	if err == nil {
		t.Fatal("missing depmod must still fail")
	}
	if len(warnings) != 1 {
		t.Fatalf("the man-db finding must survive the error: %v", warnings)
	}
}

// Directory entries carry no content; a directory named like a module
// must not make a package declare depmod.
func TestDirectoriesAreIgnored(t *testing.T) {
	_, err := validateSideEffectEntries(nil, []entry{
		{path: "usr/lib/modules/7.0.9-peios/kernel/fs/xfs.ko", kind: kindDir},
	})
	if err != nil {
		t.Fatalf("directories must be ignored: %v", err)
	}
}
