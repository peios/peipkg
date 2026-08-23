package install

import (
	"reflect"
	"testing"

	"github.com/peios/peipkg/internal/db"
)

func modulePackage(name string, paths ...string) stagedOp {
	files := make([]db.PackageFile, 0, len(paths))
	for _, p := range paths {
		files = append(files, db.PackageFile{PackageName: name, Path: p, Type: db.FileTypeFile})
	}
	return stagedOp{
		pkg:         &db.Package{Name: name},
		files:       files,
		sideEffects: []string{"depmod"},
	}
}

// PEI-215: bare `depmod -a` indexes the *running* kernel. Installing modules
// for a release you are not running -- which is every kernel update -- left
// that release with no usable modules.dep, and modprobe resolving nothing on
// the next boot with no error naming the cause.
func TestDepmodTargetsTheInstalledReleasesNotTheRunningKernel(t *testing.T) {
	staged := []stagedOp{modulePackage("kernel-modules",
		"usr/lib/modules/7.0.9-peios-X/kernel/fs/xfs/xfs.ko",
		"usr/lib/modules/7.0.9-peios-X/modules.dep",
	)}

	effects, warnings := plannedSideEffects(staged)
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
	want := []sideEffect{{name: "depmod", argv: []string{depmodBinary, "-a", "7.0.9-peios-X"}}}
	if !reflect.DeepEqual(effects, want) {
		t.Fatalf("effects = %+v, want %+v", effects, want)
	}
}

func TestDepmodRunsOncePerAffectedRelease(t *testing.T) {
	staged := []stagedOp{modulePackage("kernel-modules",
		"usr/lib/modules/7.0.9-peios-B/kernel/fs/xfs/xfs.ko",
		"usr/lib/modules/7.0.9-peios-A/kernel/fs/xfs/xfs.ko",
		"usr/lib/modules/7.0.9-peios-A/kernel/net/tls/tls.ko",
	)}

	effects, _ := plannedSideEffects(staged)
	want := []sideEffect{
		{name: "depmod", argv: []string{depmodBinary, "-a", "7.0.9-peios-A"}},
		{name: "depmod", argv: []string{depmodBinary, "-a", "7.0.9-peios-B"}},
	}
	if !reflect.DeepEqual(effects, want) {
		t.Fatalf("effects = %+v, want %+v", effects, want)
	}
}

// A release split across packages is the shipped arrangement, not a corner
// case: kernel-modules and kernel-modules-irf both carry modules for the same
// release, and both declare depmod. It is the release that is reindexed, so
// that is one invocation, not two.
func TestDepmodDedupesAReleaseCarriedByTwoPackages(t *testing.T) {
	staged := []stagedOp{
		modulePackage("kernel-modules", "usr/lib/modules/7.0.9-peios-X/kernel/fs/xfs/xfs.ko"),
		modulePackage("kernel-modules-irf",
			"usr/lib/modules/7.0.9-peios-X/kernel/drivers/virtio/virtio_blk.ko"),
	}

	effects, _ := plannedSideEffects(staged)
	if len(effects) != 1 || effects[0].argv[2] != "7.0.9-peios-X" {
		t.Fatalf("effects = %+v", effects)
	}
}

func TestDepmodWithoutModulesWarnsRatherThanIndexingTheRunningKernel(t *testing.T) {
	staged := []stagedOp{modulePackage("odd", "usr/bin/odd")}

	effects, warnings := plannedSideEffects(staged)
	if len(effects) != 0 {
		t.Fatalf("effects = %+v, want none", effects)
	}
	if len(warnings) != 1 {
		t.Fatalf("warnings = %v, want one", warnings)
	}
}

// Directories and the release directory itself are not modules.
func TestModuleReleaseIgnoresNonFilesAndBarePrefixes(t *testing.T) {
	cases := []struct {
		file db.PackageFile
		want string
	}{
		{db.PackageFile{Path: "usr/lib/modules/7.0.9/kernel/fs/xfs.ko", Type: db.FileTypeFile}, "7.0.9"},
		{db.PackageFile{Path: "/usr/lib/modules/7.0.9/modules.dep", Type: db.FileTypeFile}, "7.0.9"},
		{db.PackageFile{Path: "usr/lib/modules/7.0.9", Type: db.FileTypeDir}, ""},
		{db.PackageFile{Path: "usr/lib/modules/7.0.9/kernel", Type: db.FileTypeDir}, ""},
		{db.PackageFile{Path: "usr/lib/modules", Type: db.FileTypeDir}, ""},
		{db.PackageFile{Path: "usr/lib/modules/7.0.9", Type: db.FileTypeFile}, ""},
		{db.PackageFile{Path: "usr/share/man/man1/x.1", Type: db.FileTypeFile}, ""},
	}
	for _, tc := range cases {
		got, ok := moduleRelease(tc.file)
		if !ok {
			got = ""
		}
		if got != tc.want {
			t.Errorf("moduleRelease(%q, %s) = %q, want %q", tc.file.Path, tc.file.Type, got, tc.want)
		}
	}
}

// A removal declares nothing, and man-db is still a fixed command.
func TestNonDepmodEffectsAreUnchanged(t *testing.T) {
	staged := []stagedOp{
		{pkg: &db.Package{Name: "docs"}, sideEffects: []string{"man-db"}},
		{}, // a removal
	}
	effects, warnings := plannedSideEffects(staged)
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
	want := []sideEffect{{name: "man-db", argv: []string{"/bin/mandb", "-q"}}}
	if !reflect.DeepEqual(effects, want) {
		t.Fatalf("effects = %+v, want %+v", effects, want)
	}
}
