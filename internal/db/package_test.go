package db_test

import (
	"slices"
	"testing"

	"github.com/peios/peipkg/internal/db"
)

// fileEntry, dirEntry and symlinkEntry build the three kinds of
// package_file row.
func fileEntry(pkg, path, hash string) db.PackageFile {
	return db.PackageFile{PackageName: pkg, Path: path, Type: db.FileTypeFile, Hash: hash}
}

func dirEntry(pkg, path string) db.PackageFile {
	return db.PackageFile{PackageName: pkg, Path: path, Type: db.FileTypeDir}
}

func symlinkEntry(pkg, path, target string) db.PackageFile {
	return db.PackageFile{PackageName: pkg, Path: path, Type: db.FileTypeSymlink, SymlinkTarget: target}
}

func TestPackageInsertAndGet(t *testing.T) {
	d, _ := newTestDB(t)
	ctx := t.Context()
	want := samplePackage("nginx")

	if err := d.InsertPackage(ctx, want); err != nil {
		t.Fatalf("InsertPackage: %v", err)
	}
	got, found, err := d.GetPackage(ctx, "nginx")
	if err != nil {
		t.Fatalf("GetPackage: %v", err)
	}
	if !found {
		t.Fatal("GetPackage: an installed package was not found")
	}
	assertSamePackage(t, got, want)
}

func TestGetMissingPackage(t *testing.T) {
	d, _ := newTestDB(t)
	if _, found, err := d.GetPackage(t.Context(), "absent"); err != nil || found {
		t.Errorf("GetPackage of an absent package: found=%v err=%v", found, err)
	}
}

func TestInsertDuplicatePackageFails(t *testing.T) {
	d, _ := newTestDB(t)
	ctx := t.Context()
	if err := d.InsertPackage(ctx, samplePackage("dup")); err != nil {
		t.Fatalf("first InsertPackage: %v", err)
	}
	if err := d.InsertPackage(ctx, samplePackage("dup")); err == nil {
		t.Error("inserting a second package with the same name should fail")
	}
}

func TestListPackagesIsOrderedByName(t *testing.T) {
	d, _ := newTestDB(t)
	ctx := t.Context()
	for _, name := range []string{"charlie", "alpha", "bravo"} {
		if err := d.InsertPackage(ctx, samplePackage(name)); err != nil {
			t.Fatalf("InsertPackage %q: %v", name, err)
		}
	}
	pkgs, err := d.ListPackages(ctx)
	if err != nil {
		t.Fatalf("ListPackages: %v", err)
	}
	got := make([]string, len(pkgs))
	for i, p := range pkgs {
		got[i] = p.Name
	}
	if want := []string{"alpha", "bravo", "charlie"}; !slices.Equal(got, want) {
		t.Errorf("ListPackages order: got %v, want %v", got, want)
	}
}

func TestLocalInstallHasNoOriginRepo(t *testing.T) {
	d, _ := newTestDB(t)
	ctx := t.Context()
	p := samplePackage("local")
	p.OriginRepo = "" // installed from a local .peipkg file

	if err := d.InsertPackage(ctx, p); err != nil {
		t.Fatalf("InsertPackage: %v", err)
	}
	got, _, err := d.GetPackage(ctx, "local")
	if err != nil {
		t.Fatalf("GetPackage: %v", err)
	}
	if got.OriginRepo != "" {
		t.Errorf("OriginRepo of a local install: got %q, want empty", got.OriginRepo)
	}
}

func TestDeletePackageCascadesToFiles(t *testing.T) {
	d, _ := newTestDB(t)
	ctx := t.Context()
	if err := d.InsertPackage(ctx, samplePackage("withfiles")); err != nil {
		t.Fatalf("InsertPackage: %v", err)
	}
	if err := d.InsertPackageFiles(ctx, []db.PackageFile{
		dirEntry("withfiles", "/usr/share/withfiles"),
		fileEntry("withfiles", "/usr/share/withfiles/data", "abc123"),
	}); err != nil {
		t.Fatalf("InsertPackageFiles: %v", err)
	}

	if err := d.DeletePackage(ctx, "withfiles"); err != nil {
		t.Fatalf("DeletePackage: %v", err)
	}
	remaining, err := d.PackageFiles(ctx, "withfiles")
	if err != nil {
		t.Fatalf("PackageFiles: %v", err)
	}
	if len(remaining) != 0 {
		t.Errorf("package_file rows should cascade-delete; %d remain", len(remaining))
	}
}

func TestDeleteAbsentPackageIsNotAnError(t *testing.T) {
	d, _ := newTestDB(t)
	if err := d.DeletePackage(t.Context(), "never-installed"); err != nil {
		t.Errorf("DeletePackage of an absent package: %v", err)
	}
}

func TestPackageFilesRoundTrip(t *testing.T) {
	d, _ := newTestDB(t)
	ctx := t.Context()
	if err := d.InsertPackage(ctx, samplePackage("rt")); err != nil {
		t.Fatalf("InsertPackage: %v", err)
	}
	// Already in path order, which is what PackageFiles returns.
	want := []db.PackageFile{
		dirEntry("rt", "/opt/rt"),
		fileEntry("rt", "/opt/rt/bin", "deadbeef"),
		symlinkEntry("rt", "/opt/rt/latest", "/opt/rt/bin"),
	}
	if err := d.InsertPackageFiles(ctx, want); err != nil {
		t.Fatalf("InsertPackageFiles: %v", err)
	}
	got, err := d.PackageFiles(ctx, "rt")
	if err != nil {
		t.Fatalf("PackageFiles: %v", err)
	}
	if !slices.Equal(got, want) {
		t.Errorf("PackageFiles round-trip:\n got %+v\nwant %+v", got, want)
	}
}

// TestNonDirectoryPathCollisionIsRejected exercises the partial unique
// index: no two packages may own the same non-directory path.
func TestNonDirectoryPathCollisionIsRejected(t *testing.T) {
	d, _ := newTestDB(t)
	ctx := t.Context()
	for _, name := range []string{"pkg-a", "pkg-b"} {
		if err := d.InsertPackage(ctx, samplePackage(name)); err != nil {
			t.Fatalf("InsertPackage %q: %v", name, err)
		}
	}
	if err := d.InsertPackageFiles(ctx, []db.PackageFile{
		fileEntry("pkg-a", "/usr/bin/contended", "hash-a"),
	}); err != nil {
		t.Fatalf("first owner InsertPackageFiles: %v", err)
	}
	err := d.InsertPackageFiles(ctx, []db.PackageFile{
		fileEntry("pkg-b", "/usr/bin/contended", "hash-b"),
	})
	if err == nil {
		t.Error("two packages owning the same file path should be rejected")
	}
}

// TestPackagesMayShareDirectories is the companion: directories are
// shared trees, never collisions.
func TestPackagesMayShareDirectories(t *testing.T) {
	d, _ := newTestDB(t)
	ctx := t.Context()
	for _, name := range []string{"pkg-a", "pkg-b"} {
		if err := d.InsertPackage(ctx, samplePackage(name)); err != nil {
			t.Fatalf("InsertPackage %q: %v", name, err)
		}
	}
	if err := d.InsertPackageFiles(ctx, []db.PackageFile{
		dirEntry("pkg-a", "/usr/share/common"),
	}); err != nil {
		t.Fatalf("first directory owner: %v", err)
	}
	if err := d.InsertPackageFiles(ctx, []db.PackageFile{
		dirEntry("pkg-b", "/usr/share/common"),
	}); err != nil {
		t.Errorf("two packages sharing a directory should be allowed: %v", err)
	}
}

// TestPackageFileTypeInvariants exercises the CHECK constraints that tie
// the hash and symlink_target columns to the file type.
func TestPackageFileTypeInvariants(t *testing.T) {
	d, _ := newTestDB(t)
	ctx := t.Context()
	if err := d.InsertPackage(ctx, samplePackage("checks")); err != nil {
		t.Fatalf("InsertPackage: %v", err)
	}
	cases := []struct {
		name string
		file db.PackageFile
	}{
		{"file without a hash", db.PackageFile{
			PackageName: "checks", Path: "/a", Type: db.FileTypeFile}},
		{"file carrying a symlink target", db.PackageFile{
			PackageName: "checks", Path: "/b", Type: db.FileTypeFile,
			Hash: "h", SymlinkTarget: "/elsewhere"}},
		{"symlink without a target", db.PackageFile{
			PackageName: "checks", Path: "/c", Type: db.FileTypeSymlink}},
		{"symlink carrying a hash", db.PackageFile{
			PackageName: "checks", Path: "/d", Type: db.FileTypeSymlink,
			SymlinkTarget: "/t", Hash: "h"}},
		{"directory carrying a hash", db.PackageFile{
			PackageName: "checks", Path: "/e", Type: db.FileTypeDir, Hash: "h"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := d.InsertPackageFiles(ctx, []db.PackageFile{tc.file}); err == nil {
				t.Errorf("a %s should be rejected by the schema", tc.name)
			}
		})
	}
}

// TestPackageFileRequiresItsPackage exercises the foreign key — and so
// proves foreign-key enforcement is active on peipkg's connections.
func TestPackageFileRequiresItsPackage(t *testing.T) {
	d, _ := newTestDB(t)
	err := d.InsertPackageFiles(t.Context(), []db.PackageFile{
		fileEntry("ghost", "/usr/bin/orphan", "hash"),
	})
	if err == nil {
		t.Error("a package_file for a non-existent package should be rejected (foreign key)")
	}
}

func TestFileOwners(t *testing.T) {
	d, _ := newTestDB(t)
	ctx := t.Context()
	for _, name := range []string{"owner-x", "owner-y"} {
		if err := d.InsertPackage(ctx, samplePackage(name)); err != nil {
			t.Fatalf("InsertPackage %q: %v", name, err)
		}
	}
	if err := d.InsertPackageFiles(ctx, []db.PackageFile{
		dirEntry("owner-x", "/shared"),
		fileEntry("owner-x", "/shared/x-only", "hx"),
	}); err != nil {
		t.Fatalf("owner-x files: %v", err)
	}
	if err := d.InsertPackageFiles(ctx, []db.PackageFile{
		dirEntry("owner-y", "/shared"),
	}); err != nil {
		t.Fatalf("owner-y files: %v", err)
	}

	if owners, err := d.FileOwners(ctx, "/shared"); err != nil || len(owners) != 2 {
		t.Errorf("FileOwners of a shared directory: got %d owners (err %v), want 2",
			len(owners), err)
	}
	owners, err := d.FileOwners(ctx, "/shared/x-only")
	if err != nil {
		t.Fatalf("FileOwners(/shared/x-only): %v", err)
	}
	if len(owners) != 1 || owners[0].PackageName != "owner-x" {
		t.Errorf("FileOwners of a file: got %+v, want a single owner-x row", owners)
	}
	if owners, err := d.FileOwners(ctx, "/unowned"); err != nil || len(owners) != 0 {
		t.Errorf("FileOwners of an unowned path: got %d (err %v), want 0", len(owners), err)
	}
}
