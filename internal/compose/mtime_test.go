package compose

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/peios/peipkg/internal/archive"
)

func timestampFixture(t *testing.T) ([]fetchedPackage, Manifest) {
	t.Helper()
	raw := buildPeipkg(t, minimalManifestJSON(t, "headers", "1.0-1", "x86_64", 3), []testEntry{
		{Path: "usr", IsDir: true}, {Path: "usr/include", IsDir: true}, {Path: "usr/include/detail", IsDir: true},
		{Path: "usr/include/detail/value.h", Content: []byte("42\n")},
		{Path: "usr/include/value.h", Symlink: "detail/value.h"},
	})
	pkg, err := archive.VerifyFormat(bytes.NewReader(raw), archive.NoDeclaredSize)
	if err != nil {
		t.Fatal(err)
	}
	return []fetchedPackage{{Raw: raw, Pkg: pkg, Locked: LockedPackage{Name: "headers", Version: "1.0-1", Architecture: "x86_64"}}}, Manifest{Arch: "x86_64", SourceDate: time.Date(2026, 6, 2, 0, 0, 0, 0, time.UTC)}
}

func TestComposePreservesPayloadTimes(t *testing.T) {
	fetched, m := timestampFixture(t)
	for i := 0; i < 2; i++ {
		root := filepath.Join(t.TempDir(), "root")
		if err := assemble(context.Background(), root, m, fetched, false, nil); err != nil {
			t.Fatal(err)
		}
		for _, rel := range []string{"usr", "usr/include", "usr/include/detail", "usr/include/detail/value.h", "usr/include/value.h"} {
			info, err := os.Lstat(filepath.Join(root, rel))
			if err != nil {
				t.Fatal(err)
			}
			if !info.ModTime().Equal(fetched[0].Pkg.Manifest.Build.Timestamp) {
				t.Errorf("composition %d %s mtime %s, want authenticated package time %s", i, rel, info.ModTime(), fetched[0].Pkg.Manifest.Build.Timestamp)
			}
		}
	}
}

// This invokes Ninja only in this test's new temporary directory; no compiler
// checkout, build cache or active package output is read or modified.
func TestComposeIdenticalRootDoesNotDirtyNinja(t *testing.T) {
	ninja, err := exec.LookPath("ninja")
	if err != nil {
		t.Skip("Ninja unavailable")
	}
	fetched, m := timestampFixture(t)
	work := t.TempDir()
	composeRoot := func(name string) string {
		root := filepath.Join(work, name)
		if err := assemble(context.Background(), root, m, fetched, false, nil); err != nil {
			t.Fatal(err)
		}
		return root
	}
	first := composeRoot("first")
	sdk := filepath.Join(work, "sdk")
	if err := os.Symlink(first, sdk); err != nil {
		t.Fatal(err)
	}
	script := "rule copy\n  command = cp $in $out\nbuild result: copy sdk/usr/include/value.h\n"
	if err := os.WriteFile(filepath.Join(work, "build.ninja"), []byte(script), 0600); err != nil {
		t.Fatal(err)
	}
	run := func() string {
		cmd := exec.Command(ninja, "-C", work)
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("isolated Ninja fixture: %v\n%s", err, output)
		}
		return string(output)
	}
	run()
	before, err := os.Stat(filepath.Join(work, "result"))
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	second := composeRoot("second")
	if err := os.Remove(sdk); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(second, sdk); err != nil {
		t.Fatal(err)
	}
	output := run()
	after, err := os.Stat(filepath.Join(work, "result"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output, "no work to do") || !before.ModTime().Equal(after.ModTime()) {
		t.Fatalf("identical newly composed SDK dirtied output: %s", output)
	}
	// Positive control for this timestamp-trigger regression, not a test of
	// arbitrary package upgrades. Changed package identities must invalidate
	// build reuse even when their canonical timestamps predate the output.
	header := filepath.Join(second, "usr/include/detail/value.h")
	if err := os.WriteFile(header, []byte("43\n"), 0600); err != nil {
		t.Fatal(err)
	}
	newer := after.ModTime().Add(time.Second)
	if err := os.Chtimes(header, newer, newer); err != nil {
		t.Fatal(err)
	}
	if output := run(); strings.Contains(output, "no work to do") {
		t.Fatalf("Ninja ignored newer dependency: %s", output)
	}
	content, err := os.ReadFile(filepath.Join(work, "result"))
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "43\n" {
		t.Fatalf("Ninja did not rebuild changed dependency: %q", content)
	}
}

func TestComposeSharedDirectoryTimeIndependentOfPackageOrder(t *testing.T) {
	fetched, m := timestampFixture(t)
	newer := fetched[0].Pkg.Manifest.Build.Timestamp.Add(24 * time.Hour)
	manifest := bytes.ReplaceAll(minimalManifestJSON(t, "more-headers", "1.0-1", "x86_64", 2), []byte("2026-06-01T00:00:00Z"), []byte(newer.Format(time.RFC3339)))
	raw := buildPeipkgSignedAt(t, manifest, []testEntry{{Path: "usr", IsDir: true}, {Path: "usr/include", IsDir: true}, {Path: "usr/include/more.h", Content: []byte("7\n")}}, nil, newer)
	pkg, err := archive.VerifyFormat(bytes.NewReader(raw), archive.NoDeclaredSize)
	if err != nil {
		t.Fatal(err)
	}
	fetched = append(fetched, fetchedPackage{Raw: raw, Pkg: pkg, Locked: LockedPackage{Name: "more-headers", Version: "1.0-1", Architecture: "x86_64"}})
	for i := 0; i < 2; i++ {
		root := filepath.Join(t.TempDir(), "root")
		if err := assemble(context.Background(), root, m, fetched, false, nil); err != nil {
			t.Fatal(err)
		}
		for _, rel := range []string{"usr", "usr/include"} {
			info, err := os.Stat(filepath.Join(root, rel))
			if err != nil {
				t.Fatal(err)
			}
			if !info.ModTime().Equal(newer) {
				t.Errorf("shared %s mtime %s, want newest owner %s", rel, info.ModTime(), newer)
			}
		}
		fetched[0], fetched[1] = fetched[1], fetched[0]
	}
}

func TestPayloadTimeDoesNotFollowSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "outside")
	if err := os.WriteFile(target, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	want := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	if err := setPayloadTime(link, want); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if !before.ModTime().Equal(after.ModTime()) || !info.ModTime().Equal(want) {
		t.Fatal("timestamp update followed symlink or failed to update link")
	}
}

func TestPayloadTimeEpochAndFilesystemRange(t *testing.T) {
	for _, timestamp := range []time.Time{time.Unix(0, 0), time.Time{}, time.Date(3000, 1, 1, 0, 0, 0, 0, time.UTC)} {
		t.Run(timestamp.Format(time.RFC3339), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "file")
			if err := os.WriteFile(path, nil, 0600); err != nil {
				t.Fatal(err)
			}
			err := setPayloadTime(path, timestamp)
			if timestamp.Equal(time.Unix(0, 0)) && err != nil {
				t.Fatalf("Unix epoch is a valid timestamp: %v", err)
			}
			if err == nil {
				info, err := os.Lstat(path)
				if err != nil {
					t.Fatal(err)
				}
				if !info.ModTime().Equal(timestamp) {
					t.Fatal("timestamp silently clamped")
				}
			}
		})
	}
}

func TestComposePayloadTimesInNamedRoot(t *testing.T) {
	fetched, m := timestampFixture(t)
	fetched[0].Locked.Root = "boot/initramfs"
	m.Roots = []Root{{Name: "initramfs", Path: "boot/initramfs"}}
	root := filepath.Join(t.TempDir(), "root")
	if err := assemble(context.Background(), root, m, fetched, false, nil); err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{"usr", "usr/include", "usr/include/detail/value.h"} {
		info, err := os.Lstat(filepath.Join(root, "boot/initramfs", rel))
		if err != nil {
			t.Fatal(err)
		}
		if !info.ModTime().Equal(fetched[0].Pkg.Manifest.Build.Timestamp) {
			t.Errorf("named root %s lost package timestamp", rel)
		}
	}
}
