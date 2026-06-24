package cli

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/peios/peipkg/internal/db"
	"github.com/peios/peipkg/internal/resolver"
)

func TestValidRootSegment(t *testing.T) {
	cases := map[string]bool{
		"initramfs":  true,
		"a":          true,
		"0":          true,
		"sub-root_1": true,
		"":           false,
		"-leading":   false,
		"_leading":   false,
		"Upper":      false,
		"has.dot":    false,
		"has/slash":  false,
		"has space":  false,
	}
	for in, want := range cases {
		if got := validRootSegment(in); got != want {
			t.Errorf("validRootSegment(%q) = %v, want %v", in, got, want)
		}
	}
}

// addNamedRoot registers name -> path in the registry of the root rooted
// at the given app, creating the database if necessary.
func addNamedRoot(t *testing.T, app *App, name, path string) {
	t.Helper()
	if err := cmdRoot(app, []string{"add", name, path}); err != nil {
		t.Fatalf("root add %q %q: %v", name, path, err)
	}
}

func TestResolveRootRefLiteralPath(t *testing.T) {
	// A value containing '/' is a literal path, returned unchanged —
	// never touching any registry.
	for _, p := range []string{"/", "/mnt/target", "./build/root", "boot/x"} {
		got, err := resolveRootRef(context.Background(), "/nonexistent-anchor", p)
		if err != nil {
			t.Fatalf("resolveRootRef(%q): %v", p, err)
		}
		if got != p {
			t.Errorf("resolveRootRef(%q) = %q, want it unchanged", p, got)
		}
	}
}

func TestResolveRootRefNamed(t *testing.T) {
	anchor := t.TempDir()
	app := newApp(anchor, strings.NewReader(""), &strings.Builder{}, &strings.Builder{})
	addNamedRoot(t, app, "initramfs", "boot/initramfs")

	got, err := resolveRootRef(context.Background(), anchor, "initramfs")
	if err != nil {
		t.Fatalf("resolveRootRef: %v", err)
	}
	if want := filepath.Join(anchor, "boot/initramfs"); got != want {
		t.Errorf("resolved path: got %q, want %q", got, want)
	}
}

func TestResolveRootRefNested(t *testing.T) {
	anchor := t.TempDir()
	app := newApp(anchor, strings.NewReader(""), &strings.Builder{}, &strings.Builder{})
	addNamedRoot(t, app, "initramfs", "boot/initramfs")

	// Register a child in the initramfs root's own registry.
	initramfs := filepath.Join(anchor, "boot/initramfs")
	child := newApp(initramfs, strings.NewReader(""), &strings.Builder{}, &strings.Builder{})
	addNamedRoot(t, child, "subroot", "sub")

	got, err := resolveRootRef(context.Background(), anchor, "initramfs.subroot")
	if err != nil {
		t.Fatalf("resolveRootRef nested: %v", err)
	}
	if want := filepath.Join(initramfs, "sub"); got != want {
		t.Errorf("nested resolved path: got %q, want %q", got, want)
	}
}

func TestResolveRootRefUnregisteredIsError(t *testing.T) {
	anchor := t.TempDir()
	// No registry at all, and a registered-but-wrong-name case.
	if _, err := resolveRootRef(context.Background(), anchor, "ghost"); err == nil {
		t.Error("an unregistered name should be a hard error")
	}

	app := newApp(anchor, strings.NewReader(""), &strings.Builder{}, &strings.Builder{})
	addNamedRoot(t, app, "initramfs", "boot/initramfs")
	if _, err := resolveRootRef(context.Background(), anchor, "initramfs.ghost"); err == nil {
		t.Error("an unregistered nested name should be a hard error")
	}
}

func TestResolveRootRefInvalidName(t *testing.T) {
	anchor := t.TempDir()
	if _, err := resolveRootRef(context.Background(), anchor, "Bad Name"); err == nil {
		t.Error("an invalid name (no slash, not grammar-conforming) should error")
	}
}

func TestResolveRootRefCycle(t *testing.T) {
	anchor := t.TempDir()
	// a -> "." (points back at the anchor), then resolve a.a — the second
	// hop revisits the anchor and must be rejected as a cycle.
	app := newApp(anchor, strings.NewReader(""), &strings.Builder{}, &strings.Builder{})
	addNamedRoot(t, app, "a", ".")
	if _, err := resolveRootRef(context.Background(), anchor, "a.a"); err == nil ||
		!strings.Contains(err.Error(), "cycle") {
		t.Errorf("a cycle should be rejected: %v", err)
	}
}

func TestCmdRootAddStoresRelative(t *testing.T) {
	app, out := testApp(t)
	// An absolute path under the root is stored relative to it.
	abs := filepath.Join(app.paths.root, "boot/initramfs")
	if err := cmdRoot(app, []string{"add", "initramfs", abs}); err != nil {
		t.Fatalf("root add: %v", err)
	}
	if !strings.Contains(out.String(), "boot/initramfs") {
		t.Errorf("add output: %q", out.String())
	}
	withDB(t, app, func(store *db.DB) {
		path, found, err := store.NamedRoot(context.Background(), "initramfs")
		if err != nil || !found {
			t.Fatalf("lookup: found=%v err=%v", found, err)
		}
		if path != "boot/initramfs" {
			t.Errorf("stored path: got %q, want relative %q", path, "boot/initramfs")
		}
	})
}

func TestCmdRootAddRejectsInvalidName(t *testing.T) {
	app, _ := testApp(t)
	if err := cmdRoot(app, []string{"add", "Bad.Name", "x"}); err == nil {
		t.Error("root add should reject an invalid name")
	}
}

func TestCmdRootRemove(t *testing.T) {
	app, _ := testApp(t)
	addNamedRoot(t, app, "initramfs", "boot/initramfs")
	if err := cmdRoot(app, []string{"remove", "initramfs"}); err != nil {
		t.Fatalf("root remove: %v", err)
	}
	withDB(t, app, func(store *db.DB) {
		if _, found, _ := store.NamedRoot(context.Background(), "initramfs"); found {
			t.Error("root still registered after remove")
		}
	})
	// Removing an unregistered name is an error (it names nothing).
	if err := cmdRoot(app, []string{"remove", "initramfs"}); err == nil {
		t.Error("removing an unregistered root should error")
	}
}

func TestCmdRootListAndShow(t *testing.T) {
	app, out := testApp(t)

	// Empty registry lists nothing.
	if err := cmdRoot(app, []string{"list"}); err != nil {
		t.Fatalf("root list (empty): %v", err)
	}
	if !strings.Contains(out.String(), "no named roots") {
		t.Errorf("empty list output: %q", out.String())
	}

	addNamedRoot(t, app, "initramfs", "boot/initramfs")
	out.Reset()
	if err := cmdRoot(app, []string{"list"}); err != nil {
		t.Fatalf("root list: %v", err)
	}
	if !strings.Contains(out.String(), "initramfs") {
		t.Errorf("list output missing the root: %q", out.String())
	}

	// show reports the resolved path and dangling status (the tree was
	// never created on disk).
	out.Reset()
	if err := cmdRoot(app, []string{"show", "initramfs"}); err != nil {
		t.Fatalf("root show: %v", err)
	}
	s := out.String()
	if !strings.Contains(s, "dangling") || !strings.Contains(s, "boot/initramfs") {
		t.Errorf("show output: %q", s)
	}
}

// --- Slice 2: default_root top-level placement ---

func TestTopLevelTargetRootSingleDeclared(t *testing.T) {
	app, _ := testApp(t)
	addNamedRoot(t, app, "initramfs", "boot/initramfs")

	locals := []resolver.Candidate{{Name: "live-boot", DefaultRoot: "initramfs"}}
	reqs := []resolver.Request{{Kind: resolver.Install, Name: "live-boot"}}
	got, err := app.topLevelTargetRoot(context.Background(), reqs, locals)
	if err != nil {
		t.Fatalf("topLevelTargetRoot: %v", err)
	}
	if want := filepath.Join(app.paths.root, "boot/initramfs"); got != want {
		t.Errorf("target root: got %q, want %q", got, want)
	}
}

func TestTopLevelTargetRootNoneDeclared(t *testing.T) {
	app, _ := testApp(t)
	locals := []resolver.Candidate{{Name: "ordinary"}} // no default_root
	reqs := []resolver.Request{{Kind: resolver.Install, Name: "ordinary"}}
	got, err := app.topLevelTargetRoot(context.Background(), reqs, locals)
	if err != nil {
		t.Fatalf("topLevelTargetRoot: %v", err)
	}
	if got != app.paths.root {
		t.Errorf("target root: got %q, want the current root %q", got, app.paths.root)
	}
}

func TestTopLevelTargetRootDivergentIsError(t *testing.T) {
	app, _ := testApp(t)
	addNamedRoot(t, app, "initramfs", "boot/initramfs")
	addNamedRoot(t, app, "recovery", "boot/recovery")

	locals := []resolver.Candidate{
		{Name: "a", DefaultRoot: "initramfs"},
		{Name: "b", DefaultRoot: "recovery"},
	}
	reqs := []resolver.Request{
		{Kind: resolver.Install, Name: "a"},
		{Kind: resolver.Install, Name: "b"},
	}
	if _, err := app.topLevelTargetRoot(context.Background(), reqs, locals); err == nil {
		t.Error("divergent default roots should be rejected")
	}
}

// TestDefaultRootEndToEndPlacement installs a local package whose
// default_root names a registered root, with no --root given, and
// confirms the payload lands in that root and is recorded in its DB.
func TestDefaultRootEndToEndPlacement(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pkgBytes, _ := buildSignedPackageEx(t, priv, pub, "live-boot", "1.0-1",
		map[string]string{"init": "#!/bin/sh\n"},
		map[string]any{"default_root": "initramfs"})
	pkgPath := filepath.Join(t.TempDir(), "live-boot_1.0-1_x86_64.peipkg")
	if err := os.WriteFile(pkgPath, pkgBytes, 0o644); err != nil {
		t.Fatalf("write package: %v", err)
	}

	app, _ := testApp(t)
	anchor := app.paths.root
	initramfs := filepath.Join(anchor, "boot/initramfs")
	addNamedRoot(t, app, "initramfs", "boot/initramfs")
	// No --root: default_root should re-root the install into initramfs.
	if err := cmdInstall(app, []string{pkgPath, "--yes"}); err != nil {
		t.Fatalf("install: %v", err)
	}

	if _, err := os.Stat(filepath.Join(initramfs, "init")); err != nil {
		t.Errorf("payload did not land in the initramfs root: %v", err)
	}
	// The app re-rooted: its operating root is now the initramfs.
	if app.paths.root != initramfs {
		t.Errorf("app root after install: got %q, want %q", app.paths.root, initramfs)
	}
	// And nothing landed in the anchor root.
	if _, err := os.Stat(filepath.Join(anchor, "init")); !os.IsNotExist(err) {
		t.Errorf("payload should not be in the anchor root: %v", err)
	}
}

// --- Slice 3: cascade upgrade ---

func TestGatherUpgradeRootsPresentAndDangling(t *testing.T) {
	app, _ := testApp(t)
	start := app.paths.root
	addNamedRoot(t, app, "present", "sub-present")
	addNamedRoot(t, app, "gone", "sub-gone")
	if err := os.MkdirAll(filepath.Join(start, "sub-present"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// sub-gone is never created → dangling.

	present, dangling, err := gatherUpgradeRoots(context.Background(), start)
	if err != nil {
		t.Fatalf("gatherUpgradeRoots: %v", err)
	}
	if len(present) != 2 || present[0] != start {
		t.Errorf("present roots: got %v, want [%s, %s/sub-present]", present, start, start)
	}
	if len(dangling) != 1 || dangling[0] != filepath.Join(start, "sub-gone") {
		t.Errorf("dangling roots: got %v", dangling)
	}
}

func TestCascadeUpgradeVisitsRootsAndSummarises(t *testing.T) {
	app, out := testApp(t)
	start := app.paths.root
	addNamedRoot(t, app, "present", "sub")
	addNamedRoot(t, app, "gone", "missing")
	if err := os.MkdirAll(filepath.Join(start, "sub"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// No repositories configured: each present root has nothing to upgrade,
	// so the cascade succeeds for both and skips the dangling one.
	if err := cmdUpgrade(app, []string{"--yes"}); err != nil {
		t.Fatalf("cascade upgrade: %v", err)
	}
	s := out.String()
	if !strings.Contains(s, "cascade:") {
		t.Errorf("cascade summary missing:\n%s", s)
	}
	if !strings.Contains(s, "2 upgraded") || !strings.Contains(s, "1 skipped") {
		t.Errorf("cascade summary wrong:\n%s", s)
	}
}

func TestUpgradeNoRecurseDoesNotCascade(t *testing.T) {
	app, out := testApp(t)
	addNamedRoot(t, app, "present", "sub")
	if err := os.MkdirAll(filepath.Join(app.paths.root, "sub"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := cmdUpgrade(app, []string{"--yes", "--no-recurse"}); err != nil {
		t.Fatalf("upgrade --no-recurse: %v", err)
	}
	if strings.Contains(out.String(), "cascade:") {
		t.Errorf("--no-recurse should not cascade:\n%s", out.String())
	}
}
