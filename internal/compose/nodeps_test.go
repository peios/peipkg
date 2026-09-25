package compose

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// noDepsFixture writes a local package "tool" that depends on "absent",
// which nothing provides, and a manifest asking for tool.
func noDepsFixture(t *testing.T) (manifestPath string) {
	t.Helper()
	dir := t.TempDir()
	var doc map[string]any
	if err := json.Unmarshal(minimalManifestJSON(t, "tool", "1.0-1", "x86_64", 1), &doc); err != nil {
		t.Fatal(err)
	}
	doc["dependencies"] = []any{map[string]any{"name": "absent", "constraint": ">= 1"}}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	raw := buildPeipkg(t, data, []testEntry{{Path: "usr/bin/tool", Content: []byte("x")}})
	if err := os.WriteFile(filepath.Join(dir, "tool.peipkg"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	manifestPath = filepath.Join(dir, "manifest.toml")
	if err := os.WriteFile(manifestPath, []byte(`
schema = 1
arch = "x86_64"
source_date = "2026-06-01T00:00:00Z"
local_packages = ["*.peipkg"]

[[package]]
name = "tool"
`), 0o644); err != nil {
		t.Fatal(err)
	}
	return manifestPath
}

// Without dependencies, a package whose dependency the sources cannot
// satisfy still composes: the root holds exactly that package, and the lock
// says so. With dependencies the same manifest fails to resolve.
func TestBuildNoDependencies(t *testing.T) {
	manifestPath := noDepsFixture(t)
	dir := filepath.Dir(manifestPath)

	_, err := BuildWithResult(context.Background(), BuildOptions{
		ManifestPath: manifestPath, OutDir: filepath.Join(dir, "full"),
		LockPath: filepath.Join(dir, "full.lock.toml"),
	})
	if err == nil || !strings.Contains(err.Error(), "absent") {
		t.Fatalf("build with dependencies = %v, want an unsatisfied-dependency failure", err)
	}

	lockPath := filepath.Join(dir, "files.lock.toml")
	outDir := filepath.Join(dir, "files")
	result, err := BuildWithResult(context.Background(), BuildOptions{
		ManifestPath: manifestPath, OutDir: outDir, LockPath: lockPath, NoDependencies: true,
	})
	if err != nil {
		t.Fatalf("build without dependencies: %v", err)
	}
	if result.PackageCount != 1 || !result.Lock.NoDependencies {
		t.Fatalf("result = %+v, want one package and a no-dependencies lock", result)
	}
	if _, err := os.Stat(filepath.Join(outDir, "usr/bin/tool")); err != nil {
		t.Fatalf("tool's payload missing: %v", err)
	}
	lock, err := LoadLock(lockPath)
	if err != nil {
		t.Fatalf("reading the written lock: %v", err)
	}
	if !lock.NoDependencies {
		t.Fatal("the written lock lost no_dependencies")
	}
}

// A lock resolved without dependencies never stands in for a complete root,
// and a complete lock is not reused for a no-dependencies build.
func TestNoDependenciesLockModeIsEnforced(t *testing.T) {
	manifestPath := noDepsFixture(t)
	dir := filepath.Dir(manifestPath)
	lockPath := filepath.Join(dir, "files.lock.toml")
	if _, err := BuildWithResult(context.Background(), BuildOptions{
		ManifestPath: manifestPath, OutDir: filepath.Join(dir, "first"), LockPath: lockPath,
		NoDependencies: true,
	}); err != nil {
		t.Fatalf("build without dependencies: %v", err)
	}
	for name, opts := range map[string]BuildOptions{
		"default": {ManifestPath: manifestPath, OutDir: filepath.Join(dir, "second"), LockPath: lockPath},
		"locked":  {ManifestPath: manifestPath, OutDir: filepath.Join(dir, "third"), LockPath: lockPath, Locked: true},
	} {
		if _, err := BuildWithResult(context.Background(), opts); err == nil ||
			!strings.Contains(err.Error(), "without dependencies") {
			t.Errorf("%s reuse of a no-dependencies lock = %v, want a refusal", name, err)
		}
	}

	// The reverse: a complete lock, requested without dependencies.
	full := Lock{}
	full.NoDependencies = false
	if err := ensureLockMode(full, true); err == nil {
		t.Fatal("a complete lock was accepted for a no-dependencies build")
	}
}
