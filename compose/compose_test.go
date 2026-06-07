package compose

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBuildRejectsFlagConflict(t *testing.T) {
	_, err := Build(context.Background(), BuildOptions{
		ManifestPath: "unused",
		OutDir:       "unused",
		Locked:       true,
		Update:       true,
	})
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("Build error = %v, want mutual-exclusion error", err)
	}
}

func TestLockRoundTrip(t *testing.T) {
	lock := Lock{
		Arch:       "x86_64",
		SourceDate: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
		Manifest:   "peipkg.toml",
		Packages: []LockedPackage{{
			Name:         "base",
			Version:      "1.0-1",
			Architecture: "x86_64",
			Source:       "official",
			URL:          "https://pkgs.peios.org/base.peipkg",
			Hash:         strings.Repeat("a", 64),
		}},
	}

	encoded, err := lock.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	decoded, err := DecodeLock(encoded)
	if err != nil {
		t.Fatalf("DecodeLock: %v", err)
	}
	if decoded.Arch != lock.Arch || decoded.Manifest != lock.Manifest ||
		len(decoded.Packages) != 1 || decoded.Packages[0].Name != "base" {
		t.Fatalf("decoded lock = %+v, want %+v", decoded, lock)
	}

	path := filepath.Join(t.TempDir(), "root.lock.toml")
	if err := os.WriteFile(path, encoded, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	loaded, err := LoadLock(path)
	if err != nil {
		t.Fatalf("LoadLock: %v", err)
	}
	if loaded.Packages[0].Hash != lock.Packages[0].Hash {
		t.Fatalf("loaded hash = %q, want %q", loaded.Packages[0].Hash, lock.Packages[0].Hash)
	}
}

func TestLockPath(t *testing.T) {
	got := LockPath("peipkg-manifest.toml")
	if want := "peipkg-manifest.lock.toml"; got != want {
		t.Fatalf("LockPath = %q, want %q", got, want)
	}
}
