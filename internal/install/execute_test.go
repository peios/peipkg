package install_test

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/peios/peipkg/internal/archive"
	"github.com/peios/peipkg/internal/db"
	"github.com/peios/peipkg/internal/install"
	"github.com/peios/peipkg/internal/manifest"
	"github.com/peios/peipkg/internal/resolver"
	"github.com/peios/peipkg/internal/version"
)

// testPkg describes a package fixture for an execution test.
type testPkg struct {
	name, version string
	files         map[string]string // payload path -> content
	dirs          []string          // payload paths
	symlinks      map[string]string // payload path -> target
}

// fakeProvider serves pre-built verified packages by name.
type fakeProvider map[string]install.ProvidedPackage

func (f fakeProvider) Provide(_ context.Context, op resolver.Operation) (install.ProvidedPackage, error) {
	pp, ok := f[op.Name]
	if !ok {
		return install.ProvidedPackage{}, fmt.Errorf("fakeProvider: no package %q", op.Name)
	}
	return pp, nil
}

func mustVer(t *testing.T, s string) version.Version {
	t.Helper()
	v, err := version.Parse(s)
	if err != nil {
		t.Fatalf("version.Parse(%q): %v", s, err)
	}
	return v
}

// archiveBytes builds a minimal .peipkg container — a zstd-compressed
// tar of just the payload entries, which is all archive.Extract needs.
func archiveBytes(t *testing.T, p testPkg) []byte {
	t.Helper()
	type entry struct {
		name    string
		typ     byte
		content string
		link    string
	}
	var entries []entry
	for path, content := range p.files {
		entries = append(entries, entry{path, tar.TypeReg, content, ""})
	}
	for _, d := range p.dirs {
		entries = append(entries, entry{d + "/", tar.TypeDir, "", ""})
	}
	for path, target := range p.symlinks {
		entries = append(entries, entry{path, tar.TypeSymlink, "", target})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].name < entries[j].name })

	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	for _, e := range entries {
		hdr := &tar.Header{
			Name: e.name, Typeflag: e.typ, Mode: 0o777,
			Size: int64(len(e.content)), Linkname: e.link, ModTime: time.Unix(0, 0),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("WriteHeader %q: %v", e.name, err)
		}
		if e.content != "" {
			if _, err := tw.Write([]byte(e.content)); err != nil {
				t.Fatalf("Write %q: %v", e.name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar Close: %v", err)
	}
	var zBuf bytes.Buffer
	zw, err := zstd.NewWriter(&zBuf)
	if err != nil {
		t.Fatalf("zstd NewWriter: %v", err)
	}
	if _, err := zw.Write(tarBuf.Bytes()); err != nil {
		t.Fatalf("zstd Write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zstd Close: %v", err)
	}
	return zBuf.Bytes()
}

// provide builds the verified ProvidedPackage a fake provider serves.
func provide(t *testing.T, p testPkg) install.ProvidedPackage {
	t.Helper()
	var payload []archive.PayloadEntry
	for path, content := range p.files {
		sum := sha256.Sum256([]byte(content))
		payload = append(payload, archive.PayloadEntry{
			Path: path, Type: archive.EntryFile,
			Size: int64(len(content)), Hash: hex.EncodeToString(sum[:]),
		})
	}
	for _, d := range p.dirs {
		payload = append(payload, archive.PayloadEntry{Path: d, Type: archive.EntryDir})
	}
	for path, target := range p.symlinks {
		payload = append(payload, archive.PayloadEntry{
			Path: path, Type: archive.EntrySymlink, LinkTarget: target})
	}
	pkg := &archive.Package{
		Manifest: manifest.Manifest{
			Name: p.name, Version: mustVer(t, p.version), Architecture: "x86_64",
		},
		ManifestJSON: []byte(fmt.Sprintf(`{"name":%q,"version":%q}`, p.name, p.version)),
		Payload:      payload,
	}
	return install.ProvidedPackage{Pkg: pkg, Archive: bytes.NewReader(archiveBytes(t, p))}
}

// freshEnv returns an open database and the root and lock paths for an
// execution test, all under one temporary directory.
func freshEnv(t *testing.T) (store *db.DB, root, lock string) {
	t.Helper()
	dir := t.TempDir()
	store, err := db.Open(t.Context(), filepath.Join(dir, "db.sqlite"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store, filepath.Join(dir, "root"), filepath.Join(dir, "lock")
}

func installOp(t *testing.T, name, ver string) resolver.Operation {
	return resolver.Operation{
		Kind: resolver.OpInstall, Name: name, ToVersion: mustVer(t, ver),
		Candidate: &resolver.Candidate{Repo: "official"},
	}
}

func TestExecuteInstall(t *testing.T) {
	ctx := t.Context()
	store, root, lock := freshEnv(t)
	nginx := testPkg{
		name: "nginx", version: "1.26.2-3",
		files:    map[string]string{"usr/bin/nginx": "the nginx binary"},
		dirs:     []string{"usr/share/nginx"},
		symlinks: map[string]string{"usr/bin/nginx-latest": "nginx"},
	}
	env := install.Env{
		Root: root, DB: store, LockPath: lock, PeipkgVersion: "0.1.0-test",
		Provider: fakeProvider{"nginx": provide(t, nginx)},
	}
	plan := resolver.Plan{Operations: []resolver.Operation{installOp(t, "nginx", "1.26.2-3")}}

	if _, err := install.Execute(ctx, plan, env); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	// The payload landed at its final path.
	got, err := os.ReadFile(filepath.Join(root, "usr/bin/nginx"))
	if err != nil || string(got) != "the nginx binary" {
		t.Errorf("installed file: content %q, err %v", got, err)
	}
	if target, err := os.Readlink(filepath.Join(root, "usr/bin/nginx-latest")); err != nil ||
		target != "nginx" {
		t.Errorf("installed symlink: target %q, err %v", target, err)
	}
	// The database records the package and its files.
	pkg, found, err := store.GetPackage(ctx, "nginx")
	if err != nil || !found || pkg.Version != "1.26.2-3" {
		t.Errorf("GetPackage: %+v found=%v err=%v", pkg, found, err)
	}
	if files, _ := store.PackageFiles(ctx, "nginx"); len(files) != 3 {
		t.Errorf("PackageFiles: got %d, want 3", len(files))
	}
	// The transaction committed and is no longer pending.
	if _, pending, _ := store.PendingTxn(ctx); pending {
		t.Error("a transaction is still pending after a successful install")
	}
}

func TestExecuteInstallMultiplePackages(t *testing.T) {
	ctx := t.Context()
	store, root, lock := freshEnv(t)
	env := install.Env{
		Root: root, DB: store, LockPath: lock, PeipkgVersion: "0.1.0-test",
		Provider: fakeProvider{
			"libc":  provide(t, testPkg{name: "libc", version: "2.39-1", files: map[string]string{"usr/lib/libc.so": "libc"}}),
			"nginx": provide(t, testPkg{name: "nginx", version: "1.0-1", files: map[string]string{"usr/bin/nginx": "nginx"}}),
		},
	}
	plan := resolver.Plan{Operations: []resolver.Operation{
		installOp(t, "libc", "2.39-1"),
		installOp(t, "nginx", "1.0-1"),
	}}
	if _, err := install.Execute(ctx, plan, env); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	for _, name := range []string{"libc", "nginx"} {
		if _, found, _ := store.GetPackage(ctx, name); !found {
			t.Errorf("%s was not installed", name)
		}
	}
}

func TestExecuteRemove(t *testing.T) {
	ctx := t.Context()
	store, root, lock := freshEnv(t)
	baseEnv := install.Env{Root: root, DB: store, LockPath: lock, PeipkgVersion: "0.1.0-test"}

	installEnv := baseEnv
	installEnv.Provider = fakeProvider{"nginx": provide(t, testPkg{
		name: "nginx", version: "1.0-1", files: map[string]string{"usr/bin/nginx": "nginx"}})}
	if _, err := install.Execute(ctx, resolver.Plan{Operations: []resolver.Operation{
		installOp(t, "nginx", "1.0-1")}}, installEnv); err != nil {
		t.Fatalf("Execute (install): %v", err)
	}

	removeEnv := baseEnv
	removeEnv.Provider = fakeProvider{}
	removePlan := resolver.Plan{Operations: []resolver.Operation{
		{Kind: resolver.OpRemove, Name: "nginx", FromVersion: mustVer(t, "1.0-1")}}}
	if _, err := install.Execute(ctx, removePlan, removeEnv); err != nil {
		t.Fatalf("Execute (remove): %v", err)
	}

	if _, err := os.Lstat(filepath.Join(root, "usr/bin/nginx")); !os.IsNotExist(err) {
		t.Error("the removed file is still present")
	}
	if _, found, _ := store.GetPackage(ctx, "nginx"); found {
		t.Error("the removed package is still in the database")
	}
}

func TestExecuteUpgradeReplacesFiles(t *testing.T) {
	ctx := t.Context()
	store, root, lock := freshEnv(t)
	baseEnv := install.Env{Root: root, DB: store, LockPath: lock, PeipkgVersion: "0.1.0-test"}

	// Install version 1.0 with files A and B.
	installEnv := baseEnv
	installEnv.Provider = fakeProvider{"app": provide(t, testPkg{
		name: "app", version: "1.0-1",
		files: map[string]string{"usr/bin/app": "v1 binary", "usr/share/app/old": "obsolete"}})}
	if _, err := install.Execute(ctx, resolver.Plan{Operations: []resolver.Operation{
		installOp(t, "app", "1.0-1")}}, installEnv); err != nil {
		t.Fatalf("Execute (install): %v", err)
	}

	// Upgrade to 1.1: file A changes, file B is gone, file C is new.
	upgradeEnv := baseEnv
	upgradeEnv.Provider = fakeProvider{"app": provide(t, testPkg{
		name: "app", version: "1.1-1",
		files: map[string]string{"usr/bin/app": "v1.1 binary", "usr/share/app/new": "fresh"}})}
	upgradePlan := resolver.Plan{Operations: []resolver.Operation{{
		Kind: resolver.OpUpgrade, Name: "app",
		FromVersion: mustVer(t, "1.0-1"), ToVersion: mustVer(t, "1.1-1"),
		Candidate: &resolver.Candidate{Repo: "official"},
	}}}
	if _, err := install.Execute(ctx, upgradePlan, upgradeEnv); err != nil {
		t.Fatalf("Execute (upgrade): %v", err)
	}

	if got, _ := os.ReadFile(filepath.Join(root, "usr/bin/app")); string(got) != "v1.1 binary" {
		t.Errorf("upgraded file: content %q", got)
	}
	if _, err := os.Lstat(filepath.Join(root, "usr/share/app/old")); !os.IsNotExist(err) {
		t.Error("the obsolete file was not removed by the upgrade")
	}
	if got, _ := os.ReadFile(filepath.Join(root, "usr/share/app/new")); string(got) != "fresh" {
		t.Errorf("the new file was not installed: %q", got)
	}
	if pkg, _, _ := store.GetPackage(ctx, "app"); pkg.Version != "1.1-1" {
		t.Errorf("database version after upgrade: %q, want 1.1-1", pkg.Version)
	}
}

func TestExecuteRecoversPendingTransaction(t *testing.T) {
	ctx := t.Context()
	store, root, lock := freshEnv(t)

	// Simulate a crashed run: a staged file on disk and a pending
	// journal naming it, with no commit.
	stagedPath := filepath.Join(root, "usr/bin/ghost.peipkg-staged-1")
	if err := os.MkdirAll(filepath.Dir(stagedPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(stagedPath, []byte("orphaned"), 0o644); err != nil {
		t.Fatalf("write staged: %v", err)
	}
	txnID, err := store.BeginTxn(ctx, "0.1.0-test", 1)
	if err != nil {
		t.Fatalf("BeginTxn: %v", err)
	}
	if err := store.InsertTxnOps(ctx, txnID, []db.TxnOp{
		{Seq: 0, PackageName: "ghost", Action: db.OpInstall, ToVersion: "1.0-1"}}); err != nil {
		t.Fatalf("InsertTxnOps: %v", err)
	}
	if err := store.InsertTxnFiles(ctx, txnID, []db.TxnFile{
		{Seq: 0, PackageName: "ghost", FinalPath: filepath.Join(root, "usr/bin/ghost"),
			Action: db.FileCreate, StagedPath: stagedPath}}); err != nil {
		t.Fatalf("InsertTxnFiles: %v", err)
	}

	// A new execution recovers the pending transaction before doing
	// anything else.
	env := install.Env{Root: root, DB: store, LockPath: lock, PeipkgVersion: "0.1.0-test",
		Provider: fakeProvider{}}
	if _, err := install.Execute(ctx, resolver.Plan{}, env); err != nil {
		t.Fatalf("Execute (recovery): %v", err)
	}
	if _, err := os.Lstat(stagedPath); !os.IsNotExist(err) {
		t.Error("recovery did not discard the orphaned staged file")
	}
	if _, pending, _ := store.PendingTxn(ctx); pending {
		t.Error("a transaction is still pending after recovery")
	}
}

func TestExecuteEmptyPlan(t *testing.T) {
	store, root, lock := freshEnv(t)
	env := install.Env{Root: root, DB: store, LockPath: lock,
		PeipkgVersion: "0.1.0-test", Provider: fakeProvider{}}
	if _, err := install.Execute(t.Context(), resolver.Plan{}, env); err != nil {
		t.Errorf("Execute of an empty plan: %v", err)
	}
}
