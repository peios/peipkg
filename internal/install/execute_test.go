package install_test

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"syscall"
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
	// special marks the package as declaring special_system_package —
	// its half of the two-key §3.4 layout exemption.
	special bool
	// provides is the package's provides array, for the §5.21
	// inflated-provides-version rule.
	provides []manifest.Provides
	// sdOverrides is the package's §3.3.5 sd_overrides, payload path ->
	// descriptor bytes. The bytes are opaque here: the manifest layer
	// parses them, and by the time install sees an override it is
	// already known to be well-formed and to name a real entry.
	sdOverrides map[string]string
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
			Uid: 0, Gid: 0, Uname: "root", Gname: "root", Format: tar.FormatPAX,
			Size: int64(len(e.content)), Linkname: e.link,
			ModTime: time.Date(2026, 5, 19, 0, 0, 0, 0, time.UTC),
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
	var overrides []manifest.SDOverride
	for _, path := range slices.Sorted(maps.Keys(p.sdOverrides)) {
		overrides = append(overrides,
			manifest.SDOverride{Path: path, SD: []byte(p.sdOverrides[path])})
	}
	pkg := &archive.Package{
		Manifest: manifest.Manifest{
			Name: p.name, Version: mustVer(t, p.version), Architecture: "x86_64",
			SpecialSystemPackage: p.special,
			Provides:             p.provides,
			SDOverrides:          overrides,
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
			"libc":  provide(t, testPkg{name: "libc", version: "2.39-1", files: map[string]string{"usr/lib/x86_64-linux-peios/libc.so": "libc"}}),
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

func TestExecuteRecoversPendingTransactionRemovesCreatedDirs(t *testing.T) {
	ctx := t.Context()
	store, root, lock := freshEnv(t)

	dir := filepath.Join(root, "usr/share/ghost")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir staged dir: %v", err)
	}
	txnID, err := store.BeginTxn(ctx, "0.1.0-test", 2)
	if err != nil {
		t.Fatalf("BeginTxn: %v", err)
	}
	if err := store.InsertTxnDirs(ctx, txnID, []db.TxnDir{
		{Seq: 0, Path: filepath.Join(root, "usr")},
		{Seq: 1, Path: filepath.Join(root, "usr/share")},
		{Seq: 2, Path: dir},
	}); err != nil {
		t.Fatalf("InsertTxnDirs: %v", err)
	}

	env := install.Env{Root: root, DB: store, LockPath: lock, PeipkgVersion: "0.1.0-test",
		Provider: fakeProvider{}}
	if _, err := install.Execute(ctx, resolver.Plan{}, env); err != nil {
		t.Fatalf("Execute (recovery): %v", err)
	}
	if _, err := os.Lstat(dir); !os.IsNotExist(err) {
		t.Fatalf("recovery did not remove created dir: %v", err)
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

// upgradeOp builds the plan operation for an app upgrade.
func upgradeOp(t *testing.T, from, to string) resolver.Operation {
	return resolver.Operation{
		Kind: resolver.OpUpgrade, Name: "app",
		FromVersion: mustVer(t, from), ToVersion: mustVer(t, to),
		Candidate: &resolver.Candidate{Repo: "official"},
	}
}

func TestExecuteUpgradeKeepsModifiedEtcFile(t *testing.T) {
	ctx := t.Context()
	store, root, lock := freshEnv(t)
	baseEnv := install.Env{Root: root, DB: store, LockPath: lock, PeipkgVersion: "0.1.0-test"}

	installEnv := baseEnv
	installEnv.Provider = fakeProvider{"app": provide(t, testPkg{
		name: "app", version: "1.0-1",
		files: map[string]string{"usr/etc/app.conf": "default config v1"}})}
	if _, err := install.Execute(ctx, resolver.Plan{Operations: []resolver.Operation{
		installOp(t, "app", "1.0-1")}}, installEnv); err != nil {
		t.Fatalf("Execute (install): %v", err)
	}

	// The operator edits the config file after install.
	confPath := filepath.Join(root, "usr/etc/app.conf")
	if err := os.WriteFile(confPath, []byte("operator's edits"), 0o644); err != nil {
		t.Fatalf("edit conf: %v", err)
	}

	upgradeEnv := baseEnv
	upgradeEnv.Provider = fakeProvider{"app": provide(t, testPkg{
		name: "app", version: "1.1-1",
		files: map[string]string{"usr/etc/app.conf": "default config v2"}})}
	result, err := install.Execute(ctx, resolver.Plan{
		Operations: []resolver.Operation{upgradeOp(t, "1.0-1", "1.1-1")}}, upgradeEnv)
	if err != nil {
		t.Fatalf("Execute (upgrade): %v", err)
	}

	// §7.2.2: the operator's file is kept; the new default lands beside it.
	if got, _ := os.ReadFile(confPath); string(got) != "operator's edits" {
		t.Errorf("modified /etc file: content %q, want the operator's edits", got)
	}
	if got, _ := os.ReadFile(confPath + ".peipkg-new"); string(got) != "default config v2" {
		t.Errorf(".peipkg-new: content %q, want the new default", got)
	}
	if len(result.Warnings) == 0 {
		t.Error("the upgrade did not report the modified /etc file")
	}
}

func TestExecuteUpgradeReplacesUnmodifiedEtcFile(t *testing.T) {
	ctx := t.Context()
	store, root, lock := freshEnv(t)
	baseEnv := install.Env{Root: root, DB: store, LockPath: lock, PeipkgVersion: "0.1.0-test"}

	installEnv := baseEnv
	installEnv.Provider = fakeProvider{"app": provide(t, testPkg{
		name: "app", version: "1.0-1",
		files: map[string]string{"usr/etc/app.conf": "default config v1"}})}
	if _, err := install.Execute(ctx, resolver.Plan{Operations: []resolver.Operation{
		installOp(t, "app", "1.0-1")}}, installEnv); err != nil {
		t.Fatalf("Execute (install): %v", err)
	}

	// The operator leaves the file untouched, so the upgrade replaces it.
	upgradeEnv := baseEnv
	upgradeEnv.Provider = fakeProvider{"app": provide(t, testPkg{
		name: "app", version: "1.1-1",
		files: map[string]string{"usr/etc/app.conf": "default config v2"}})}
	if _, err := install.Execute(ctx, resolver.Plan{
		Operations: []resolver.Operation{upgradeOp(t, "1.0-1", "1.1-1")}}, upgradeEnv); err != nil {
		t.Fatalf("Execute (upgrade): %v", err)
	}

	confPath := filepath.Join(root, "usr/etc/app.conf")
	if got, _ := os.ReadFile(confPath); string(got) != "default config v2" {
		t.Errorf("an unmodified /etc file should be replaced: content %q", got)
	}
	if _, err := os.Lstat(confPath + ".peipkg-new"); !os.IsNotExist(err) {
		t.Error("an unmodified /etc file should not produce a .peipkg-new")
	}
}

func TestExecuteDiscardsBackupsAfterCommit(t *testing.T) {
	ctx := t.Context()
	store, root, lock := freshEnv(t)
	baseEnv := install.Env{Root: root, DB: store, LockPath: lock, PeipkgVersion: "0.1.0-test"}

	installEnv := baseEnv
	installEnv.Provider = fakeProvider{"app": provide(t, testPkg{
		name: "app", version: "1.0-1", files: map[string]string{"usr/bin/app": "v1"}})}
	if _, err := install.Execute(ctx, resolver.Plan{Operations: []resolver.Operation{
		installOp(t, "app", "1.0-1")}}, installEnv); err != nil {
		t.Fatalf("Execute (install): %v", err)
	}
	upgradeEnv := baseEnv
	upgradeEnv.Provider = fakeProvider{"app": provide(t, testPkg{
		name: "app", version: "1.1-1", files: map[string]string{"usr/bin/app": "v2"}})}
	if _, err := install.Execute(ctx, resolver.Plan{
		Operations: []resolver.Operation{upgradeOp(t, "1.0-1", "1.1-1")}}, upgradeEnv); err != nil {
		t.Fatalf("Execute (upgrade): %v", err)
	}

	// §7.2.2 step 4.3: no backup survives a committed transaction.
	entries, err := os.ReadDir(filepath.Join(root, "usr/bin"))
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".peipkg-backup-") {
			t.Errorf("backup %q survived the committed transaction", e.Name())
		}
	}
}

// §7.2.2 keeps an operator-edited /etc file and writes the new default
// beside it. The database row for the logical path was still written with
// the *new version's* hash, so it described bytes that are not there.
//
// Two consequences, and the first is the serious one: `peipkg verify`
// reported the path as modified forever, on every run, for a file peipkg
// itself deliberately preserved — poisoning the one signal an operator
// has for a failed rollback or for tampering. And the .peipkg-new file
// was recorded nowhere, so uninstall never removed it and `peipkg owns`
// could not attribute it.
func TestPreservedEtcFileIsRecordedAsWhatIsActuallyOnDisk(t *testing.T) {
	ctx := t.Context()
	store, root, lock := freshEnv(t)
	baseEnv := install.Env{Root: root, DB: store, LockPath: lock, PeipkgVersion: "0.1.0-test"}

	installEnv := baseEnv
	installEnv.Provider = fakeProvider{"app": provide(t, testPkg{
		name: "app", version: "1.0-1",
		files: map[string]string{"usr/etc/app.conf": "default config v1"}})}
	if _, err := install.Execute(ctx, resolver.Plan{Operations: []resolver.Operation{
		installOp(t, "app", "1.0-1")}}, installEnv); err != nil {
		t.Fatalf("Execute (install): %v", err)
	}

	const edits = "operator's edits"
	confPath := filepath.Join(root, "usr/etc/app.conf")
	if err := os.WriteFile(confPath, []byte(edits), 0o644); err != nil {
		t.Fatalf("edit conf: %v", err)
	}

	upgradeEnv := baseEnv
	upgradeEnv.Provider = fakeProvider{"app": provide(t, testPkg{
		name: "app", version: "1.1-1",
		files: map[string]string{"usr/etc/app.conf": "default config v2"}})}
	if _, err := install.Execute(ctx, resolver.Plan{
		Operations: []resolver.Operation{upgradeOp(t, "1.0-1", "1.1-1")}}, upgradeEnv); err != nil {
		t.Fatalf("Execute (upgrade): %v", err)
	}

	files, err := store.PackageFiles(ctx, "app")
	if err != nil {
		t.Fatalf("PackageFiles: %v", err)
	}
	byPath := map[string]string{}
	for _, f := range files {
		byPath[f.Path] = f.Hash
	}

	// The recorded hash must describe the bytes that are actually at the
	// logical path — the operator's — so a verify run comes back clean.
	editsSum := sha256.Sum256([]byte(edits))
	wantPreserved := hex.EncodeToString(editsSum[:])
	if got := byPath["/usr/etc/app.conf"]; got != wantPreserved {
		t.Errorf("recorded hash for the preserved file = %q, want the on-disk hash %q",
			got, wantPreserved)
	}

	// And .peipkg-new must be an owned file rather than an orphan.
	newSum := sha256.Sum256([]byte("default config v2"))
	wantNew := hex.EncodeToString(newSum[:])
	got, owned := byPath["/usr/etc/app.conf.peipkg-new"]
	if !owned {
		t.Fatal(".peipkg-new is not recorded in package_file, so it is an orphan")
	}
	if got != wantNew {
		t.Errorf(".peipkg-new hash = %q, want the new version's %q", got, wantNew)
	}
}

// §7.1.2.2 step 3 requires a consumer to verify that no payload path
// collides with a path already owned by another installed package.
//
// No prepare-time check existed. The sole enforcement was the unique
// index on package_file, which fires inside the commit transaction — that
// is, after a full download, extraction, and an on-disk clobber in which
// the victim's file has already been renamed aside and the new file
// renamed into place. The collision was caught, but only after paying for
// it, with recovery depending entirely on the rollback succeeding.
func TestCollidingPayloadPathIsRejectedBeforeAnythingIsStaged(t *testing.T) {
	ctx := t.Context()
	store, root, lock := freshEnv(t)
	baseEnv := install.Env{Root: root, DB: store, LockPath: lock, PeipkgVersion: "0.1.0-test"}

	const shared = "usr/bin/tool"
	firstEnv := baseEnv
	firstEnv.Provider = fakeProvider{"alpha": provide(t, testPkg{
		name: "alpha", version: "1.0-1",
		files: map[string]string{shared: "alpha's tool"}})}
	if _, err := install.Execute(ctx, resolver.Plan{Operations: []resolver.Operation{
		installOp(t, "alpha", "1.0-1")}}, firstEnv); err != nil {
		t.Fatalf("Execute (alpha): %v", err)
	}

	secondEnv := baseEnv
	secondEnv.Provider = fakeProvider{"beta": provide(t, testPkg{
		name: "beta", version: "1.0-1",
		files: map[string]string{shared: "beta's tool"}})}
	_, err := install.Execute(ctx, resolver.Plan{Operations: []resolver.Operation{
		installOp(t, "beta", "1.0-1")}}, secondEnv)
	if err == nil {
		t.Fatal("installing a package over another's payload path succeeded")
	}
	if !strings.Contains(err.Error(), "already owned by alpha") {
		t.Errorf("error %q does not name the owning package", err)
	}

	// The victim's file must be untouched — the whole point of catching
	// this before staging rather than after the clobber.
	if got, _ := os.ReadFile(filepath.Join(root, shared)); string(got) != "alpha's tool" {
		t.Errorf("alpha's file is %q after the rejected install, want it untouched", got)
	}
	// And no staged sibling may be left behind.
	entries, err := os.ReadDir(filepath.Join(root, "usr/bin"))
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if e.Name() != "tool" {
			t.Errorf("residue left in usr/bin after the rejected install: %s", e.Name())
		}
	}
}

// A path owned by a package the same transaction is upgrading or removing
// is not a collision — the transaction is what frees it. Without that
// exemption the check would reject every upgrade.
func TestUpgradeAndReplacementAreNotCollisions(t *testing.T) {
	ctx := t.Context()
	store, root, lock := freshEnv(t)
	baseEnv := install.Env{Root: root, DB: store, LockPath: lock, PeipkgVersion: "0.1.0-test"}

	const shared = "usr/bin/tool"
	firstEnv := baseEnv
	firstEnv.Provider = fakeProvider{"app": provide(t, testPkg{
		name: "app", version: "1.0-1",
		files: map[string]string{shared: "v1"}})}
	if _, err := install.Execute(ctx, resolver.Plan{Operations: []resolver.Operation{
		installOp(t, "app", "1.0-1")}}, firstEnv); err != nil {
		t.Fatalf("Execute (install): %v", err)
	}

	// The same package upgrading over its own path.
	upEnv := baseEnv
	upEnv.Provider = fakeProvider{"app": provide(t, testPkg{
		name: "app", version: "1.1-1",
		files: map[string]string{shared: "v2"}})}
	if _, err := install.Execute(ctx, resolver.Plan{Operations: []resolver.Operation{
		upgradeOp(t, "1.0-1", "1.1-1")}}, upEnv); err != nil {
		t.Fatalf("Execute (upgrade over its own path): %v", err)
	}
	if got, _ := os.ReadFile(filepath.Join(root, shared)); string(got) != "v2" {
		t.Errorf("after upgrade the file is %q, want v2", got)
	}
}

// §5.21: "A provides.version greater than the providing package's own
// version MUST generate an operator warning at install time, because an
// inflated provides-version defeats constraint-based resolution."
//
// It was implemented nowhere. The attack is live rather than
// theoretical: libfoo 1.0-1 declaring provides libfoo 5.0 satisfies a
// `>= 4.0` dependency and installs silently. Where a genuine libfoo
// 4.0-1 is also a candidate it wins on the name match, so this lands
// exactly where the real package is absent — the shadowing case the
// warning exists for.
func TestInflatedProvidesVersionWarns(t *testing.T) {
	ctx := t.Context()
	store, root, lock := freshEnv(t)
	env := install.Env{Root: root, DB: store, LockPath: lock, PeipkgVersion: "0.1.0-test"}
	env.Provider = fakeProvider{"libfoo": provide(t, testPkg{
		name: "libfoo", version: "1.0-1",
		provides: []manifest.Provides{{Name: "libfoo", Version: verPtr(t, "5.0-1")}},
		files:    map[string]string{"usr/lib/x86_64-linux-peios/libfoo.so": "x"}})}

	result, err := install.Execute(ctx, resolver.Plan{Operations: []resolver.Operation{
		installOp(t, "libfoo", "1.0-1")}}, env)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	var found bool
	for _, w := range result.Warnings {
		if strings.Contains(w, "libfoo") && strings.Contains(w, "5.0-1") {
			found = true
		}
	}
	if !found {
		t.Errorf("an inflated provides-version produced no warning; got %v", result.Warnings)
	}
}

// A provides-version at or below the package's own version is the normal
// case and must stay quiet, or the warning is noise.
func TestProvidesVersionAtOrBelowDoesNotWarn(t *testing.T) {
	for _, pv := range []string{"1.0-1", "0.9-1"} {
		t.Run(pv, func(t *testing.T) {
			ctx := t.Context()
			store, root, lock := freshEnv(t)
			env := install.Env{Root: root, DB: store, LockPath: lock, PeipkgVersion: "0.1.0-test"}
			env.Provider = fakeProvider{"libfoo": provide(t, testPkg{
				name: "libfoo", version: "1.0-1",
				provides: []manifest.Provides{{Name: "libfoo", Version: verPtr(t, pv)}},
				files:    map[string]string{"usr/lib/x86_64-linux-peios/libfoo.so": "x"}})}

			result, err := install.Execute(ctx, resolver.Plan{Operations: []resolver.Operation{
				installOp(t, "libfoo", "1.0-1")}}, env)
			if err != nil {
				t.Fatalf("Execute: %v", err)
			}
			for _, w := range result.Warnings {
				if strings.Contains(w, "inflated") {
					t.Errorf("provides %s produced an inflation warning: %s", pv, w)
				}
			}
		})
	}
}

func verPtr(t *testing.T, s string) *version.Version {
	t.Helper()
	v := mustVer(t, s)
	return &v
}

// §7.2.2: "Files in both old and new with identical content hash:
// untouched." Every upgrade used to rewrite and re-back-up its whole
// payload, bit-identical files included (PEI-400).
func TestUpgradeLeavesUnchangedFilesUntouched(t *testing.T) {
	ctx := t.Context()
	store, root, lock := freshEnv(t)

	v1 := testPkg{name: "app", version: "1.0-1", files: map[string]string{
		"usr/bin/app":        "the binary",
		"usr/share/app/data": "unchanging data",
	}}
	env := install.Env{Root: root, DB: store, LockPath: lock, PeipkgVersion: "test",
		Provider: fakeProvider{"app": provide(t, v1)}}
	if _, err := install.Execute(ctx,
		resolver.Plan{Operations: []resolver.Operation{installOp(t, "app", "1.0-1")}},
		env); err != nil {
		t.Fatalf("install: %v", err)
	}

	unchanged := filepath.Join(root, "usr/share/app/data")
	before, err := os.Stat(unchanged)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	beforeIno := before.Sys().(*syscall.Stat_t).Ino

	// The upgrade changes the binary and leaves the data byte-identical.
	v2 := testPkg{name: "app", version: "2.0-1", files: map[string]string{
		"usr/bin/app":        "the new binary",
		"usr/share/app/data": "unchanging data",
	}}
	env.Provider = fakeProvider{"app": provide(t, v2)}
	if _, err := install.Execute(ctx,
		resolver.Plan{Operations: []resolver.Operation{upgradeOp(t, "1.0-1", "2.0-1")}},
		env); err != nil {
		t.Fatalf("upgrade: %v", err)
	}

	after, err := os.Stat(unchanged)
	if err != nil {
		t.Fatalf("the unchanged file is gone after the upgrade: %v", err)
	}
	if got := after.Sys().(*syscall.Stat_t).Ino; got != beforeIno {
		t.Errorf("the unchanged file was rewritten: inode %d -> %d", beforeIno, got)
	}
	if got, err := os.ReadFile(unchanged); err != nil || string(got) != "unchanging data" {
		t.Errorf("unchanged file holds %q (err %v)", got, err)
	}
	// The changed one did move.
	if got, err := os.ReadFile(filepath.Join(root, "usr/bin/app")); err != nil ||
		string(got) != "the new binary" {
		t.Errorf("the changed file did not update: %q (err %v)", got, err)
	}
	// And ownership survives: an untouched file is still the new
	// version's, or uninstall would leave it behind.
	files, err := store.PackageFiles(ctx, "app")
	if err != nil {
		t.Fatalf("PackageFiles: %v", err)
	}
	var found bool
	for _, f := range files {
		if f.Path == "/usr/share/app/data" {
			found = true
		}
	}
	if !found {
		t.Error("the untouched file lost its package_file row")
	}
}

// A file deleted by hand is not untouched: an upgrade is the right
// moment to put it back.
func TestUpgradeRestoresAnUnchangedFileThatWasDeleted(t *testing.T) {
	ctx := t.Context()
	store, root, lock := freshEnv(t)
	pkg := func(v string) testPkg {
		return testPkg{name: "app", version: v, files: map[string]string{
			"usr/share/app/data": "unchanging data"}}
	}
	env := install.Env{Root: root, DB: store, LockPath: lock, PeipkgVersion: "test",
		Provider: fakeProvider{"app": provide(t, pkg("1.0-1"))}}
	if _, err := install.Execute(ctx,
		resolver.Plan{Operations: []resolver.Operation{installOp(t, "app", "1.0-1")}},
		env); err != nil {
		t.Fatalf("install: %v", err)
	}
	victim := filepath.Join(root, "usr/share/app/data")
	if err := os.Remove(victim); err != nil {
		t.Fatalf("remove: %v", err)
	}

	env.Provider = fakeProvider{"app": provide(t, pkg("2.0-1"))}
	if _, err := install.Execute(ctx,
		resolver.Plan{Operations: []resolver.Operation{upgradeOp(t, "1.0-1", "2.0-1")}},
		env); err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	if got, err := os.ReadFile(victim); err != nil || string(got) != "unchanging data" {
		t.Errorf("the deleted file was not restored: %q (err %v)", got, err)
	}
}
