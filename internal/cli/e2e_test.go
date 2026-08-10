package cli

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/peios/peipkg/internal/archive"
	"github.com/peios/peipkg/internal/audit"
	"github.com/peios/peipkg/internal/db"
	"github.com/peios/peipkg/internal/manifest"
	"github.com/peios/peipkg/internal/resolver"
	"github.com/peios/peipkg/internal/signature"
	"github.com/peios/peipkg/internal/version"
)

// detachedSig builds a detached-signature .sig body: a signature envelope
// (§5.1.3) over SHA-256 of content — the scheme VerifyDetached expects.
func detachedSig(priv ed25519.PrivateKey, content []byte) []byte {
	digest := sha256.Sum256(content)
	env, _ := json.Marshal(map[string]any{
		"schema_version":  1,
		"algorithm":       "ed25519",
		"key_fingerprint": signature.Fingerprint(priv.Public().(ed25519.PublicKey)),
		"signature":       base64.RawStdEncoding.EncodeToString(ed25519.Sign(priv, digest[:])),
	})
	return env
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return data
}

// buildSignedPackage assembles a signed .peipkg for one package whose
// payload is the given files (payload path -> content).
func buildSignedPackage(t *testing.T, priv ed25519.PrivateKey, pub ed25519.PublicKey,
	name, ver string, files map[string]string) (data []byte, sizeInstalled int64) {
	return buildSignedPackageEx(t, priv, pub, name, ver, files, nil)
}

// buildSignedPackageEx is buildSignedPackage with extra manifest fields
// merged in (e.g. default_root) — for tests that exercise optional fields.
func buildSignedPackageEx(t *testing.T, priv ed25519.PrivateKey, pub ed25519.PublicKey,
	name, ver string, files map[string]string, extra map[string]any) (data []byte, sizeInstalled int64) {
	t.Helper()

	type fileEntry struct {
		Path string `json:"path"`
		Size int64  `json:"size"`
		Hash string `json:"hash"`
	}
	var entries []fileEntry
	for path, content := range files {
		sum := sha256.Sum256([]byte(content))
		entries = append(entries, fileEntry{path, int64(len(content)), hex.EncodeToString(sum[:])})
		sizeInstalled += int64(len(content))
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })

	filesJSON := mustMarshal(t, map[string]any{
		"schema_version": 1, "algorithm": "sha256", "entries": entries})
	manifestMap := map[string]any{
		"schema_version": 1, "name": name, "version": ver, "architecture": "x86_64",
		"dependencies": []any{}, "conflicts": []any{}, "size_installed": sizeInstalled,
		"build": map[string]any{
			"timestamp": "2026-05-19T00:00:00Z", "farm_id": "test", "source_ref": "test"},
	}
	for k, v := range extra {
		manifestMap[k] = v
	}
	manifestJSON := mustMarshal(t, manifestMap)

	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	write := func(name string, content []byte) {
		hdr := &tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o777,
			Size: int64(len(content)), ModTime: time.Unix(0, 0)}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("WriteHeader %q: %v", name, err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatalf("Write %q: %v", name, err)
		}
	}
	write(".peipkg/manifest.json", manifestJSON)
	write(".peipkg/files.json", filesJSON)
	var paths []string
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		write(p, []byte(files[p]))
	}
	if err := tw.Flush(); err != nil {
		t.Fatalf("tar Flush: %v", err)
	}
	signed := bytes.Clone(tarBuf.Bytes())
	digest := sha256.Sum256(signed)
	envelope := mustMarshal(t, map[string]any{
		"schema_version": 1, "algorithm": "ed25519",
		"key_fingerprint": signature.Fingerprint(pub),
		"signature":       base64.RawStdEncoding.EncodeToString(ed25519.Sign(priv, digest[:])),
	})
	write(".peipkg/signature", envelope)
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
	return zBuf.Bytes(), sizeInstalled
}

// TestEndToEndInstall drives the whole stack: it stands up a signed
// repository, adds it through the CLI, and installs a package from it,
// then confirms the payload landed and the database recorded it.
func TestEndToEndInstall(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	fp := signature.Fingerprint(pub)

	const pkgName, pkgVer = "hello", "1.0-1"
	payload := map[string]string{"usr/bin/hello": "#!/bin/sh\necho hi\n"}
	pkgBytes, sizeInstalled := buildSignedPackage(t, priv, pub, pkgName, pkgVer, payload)
	pkgSum := sha256.Sum256(pkgBytes)
	pkgURL := "/p/" + pkgName + "/" + pkgVer + "/" + pkgName + "_" + pkgVer + "_x86_64.peipkg"

	descriptor := mustMarshal(t, map[string]any{
		"schema_version": 1,
		"repo": map[string]any{"name": "test", "signing": map[string]any{
			"algorithm": "ed25519",
			"keys": []any{map[string]any{
				"fingerprint": fp, "url": "/keys/" + fp + ".pub", "status": "active"}}}},
		"indexes": map[string]any{
			"active": map[string]any{
				"url": "/index/active.json", "signature_url": "/index/active.json.sig"},
			"archive": map[string]any{
				"url": "/index/archive.json", "signature_url": "/index/archive.json.sig"}},
	})
	index := mustMarshal(t, map[string]any{
		"schema_version": 1, "repo": "test", "kind": "active",
		"index_version": 1, "generated_at": "2026-05-19T00:00:00Z",
		"packages": []any{map[string]any{
			"name": pkgName, "version": pkgVer, "architecture": "x86_64",
			"dependencies": []any{}, "conflicts": []any{},
			"size_compressed": len(pkgBytes), "size_installed": sizeInstalled,
			"hash": map[string]any{"algorithm": "sha256", "value": hex.EncodeToString(pkgSum[:])},
			"url":  pkgURL}},
	})
	sign := func(b []byte) []byte {
		return detachedSig(priv, b)
	}
	served := map[string][]byte{
		"/repo.json":             descriptor,
		"/repo.json.sig":         sign(descriptor),
		"/keys/" + fp + ".pub":   []byte(pub),
		"/index/active.json":     index,
		"/index/active.json.sig": sign(index),
		pkgURL:                   pkgBytes,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if body, ok := served[r.URL.Path]; ok {
			_, _ = w.Write(body)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	app, out := testApp(t)

	// Add the repository — the trust ceremony runs against the server.
	if err := cmdRepoAdd(app, []string{"test", srv.URL, "--anchor", fp, "--insecure"}); err != nil {
		t.Fatalf("repo add: %v", err)
	}
	// search finds the package in the freshly-added repository.
	out.Reset()
	if err := cmdSearch(app, []string{pkgName}); err != nil {
		t.Fatalf("search: %v", err)
	}
	if !strings.Contains(out.String(), pkgName) {
		t.Errorf("search did not find the package:\n%s", out.String())
	}

	// Install the package end to end.
	out.Reset()
	if err := cmdInstall(app, []string{pkgName, "--yes"}); err != nil {
		t.Fatalf("install: %v", err)
	}

	// The payload landed under the operating root.
	got, err := os.ReadFile(filepath.Join(app.paths.root, "usr/bin/hello"))
	if err != nil || !strings.Contains(string(got), "echo hi") {
		t.Errorf("installed file: content %q, err %v", got, err)
	}
	// The package is recorded as installed.
	out.Reset()
	if err := cmdList(app, nil); err != nil {
		t.Fatalf("list: %v", err)
	}
	if !strings.Contains(out.String(), pkgName) {
		t.Errorf("installed package not listed:\n%s", out.String())
	}

	// Uninstalling it removes the file again.
	if err := cmdUninstall(app, []string{pkgName, "--yes"}); err != nil {
		t.Fatalf("uninstall: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(app.paths.root, "usr/bin/hello")); !os.IsNotExist(err) {
		t.Error("the file was not removed by uninstall")
	}
}

// TestEndToEndLocalInstall installs a package straight from a .peipkg
// file on disk — a raw local install, with no repository involved.
func TestEndToEndLocalInstall(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pkgBytes, _ := buildSignedPackage(t, priv, pub, "tool", "2.0-1",
		map[string]string{"usr/bin/tool": "#!/bin/sh\necho tool\n"})

	pkgPath := filepath.Join(t.TempDir(), "tool_2.0-1_x86_64.peipkg")
	if err := os.WriteFile(pkgPath, pkgBytes, 0o644); err != nil {
		t.Fatalf("write package: %v", err)
	}

	app, out := testApp(t)
	if err := cmdInstall(app, []string{pkgPath, "--yes"}); err != nil {
		t.Fatalf("install (local file): %v", err)
	}

	// The payload landed under the operating root.
	got, err := os.ReadFile(filepath.Join(app.paths.root, "usr/bin/tool"))
	if err != nil || !strings.Contains(string(got), "echo tool") {
		t.Errorf("installed file: content %q, err %v", got, err)
	}
	// The package is recorded with no origin repository.
	out.Reset()
	if err := cmdInfo(app, []string{"tool"}); err != nil {
		t.Fatalf("info: %v", err)
	}
	if !strings.Contains(out.String(), "(local file)") {
		t.Errorf("info should mark the local-file origin:\n%s", out.String())
	}
}

func TestLocalInstallRejectsPackageChangedAfterPlanning(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	first, _ := buildSignedPackage(t, priv, pub, "tool", "2.0-1",
		map[string]string{"usr/bin/tool": "planned"})
	second, _ := buildSignedPackage(t, priv, pub, "tool", "2.0-1",
		map[string]string{"usr/bin/tool": "changed"})

	pkgPath := filepath.Join(t.TempDir(), "tool_2.0-1_x86_64.peipkg")
	if err := os.WriteFile(pkgPath, first, 0o644); err != nil {
		t.Fatalf("write package: %v", err)
	}
	cand, err := readLocalPackage(pkgPath)
	if err != nil {
		t.Fatalf("readLocalPackage: %v", err)
	}
	if err := os.WriteFile(pkgPath, second, 0o644); err != nil {
		t.Fatalf("replace package: %v", err)
	}

	_, err = provideLocal(cand)
	if err == nil || !strings.Contains(err.Error(), "hash mismatch") {
		t.Fatalf("provideLocal after file replacement error = %v, want hash mismatch", err)
	}
}

func TestVerifyCandidatePackageRejectsIdentityMismatch(t *testing.T) {
	plannedVersion, err := version.Parse("1.0-1")
	if err != nil {
		t.Fatalf("Parse planned version: %v", err)
	}
	actualVersion, err := version.Parse("2.0-1")
	if err != nil {
		t.Fatalf("Parse actual version: %v", err)
	}
	cand := resolver.Candidate{Name: "tool", Version: plannedVersion, Architecture: "x86_64"}
	pkg := &archive.Package{Manifest: manifest.Manifest{
		Name: "tool", Version: actualVersion, Architecture: "x86_64",
	}}
	err = verifyCandidatePackage(cand, pkg, "repository package https://repo/tool.peipkg")
	if err == nil || !strings.Contains(err.Error(), "planned 1.0-1") {
		t.Fatalf("verifyCandidatePackage error = %v, want planned-version mismatch", err)
	}
}

// TestAuditLocalInstallEmitsEvent confirms a successful install emits a
// §7.6 peipkg.install audit event.
func TestAuditLocalInstallEmitsEvent(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pkgBytes, _ := buildSignedPackage(t, priv, pub, "tool", "1.0-1",
		map[string]string{"usr/bin/tool": "x"})
	pkgPath := filepath.Join(t.TempDir(), "tool_1.0-1_x86_64.peipkg")
	if err := os.WriteFile(pkgPath, pkgBytes, 0o644); err != nil {
		t.Fatalf("write package: %v", err)
	}

	app, _ := testApp(t) // testApp wires an audit.Recorder
	rec := app.emitter.(*audit.Recorder)
	if err := cmdInstall(app, []string{pkgPath, "--yes"}); err != nil {
		t.Fatalf("install: %v", err)
	}
	if len(rec.Events) != 1 {
		t.Fatalf("expected one audit event, got %d: %+v", len(rec.Events), rec.Events)
	}
	e := rec.Events[0]
	if e.Type != audit.TypeInstall || e.Outcome != audit.OutcomeSuccess {
		t.Errorf("event: type=%q outcome=%q, want %q success", e.Type, e.Outcome, audit.TypeInstall)
	}
	if len(e.Packages) != 1 || e.Packages[0].Name != "tool" {
		t.Errorf("event packages: %+v", e.Packages)
	}
	if e.TxnID == 0 {
		t.Error("event has no transaction id")
	}
}

// TestEndToEndDowngradeUndo installs a package, downgrades it to an
// older version drawn from the archive index, then undoes the
// downgrade — exercising the archive-index path and the inverse
// transaction end to end.
func TestEndToEndDowngradeUndo(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	fp := signature.Fingerprint(pub)

	v1, _ := buildSignedPackage(t, priv, pub, "widget", "1.0-1",
		map[string]string{"usr/bin/widget": "widget v1"})
	v2, _ := buildSignedPackage(t, priv, pub, "widget", "2.0-1",
		map[string]string{"usr/bin/widget": "widget v2"})
	url1 := "/p/widget/1.0-1/widget_1.0-1_x86_64.peipkg"
	url2 := "/p/widget/2.0-1/widget_2.0-1_x86_64.peipkg"
	hash := func(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

	entry := func(ver, hashHex, url string, size int) map[string]any {
		return map[string]any{
			"name": "widget", "version": ver, "architecture": "x86_64",
			"dependencies": []any{}, "conflicts": []any{},
			"size_compressed": size, "size_installed": 100,
			"hash": map[string]any{"algorithm": "sha256", "value": hashHex},
			"url":  url,
		}
	}
	descriptor := mustMarshal(t, map[string]any{
		"schema_version": 1,
		"repo": map[string]any{"name": "test", "signing": map[string]any{
			"algorithm": "ed25519",
			"keys": []any{map[string]any{
				"fingerprint": fp, "url": "/keys/" + fp + ".pub", "status": "active"}}}},
		"indexes": map[string]any{
			"active": map[string]any{
				"url": "/index/active.json", "signature_url": "/index/active.json.sig"},
			"archive": map[string]any{
				"url": "/index/archive.json", "signature_url": "/index/archive.json.sig"}},
	})
	active := mustMarshal(t, map[string]any{
		"schema_version": 1, "repo": "test", "kind": "active",
		"index_version": 2, "generated_at": "2026-05-19T00:00:00Z",
		"packages": []any{entry("2.0-1", hash(v2), url2, len(v2))},
	})
	archive := mustMarshal(t, map[string]any{
		"schema_version": 1, "repo": "test", "kind": "archive",
		"index_version": 2, "generated_at": "2026-05-19T00:00:00Z",
		"packages": []any{
			entry("2.0-1", hash(v2), url2, len(v2)),
			entry("1.0-1", hash(v1), url1, len(v1)),
		},
	})
	sign := func(b []byte) []byte {
		return detachedSig(priv, b)
	}
	served := map[string][]byte{
		"/repo.json": descriptor, "/repo.json.sig": sign(descriptor),
		"/keys/" + fp + ".pub":    []byte(pub),
		"/index/active.json":      active,
		"/index/active.json.sig":  sign(active),
		"/index/archive.json":     archive,
		"/index/archive.json.sig": sign(archive),
		url1:                      v1,
		url2:                      v2,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if body, ok := served[r.URL.Path]; ok {
			_, _ = w.Write(body)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	// The downgrade's elevated authorisation reads one "y" from input.
	out := &bytes.Buffer{}
	app := newApp(t.TempDir(), strings.NewReader("y\n"), out, &bytes.Buffer{})
	widgetPath := filepath.Join(app.paths.root, "usr/bin/widget")

	if err := cmdRepoAdd(app, []string{"test", srv.URL, "--anchor", fp, "--insecure"}); err != nil {
		t.Fatalf("repo add: %v", err)
	}
	if err := cmdInstall(app, []string{"widget", "--yes"}); err != nil {
		t.Fatalf("install: %v", err)
	}
	if got, _ := os.ReadFile(widgetPath); string(got) != "widget v2" {
		t.Fatalf("after install: content %q, want widget v2", got)
	}

	// Downgrade to the archived 1.0-1.
	if err := cmdDowngrade(app, []string{"widget", "1.0-1", "--yes"}); err != nil {
		t.Fatalf("downgrade: %v", err)
	}
	if got, _ := os.ReadFile(widgetPath); string(got) != "widget v1" {
		t.Fatalf("after downgrade: content %q, want widget v1", got)
	}

	// Undo the downgrade — widget returns to 2.0-1.
	if err := cmdUndo(app, []string{"--yes"}); err != nil {
		t.Fatalf("undo: %v", err)
	}
	if got, _ := os.ReadFile(widgetPath); string(got) != "widget v2" {
		t.Errorf("after undo: content %q, want widget v2", got)
	}
}

// installLiveBootCrossRoot stands up a repository serving live-boot
// (which declares a dependency placed `IN initramfs`) and peiosutils,
// registers the initramfs root, and installs live-boot through the whole
// stack. It returns the app and the anchor and initramfs paths, ready for
// an install or undo assertion. The repository server is closed before it
// returns — the index is cached and the packages are fetched, so a
// follow-on undo (removals) needs no network.
func installLiveBootCrossRoot(t *testing.T) (app *App, anchor, initramfs string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	fp := signature.Fingerprint(pub)

	liveBytes, liveSize := buildSignedPackageEx(t, priv, pub, "live-boot", "1.0-1",
		map[string]string{"usr/bin/live-boot": "live-boot"},
		map[string]any{"dependencies": []any{
			map[string]any{"name": "peiosutils", "root": "initramfs"}}})
	puBytes, puSize := buildSignedPackage(t, priv, pub, "peiosutils", "1.0-1",
		map[string]string{"bin/peiosutils": "peiosutils"})
	liveSum, puSum := sha256.Sum256(liveBytes), sha256.Sum256(puBytes)
	liveURL := "/p/live-boot/1.0-1/live-boot_1.0-1_x86_64.peipkg"
	puURL := "/p/peiosutils/1.0-1/peiosutils_1.0-1_x86_64.peipkg"

	descriptor := mustMarshal(t, map[string]any{
		"schema_version": 1,
		"repo": map[string]any{"name": "test", "signing": map[string]any{
			"algorithm": "ed25519",
			"keys": []any{map[string]any{
				"fingerprint": fp, "url": "/keys/" + fp + ".pub", "status": "active"}}}},
		"indexes": map[string]any{
			"active": map[string]any{
				"url": "/index/active.json", "signature_url": "/index/active.json.sig"},
			"archive": map[string]any{
				"url": "/index/archive.json", "signature_url": "/index/archive.json.sig"}},
	})
	// Entries are sorted by name: live-boot, peiosutils.
	index := mustMarshal(t, map[string]any{
		"schema_version": 1, "repo": "test", "kind": "active",
		"index_version": 1, "generated_at": "2026-05-19T00:00:00Z",
		"packages": []any{
			map[string]any{
				"name": "live-boot", "version": "1.0-1", "architecture": "x86_64",
				"dependencies": []any{map[string]any{"name": "peiosutils", "root": "initramfs"}},
				"conflicts":       []any{},
				"size_compressed": len(liveBytes), "size_installed": liveSize,
				"hash": map[string]any{"algorithm": "sha256", "value": hex.EncodeToString(liveSum[:])},
				"url":  liveURL},
			map[string]any{
				"name": "peiosutils", "version": "1.0-1", "architecture": "x86_64",
				"dependencies": []any{}, "conflicts": []any{},
				"size_compressed": len(puBytes), "size_installed": puSize,
				"hash": map[string]any{"algorithm": "sha256", "value": hex.EncodeToString(puSum[:])},
				"url":  puURL},
		},
	})
	sign := func(b []byte) []byte { return detachedSig(priv, b) }
	served := map[string][]byte{
		"/repo.json": descriptor, "/repo.json.sig": sign(descriptor),
		"/keys/" + fp + ".pub":   []byte(pub),
		"/index/active.json":     index,
		"/index/active.json.sig": sign(index),
		liveURL:                  liveBytes,
		puURL:                    puBytes,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if body, ok := served[r.URL.Path]; ok {
			_, _ = w.Write(body)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	app, _ = testApp(t)
	anchor = app.paths.root
	if err := cmdRepoAdd(app, []string{"test", srv.URL, "--anchor", fp, "--insecure"}); err != nil {
		t.Fatalf("repo add: %v", err)
	}
	// Register the initramfs root the dependency is placed into.
	if err := cmdRoot(app, []string{"add", "initramfs", "boot/initramfs"}); err != nil {
		t.Fatalf("root add: %v", err)
	}
	if err := cmdInstall(app, []string{"live-boot", "--yes"}); err != nil {
		t.Fatalf("cross-root install: %v", err)
	}
	return app, anchor, filepath.Join(anchor, "boot/initramfs")
}

// TestCrossRootInstallEndToEnd installs live-boot, whose dependency is
// placed `IN initramfs`: live-boot must land in the anchor root and
// peiosutils in the registered initramfs root, recorded in each root's own
// database under a shared cross-root id.
func TestCrossRootInstallEndToEnd(t *testing.T) {
	app, anchor, initramfs := installLiveBootCrossRoot(t)

	if b, err := os.ReadFile(filepath.Join(anchor, "usr/bin/live-boot")); err != nil || string(b) != "live-boot" {
		t.Errorf("live-boot in anchor: %q err %v", b, err)
	}
	if b, err := os.ReadFile(filepath.Join(initramfs, "bin/peiosutils")); err != nil || string(b) != "peiosutils" {
		t.Errorf("peiosutils in initramfs: %q err %v", b, err)
	}
	// peiosutils must NOT have been installed into the anchor.
	if _, err := os.Stat(filepath.Join(anchor, "bin/peiosutils")); !os.IsNotExist(err) {
		t.Errorf("peiosutils should not be in the anchor root: %v", err)
	}

	// Each root's database records its own package, sharing one cross-root id.
	ctx := context.Background()
	anchorDB, _ := app.openDBAt(ctx, anchor)
	defer anchorDB.Close()
	irfDB, _ := app.openDBAt(ctx, initramfs)
	defer irfDB.Close()
	if _, found, _ := anchorDB.GetPackage(ctx, "live-boot"); !found {
		t.Error("anchor database missing live-boot")
	}
	if _, found, _ := irfDB.GetPackage(ctx, "peiosutils"); !found {
		t.Error("initramfs database missing peiosutils")
	}
	anchorTxns, _ := anchorDB.ListTxns(ctx, 0)
	irfTxns, _ := irfDB.ListTxns(ctx, 0)
	if len(anchorTxns) != 1 || len(irfTxns) != 1 {
		t.Fatalf("expected one txn per root, got anchor=%d irf=%d", len(anchorTxns), len(irfTxns))
	}
	if anchorTxns[0].CrossRootID == "" || anchorTxns[0].CrossRootID != irfTxns[0].CrossRootID {
		t.Errorf("roots should share one cross-root id: anchor=%q irf=%q",
			anchorTxns[0].CrossRootID, irfTxns[0].CrossRootID)
	}
}

// TestCrossRootUndoEndToEnd undoes a cross-root install as a unit: undoing
// live-boot must remove it from the anchor AND remove peiosutils from the
// initramfs root — never leave the other root's packages orphaned.
func TestCrossRootUndoEndToEnd(t *testing.T) {
	app, anchor, initramfs := installLiveBootCrossRoot(t)

	if err := cmdUndo(app, []string{"--yes"}); err != nil {
		t.Fatalf("cross-root undo: %v", err)
	}

	// Both payloads are gone from both roots.
	if _, err := os.Stat(filepath.Join(anchor, "usr/bin/live-boot")); !os.IsNotExist(err) {
		t.Errorf("live-boot should be removed from the anchor: %v", err)
	}
	if _, err := os.Stat(filepath.Join(initramfs, "bin/peiosutils")); !os.IsNotExist(err) {
		t.Errorf("peiosutils should be removed from the initramfs root: %v", err)
	}
	// Both databases no longer record the packages.
	ctx := context.Background()
	anchorDB, _ := app.openDBAt(ctx, anchor)
	defer anchorDB.Close()
	irfDB, _ := app.openDBAt(ctx, initramfs)
	defer irfDB.Close()
	if _, found, _ := anchorDB.GetPackage(ctx, "live-boot"); found {
		t.Error("live-boot still recorded in the anchor after undo")
	}
	if _, found, _ := irfDB.GetPackage(ctx, "peiosutils"); found {
		t.Error("peiosutils still recorded in the initramfs root after undo")
	}
}

// TestInstallMaxTrustedAgeGate exercises the §6.5.4 maximum-trusted-age
// gate end to end: an aged repository blocks install when its refresh
// makes no progress (frozen index) or fails outright, --allow-stale
// overrides with a warning and an audit record, and a refresh that
// makes progress unblocks without ceremony.
func TestInstallMaxTrustedAgeGate(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	fp := signature.Fingerprint(pub)

	const pkgName, pkgVer = "hello", "1.0-1"
	pkgBytes, sizeInstalled := buildSignedPackage(t, priv, pub, pkgName, pkgVer,
		map[string]string{"usr/bin/hello": "#!/bin/sh\necho hi\n"})
	pkgSum := sha256.Sum256(pkgBytes)
	pkgURL := "/p/hello/1.0-1/hello_1.0-1_x86_64.peipkg"

	descriptor := mustMarshal(t, map[string]any{
		"schema_version": 1,
		"repo": map[string]any{"name": "test", "signing": map[string]any{
			"algorithm": "ed25519",
			"keys": []any{map[string]any{
				"fingerprint": fp, "url": "/keys/" + fp + ".pub", "status": "active"}}}},
		"indexes": map[string]any{
			"active": map[string]any{
				"url": "/index/active.json", "signature_url": "/index/active.json.sig"},
			"archive": map[string]any{
				"url": "/index/archive.json", "signature_url": "/index/archive.json.sig"}},
	})
	makeIndex := func(indexVersion int, generatedAt string) []byte {
		return mustMarshal(t, map[string]any{
			"schema_version": 1, "repo": "test", "kind": "active",
			"index_version": indexVersion, "generated_at": generatedAt,
			"packages": []any{map[string]any{
				"name": pkgName, "version": pkgVer, "architecture": "x86_64",
				"dependencies": []any{}, "conflicts": []any{},
				"size_compressed": len(pkgBytes), "size_installed": sizeInstalled,
				"hash": map[string]any{"algorithm": "sha256", "value": hex.EncodeToString(pkgSum[:])},
				"url":  pkgURL}},
		})
	}
	index := makeIndex(1, "2026-05-19T00:00:00Z")
	served := map[string][]byte{
		"/repo.json":             descriptor,
		"/repo.json.sig":         detachedSig(priv, descriptor),
		"/keys/" + fp + ".pub":   []byte(pub),
		"/index/active.json":     index,
		"/index/active.json.sig": detachedSig(priv, index),
		pkgURL:                   pkgBytes,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if body, ok := served[r.URL.Path]; ok {
			_, _ = w.Write(body)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	out, errOut := &bytes.Buffer{}, &bytes.Buffer{}
	app := newApp(t.TempDir(), strings.NewReader(""), out, errOut)
	app.emitter = &audit.Recorder{}

	if err := cmdRepoAdd(app, []string{"test", srv.URL, "--anchor", fp, "--insecure"}); err != nil {
		t.Fatalf("repo add: %v", err)
	}

	// ageRepo backdates the recorded trust state past the 30-day default.
	ageRepo := func() {
		t.Helper()
		withDB(t, app, func(store *db.DB) {
			row, found, err := store.GetRepository(context.Background(), "test")
			if err != nil || !found {
				t.Fatalf("GetRepository: found=%v, err=%v", found, err)
			}
			row.LastRefreshAt = time.Now().Add(-31 * 24 * time.Hour)
			if err := store.UpsertRepository(context.Background(), row); err != nil {
				t.Fatalf("UpsertRepository: %v", err)
			}
		})
	}

	// Frozen: the server still serves index 1, so the forced refresh makes
	// no progress and the install is refused.
	ageRepo()
	err = cmdInstall(app, []string{pkgName, "--yes"})
	if err == nil || !strings.Contains(err.Error(), "--allow-stale") {
		t.Fatalf("frozen repository: expected a refusal naming --allow-stale, got %v", err)
	}

	// --allow-stale overrides, with a warning on stderr.
	errOut.Reset()
	if err := cmdInstall(app, []string{pkgName, "--yes", "--allow-stale"}); err != nil {
		t.Fatalf("install --allow-stale: %v", err)
	}
	if !strings.Contains(errOut.String(), "--allow-stale") {
		t.Errorf("expected a stale-trust warning on stderr, got:\n%s", errOut.String())
	}
	if err := cmdUninstall(app, []string{pkgName, "--yes"}); err != nil {
		t.Fatalf("uninstall: %v", err)
	}

	// A refresh that makes progress unblocks the operation on its own.
	ageRepo()
	index2 := makeIndex(2, "2026-05-20T00:00:00Z")
	served["/index/active.json"] = index2
	served["/index/active.json.sig"] = detachedSig(priv, index2)
	if err := cmdInstall(app, []string{pkgName, "--yes"}); err != nil {
		t.Fatalf("install after progressed refresh: %v", err)
	}
	if err := cmdUninstall(app, []string{pkgName, "--yes"}); err != nil {
		t.Fatalf("uninstall: %v", err)
	}

	// A failed refresh (repository unreachable) also refuses, with the
	// refresh error surfaced.
	ageRepo()
	srv.Close()
	err = cmdInstall(app, []string{pkgName, "--yes"})
	if err == nil || !strings.Contains(err.Error(), "refresh failed") {
		t.Fatalf("unreachable repository: expected a refresh-failed refusal, got %v", err)
	}
}
