package cli

import (
	"archive/tar"
	"bytes"
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
	"github.com/peios/peipkg/internal/audit"
	"github.com/peios/peipkg/internal/signature"
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
	manifestJSON := mustMarshal(t, map[string]any{
		"schema_version": 1, "name": name, "version": ver, "architecture": "x86_64",
		"dependencies": []any{}, "conflicts": []any{}, "size_installed": sizeInstalled,
		"build": map[string]any{
			"timestamp": "2026-05-19T00:00:00Z", "farm_id": "test", "source_ref": "test"},
	})

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
