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
	"github.com/peios/peipkg/internal/signature"
)

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
		return []byte(base64.RawStdEncoding.EncodeToString(ed25519.Sign(priv, b)))
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
