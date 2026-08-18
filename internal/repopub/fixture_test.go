package repopub_test

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/peios/peipkg/internal/signature"
)

// This file builds .peipkg fixtures. It writes the archive by hand
// rather than reaching for a builder because there isn't one to reach
// for: peipkg is the consumer side, and the producer is pekit, in
// another repository. Hand-assembly also keeps the fixtures honest —
// a test that built packages with the same code the publisher reads
// them with could agree with itself about a format neither had right.

type pkgSpec struct {
	name    string
	version string
	arch    string
	// unsigned omits the .peipkg/signature entry entirely.
	unsigned bool
	// signWith overrides the signing key, for the case where a package
	// is signed by a key the repository does not publish.
	signWith ed25519.PrivateKey
}

func keypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return pub, priv
}

// writePackage builds a .peipkg into dir and returns its path.
func writePackage(t *testing.T, dir string, key ed25519.PrivateKey, spec pkgSpec) string {
	t.Helper()
	if spec.arch == "" {
		spec.arch = "x86_64"
	}
	if spec.signWith == nil {
		spec.signWith = key
	}

	payload := map[string]string{
		"usr/bin/" + spec.name: "#!/usr/bin/sh\necho " + spec.name + " " + spec.version + "\n",
	}
	type fileEntry struct {
		Path string `json:"path"`
		Size int64  `json:"size"`
		Hash string `json:"hash"`
	}
	var entries []fileEntry
	var installed int64
	for path, content := range payload {
		sum := sha256.Sum256([]byte(content))
		entries = append(entries, fileEntry{path, int64(len(content)), hex.EncodeToString(sum[:])})
		installed += int64(len(content))
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })

	filesJSON := mustJSON(t, map[string]any{
		"schema_version": 1, "algorithm": "sha256", "entries": entries})
	manifestJSON := mustJSON(t, map[string]any{
		"schema_version": 1,
		"name":           spec.name,
		"version":        spec.version,
		"architecture":   spec.arch,
		"description":    spec.name + " test package",
		"license":        "MIT",
		"dependencies":   []any{},
		"conflicts":      []any{},
		"size_installed": installed,
		"build": map[string]any{
			"timestamp": "2026-05-19T00:00:00Z", "farm_id": "test", "source_ref": "test"},
	})

	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	write := func(name string, content []byte) {
		t.Helper()
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
	for p := range payload {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		write(p, []byte(payload[p]))
	}

	if !spec.unsigned {
		if err := tw.Flush(); err != nil {
			t.Fatalf("tar Flush: %v", err)
		}
		// §5.1.2: the signature covers every tar entry that precedes it.
		digest := sha256.Sum256(bytes.Clone(tarBuf.Bytes()))
		pub := spec.signWith.Public().(ed25519.PublicKey)
		write(".peipkg/signature", mustJSON(t, map[string]any{
			"schema_version":  1,
			"algorithm":       "ed25519",
			"key_fingerprint": signature.Fingerprint(pub),
			"signature": base64.RawStdEncoding.EncodeToString(
				ed25519.Sign(spec.signWith, digest[:])),
		}))
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

	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	path := filepath.Join(dir,
		spec.name+"_"+spec.version+"_"+spec.arch+".peipkg")
	if err := os.WriteFile(path, zBuf.Bytes(), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return data
}

func readJSON(t *testing.T, path string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}
	return out
}

func readFile(path string) ([]byte, error)  { return os.ReadFile(path) }
func writeFile(path string, b []byte) error { return os.WriteFile(path, b, 0o644) }
func replaceOnce(s, old, new string) string { return strings.Replace(s, old, new, 1) }
