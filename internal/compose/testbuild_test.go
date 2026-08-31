package compose

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/peios/peipkg/internal/signature"
)

// testEntry is one payload entry in a test .peipkg.
type testEntry struct {
	// Path is the tar entry name — no leading slash, no trailing slash
	// for directories (the helper adds it).
	Path    string
	Content []byte // regular-file content; nil for dir or symlink
	Symlink string // symlink target; non-empty marks an EntrySymlink
	IsDir   bool   // true marks an EntryDir
}

// buildPeipkg builds a syntactically-valid unsigned .peipkg in memory.
// The caller supplies the manifest JSON and the payload entries; the
// helper computes files.json from the regular-file entries and writes
// the tar+zstd archive in the order archive.VerifyFormat requires.
func buildPeipkg(t *testing.T, manifestJSON []byte, entries []testEntry) []byte {
	t.Helper()
	return buildPeipkgSigned(t, manifestJSON, entries, nil)
}

// buildPeipkgSigned is buildPeipkg with an inline §5.3 signature. A nil
// priv builds the unsigned archive.
func buildPeipkgSigned(t *testing.T, manifestJSON []byte, entries []testEntry,
	priv ed25519.PrivateKey) []byte {
	t.Helper()

	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })

	type wireFile struct {
		Path string `json:"path"`
		Size int64  `json:"size"`
		Hash string `json:"hash"`
	}
	type wireFiles struct {
		SchemaVersion int        `json:"schema_version"`
		Algorithm     string     `json:"algorithm"`
		Entries       []wireFile `json:"entries"`
	}
	files := wireFiles{SchemaVersion: 1, Algorithm: "sha256"}
	for _, e := range entries {
		if e.IsDir || e.Symlink != "" {
			continue
		}
		h := sha256.Sum256(e.Content)
		files.Entries = append(files.Entries, wireFile{
			Path: e.Path, Size: int64(len(e.Content)), Hash: hex.EncodeToString(h[:]),
		})
	}
	filesJSON, err := json.Marshal(files)
	if err != nil {
		t.Fatalf("encode files.json: %v", err)
	}

	// The tar is assembled uncompressed so the §5.1.2 signed byte range —
	// everything before the signature entry's header — can be hashed.
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)

	// §5.11 pins mode, ownership, format and mtime; §5.16 makes the mode
	// rule an explicit rejection condition.
	buildTS := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	writeReg := func(name string, data []byte) {
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Mode: 0o777, Size: int64(len(data)), Typeflag: tar.TypeReg,
			Uid: 0, Gid: 0, Uname: "root", Gname: "root",
			Format: tar.FormatPAX, ModTime: buildTS,
		}); err != nil {
			t.Fatalf("tar header %s: %v", name, err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatalf("tar write %s: %v", name, err)
		}
	}

	writeReg(".peipkg/manifest.json", manifestJSON)
	writeReg(".peipkg/files.json", filesJSON)

	for _, e := range entries {
		switch {
		case e.IsDir:
			if err := tw.WriteHeader(&tar.Header{
				Name: e.Path + "/", Mode: 0o777, Typeflag: tar.TypeDir,
				Uid: 0, Gid: 0, Uname: "root", Gname: "root",
				Format: tar.FormatPAX, ModTime: buildTS,
			}); err != nil {
				t.Fatalf("tar dir %s: %v", e.Path, err)
			}
		case e.Symlink != "":
			if err := tw.WriteHeader(&tar.Header{
				Name: e.Path, Typeflag: tar.TypeSymlink, Linkname: e.Symlink,
				Mode: 0o777, Uid: 0, Gid: 0, Uname: "root", Gname: "root",
				Format: tar.FormatPAX, ModTime: buildTS,
			}); err != nil {
				t.Fatalf("tar symlink %s: %v", e.Path, err)
			}
		default:
			writeReg(e.Path, e.Content)
		}
	}

	if priv != nil {
		if err := tw.Flush(); err != nil {
			t.Fatalf("tar flush: %v", err)
		}
		digest := sha256.Sum256(bytes.Clone(tarBuf.Bytes()))
		pub := priv.Public().(ed25519.PublicKey)
		env, err := json.Marshal(map[string]any{
			"schema_version":  1,
			"algorithm":       "ed25519",
			"key_fingerprint": signature.Fingerprint(pub),
			"signature":       base64.RawStdEncoding.EncodeToString(ed25519.Sign(priv, digest[:])),
		})
		if err != nil {
			t.Fatalf("encode signature envelope: %v", err)
		}
		writeReg(".peipkg/signature", env)
	}

	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}

	var buf bytes.Buffer
	zw, err := zstd.NewWriter(&buf)
	if err != nil {
		t.Fatalf("zstd writer: %v", err)
	}
	if _, err := zw.Write(tarBuf.Bytes()); err != nil {
		t.Fatalf("zstd write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zstd close: %v", err)
	}
	return buf.Bytes()
}

// minimalManifestJSON renders a valid PSD-009 manifest JSON with the
// fields the format insists on. sizeInstalled must equal the sum of the
// package's regular-file sizes — the relationship §3.3 fixes between
// the manifest and files.json.
func minimalManifestJSON(t *testing.T, name, ver, arch string, sizeInstalled int64) []byte {
	t.Helper()
	m := map[string]any{
		"schema_version": 1,
		"name":           name,
		"version":        ver,
		"architecture":   arch,
		"dependencies":   []any{},
		"conflicts":      []any{},
		"size_installed": sizeInstalled,
		"build": map[string]any{
			"timestamp":  "2026-06-01T00:00:00Z",
			"farm_id":    "test",
			"source_ref": "test",
		},
	}
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("encode manifest: %v", err)
	}
	return data
}

// providerManifestJSON is minimalManifestJSON plus a single provides entry
// that fills one claim slot (role/slot -> target, with a provider default
// path) — the shape of a claim-holding package like prelude.
func providerManifestJSON(t *testing.T, name, ver, arch string, sizeInstalled int64,
	role, slot, target, path string) []byte {
	t.Helper()
	m := map[string]any{
		"schema_version": 1,
		"name":           name,
		"version":        ver,
		"architecture":   arch,
		"dependencies":   []any{},
		"conflicts":      []any{},
		"provides": []any{map[string]any{
			"name":    role,
			"version": "1",
			"claims":  map[string]any{slot: map[string]any{"target": target, "path": path}},
		}},
		"size_installed": sizeInstalled,
		"build": map[string]any{
			"timestamp":  "2026-06-01T00:00:00Z",
			"farm_id":    "test",
			"source_ref": "test",
		},
	}
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("encode manifest: %v", err)
	}
	return data
}

// fakeFetcher is a repository.Fetcher backed by an in-memory map.
type fakeFetcher map[string][]byte

func (f fakeFetcher) Fetch(_ context.Context, url string, limit int64) ([]byte, error) {
	data, ok := f[url]
	if !ok {
		return nil, fmt.Errorf("fake fetcher: no data for %s", url)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("fake fetcher: %s exceeds the %d-byte limit", url, limit)
	}
	return data, nil
}
