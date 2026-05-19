package archive_test

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/peios/peipkg/internal/archive"
	"github.com/peios/peipkg/internal/signature"
)

// pkgFile is a regular-file payload entry for a test fixture.
type pkgFile struct {
	path    string
	content []byte
}

// pkgSymlink is a symlink payload entry for a test fixture.
type pkgSymlink struct {
	path, target string
}

// pkgSpec describes a .peipkg to assemble. The knobs deliberately
// produce malformed archives for rejection tests.
type pkgSpec struct {
	manifest map[string]any
	files    []pkgFile
	dirs     []string
	symlinks []pkgSymlink

	priv ed25519.PrivateKey
	pub  ed25519.PublicKey

	unsigned         bool   // omit the signature entry
	corruptSignature bool   // sign a digest other than the real signed bytes
	wrongFileHash    bool   // record a wrong hash for the first file in files.json
	orphanFilesEntry bool   // add a files.json entry with no payload file
	hardlinkPath     string // add a hardlink payload entry at this path
}

// validManifest returns a minimal valid manifest map. buildPkg fills in
// size_installed unless the caller has already set it.
func validManifest() map[string]any {
	return map[string]any{
		"schema_version": 1,
		"name":           "testpkg",
		"version":        "1.0.0-1",
		"architecture":   "x86_64",
		"dependencies":   []any{},
		"conflicts":      []any{},
		"build": map[string]any{
			"timestamp":  "2026-05-19T00:00:00Z",
			"farm_id":    "test-farm",
			"source_ref": "test",
		},
	}
}

// buildPkg assembles a .peipkg byte stream from spec.
func buildPkg(t *testing.T, spec pkgSpec) []byte {
	t.Helper()

	var sum int64
	for _, f := range spec.files {
		sum += int64(len(f.content))
	}
	if _, set := spec.manifest["size_installed"]; !set {
		spec.manifest["size_installed"] = sum
	}

	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	write := func(name string, typ byte, content []byte, linkname string) {
		hdr := &tar.Header{
			Name: name, Typeflag: typ, Mode: 0o777,
			Size: int64(len(content)), Linkname: linkname, ModTime: time.Unix(0, 0),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("WriteHeader %q: %v", name, err)
		}
		if len(content) > 0 {
			if _, err := tw.Write(content); err != nil {
				t.Fatalf("Write %q: %v", name, err)
			}
		}
	}

	manifestJSON, err := json.Marshal(spec.manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	write(".peipkg/manifest.json", tar.TypeReg, manifestJSON, "")
	write(".peipkg/files.json", tar.TypeReg, buildFilesJSON(t, spec), "")

	// Payload entries, sorted lexicographically by tar path (§3.2.3).
	type entry struct {
		name    string
		typ     byte
		content []byte
		link    string
	}
	var payload []entry
	for _, f := range spec.files {
		payload = append(payload, entry{f.path, tar.TypeReg, f.content, ""})
	}
	for _, d := range spec.dirs {
		payload = append(payload, entry{d + "/", tar.TypeDir, nil, ""})
	}
	for _, s := range spec.symlinks {
		payload = append(payload, entry{s.path, tar.TypeSymlink, nil, s.target})
	}
	if spec.hardlinkPath != "" {
		payload = append(payload, entry{spec.hardlinkPath, tar.TypeLink, nil, "testpkg-target"})
	}
	slices.SortFunc(payload, func(a, b entry) int { return strings.Compare(a.name, b.name) })
	for _, e := range payload {
		write(e.name, e.typ, e.content, e.link)
	}

	// The signed bytes are everything written so far (§5.1.2).
	if err := tw.Flush(); err != nil {
		t.Fatalf("tar Flush: %v", err)
	}
	signedBytes := bytes.Clone(tarBuf.Bytes())

	if !spec.unsigned {
		digest := sha256.Sum256(signedBytes)
		if spec.corruptSignature {
			digest = sha256.Sum256([]byte("not the real signed bytes"))
		}
		sig := ed25519.Sign(spec.priv, digest[:])
		envJSON, err := json.Marshal(map[string]any{
			"schema_version":  1,
			"algorithm":       "ed25519",
			"key_fingerprint": signature.Fingerprint(spec.pub),
			"signature":       base64.RawStdEncoding.EncodeToString(sig),
		})
		if err != nil {
			t.Fatalf("marshal envelope: %v", err)
		}
		write(".peipkg/signature", tar.TypeReg, envJSON, "")
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

// buildFilesJSON builds the .peipkg/files.json document for spec.
func buildFilesJSON(t *testing.T, spec pkgSpec) []byte {
	t.Helper()
	type entry struct {
		Path string `json:"path"`
		Size int64  `json:"size"`
		Hash string `json:"hash"`
	}
	var entries []entry
	for i, f := range spec.files {
		sum := sha256.Sum256(f.content)
		hash := hex.EncodeToString(sum[:])
		if spec.wrongFileHash && i == 0 {
			hash = strings.Repeat("0", 64)
		}
		entries = append(entries, entry{f.path, int64(len(f.content)), hash})
	}
	if spec.orphanFilesEntry {
		entries = append(entries, entry{"zzz-orphan", 0, strings.Repeat("0", 64)})
	}
	slices.SortFunc(entries, func(a, b entry) int { return strings.Compare(a.Path, b.Path) })
	data, err := json.Marshal(map[string]any{
		"schema_version": 1, "algorithm": "sha256", "entries": entries,
	})
	if err != nil {
		t.Fatalf("marshal files.json: %v", err)
	}
	return data
}

// keypair generates an Ed25519 key pair for a test.
func keypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return pub, priv
}

// resolverFor returns a KeyResolver that trusts exactly pub.
func resolverFor(pub ed25519.PublicKey) archive.KeyResolver {
	want := signature.Fingerprint(pub)
	return func(fp string) (ed25519.PublicKey, bool) {
		if fp == want {
			return pub, true
		}
		return nil, false
	}
}

func TestVerifyValidPackage(t *testing.T) {
	pub, priv := keypair(t)
	data := buildPkg(t, pkgSpec{
		manifest: validManifest(),
		files: []pkgFile{
			{"usr/bin/testpkg", []byte("#!/bin/sh\necho hi\n")},
			{"usr/share/testpkg/data", []byte("some data")},
		},
		dirs:     []string{"usr/share/testpkg"},
		symlinks: []pkgSymlink{{"usr/bin/testpkg-link", "usr/bin/testpkg"}},
		pub:      pub,
		priv:     priv,
	})

	pkg, err := archive.Verify(bytes.NewReader(data), resolverFor(pub))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !pkg.Signed {
		t.Error("Signed: got false, want true")
	}
	if pkg.Manifest.Name != "testpkg" {
		t.Errorf("Manifest.Name: got %q", pkg.Manifest.Name)
	}
	if len(pkg.Payload) != 4 { // 2 files, 1 dir, 1 symlink
		t.Errorf("Payload: got %d entries, want 4", len(pkg.Payload))
	}
	for _, e := range pkg.Payload {
		if e.Type == archive.EntryFile && e.Hash == "" {
			t.Errorf("payload file %q has no verified hash", e.Path)
		}
	}
}

func TestVerifyUnsignedPackage(t *testing.T) {
	pub, priv := keypair(t)
	data := buildPkg(t, pkgSpec{
		manifest: validManifest(),
		files:    []pkgFile{{"usr/bin/x", []byte("x")}},
		pub:      pub, priv: priv, unsigned: true,
	})
	pkg, err := archive.Verify(bytes.NewReader(data), resolverFor(pub))
	if err != nil {
		t.Fatalf("Verify of an unsigned package: %v", err)
	}
	if pkg.Signed {
		t.Error("Signed: got true, want false for an unsigned package")
	}
}

func TestVerifyRejectsUntrustedKey(t *testing.T) {
	pub, priv := keypair(t)
	otherPub, _ := keypair(t)
	data := buildPkg(t, pkgSpec{
		manifest: validManifest(),
		files:    []pkgFile{{"usr/bin/x", []byte("x")}},
		pub:      pub, priv: priv,
	})
	// The resolver trusts a different key.
	if _, err := archive.Verify(bytes.NewReader(data), resolverFor(otherPub)); err == nil {
		t.Error("Verify should reject a package signed by an untrusted key")
	}
}

func TestVerifyRejectsCorruptSignature(t *testing.T) {
	pub, priv := keypair(t)
	data := buildPkg(t, pkgSpec{
		manifest: validManifest(),
		files:    []pkgFile{{"usr/bin/x", []byte("x")}},
		pub:      pub, priv: priv, corruptSignature: true,
	})
	if _, err := archive.Verify(bytes.NewReader(data), resolverFor(pub)); err == nil {
		t.Error("Verify should reject a package whose signature does not verify")
	}
}

func TestVerifyRejectsTamperedFile(t *testing.T) {
	pub, priv := keypair(t)
	data := buildPkg(t, pkgSpec{
		manifest: validManifest(),
		files:    []pkgFile{{"usr/bin/x", []byte("real content")}},
		pub:      pub, priv: priv, wrongFileHash: true,
	})
	if _, err := archive.Verify(bytes.NewReader(data), resolverFor(pub)); err == nil {
		t.Error("Verify should reject a payload file whose hash does not match files.json")
	}
}

func TestVerifyRejectsPathTraversal(t *testing.T) {
	pub, priv := keypair(t)
	data := buildPkg(t, pkgSpec{
		manifest: validManifest(),
		files:    []pkgFile{{"../escape", []byte("escape")}},
		pub:      pub, priv: priv,
	})
	if _, err := archive.Verify(bytes.NewReader(data), resolverFor(pub)); err == nil {
		t.Error("Verify should reject a payload path containing ..")
	}
}

func TestVerifyRejectsHardlink(t *testing.T) {
	pub, priv := keypair(t)
	data := buildPkg(t, pkgSpec{
		manifest: validManifest(),
		files:    []pkgFile{{"usr/bin/x", []byte("x")}},
		pub:      pub, priv: priv, hardlinkPath: "usr/bin/zzz-hardlink",
	})
	if _, err := archive.Verify(bytes.NewReader(data), resolverFor(pub)); err == nil {
		t.Error("Verify should reject a hardlink payload entry")
	}
}

func TestVerifyRejectsOrphanFilesEntry(t *testing.T) {
	pub, priv := keypair(t)
	data := buildPkg(t, pkgSpec{
		manifest: validManifest(),
		files:    []pkgFile{{"usr/bin/x", []byte("x")}},
		pub:      pub, priv: priv, orphanFilesEntry: true,
	})
	if _, err := archive.Verify(bytes.NewReader(data), resolverFor(pub)); err == nil {
		t.Error("Verify should reject a files.json entry with no matching payload file")
	}
}

func TestVerifyRejectsBadManifest(t *testing.T) {
	pub, priv := keypair(t)
	m := validManifest()
	delete(m, "name") // a required field
	data := buildPkg(t, pkgSpec{
		manifest: m,
		files:    []pkgFile{{"usr/bin/x", []byte("x")}},
		pub:      pub, priv: priv,
	})
	if _, err := archive.Verify(bytes.NewReader(data), resolverFor(pub)); err == nil {
		t.Error("Verify should reject a package with an invalid manifest")
	}
}

func TestVerifyRejectsSizeInstalledMismatch(t *testing.T) {
	pub, priv := keypair(t)
	m := validManifest()
	m["size_installed"] = 999999 // does not match the payload
	data := buildPkg(t, pkgSpec{
		manifest: m,
		files:    []pkgFile{{"usr/bin/x", []byte("x")}},
		pub:      pub, priv: priv,
	})
	if _, err := archive.Verify(bytes.NewReader(data), resolverFor(pub)); err == nil {
		t.Error("Verify should reject a manifest whose size_installed is wrong")
	}
}

func TestVerifyRejectsGarbage(t *testing.T) {
	pub, _ := keypair(t)
	if _, err := archive.Verify(bytes.NewReader([]byte("not a zstd archive")), resolverFor(pub)); err == nil {
		t.Error("Verify should reject input that is not a .peipkg archive")
	}
}
