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
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/peios/libp-go/sddl"
	"github.com/peios/peipkg/internal/archive"
	"github.com/peios/peipkg/internal/manifest"
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

	// tweakHeader mutates every tar header just before it is written, so
	// a test can build a deliberately non-canonical archive (§5.11).
	tweakHeader func(*tar.Header)
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
	// §5.11 pins every one of these. The fixtures used to set only Mode
	// and an epoch ModTime, which is precisely the non-conformance the
	// read-side determinism check now rejects.
	buildTS, err := time.Parse(time.RFC3339,
		spec.manifest["build"].(map[string]any)["timestamp"].(string))
	if err != nil {
		t.Fatalf("parse fixture build.timestamp: %v", err)
	}
	write := func(name string, typ byte, content []byte, linkname string) {
		hdr := &tar.Header{
			Name: name, Typeflag: typ, Mode: 0o777,
			Uid: 0, Gid: 0, Uname: "root", Gname: "root",
			Format: tar.FormatPAX,
			Size:   int64(len(content)), Linkname: linkname, ModTime: buildTS,
		}
		if spec.tweakHeader != nil {
			spec.tweakHeader(hdr)
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

func TestReadManifest(t *testing.T) {
	pub, priv := keypair(t)
	data := buildPkg(t, pkgSpec{
		manifest: validManifest(),
		files:    []pkgFile{{"usr/bin/testpkg", []byte("#!/bin/sh\n")}},
		pub:      pub, priv: priv,
	})
	m, err := archive.ReadManifest(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("ReadManifest: %v", err)
	}
	if m.Name != "testpkg" || m.Version.String() != "1.0.0-1" || m.Architecture != "x86_64" {
		t.Errorf("manifest: got %s %s %s", m.Name, m.Version, m.Architecture)
	}
}

// ReadManifest is candidacy, not verification: an archive whose payload
// would fail VerifyFormat still yields its manifest.
func TestReadManifestIgnoresPayload(t *testing.T) {
	pub, priv := keypair(t)
	data := buildPkg(t, pkgSpec{
		manifest: validManifest(),
		files:    []pkgFile{{"usr/bin/testpkg", []byte("#!/bin/sh\n")}},
		pub:      pub, priv: priv, wrongFileHash: true,
	})
	if _, err := archive.VerifyFormat(bytes.NewReader(data)); err == nil {
		t.Fatal("fixture is not actually malformed")
	}
	m, err := archive.ReadManifest(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("ReadManifest: %v", err)
	}
	if m.Name != "testpkg" {
		t.Errorf("Name: got %q", m.Name)
	}
}

func TestReadManifestRejectsMisplacedManifest(t *testing.T) {
	pub, priv := keypair(t)
	data := buildPkg(t, pkgSpec{
		manifest: validManifest(),
		files:    []pkgFile{{"usr/bin/testpkg", []byte("#!/bin/sh\n")}},
		pub:      pub, priv: priv,
		tweakHeader: func(hdr *tar.Header) {
			if hdr.Name == ".peipkg/manifest.json" {
				hdr.Name = ".peipkg/zz-manifest.json"
			}
		},
	})
	if _, err := archive.ReadManifest(bytes.NewReader(data)); err == nil ||
		!strings.Contains(err.Error(), "first archive entry") {
		t.Errorf("ReadManifest = %v, want a first-entry error", err)
	}
}

func TestReadManifestRejectsGarbage(t *testing.T) {
	if _, err := archive.ReadManifest(bytes.NewReader([]byte("not a zstd archive"))); err == nil {
		t.Error("ReadManifest should reject input that is not a .peipkg archive")
	}
}

func TestExtract(t *testing.T) {
	pub, priv := keypair(t)
	data := buildPkg(t, pkgSpec{
		manifest: validManifest(),
		files: []pkgFile{
			{"usr/bin/testpkg", []byte("binary content")},
			{"usr/share/testpkg/data", []byte("payload data")},
		},
		dirs:     []string{"usr/share/testpkg"},
		symlinks: []pkgSymlink{{"usr/bin/testpkg-link", "usr/bin/testpkg"}},
		pub:      pub, priv: priv,
	})
	if _, err := archive.Verify(bytes.NewReader(data), resolverFor(pub)); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	files := map[string]string{}
	count := 0
	err := archive.Extract(bytes.NewReader(data), func(e archive.PayloadEntry, content io.Reader) error {
		count++
		body, err := io.ReadAll(content)
		if err != nil {
			return err
		}
		if e.Type == archive.EntryFile {
			files[e.Path] = string(body)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if count != 4 { // two files, one directory, one symlink
		t.Errorf("Extract yielded %d entries, want 4", count)
	}
	if files["usr/bin/testpkg"] != "binary content" {
		t.Errorf("extracted file content: got %q", files["usr/bin/testpkg"])
	}
}

// PSPU §5.17 subjects a symlink target to the same path-validity
// constraints as a payload path, and requires a consumer to validate
// every target before extracting the entry.
//
// The linkname was previously copied out of the tar header untouched, so
// Verify — which is what `peipkg verify`, publication and repository
// ingest all use — never looked at a target at all. A target carrying an
// escape sequence, invalid UTF-8 or an NFD-normalised name passed
// verification and was created verbatim.
func TestVerifyRejectsNonConformingSymlinkTargets(t *testing.T) {
	// U+00E9 decomposed: "e" followed by COMBINING ACUTE ACCENT. It
	// silently fails to resolve against an NFC-normalised payload path,
	// producing a dangling link that verification called clean.
	nfd := "usr/share/café/data"

	cases := map[string]string{
		"absolute":            "/etc/passwd",
		"empty":               "",
		"backslash":           "usr\\bin\\testpkg",
		"terminal escape":     "usr/bin/\x1b[2Jtestpkg",
		"DEL":                 "usr/bin/\x7ftestpkg",
		"invalid UTF-8":       "usr/bin/\xff\xfe",
		"NFD normalisation":   nfd,
		"over 4096 bytes":     strings.Repeat("a", 4097),
		"component over 255":  "usr/bin/" + strings.Repeat("b", 256),
		"over 256 components": strings.Repeat("a/", 257) + "x",
	}
	// A NUL is absent from this table only because Go's tar writer
	// refuses to encode one in a linkname; the rule itself is covered by
	// TestValidateSymlinkTarget below.
	for name, target := range cases {
		t.Run(name, func(t *testing.T) {
			data := buildPkg(t, pkgSpec{
				manifest: validManifest(),
				files:    []pkgFile{{"usr/bin/testpkg", []byte("hi\n")}},
				symlinks: []pkgSymlink{{"usr/bin/testpkg-link", target}},
				unsigned: true,
			})
			if _, err := archive.VerifyFormat(bytes.NewReader(data)); err == nil {
				t.Errorf("VerifyFormat accepted symlink target %q", target)
			}
		})
	}
}

// A target legitimately contains "..": that is how the conventional
// library split reaches a sibling directory. The component rules a
// payload path adds must not be applied to targets.
func TestVerifyAcceptsConformingSymlinkTargets(t *testing.T) {
	for name, target := range map[string]string{
		"sibling":          "testpkg",
		"parent traversal": "../lib/libtestpkg.so.1",
		"deeper traversal": "../../usr/lib/libtestpkg.so.1",
		"dot component":    "./testpkg",
		"NFC non-ASCII":    "usr/share/café/data",
		// 16 components of 254 bytes plus separators: 4079 bytes, inside
		// both the 4096-byte total and the 255-byte component limit.
		"long but legal": strings.TrimSuffix(strings.Repeat(strings.Repeat("a", 254)+"/", 16), "/"),
	} {
		t.Run(name, func(t *testing.T) {
			data := buildPkg(t, pkgSpec{
				manifest: validManifest(),
				files:    []pkgFile{{"usr/bin/testpkg", []byte("hi\n")}},
				symlinks: []pkgSymlink{{"usr/bin/testpkg-link", target}},
				unsigned: true,
			})
			pkg, err := archive.VerifyFormat(bytes.NewReader(data))
			if err != nil {
				t.Fatalf("VerifyFormat rejected target %q: %v", target, err)
			}
			var found bool
			for _, e := range pkg.Payload {
				if e.Type == archive.EntrySymlink {
					found = true
					if e.LinkTarget != target {
						t.Errorf("LinkTarget: got %q, want %q", e.LinkTarget, target)
					}
				}
			}
			if !found {
				t.Error("no symlink entry in the verified payload")
			}
		})
	}
}

// The §5.17 rules themselves, exercised directly. The producer side
// shares this function, so a target rejected here is rejected at pack
// time as well as at verification.
func TestValidateSymlinkTarget(t *testing.T) {
	bad := map[string]string{
		"empty":               "",
		"absolute":            "/etc/passwd",
		"NUL byte":            "usr/bin/\x00testpkg",
		"backslash":           "usr\\bin\\testpkg",
		"C0 control":          "usr/bin/\x01testpkg",
		"ESC":                 "usr/bin/\x1btestpkg",
		"DEL":                 "usr/bin/\x7ftestpkg",
		"invalid UTF-8":       "usr/bin/\xff\xfe",
		"NFD":                 "usr/share/cafe\u0301/data",
		"total over 4096":     strings.Repeat("a", 4097),
		"component over 255":  strings.Repeat("b", 256),
		"over 256 components": strings.Repeat("a/", 257) + "x",
	}
	for name, target := range bad {
		t.Run("reject/"+name, func(t *testing.T) {
			if err := archive.ValidateSymlinkTarget(target); err == nil {
				t.Errorf("ValidateSymlinkTarget(%q) = nil, want an error", target)
			}
		})
	}

	good := map[string]string{
		"sibling":          "testpkg",
		"parent traversal": "../lib/libtestpkg.so.1",
		"dot component":    "./testpkg",
		"NFC non-ASCII":    "usr/share/caf\u00e9/data",
		"component at 255": strings.Repeat("b", 255),
		"256 components":   strings.Repeat("a/", 255) + "x",
	}
	for name, target := range good {
		t.Run("accept/"+name, func(t *testing.T) {
			if err := archive.ValidateSymlinkTarget(target); err != nil {
				t.Errorf("ValidateSymlinkTarget(%q) = %v, want nil", target, err)
			}
		})
	}
}

// PSPU §5.11's twelve determinism rules constrain the archive's bytes,
// and a consumer rejects a package violating any of them. §5.16 makes the
// mode rule an explicit rejection condition: "Every payload entry's
// permission bits MUST be 0777. Any other value MUST cause the package to
// be rejected."
//
// Entry ordering was the only rule enforced on read. So a hand-built
// .peipkg with mode 04755, uid 1000, uname "attacker", an mtime unrelated
// to its manifest and SCHILY.xattr records installed cleanly and `peipkg
// verify` reported it clean.
//
// There is no escalation on Peios — extraction ignores modes entirely —
// but the package is non-conformant, and a non-Peios consumer extracting
// the same file with GNU tar honours the setuid bit. It also defeats the
// reproducibility claim §5.11 exists to make: a repacked archive whose
// mtimes diverge from build.timestamp verified successfully, so a third
// party re-running the build and diffing bytes got a mismatch peipkg
// itself would have accepted.
func TestVerifyRejectsNonCanonicalHeaders(t *testing.T) {
	cases := map[string]func(*tar.Header){
		"setuid mode":       func(h *tar.Header) { h.Mode = 0o4755 },
		"setgid mode":       func(h *tar.Header) { h.Mode = 0o2777 },
		"plain 0644":        func(h *tar.Header) { h.Mode = 0o644 },
		"sticky bit":        func(h *tar.Header) { h.Mode = 0o1777 },
		"non-zero uid":      func(h *tar.Header) { h.Uid = 1000 },
		"non-zero gid":      func(h *tar.Header) { h.Gid = 1000 },
		"attacker uname":    func(h *tar.Header) { h.Uname = "attacker" },
		"empty gname":       func(h *tar.Header) { h.Gname = "" },
		"xattrs":            func(h *tar.Header) { h.PAXRecords = map[string]string{"SCHILY.xattr.security.capability": "x"} },
		"libarchive xattrs": func(h *tar.Header) { h.PAXRecords = map[string]string{"LIBARCHIVE.xattr.user.foo": "x"} },
		"devmajor":          func(h *tar.Header) { h.Devmajor = 8 },
		"devminor":          func(h *tar.Header) { h.Devminor = 1 },
		"epoch mtime":       func(h *tar.Header) { h.ModTime = time.Unix(0, 0) },
		"mtime off by 1s": func(h *tar.Header) {
			h.ModTime = h.ModTime.Add(time.Second)
		},
	}
	for name, tweak := range cases {
		t.Run(name, func(t *testing.T) {
			data := buildPkg(t, pkgSpec{
				manifest:    validManifest(),
				files:       []pkgFile{{"usr/bin/testpkg", []byte("hi\n")}},
				unsigned:    true,
				tweakHeader: tweak,
			})
			if _, err := archive.VerifyFormat(bytes.NewReader(data)); err == nil {
				t.Errorf("VerifyFormat accepted a non-canonical header (%s)", name)
			}
		})
	}
}

// The determinism rules must not reject a conformant archive, including
// the metadata entries, which are checked on the same terms as the
// payload.
func TestVerifyAcceptsCanonicalHeaders(t *testing.T) {
	data := buildPkg(t, pkgSpec{
		manifest: validManifest(),
		files: []pkgFile{
			{"usr/bin/testpkg", []byte("hi\n")},
			{"usr/share/testpkg/data", []byte("data")},
		},
		dirs:     []string{"usr/share/testpkg"},
		symlinks: []pkgSymlink{{"usr/bin/testpkg-link", "testpkg"}},
		unsigned: true,
	})
	if _, err := archive.VerifyFormat(bytes.NewReader(data)); err != nil {
		t.Fatalf("VerifyFormat rejected a canonical archive: %v", err)
	}
}

// §5.11 rule 2 forbids sub-second precision on build.timestamp, and rule
// 12 permits a PAX extended header only for an over-long path or
// linkname. The two interact badly: the timestamp *is* every entry's
// mtime, and Go's tar writer sets preferPAX for a non-zero nanosecond
// field, so a fractional timestamp puts a forbidden `x` header on every
// entry in the archive.
//
// The severe consequence is that a signed package built this way fails
// its own signature check — the signature entry's header becomes three
// blocks instead of one, signedLen overshoots by 1024, and Verify reports
// "signature verification failed", pointing at the key rather than at the
// timestamp.
func TestSubSecondBuildTimestampIsRejected(t *testing.T) {
	for _, ts := range []string{
		"2026-05-19T00:00:00.5Z",
		"2026-05-19T00:00:00.000000001Z",
		"2026-05-19T00:00:00.999Z",
	} {
		t.Run(ts, func(t *testing.T) {
			m := validManifest()
			m["size_installed"] = 0
			m["build"].(map[string]any)["timestamp"] = ts
			if _, err := manifest.Decode(mustJSON(t, m)); err == nil {
				t.Errorf("Decode accepted build.timestamp %q", ts)
			}
		})
	}

	// Whole seconds must still decode.
	m := validManifest()
	m["size_installed"] = 0
	m["build"].(map[string]any)["timestamp"] = "2026-05-19T00:00:00Z"
	if _, err := manifest.Decode(mustJSON(t, m)); err != nil {
		t.Errorf("Decode rejected a whole-second timestamp: %v", err)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

// §5.20 requires an override's `path` to name a real payload entry, and that
// entry to be a regular file or a directory rather than a symlink.
//
// walk is the only place that sees both the manifest and the tar entries, and
// it never consulted SDOverrides — so an override could name a path the
// package does not ship, or a symlink, and be accepted.
func TestVerifyRejectsAnSDOverrideThatNamesNoPayloadEntry(t *testing.T) {
	m := validManifest()
	m["sd_overrides"] = []any{
		map[string]any{
			"path": "usr/bin/not-shipped",
			"sd":   base64.RawStdEncoding.EncodeToString(testDescriptor(t)),
		},
	}
	data := buildPkg(t, pkgSpec{
		manifest: m,
		files:    []pkgFile{{"usr/bin/testpkg", []byte("hi\n")}},
		unsigned: true,
	})
	if _, err := archive.VerifyFormat(bytes.NewReader(data)); err == nil {
		t.Error("an override naming a path the package does not ship was accepted")
	}
}

// A symlink carries no independent descriptor — §5.17 makes access to one
// governed by access to its target — so an override on a symlink is not merely
// useless, it names something that cannot hold what it assigns.
func TestVerifyRejectsAnSDOverrideOnASymlink(t *testing.T) {
	m := validManifest()
	m["sd_overrides"] = []any{
		map[string]any{
			"path": "usr/bin/testpkg-link",
			"sd":   base64.RawStdEncoding.EncodeToString(testDescriptor(t)),
		},
	}
	data := buildPkg(t, pkgSpec{
		manifest: m,
		files:    []pkgFile{{"usr/bin/testpkg", []byte("hi\n")}},
		symlinks: []pkgSymlink{{"usr/bin/testpkg-link", "testpkg"}},
		unsigned: true,
	})
	if _, err := archive.VerifyFormat(bytes.NewReader(data)); err == nil {
		t.Error("an override on a symlink was accepted")
	}
}

// An override naming a real file must still verify.
func TestVerifyAcceptsAnSDOverrideOnAFile(t *testing.T) {
	m := validManifest()
	m["sd_overrides"] = []any{
		map[string]any{
			"path": "usr/bin/testpkg",
			"sd":   base64.RawStdEncoding.EncodeToString(testDescriptor(t)),
		},
	}
	data := buildPkg(t, pkgSpec{
		manifest: m,
		files:    []pkgFile{{"usr/bin/testpkg", []byte("hi\n")}},
		unsigned: true,
	})
	if _, err := archive.VerifyFormat(bytes.NewReader(data)); err != nil {
		t.Errorf("an override on a real file was rejected: %v", err)
	}
}

func testDescriptor(t *testing.T) []byte {
	t.Helper()
	d, err := sddl.Parse("O:BAG:SY")
	if err != nil {
		t.Fatalf("sddl.Parse: %v", err)
	}
	raw, err := d.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return raw
}
