// Package archive reads and verifies a .peipkg container — the
// Zstandard-compressed pax tar archive that is a package on the wire
// (PSD-009 chapter 3).
//
// [Verify] performs the consumer half of the §3.5.3 verification flow:
// decompress, walk the tar, validate the manifest and the per-file
// integrity manifest, check every payload file's hash, and verify the
// inline Ed25519 signature (§5.3). It does not extract the payload to
// disk — that is the execution layer's job, which re-reads the archive
// once Verify has passed.
package archive

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/klauspost/compress/zstd"
	"github.com/peios/peipkg/internal/manifest"
	"github.com/peios/peipkg/internal/signature"
)

// Resource limits (§3.2.7, §3.5.4).
const (
	tarBlock          = 512
	maxDecompressed   = 4 << 30  // §3.5.4 absolute decompression cap: 4 GiB
	maxManifest       = 16 << 20 // §3.2.7: .peipkg/manifest.json
	maxFiles          = 64 << 20 // §3.2.7: .peipkg/files.json
	maxSignature      = 64 << 10 // §3.2.7: .peipkg/signature
	maxPayloadEntries = 100_000  // §3.2.7
)

// decompressionAllowance bounds the decompressed tar above the manifest's
// size_installed. §3.5.4 fixes this at a flat 320 MiB: enough to cover the
// tar header and block-padding overhead of the §3.2.7 limit of 100,000
// entries plus the metadata files (manifest up to 16 MiB, files.json up
// to 64 MiB), so that no package conforming to §3.2.7 is ever rejected.
const decompressionAllowance = 320 << 20

// Reserved metadata entry paths (§3.2.2).
const (
	metadataManifest  = ".peipkg/manifest.json"
	metadataFiles     = ".peipkg/files.json"
	metadataSignature = ".peipkg/signature"
)

// EntryType is the kind of a payload filesystem object (§3.2.5).
type EntryType uint8

const (
	EntryFile EntryType = iota
	EntryDir
	EntrySymlink
)

// PayloadEntry is one verified payload entry of a package. For a
// regular file, Hash is the verified SHA-256 from the integrity
// manifest; the content itself is not retained.
type PayloadEntry struct {
	Path       string
	Type       EntryType
	Size       int64  // regular files only
	LinkTarget string // symlinks only
	Hash       string // regular files only — lowercase hex SHA-256
}

// Package is a fully-verified .peipkg, the result of [Verify].
type Package struct {
	Manifest manifest.Manifest
	// ManifestJSON is the manifest's exact bytes, retained verbatim for
	// the package database to store unaltered.
	ManifestJSON []byte
	Payload      []PayloadEntry
	// Signed reports whether the package carried an inline signature.
	// An unsigned package is not an error here; whether to accept one
	// is the caller's per-repository trust-policy decision (§6.5.3).
	Signed bool
}

// KeyResolver looks up a trusted public key by its fingerprint. It is
// an alias for [signature.KeyResolver]; the canonical definition lives
// with the signing primitives.
type KeyResolver = signature.KeyResolver

// Verify reads a .peipkg archive from r and checks it end to end:
// decompression bounds, tar structure, payload paths and types, the
// manifest and integrity-manifest schemas, every payload file's hash,
// and — when the package is signed — the inline signature against a
// trusted key. It returns the verified package, or an error naming the
// first failure.
//
// r must be positioned at the start of the archive and is read twice:
// once to walk and validate, once to hash the signed byte range.
func Verify(r io.ReadSeeker, resolveKey KeyResolver) (*Package, error) {
	res, err := walk(r)
	if err != nil {
		return nil, err
	}
	if !res.signed {
		return &Package{Manifest: res.manifest, ManifestJSON: res.manifestJSON,
			Payload: res.payload, Signed: false}, nil
	}

	digest, err := signedDigest(r, res.signedLen)
	if err != nil {
		return nil, err
	}
	key, ok := resolveKey(res.envelope.KeyFingerprint)
	if !ok {
		return nil, fmt.Errorf(
			"peipkg/archive: signing key %s is not in the trust set", res.envelope.KeyFingerprint)
	}
	if err := res.envelope.Verify(key, digest); err != nil {
		return nil, fmt.Errorf("peipkg/archive: %w", err)
	}
	return &Package{Manifest: res.manifest, ManifestJSON: res.manifestJSON,
		Payload: res.payload, Signed: true}, nil
}

// VerifyFormat reads a .peipkg archive from r and checks everything
// Verify does — decompression bounds, tar structure, payload paths and
// types, the manifest and integrity-manifest schemas, and every payload
// file's hash — except the inline signature's trust. The returned
// Package's Signed reports whether a well-formed signature was present;
// it is not checked against any key.
//
// It is the entry point for a raw local-file install, where there is no
// repository and so no trust set to verify a signature against. A
// repository install uses Verify.
func VerifyFormat(r io.ReadSeeker) (*Package, error) {
	res, err := walk(r)
	if err != nil {
		return nil, err
	}
	return &Package{Manifest: res.manifest, ManifestJSON: res.manifestJSON,
		Payload: res.payload, Signed: res.signed}, nil
}

// ReadManifest reads a .peipkg archive's manifest and nothing else.
// §3.2.2 fixes .peipkg/manifest.json as the first archive entry, so a
// package's identity — name, version, architecture, its dependency
// edges — costs a few decompressed kilobytes, however large the
// archive. Nothing is verified beyond the manifest's own schema: the
// payload is not walked, no hash is checked, and a signature is not
// even reached. A caller that goes on to trust the archive's content
// must still Verify or VerifyFormat it.
func ReadManifest(r io.Reader) (manifest.Manifest, error) {
	zr, err := zstd.NewReader(r)
	if err != nil {
		return manifest.Manifest{}, fmt.Errorf("peipkg/archive: open zstd stream: %w", err)
	}
	defer zr.Close()
	// The cap covers exactly what is read: the manifest entry's header
	// block and its §3.2.7-bounded content.
	tr := tar.NewReader(&cappedReader{r: zr, limit: maxManifest + 4*tarBlock})
	hdr, err := tr.Next()
	if err != nil {
		return manifest.Manifest{}, fmt.Errorf("peipkg/archive: reading tar: %w", err)
	}
	if hdr.Name != metadataManifest {
		return manifest.Manifest{}, fmt.Errorf("peipkg/archive: first archive entry is %q, want %q",
			hdr.Name, metadataManifest)
	}
	data, err := readMetadata(tr, hdr, maxManifest, "manifest.json")
	if err != nil {
		return manifest.Manifest{}, err
	}
	m, err := manifest.Decode(data)
	if err != nil {
		return manifest.Manifest{}, fmt.Errorf("peipkg/archive: %w", err)
	}
	return m, nil
}

// walkResult carries everything pass one of Verify extracts.
type walkResult struct {
	manifest     manifest.Manifest
	manifestJSON []byte
	payload      []PayloadEntry
	signed       bool
	envelope     signature.Envelope
	signedLen    int64 // length of the signature's signed byte range (§5.1.2)
}

// walk decompresses and validates the archive in a single pass: tar
// structure and ordering, payload paths and types, the manifest and
// integrity manifest, and every payload file's hash.
func walk(r io.ReadSeeker) (walkResult, error) {
	var res walkResult

	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return res, fmt.Errorf("peipkg/archive: seek to start: %w", err)
	}
	zr, err := zstd.NewReader(r)
	if err != nil {
		return res, fmt.Errorf("peipkg/archive: open zstd stream: %w", err)
	}
	defer zr.Close()

	capped := &cappedReader{r: zr, limit: maxDecompressed}
	tr := tar.NewReader(capped)

	var (
		files       *filesManifest
		index       int // count of metadata+payload entries processed
		seenFiles   = map[string]bool{}
		havePayload bool
		prevPayload string
	)

walkLoop:
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return res, fmt.Errorf("peipkg/archive: reading tar: %w", err)
		}

		// §5.11 determinism, on every entry — metadata and payload alike.
		if err := checkCanonicalHeader(hdr); err != nil {
			return res, fmt.Errorf("peipkg/archive: %w", err)
		}
		// The mtime rule needs build.timestamp, which arrives with the
		// first entry. Entry 0 is checked just after it is decoded.
		if index > 0 || res.manifest.Name != "" {
			if err := checkCanonicalModTime(hdr, res.manifest.Build.Timestamp); err != nil {
				return res, fmt.Errorf("peipkg/archive: %w", err)
			}
		}

		switch {
		case index == 0:
			if hdr.Name != metadataManifest {
				return res, fmt.Errorf("peipkg/archive: first archive entry is %q, want %q",
					hdr.Name, metadataManifest)
			}
			data, err := readMetadata(tr, hdr, maxManifest, "manifest.json")
			if err != nil {
				return res, err
			}
			res.manifest, err = manifest.Decode(data)
			if err != nil {
				return res, fmt.Errorf("peipkg/archive: %w", err)
			}
			res.manifestJSON = data
			// The manifest entry's own mtime, now that build.timestamp is
			// known. Every later entry is checked before its switch arm.
			if err := checkCanonicalModTime(hdr, res.manifest.Build.Timestamp); err != nil {
				return res, fmt.Errorf("peipkg/archive: %w", err)
			}
			// size_installed is now known; tighten the decompression cap.
			capped.limit = min(maxDecompressed, res.manifest.SizeInstalled+decompressionAllowance)

		case index == 1:
			if hdr.Name != metadataFiles {
				return res, fmt.Errorf("peipkg/archive: second archive entry is %q, want %q",
					hdr.Name, metadataFiles)
			}
			data, err := readMetadata(tr, hdr, maxFiles, "files.json")
			if err != nil {
				return res, err
			}
			files, err = decodeFiles(data)
			if err != nil {
				return res, err
			}

		case hdr.Name == metadataSignature:
			// The signed bytes are everything before this entry's header,
			// and capped.read is currently the end of that header — so
			// the arithmetic below depends on the header being exactly one
			// 512-byte ustar block.
			//
			// §5.11 rule 12 guarantees that: an extended header appears
			// only for an over-long path or linkname, and
			// `.peipkg/signature` is neither. But when the guarantee was
			// merely assumed, a producer emitting a PAX record here made
			// the header three blocks, signedLen overshot by 1024, the
			// digest covered bytes it must not, and Verify failed with
			// "signature verification failed" — pointing at the key rather
			// than at the real cause. Check the assumption so the archive
			// is rejected for what is actually wrong with it.
			if len(hdr.PAXRecords) > 0 {
				return res, fmt.Errorf(
					"peipkg/archive: %s carries a PAX extended header, which §5.11 rule 12 "+
						"permits only for an over-long path or linkname", metadataSignature)
			}
			res.signedLen = capped.read - tarBlock
			data, err := readMetadata(tr, hdr, maxSignature, "signature")
			if err != nil {
				return res, err
			}
			res.envelope, err = signature.DecodeEnvelope(data)
			if err != nil {
				return res, err
			}
			res.signed = true
			// §5.3 condition 2: nothing may follow the signature entry.
			if _, err := tr.Next(); err != io.EOF {
				return res, fmt.Errorf(
					"peipkg/archive: the signature entry is not the last archive entry")
			}
			break walkLoop

		case strings.HasPrefix(hdr.Name, metadataPrefix):
			// An optional/unrecognised metadata entry (§3.2.4): ignored,
			// but it must precede the payload.
			if havePayload {
				return res, fmt.Errorf(
					"peipkg/archive: metadata entry %q appears after payload", hdr.Name)
			}

		default:
			entry, err := payloadEntry(hdr)
			if err != nil {
				return res, err
			}
			if havePayload && hdr.Name <= prevPayload {
				return res, fmt.Errorf(
					"peipkg/archive: payload entries are not sorted (%q after %q)",
					hdr.Name, prevPayload)
			}
			if len(res.payload) == maxPayloadEntries {
				return res, fmt.Errorf("peipkg/archive: more than %d payload entries",
					maxPayloadEntries)
			}
			if entry.Type == EntryFile {
				fe, ok := files.byPath[entry.Path]
				if !ok {
					return res, fmt.Errorf(
						"peipkg/archive: payload file %q has no files.json entry", entry.Path)
				}
				if err := verifyFileContent(tr, entry.Path, fe); err != nil {
					return res, err
				}
				entry.Hash = fe.hash
				seenFiles[entry.Path] = true
			}
			res.payload = append(res.payload, entry)
			havePayload = true
			prevPayload = hdr.Name
		}
		index++
	}

	if index < 2 || files == nil {
		return res, fmt.Errorf("peipkg/archive: archive is missing manifest.json or files.json")
	}
	// §3.5.2: the integrity manifest covers exactly the regular-file
	// payload entries — no entry without a payload file.
	if len(seenFiles) != len(files.byPath) {
		return res, fmt.Errorf(
			"peipkg/archive: files.json has %d entries with no matching payload file",
			len(files.byPath)-len(seenFiles))
	}
	if err := checkInstalledSize(res.manifest.SizeInstalled, files); err != nil {
		return res, err
	}
	if err := checkSDOverrideTargets(&res); err != nil {
		return res, err
	}
	return res, nil
}

// checkSDOverrideTargets enforces the two §5.20 conditions on an override
// that only a reader of both the manifest and the payload can check: that
// `path` names a real payload entry, and that the entry is a regular file
// or a directory rather than a symlink.
//
// walk is the only place that sees both, and it never consulted
// SDOverrides — so an override could name a path the package does not
// ship, or a symlink, and be accepted. A symlink carries no independent
// descriptor at all (§5.17: access to a symlink is governed by access to
// its target), so an override on one is not merely useless, it names
// something that cannot hold what it is assigning.
func checkSDOverrideTargets(res *walkResult) error {
	if len(res.manifest.SDOverrides) == 0 {
		return nil
	}
	kinds := make(map[string]EntryType, len(res.payload))
	for _, entry := range res.payload {
		kinds[entry.Path] = entry.Type
	}
	for _, override := range res.manifest.SDOverrides {
		kind, ok := kinds[override.Path]
		if !ok {
			return fmt.Errorf(
				"peipkg/archive: sd_override names %q, which is not a payload entry",
				override.Path)
		}
		if kind == EntrySymlink {
			return fmt.Errorf(
				"peipkg/archive: sd_override names %q, which is a symlink; a symlink "+
					"carries no independent security descriptor", override.Path)
		}
	}
	return nil
}

// signedDigest re-reads the archive and returns the SHA-256 of its
// signed byte range — the first signedLen bytes of the decompressed tar
// (§5.1.2).
func signedDigest(r io.ReadSeeker, signedLen int64) ([]byte, error) {
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("peipkg/archive: seek to start: %w", err)
	}
	zr, err := zstd.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("peipkg/archive: open zstd stream: %w", err)
	}
	defer zr.Close()

	h := sha256.New()
	if _, err := io.CopyN(h, zr, signedLen); err != nil {
		return nil, fmt.Errorf("peipkg/archive: hashing signed bytes: %w", err)
	}
	return h.Sum(nil), nil
}

// payloadEntry validates a payload tar header and converts it to a
// PayloadEntry (§3.2.5, §3.2.6).
func payloadEntry(hdr *tar.Header) (PayloadEntry, error) {
	var entry PayloadEntry
	name := hdr.Name

	switch hdr.Typeflag {
	case tar.TypeReg:
		entry.Type = EntryFile
		entry.Size = hdr.Size
	case tar.TypeDir:
		entry.Type = EntryDir
		name = strings.TrimSuffix(name, "/") // tar directory entries carry a trailing slash
	case tar.TypeSymlink:
		entry.Type = EntrySymlink
		// §5.17 requires a consumer to validate every symlink target
		// before extracting the entry. Validating here rather than at
		// install time is what makes Verify alone sufficient: the
		// linkname was previously copied through untouched, so
		// `peipkg verify`, publication and repository ingest never
		// looked at it at all.
		if err := validateSymlinkTargetPath(hdr.Linkname); err != nil {
			return PayloadEntry{}, fmt.Errorf(
				"peipkg/archive: payload entry %q: %w", hdr.Name, err)
		}
		entry.LinkTarget = hdr.Linkname
	default:
		return PayloadEntry{}, fmt.Errorf(
			"peipkg/archive: payload entry %q has unsupported tar type %q", hdr.Name, hdr.Typeflag)
	}
	if err := validatePayloadPath(name); err != nil {
		return PayloadEntry{}, fmt.Errorf("peipkg/archive: %w", err)
	}
	entry.Path = name
	return entry, nil
}

// verifyFileContent streams a regular-file payload entry's content and
// confirms its size and SHA-256 match the integrity manifest (§3.5.3
// step 7).
func verifyFileContent(tr *tar.Reader, path string, fe fileEntry) error {
	h := sha256.New()
	n, err := io.Copy(h, tr)
	if err != nil {
		return fmt.Errorf("peipkg/archive: reading payload file %q: %w", path, err)
	}
	if n != fe.size {
		return fmt.Errorf("peipkg/archive: payload file %q is %d bytes, files.json says %d",
			path, n, fe.size)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != fe.hash {
		return fmt.Errorf("peipkg/archive: payload file %q hash mismatch (got %s, want %s)",
			path, got, fe.hash)
	}
	return nil
}

// readMetadata reads a `.peipkg/` metadata entry's content, enforcing
// that it is a regular file within the size limit.
func readMetadata(tr *tar.Reader, hdr *tar.Header, limit int64, label string) ([]byte, error) {
	if hdr.Typeflag != tar.TypeReg {
		return nil, fmt.Errorf("peipkg/archive: %s entry is not a regular file", label)
	}
	if hdr.Size > limit {
		return nil, fmt.Errorf("peipkg/archive: %s is %d bytes, the limit is %d",
			label, hdr.Size, limit)
	}
	data, err := io.ReadAll(tr)
	if err != nil {
		return nil, fmt.Errorf("peipkg/archive: reading %s: %w", label, err)
	}
	return data, nil
}

// checkInstalledSize confirms the manifest's size_installed equals the
// sum of the integrity manifest's file sizes, the relationship §3.3
// defines between them.
func checkInstalledSize(declared int64, files *filesManifest) error {
	var sum int64
	for _, fe := range files.byPath {
		sum += fe.size
	}
	if sum != declared {
		return fmt.Errorf(
			"peipkg/archive: manifest size_installed is %d, files.json sizes sum to %d",
			declared, sum)
	}
	return nil
}

// cappedReader fails the read once cumulative output exceeds limit,
// bounding decompression against resource-exhaustion attacks (§3.5.4).
// limit may be lowered mid-stream once the manifest reveals a tighter
// bound.
type cappedReader struct {
	r     io.Reader
	limit int64
	read  int64
}

func (c *cappedReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.read += int64(n)
	if c.read > c.limit {
		return n, fmt.Errorf("peipkg/archive: decompressed output exceeds the %d-byte limit", c.limit)
	}
	return n, err
}
