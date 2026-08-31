package compose

import (
	"bytes"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/peios/peipkg/internal/config"
	"github.com/peios/peipkg/internal/repository"
	"github.com/peios/peipkg/internal/version"
)

// lockSchema is the lock schema version peipkg-compose writes and reads.
// Bumped to 4 for verification: a lock now carries the trust state of
// each repository it drew from (§5.30) and each package's
// index-declared compressed and installed sizes (§5.27), so the build
// phase can verify signatures and bound both the download and the
// decompression without re-running the trust ceremony.
const lockSchema = 4

// LocalSource is the [LockedPackage.Source] value of a package supplied
// as a local .peipkg file rather than fetched from a repository.
const LocalSource = "local"

// Lock is a resolved package closure: the exact set of packages a build
// installs, each pinned to a version and a content hash. A build from a
// lock is deterministic and needs no resolution. Obtain one through
// [DecodeLock] or [LoadLock]; build one with [Resolve].
type Lock struct {
	// Arch is the architecture the closure was resolved for; it must
	// match the manifest's.
	Arch string
	// SourceDate is carried from the manifest, so a build from the lock
	// alone reproduces the same build-stamped times.
	SourceDate time.Time
	// Manifest is the filename of the manifest this lock was resolved
	// from — provenance for a reader; the build does not consult it.
	Manifest string
	// ManifestDigest is the sha256 digest of the decoded manifest intent
	// this lock was resolved from. A build refuses a lock whose digest no
	// longer matches the current manifest.
	ManifestDigest string
	// Packages is the resolved closure, sorted by name.
	Packages []LockedPackage
	// Sources carries forward the trust state of every repository the
	// closure draws from, sorted by name. Trust is *established* at lock
	// time — that is the design — but §5.30 requires the signature on
	// each package to be checked against it before any payload is
	// extracted, which happens in the build phase. Recording it here is
	// what lets the use of that trust survive into the build.
	Sources []LockedSource
}

// LockedSource is one repository the closure draws packages from, with
// the trust the lock phase established for it.
type LockedSource struct {
	Name string
	// SignaturePolicy is the repository's configured signature policy,
	// so the build applies the same gate the lock resolved under.
	SignaturePolicy string
	// TrustKeys is the repository's trust set — fingerprint, raw public
	// key, status and any valid_until — in the same JSON encoding the
	// package database stores in repository.trust_keys. Empty for a
	// repository in unsigned mode (§6.5.3), which has no keys.
	TrustKeys string
}

// LockedPackage is one package of a resolved closure.
type LockedPackage struct {
	Name         string
	Version      string
	Architecture string
	// Root is the path, relative to the output root, of the root this
	// package is installed into; empty for the output (anchor) root. A
	// package name may appear in more than one root (identity is the
	// (name, root) pair), so a lock is keyed by both.
	Root string
	// Source is the name of the repository the package resolves from,
	// or [LocalSource] for a package supplied as a local .peipkg file.
	Source string
	// URL fetches the package: an absolute HTTP(S) URL for a repository
	// package, or a filesystem path for a local one.
	URL string
	// Hash is the lowercase-hex SHA-256 of the .peipkg file. A build
	// verifies the fetched bytes against it.
	Hash string
	// SizeCompressed is the compressed size the index entry advertised,
	// carried forward so the build bounds the download by §5.27's rule
	// rather than by a flat figure of its own.
	SizeCompressed int64
	// SizeInstalled is the installed size the index entry advertised —
	// carried forward from the signed index so the build phase can bound
	// decompression without reading it out of the compressed stream
	// (§5.27). For a local-source package it is the manifest's own
	// figure, read at lock time and pinned by Hash like everything else.
	SizeInstalled int64
}

// wireLock mirrors the lock's TOML shape. The scalar fields are
// pointers so a missing required key is reported precisely on decode;
// [Lock.Encode] sets every one.
type wireLock struct {
	Schema         *int                `toml:"schema"`
	Arch           *string             `toml:"arch"`
	SourceDate     *string             `toml:"source_date"`
	Manifest       string              `toml:"manifest,omitempty"`
	ManifestDigest *string             `toml:"manifest_digest,omitempty"`
	Sources        []wireLockedSource  `toml:"source"`
	Packages       []wireLockedPackage `toml:"package"`
}

type wireLockedSource struct {
	Name            *string `toml:"name"`
	SignaturePolicy *string `toml:"signature_policy"`
	TrustKeys       string  `toml:"trust_keys"`
}

type wireLockedPackage struct {
	Name           *string `toml:"name"`
	Version        *string `toml:"version"`
	Architecture   *string `toml:"architecture"`
	Source         *string `toml:"source"`
	URL            *string `toml:"url"`
	Hash           *string `toml:"hash"`
	SizeCompressed *int64  `toml:"size_compressed"`
	SizeInstalled  *int64  `toml:"size_installed"`
	Root           string  `toml:"root,omitempty"`
}

// LockPath derives a lock's path from its manifest's path: the manifest
// stem with a .lock.toml extension, so the two sort adjacent and the
// pairing is plain — peipkg-manifest-2026-6-1.toml yields
// peipkg-manifest-2026-6-1.lock.toml.
func LockPath(manifestPath string) string {
	return strings.TrimSuffix(manifestPath, ".toml") + ".lock.toml"
}

// LoadLock reads and decodes a lock from a file.
func LoadLock(path string) (Lock, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Lock{}, fmt.Errorf("peipkg/compose: reading lock: %w", err)
	}
	return DecodeLock(data)
}

// DecodeLock parses and validates a lock from its raw TOML bytes.
func DecodeLock(data []byte) (Lock, error) {
	var w wireLock
	md, err := toml.Decode(string(data), &w)
	if err != nil {
		return Lock{}, fmt.Errorf("peipkg/compose: invalid lock TOML: %w", err)
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		return Lock{}, fmt.Errorf("peipkg/compose: lock has the unknown key %q",
			undecoded[0].String())
	}

	switch {
	case w.Schema == nil:
		return Lock{}, missingKey("schema")
	}
	if *w.Schema != lockSchema {
		return Lock{}, fmt.Errorf("peipkg/compose: lock schema is %d, want %d",
			*w.Schema, lockSchema)
	}

	switch {
	case w.Arch == nil:
		return Lock{}, missingKey("arch")
	case w.SourceDate == nil:
		return Lock{}, missingKey("source_date")
	case w.ManifestDigest == nil:
		return Lock{}, missingKey("manifest_digest")
	}
	sourceDate, err := time.Parse(time.RFC3339, *w.SourceDate)
	if err != nil {
		return Lock{}, fmt.Errorf("peipkg/compose: lock source_date %q is not an RFC 3339 "+
			"timestamp: %w", *w.SourceDate, err)
	}

	l := Lock{
		Arch: *w.Arch, SourceDate: sourceDate,
		Manifest: w.Manifest, ManifestDigest: *w.ManifestDigest,
	}
	if err := validateHash(l.ManifestDigest); err != nil {
		return Lock{}, fmt.Errorf("peipkg/compose: lock manifest_digest: %w", err)
	}
	sourceNames := map[string]bool{}
	for i, ws := range w.Sources {
		src, err := decodeLockedSource(ws)
		if err != nil {
			return Lock{}, fmt.Errorf("peipkg/compose: lock source %d: %w", i, err)
		}
		if sourceNames[src.Name] {
			return Lock{}, fmt.Errorf("peipkg/compose: lock names the source %q more than once",
				src.Name)
		}
		sourceNames[src.Name] = true
		l.Sources = append(l.Sources, src)
	}

	seen := map[string]bool{}
	for i, wp := range w.Packages {
		p, err := decodeLockedPackage(wp)
		if err != nil {
			return Lock{}, fmt.Errorf("peipkg/compose: lock package %d: %w", i, err)
		}
		// Every repository package must name a source the lock records
		// the trust state of, or the build has no key to verify its
		// signature against (§5.30).
		if p.Source != LocalSource && !sourceNames[p.Source] {
			return Lock{}, fmt.Errorf("peipkg/compose: lock package %q names the source %q, "+
				"which the lock records no trust state for", p.Name, p.Source)
		}
		// Identity is (name, root): the same name may appear in two roots.
		key := p.Root + "\x00" + p.Name
		if seen[key] {
			return Lock{}, fmt.Errorf("peipkg/compose: lock has the package %q in root %q more "+
				"than once", p.Name, p.Root)
		}
		seen[key] = true
		l.Packages = append(l.Packages, p)
	}
	if len(l.Packages) == 0 {
		return Lock{}, fmt.Errorf("peipkg/compose: lock contains no packages")
	}
	return l, nil
}

// decodeLockedSource validates one [[source]] entry of a lock.
func decodeLockedSource(w wireLockedSource) (LockedSource, error) {
	switch {
	case w.Name == nil || *w.Name == "":
		return LockedSource{}, fmt.Errorf("missing %q", "name")
	case w.SignaturePolicy == nil || *w.SignaturePolicy == "":
		return LockedSource{}, fmt.Errorf("missing %q", "signature_policy")
	}
	switch config.SignaturePolicy(*w.SignaturePolicy) {
	case config.PolicyRequired, config.PolicyOptional:
	default:
		return LockedSource{}, fmt.Errorf("signature_policy %q is neither %q nor %q",
			*w.SignaturePolicy, config.PolicyRequired, config.PolicyOptional)
	}
	// The trust set is parsed here rather than at first use, so a
	// corrupt lock is rejected as a lock rather than as a mid-build
	// verification failure.
	if _, err := repository.ParseTrustSet(w.TrustKeys); err != nil {
		return LockedSource{}, err
	}
	return LockedSource{
		Name: *w.Name, SignaturePolicy: *w.SignaturePolicy, TrustKeys: w.TrustKeys,
	}, nil
}

// decodeLockedPackage validates one [[package]] entry of a lock.
func decodeLockedPackage(w wireLockedPackage) (LockedPackage, error) {
	switch {
	case w.Name == nil || *w.Name == "":
		return LockedPackage{}, fmt.Errorf("missing %q", "name")
	case w.Version == nil:
		return LockedPackage{}, fmt.Errorf("missing %q", "version")
	case w.Architecture == nil || *w.Architecture == "":
		return LockedPackage{}, fmt.Errorf("missing %q", "architecture")
	case w.Source == nil || *w.Source == "":
		return LockedPackage{}, fmt.Errorf("missing %q", "source")
	case w.URL == nil || *w.URL == "":
		return LockedPackage{}, fmt.Errorf("missing %q", "url")
	case w.Hash == nil:
		return LockedPackage{}, fmt.Errorf("missing %q", "hash")
	case w.SizeCompressed == nil:
		return LockedPackage{}, fmt.Errorf("missing %q", "size_compressed")
	case w.SizeInstalled == nil:
		return LockedPackage{}, fmt.Errorf("missing %q", "size_installed")
	}
	if *w.SizeCompressed < 0 {
		return LockedPackage{}, fmt.Errorf("size_compressed is %d", *w.SizeCompressed)
	}
	if *w.SizeInstalled < 0 {
		return LockedPackage{}, fmt.Errorf("size_installed is %d", *w.SizeInstalled)
	}
	if _, err := version.Parse(*w.Version); err != nil {
		return LockedPackage{}, err
	}
	if err := validateHash(*w.Hash); err != nil {
		return LockedPackage{}, err
	}
	return LockedPackage{
		Name: *w.Name, Version: *w.Version, Architecture: *w.Architecture,
		Source: *w.Source, URL: *w.URL, Hash: *w.Hash,
		SizeCompressed: *w.SizeCompressed, SizeInstalled: *w.SizeInstalled,
		Root: w.Root,
	}, nil
}

// Encode renders the lock as TOML. Packages are sorted by name so the
// output is deterministic and a lock diff is clean.
func (l Lock) Encode() ([]byte, error) {
	if err := validateHash(l.ManifestDigest); err != nil {
		return nil, fmt.Errorf("peipkg/compose: lock manifest_digest: %w", err)
	}
	pkgs := append([]LockedPackage(nil), l.Packages...)
	sort.Slice(pkgs, func(i, j int) bool {
		if pkgs[i].Root != pkgs[j].Root {
			return pkgs[i].Root < pkgs[j].Root
		}
		return pkgs[i].Name < pkgs[j].Name
	})

	srcs := append([]LockedSource(nil), l.Sources...)
	sort.Slice(srcs, func(i, j int) bool { return srcs[i].Name < srcs[j].Name })

	w := wireLock{
		Schema:         ptr(lockSchema),
		Arch:           ptr(l.Arch),
		SourceDate:     ptr(l.SourceDate.UTC().Format(time.RFC3339)),
		Manifest:       l.Manifest,
		ManifestDigest: ptr(l.ManifestDigest),
	}
	for _, src := range srcs {
		w.Sources = append(w.Sources, wireLockedSource{
			Name: ptr(src.Name), SignaturePolicy: ptr(src.SignaturePolicy),
			TrustKeys: src.TrustKeys,
		})
	}
	for _, p := range pkgs {
		w.Packages = append(w.Packages, wireLockedPackage{
			Name: ptr(p.Name), Version: ptr(p.Version), Architecture: ptr(p.Architecture),
			Source: ptr(p.Source), URL: ptr(p.URL), Hash: ptr(p.Hash),
			SizeCompressed: ptr(p.SizeCompressed), SizeInstalled: ptr(p.SizeInstalled),
			Root: p.Root,
		})
	}

	var buf bytes.Buffer
	buf.WriteString("# generated by peipkg-compose — do not hand-edit\n")
	if err := toml.NewEncoder(&buf).Encode(w); err != nil {
		return nil, fmt.Errorf("peipkg/compose: encoding lock: %w", err)
	}
	return buf.Bytes(), nil
}

// validateHash checks a lock hash is 64 lowercase hex characters — a
// SHA-256 digest.
func validateHash(s string) error {
	if len(s) != 64 {
		return fmt.Errorf("hash %q is %d characters, want a 64-hex SHA-256", s, len(s))
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
			return fmt.Errorf("hash %q has the non-lowercase-hex character %q", s, c)
		}
	}
	return nil
}
