package compose

import (
	"bytes"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/peios/peipkg/internal/version"
)

// lockSchema is the lock schema version peipkg-compose writes and reads.
const lockSchema = 1

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
	// Packages is the resolved closure, sorted by name.
	Packages []LockedPackage
}

// LockedPackage is one package of a resolved closure.
type LockedPackage struct {
	Name         string
	Version      string
	Architecture string
	// Source is the name of the repository the package resolves from,
	// or [LocalSource] for a package supplied as a local .peipkg file.
	Source string
	// URL fetches the package: an absolute HTTP(S) URL for a repository
	// package, or a filesystem path for a local one.
	URL string
	// Hash is the lowercase-hex SHA-256 of the .peipkg file. A build
	// verifies the fetched bytes against it.
	Hash string
}

// wireLock mirrors the lock's TOML shape. The scalar fields are
// pointers so a missing required key is reported precisely on decode;
// [Lock.Encode] sets every one.
type wireLock struct {
	Schema     *int                `toml:"schema"`
	Arch       *string             `toml:"arch"`
	SourceDate *string             `toml:"source_date"`
	Manifest   string              `toml:"manifest,omitempty"`
	Packages   []wireLockedPackage `toml:"package"`
}

type wireLockedPackage struct {
	Name         *string `toml:"name"`
	Version      *string `toml:"version"`
	Architecture *string `toml:"architecture"`
	Source       *string `toml:"source"`
	URL          *string `toml:"url"`
	Hash         *string `toml:"hash"`
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
	case w.Arch == nil:
		return Lock{}, missingKey("arch")
	case w.SourceDate == nil:
		return Lock{}, missingKey("source_date")
	}
	if *w.Schema != lockSchema {
		return Lock{}, fmt.Errorf("peipkg/compose: lock schema is %d, want %d",
			*w.Schema, lockSchema)
	}
	sourceDate, err := time.Parse(time.RFC3339, *w.SourceDate)
	if err != nil {
		return Lock{}, fmt.Errorf("peipkg/compose: lock source_date %q is not an RFC 3339 "+
			"timestamp: %w", *w.SourceDate, err)
	}

	l := Lock{Arch: *w.Arch, SourceDate: sourceDate, Manifest: w.Manifest}
	seen := map[string]bool{}
	for i, wp := range w.Packages {
		p, err := decodeLockedPackage(wp)
		if err != nil {
			return Lock{}, fmt.Errorf("peipkg/compose: lock package %d: %w", i, err)
		}
		if seen[p.Name] {
			return Lock{}, fmt.Errorf("peipkg/compose: lock has the package %q more than once",
				p.Name)
		}
		seen[p.Name] = true
		l.Packages = append(l.Packages, p)
	}
	if len(l.Packages) == 0 {
		return Lock{}, fmt.Errorf("peipkg/compose: lock contains no packages")
	}
	return l, nil
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
	}, nil
}

// Encode renders the lock as TOML. Packages are sorted by name so the
// output is deterministic and a lock diff is clean.
func (l Lock) Encode() ([]byte, error) {
	pkgs := append([]LockedPackage(nil), l.Packages...)
	sort.Slice(pkgs, func(i, j int) bool { return pkgs[i].Name < pkgs[j].Name })

	w := wireLock{
		Schema:     ptr(lockSchema),
		Arch:       ptr(l.Arch),
		SourceDate: ptr(l.SourceDate.UTC().Format(time.RFC3339)),
		Manifest:   l.Manifest,
	}
	for _, p := range pkgs {
		w.Packages = append(w.Packages, wireLockedPackage{
			Name: ptr(p.Name), Version: ptr(p.Version), Architecture: ptr(p.Architecture),
			Source: ptr(p.Source), URL: ptr(p.URL), Hash: ptr(p.Hash),
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
