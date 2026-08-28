package repository

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/peios/peipkg/internal/jsonguard"
	"github.com/peios/peipkg/internal/manifest"
	"github.com/peios/peipkg/internal/version"
)

// indexSchemaVersion is the index schema version this build understands
// (§6.2.2).
const indexSchemaVersion = 1

// indexHashAlgorithm is the only package-hash algorithm valid in v0.22
// (§6.2.8, §9.2).
const indexHashAlgorithm = "sha256"

// IndexKind distinguishes the active index from the archive index.
type IndexKind string

const (
	// IndexActive lists the current version of every package (§6.2).
	IndexActive IndexKind = "active"
	// IndexArchive lists every version ever advertised (§6.3).
	IndexArchive IndexKind = "archive"
)

// IndexEntry is one package entry of a repository index (§6.2.3). It is
// a derived view of the package's manifest; the manifest remains
// authoritative if the two disagree (§3.3.7).
type IndexEntry struct {
	Name         string
	Version      version.Version
	Architecture string
	Description  string
	License      string
	// LicenseClass is the package's licence class (§3.3.6), carried in
	// the index (§6.2.4) so a consumer can apply a licence policy before
	// fetching anything.
	LicenseClass manifest.LicenseClass
	Homepage     string
	// DefaultRoot is the package's top-level placement preference, carried
	// in the index (§6.2.4) so a consumer can plan placement before
	// fetching the package. "" when absent.
	DefaultRoot string

	Dependencies         []manifest.Dependency
	OptionalDependencies []manifest.Dependency
	Conflicts            []manifest.Dependency
	Provides             []manifest.Provides
	Replaces             []manifest.Replaces
	SideEffects          []manifest.SideEffect

	SizeCompressed int64
	SizeInstalled  int64
	// Hash is the lowercase-hex SHA-256 of the .peipkg file (§6.2.8).
	Hash string
	// URL fetches the package file; it may be relative to the repo base.
	URL string

	BuildTimestamp time.Time
	BuildFarmID    string
}

// Index is a decoded, structurally-valid repository index — active or
// archive (§6.2, §6.3). Obtain one through [DecodeIndex].
type Index struct {
	RepoName     string
	Kind         IndexKind
	IndexVersion int64
	GeneratedAt  time.Time
	Packages     []IndexEntry
}

type wireIndex struct {
	SchemaVersion *int             `json:"schema_version"`
	Repo          *string          `json:"repo"`
	Kind          *string          `json:"kind"`
	IndexVersion  *int64           `json:"index_version"`
	GeneratedAt   *string          `json:"generated_at"`
	Packages      []wireIndexEntry `json:"packages"`
}

type wireIndexEntry struct {
	Name         *string `json:"name"`
	Version      *string `json:"version"`
	Architecture *string `json:"architecture"`
	Description  string  `json:"description"`
	License      string  `json:"license"`
	LicenseClass string  `json:"license_class"`
	Homepage     string  `json:"homepage"`
	DefaultRoot  string  `json:"default_root"`

	Dependencies         json.RawMessage `json:"dependencies"`
	OptionalDependencies json.RawMessage `json:"optional_dependencies"`
	Conflicts            json.RawMessage `json:"conflicts"`
	Provides             json.RawMessage `json:"provides"`
	Replaces             json.RawMessage `json:"replaces"`
	SideEffects          json.RawMessage `json:"side_effects"`

	SizeCompressed *int64 `json:"size_compressed"`
	SizeInstalled  *int64 `json:"size_installed"`
	Hash           *struct {
		Algorithm *string `json:"algorithm"`
		Value     *string `json:"value"`
	} `json:"hash"`
	URL   *string `json:"url"`
	Build *struct {
		Timestamp string `json:"timestamp"`
		FarmID    string `json:"farm_id"`
	} `json:"build"`
}

// DecodeIndex parses and validates a repository index from its raw JSON
// (§6.2, §6.3). It does not verify the index's detached signature.
func DecodeIndex(data []byte) (Index, error) {
	var w wireIndex
	if err := jsonguard.Unmarshal(data, &w); err != nil {
		return Index{}, fmt.Errorf("peipkg/repository: invalid index JSON: %w", err)
	}
	switch {
	case w.SchemaVersion == nil:
		return Index{}, fmt.Errorf("peipkg/repository: index is missing %q", "schema_version")
	case w.Repo == nil:
		return Index{}, fmt.Errorf("peipkg/repository: index is missing %q", "repo")
	case w.Kind == nil:
		return Index{}, fmt.Errorf("peipkg/repository: index is missing %q", "kind")
	case w.GeneratedAt == nil:
		return Index{}, fmt.Errorf("peipkg/repository: index is missing %q", "generated_at")
	case w.IndexVersion == nil:
		return Index{}, fmt.Errorf("peipkg/repository: index is missing %q", "index_version")
	}
	if *w.SchemaVersion != indexSchemaVersion {
		return Index{}, fmt.Errorf("peipkg/repository: index schema_version is %d, want %d",
			*w.SchemaVersion, indexSchemaVersion)
	}

	idx := Index{RepoName: *w.Repo, Kind: IndexKind(*w.Kind), IndexVersion: *w.IndexVersion}
	if idx.Kind != IndexActive && idx.Kind != IndexArchive {
		return Index{}, fmt.Errorf("peipkg/repository: index kind %q is not %q or %q",
			idx.Kind, IndexActive, IndexArchive)
	}
	if idx.IndexVersion < 1 {
		return Index{}, fmt.Errorf("peipkg/repository: index_version must be a positive integer")
	}
	generatedAt, err := parseUTCTimestamp(*w.GeneratedAt)
	if err != nil {
		return Index{}, fmt.Errorf("peipkg/repository: index generated_at: %w", err)
	}
	idx.GeneratedAt = generatedAt

	entries := make([]IndexEntry, 0, len(w.Packages))
	var prevName string
	for i, we := range w.Packages {
		entry, err := decodeIndexEntry(we)
		if err != nil {
			return Index{}, fmt.Errorf("peipkg/repository: index entry %d: %w", i, err)
		}
		// §6.2.7: the active index is sorted by name with each name
		// unique. §6.3: the archive index is sorted by name but may
		// repeat a name (one entry per historical version).
		if i > 0 {
			if entry.Name < prevName {
				return Index{}, fmt.Errorf(
					"peipkg/repository: index is not sorted by name (%q before %q)",
					prevName, entry.Name)
			}
			if entry.Name == prevName && idx.Kind == IndexActive {
				return Index{}, fmt.Errorf(
					"peipkg/repository: active index has a duplicate package %q", entry.Name)
			}
		}
		prevName = entry.Name
		entries = append(entries, entry)
	}
	idx.Packages = entries
	return idx, nil
}

// decodeIndexEntry validates one package entry (§6.2.3).
func decodeIndexEntry(w wireIndexEntry) (IndexEntry, error) {
	switch {
	case w.Name == nil:
		return IndexEntry{}, fmt.Errorf("missing %q", "name")
	case w.Version == nil:
		return IndexEntry{}, fmt.Errorf("missing %q", "version")
	case w.Architecture == nil:
		return IndexEntry{}, fmt.Errorf("missing %q", "architecture")
	case w.SizeCompressed == nil:
		return IndexEntry{}, fmt.Errorf("missing %q", "size_compressed")
	case w.SizeInstalled == nil:
		return IndexEntry{}, fmt.Errorf("missing %q", "size_installed")
	case w.Hash == nil:
		return IndexEntry{}, fmt.Errorf("missing %q", "hash")
	case w.URL == nil || *w.URL == "":
		return IndexEntry{}, fmt.Errorf("missing %q", "url")
	}

	// §5.33: an index entry's name, version and architecture are each
	// validated with the same strictness a manifest receives. Without
	// this the two paths disagreed about what a valid identity is — the
	// same repository content was rejected at manifest-decode time and
	// accepted here, after which the values flowed into installableArch,
	// into the {name} and {arch} URL placeholders, and into the local
	// package database.
	if err := manifest.ValidateName(*w.Name); err != nil {
		return IndexEntry{}, fmt.Errorf("name: %w", err)
	}
	if err := manifest.ValidateArchitecture(*w.Architecture); err != nil {
		return IndexEntry{}, fmt.Errorf("architecture: %w", err)
	}

	entry := IndexEntry{
		Name:         *w.Name,
		Architecture: *w.Architecture,
		Description:  w.Description,
		License:      w.License,
		Homepage:     w.Homepage,
		DefaultRoot:  w.DefaultRoot,
		URL:          *w.URL,
	}
	// §6.2.4: license_class is the closed set of §3.3.6; absent is unknown.
	lc, err := manifest.ParseLicenseClass(w.LicenseClass)
	if err != nil {
		return IndexEntry{}, err
	}
	entry.LicenseClass = lc
	// §6.2.4: default_root is a root reference (§3.3.6) when present.
	if w.DefaultRoot != "" {
		if err := manifest.ValidateRootRef(w.DefaultRoot); err != nil {
			return IndexEntry{}, fmt.Errorf("default_root: %w", err)
		}
	}
	ver, err := version.Parse(*w.Version)
	if err != nil {
		return IndexEntry{}, fmt.Errorf("version: %w", err)
	}
	entry.Version = ver

	if *w.SizeCompressed < 0 || *w.SizeInstalled < 0 {
		return IndexEntry{}, fmt.Errorf("size_compressed and size_installed must not be negative")
	}
	entry.SizeCompressed = *w.SizeCompressed
	entry.SizeInstalled = *w.SizeInstalled

	if w.Hash.Algorithm == nil || *w.Hash.Algorithm != indexHashAlgorithm {
		return IndexEntry{}, fmt.Errorf("hash algorithm is not %q", indexHashAlgorithm)
	}
	if w.Hash.Value == nil {
		return IndexEntry{}, fmt.Errorf("hash is missing %q", "value")
	}
	if err := validateHexFingerprint(*w.Hash.Value); err != nil {
		return IndexEntry{}, fmt.Errorf("hash value: %w", err)
	}
	entry.Hash = *w.Hash.Value

	if entry.Dependencies, err = manifest.DecodeDependencyArray(
		"dependencies", w.Dependencies, true); err != nil {
		return IndexEntry{}, err
	}
	if entry.OptionalDependencies, err = manifest.DecodeDependencyArray(
		"optional_dependencies", w.OptionalDependencies, true); err != nil {
		return IndexEntry{}, err
	}
	if entry.Conflicts, err = manifest.DecodeDependencyArray(
		"conflicts", w.Conflicts, false); err != nil {
		return IndexEntry{}, err
	}
	if entry.Provides, err = manifest.DecodeProvidesArray(w.Provides); err != nil {
		return IndexEntry{}, err
	}
	if entry.Replaces, err = manifest.DecodeReplacesArray(w.Replaces); err != nil {
		return IndexEntry{}, err
	}
	if entry.SideEffects, err = manifest.DecodeSideEffectArray(w.SideEffects); err != nil {
		return IndexEntry{}, err
	}

	if w.Build != nil && w.Build.Timestamp != "" {
		ts, err := parseUTCTimestamp(w.Build.Timestamp)
		if err != nil {
			return IndexEntry{}, fmt.Errorf("build timestamp: %w", err)
		}
		entry.BuildTimestamp = ts
		entry.BuildFarmID = w.Build.FarmID
	}
	return entry, nil
}
