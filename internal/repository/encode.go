package repository

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/peios/peipkg/internal/manifest"
	"github.com/peios/peipkg/internal/version"
)

// This file is the exact inverse of descriptor.go and index.go: it
// renders the documents those files parse. Publisher and consumer share
// one definition of the wire shape, so a repository this package writes
// is one this package can read — a property the round-trip tests assert
// directly rather than leave to review.
//
// Both encoders emit a canonical rendering per §6.1.7: fields in the
// order the schema lists them, arrays in the order the schema mandates,
// two-space indentation, and exactly one trailing newline. Canonical
// output is what makes a publish reproducible, and reproducibility is
// what lets an operator diff two states and believe the difference.

// encodeDocument renders v as an indented JSON document with a single
// trailing newline and HTML escaping disabled.
//
// Escaping is off because these documents are not embedded in HTML and
// never will be: encoding/json's default rewrites <, > and & into
// < and friends, which would mangle a package URL containing a
// query string into something that no longer resembles what the
// operator configured.
func encodeDocument(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	// Encoder.Encode already appends exactly one newline.
	return buf.Bytes(), nil
}

// --- descriptor ---------------------------------------------------------

// wireDescriptorOut mirrors [wireDescriptor] for encoding. The pointer
// fields a decoder needs (to tell "absent" from "empty") are plain
// values here, and `description` carries omitempty because §6.1.2 makes
// it optional.
type wireDescriptorOut struct {
	SchemaVersion int `json:"schema_version"`
	Repo          struct {
		Name        string `json:"name"`
		Description string `json:"description,omitempty"`
		Signing     struct {
			Algorithm string       `json:"algorithm"`
			Keys      []wireKeyOut `json:"keys"`
		} `json:"signing"`
	} `json:"repo"`
	Indexes struct {
		Active  wireIndexPointerOut `json:"active"`
		Archive wireIndexPointerOut `json:"archive"`
	} `json:"indexes"`
}

type wireKeyOut struct {
	Fingerprint string `json:"fingerprint"`
	URL         string `json:"url"`
	Status      string `json:"status"`
	ValidUntil  string `json:"valid_until,omitempty"`
}

type wireIndexPointerOut struct {
	URL          string `json:"url"`
	SignatureURL string `json:"signature_url"`
}

// EncodeDescriptor renders a repository descriptor as the bytes of
// repo.json (§6.1).
//
// The descriptor is validated as it is written. A publisher that emits
// a descriptor its own consumer would reject has produced a repository
// nobody can add, and the failure would not surface until somebody
// tried — so the checks live here, at the point of writing, rather than
// being left to a later verify.
func EncodeDescriptor(d Descriptor) ([]byte, error) {
	if d.RepoName == "" {
		return nil, fmt.Errorf("peipkg/repository: descriptor repo name must not be empty")
	}
	if len(d.Keys) == 0 {
		return nil, fmt.Errorf("peipkg/repository: descriptor must declare at least one key")
	}

	// §6.1.3: at least one key must be active. Without this a repository
	// could be published that no consumer will ever accept new content
	// from, because §6.2.1 requires the signing key to be active or
	// transitioning and a transitioning key is by definition expiring.
	active := 0
	for _, key := range d.Keys {
		if key.Status == KeyActive {
			active++
		}
	}
	if active == 0 {
		return nil, fmt.Errorf(
			"peipkg/repository: descriptor declares no %q key", KeyActive)
	}

	keys := make([]wireKeyOut, len(d.Keys))
	seen := make(map[string]bool, len(d.Keys))
	for i, key := range d.Keys {
		if err := validateHexFingerprint(key.Fingerprint); err != nil {
			return nil, fmt.Errorf("peipkg/repository: descriptor key: %w", err)
		}
		// §6.1.3: two entries with the same fingerprint are INVALID.
		// Caught here because the duplicate is silent at every later
		// stage — the trust set is keyed by fingerprint, so a repeated
		// key simply overwrites itself and the descriptor reads fine.
		if seen[key.Fingerprint] {
			return nil, fmt.Errorf(
				"peipkg/repository: descriptor lists key %s twice", key.Fingerprint)
		}
		seen[key.Fingerprint] = true

		if key.URL == "" {
			return nil, fmt.Errorf(
				"peipkg/repository: descriptor key %s has no url", key.Fingerprint)
		}
		out := wireKeyOut{
			Fingerprint: key.Fingerprint,
			URL:         key.URL,
			Status:      string(key.Status),
		}
		switch key.Status {
		case KeyActive, KeyRevoked:
			// §6.1.4: valid_until is ignored for these, so writing one
			// would be noise a reader might mistake for meaning.
			if !key.ValidUntil.IsZero() {
				return nil, fmt.Errorf(
					"peipkg/repository: key %s is %s and must not carry valid_until",
					key.Fingerprint, key.Status)
			}
		case KeyTransitioning:
			// §6.1.4: REQUIRED for transitioning keys. A transitioning
			// key without an expiry is an active key wearing a
			// different label, which defeats the point of rotation.
			if key.ValidUntil.IsZero() {
				return nil, fmt.Errorf(
					"peipkg/repository: transitioning key %s requires valid_until",
					key.Fingerprint)
			}
			out.ValidUntil = formatUTCTimestamp(key.ValidUntil)
		default:
			return nil, fmt.Errorf(
				"peipkg/repository: key %s has invalid status %q",
				key.Fingerprint, key.Status)
		}
		keys[i] = out
	}

	// §6.1.3: the keys array MUST be sorted lexicographically by
	// fingerprint.
	sort.Slice(keys, func(i, j int) bool { return keys[i].Fingerprint < keys[j].Fingerprint })

	if err := validateIndexPointer("active", d.ActiveIndex); err != nil {
		return nil, err
	}
	if err := validateIndexPointer("archive", d.ArchiveIndex); err != nil {
		return nil, err
	}

	var w wireDescriptorOut
	w.SchemaVersion = descriptorSchemaVersion
	w.Repo.Name = d.RepoName
	w.Repo.Description = d.Description
	w.Repo.Signing.Algorithm = signingAlgorithmEd25519
	w.Repo.Signing.Keys = keys
	w.Indexes.Active = wireIndexPointerOut{
		URL: d.ActiveIndex.URL, SignatureURL: d.ActiveIndex.SignatureURL}
	w.Indexes.Archive = wireIndexPointerOut{
		URL: d.ArchiveIndex.URL, SignatureURL: d.ArchiveIndex.SignatureURL}

	return encodeDocument(w)
}

func validateIndexPointer(name string, p IndexPointer) error {
	if p.URL == "" || p.SignatureURL == "" {
		return fmt.Errorf(
			"peipkg/repository: the %s index pointer needs both url and signature_url", name)
	}
	return nil
}

// --- index --------------------------------------------------------------

type wireIndexOut struct {
	SchemaVersion int                 `json:"schema_version"`
	Repo          string              `json:"repo"`
	Kind          string              `json:"kind"`
	IndexVersion  int64               `json:"index_version"`
	GeneratedAt   string              `json:"generated_at"`
	Packages      []wireIndexEntryOut `json:"packages"`
}

// wireIndexEntryOut mirrors [wireIndexEntry]. Optional fields carry
// omitempty so an absent value is absent rather than an empty string:
// §6.2.3 marks most of the entry RECOMMENDED, and the decoder treats
// absent and empty identically, so omitting is the smaller rendering of
// the same fact.
type wireIndexEntryOut struct {
	Name             string                   `json:"name"`
	Version          string                   `json:"version"`
	Architecture     string                   `json:"architecture"`
	Description      string                   `json:"description,omitempty"`
	License          string                   `json:"license,omitempty"`
	LicenseClass     string                   `json:"license_class,omitempty"`
	Homepage         string                   `json:"homepage,omitempty"`
	DefaultRoot      string                   `json:"default_root,omitempty"`
	AlternateUpgrade *wireAlternateUpgradeOut `json:"alternate_upgrade,omitempty"`

	Dependencies         json.RawMessage `json:"dependencies,omitempty"`
	OptionalDependencies json.RawMessage `json:"optional_dependencies,omitempty"`
	Conflicts            json.RawMessage `json:"conflicts,omitempty"`
	Provides             json.RawMessage `json:"provides,omitempty"`
	Replaces             json.RawMessage `json:"replaces,omitempty"`
	SideEffects          json.RawMessage `json:"side_effects,omitempty"`

	SizeCompressed int64         `json:"size_compressed"`
	SizeInstalled  int64         `json:"size_installed"`
	Hash           wireHashOut   `json:"hash"`
	URL            string        `json:"url"`
	Build          *wireBuildOut `json:"build,omitempty"`
}

// wireAlternateUpgradeOut is the alternate_upgrade object (§5.18) as
// the index carries it (§5.33).
type wireAlternateUpgradeOut struct {
	Message string `json:"message"`
}

type wireHashOut struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

type wireBuildOut struct {
	Timestamp string `json:"timestamp,omitempty"`
	FarmID    string `json:"farm_id,omitempty"`
}

// EncodeIndex renders an index as the bytes of active.json or
// archive.json (§6.2, §6.3).
//
// Packages are sorted here rather than trusted to arrive sorted: the
// ordering is normative (§6.2.9, §6.3.6), a consumer may rely on it,
// and the caller that assembled the entries has no reason to know the
// rule. Sorting at the boundary means it cannot be got wrong upstream.
func EncodeIndex(idx Index) ([]byte, error) {
	if idx.RepoName == "" {
		return nil, fmt.Errorf("peipkg/repository: index repo name must not be empty")
	}
	switch idx.Kind {
	case IndexActive, IndexArchive:
	default:
		return nil, fmt.Errorf("peipkg/repository: index kind %q is neither %q nor %q",
			idx.Kind, IndexActive, IndexArchive)
	}
	// §6.2.3: a monotonically-increasing POSITIVE integer. Zero would
	// also defeat the consumer's rollback floor, which starts at zero.
	if idx.IndexVersion < 1 {
		return nil, fmt.Errorf(
			"peipkg/repository: index_version is %d, want a positive integer", idx.IndexVersion)
	}
	if idx.GeneratedAt.IsZero() {
		return nil, fmt.Errorf("peipkg/repository: index generated_at must be set")
	}

	entries := make([]IndexEntry, len(idx.Packages))
	copy(entries, idx.Packages)
	sortIndexEntries(entries, idx.Kind)

	if idx.Kind == IndexActive {
		// §6.2.9: each name appears exactly once. This is the property
		// that makes the index "active"; a duplicate would leave the
		// consumer to pick between two entries with no rule to pick by.
		for i := 1; i < len(entries); i++ {
			if entries[i].Name == entries[i-1].Name {
				return nil, fmt.Errorf(
					"peipkg/repository: the active index lists %q twice", entries[i].Name)
			}
		}
	}

	out := make([]wireIndexEntryOut, len(entries))
	for i, entry := range entries {
		encoded, err := encodeIndexEntry(entry)
		if err != nil {
			return nil, fmt.Errorf("peipkg/repository: index entry %s: %w", entry.Name, err)
		}
		out[i] = encoded
	}

	return encodeDocument(wireIndexOut{
		SchemaVersion: indexSchemaVersion,
		Repo:          idx.RepoName,
		Kind:          string(idx.Kind),
		IndexVersion:  idx.IndexVersion,
		GeneratedAt:   formatUTCTimestamp(idx.GeneratedAt),
		Packages:      out,
	})
}

// sortIndexEntries applies the ordering the schema mandates: by name
// for both kinds, and within a name by version DESCENDING for the
// archive (§6.3.6), so the newest version of each package heads its
// group and a consumer scanning for a satisfying version can stop early.
func sortIndexEntries(entries []IndexEntry, kind IndexKind) {
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].Name != entries[j].Name {
			return entries[i].Name < entries[j].Name
		}
		if kind == IndexArchive {
			if c := version.Compare(entries[i].Version, entries[j].Version); c != 0 {
				return c > 0
			}
			// Same name and same version: order by architecture so the
			// rendering is total rather than merely stable. Two entries
			// differing only in architecture are legal in the archive.
			return entries[i].Architecture < entries[j].Architecture
		}
		return false
	})
}

func encodeIndexEntry(e IndexEntry) (wireIndexEntryOut, error) {
	if e.Name == "" {
		return wireIndexEntryOut{}, fmt.Errorf("missing name")
	}
	if e.Architecture == "" {
		return wireIndexEntryOut{}, fmt.Errorf("missing architecture")
	}
	// §6.2.3 requires url: an entry a consumer cannot fetch is worse
	// than an absent one, because resolution will select it and only
	// then discover there is nothing to download.
	if e.URL == "" {
		return wireIndexEntryOut{}, fmt.Errorf("missing url")
	}
	if err := validateHexFingerprint(e.Hash); err != nil {
		return wireIndexEntryOut{}, fmt.Errorf("hash value: %w", err)
	}
	// §6.2.7: both sizes are REQUIRED so a consumer can enforce the
	// §3.5.4 decompression bounds before it starts decompressing.
	if e.SizeCompressed < 0 || e.SizeInstalled < 0 {
		return wireIndexEntryOut{}, fmt.Errorf("sizes must not be negative")
	}
	if e.DefaultRoot != "" {
		if err := manifest.ValidateRootRef(e.DefaultRoot); err != nil {
			return wireIndexEntryOut{}, fmt.Errorf("default_root: %w", err)
		}
	}
	if e.AlternateUpgrade != nil {
		if err := manifest.ValidateAlternateUpgradeMessage(e.AlternateUpgrade.Message); err != nil {
			return wireIndexEntryOut{}, fmt.Errorf("alternate_upgrade: message: %w", err)
		}
	}
	// The zero LicenseClass (an entry built without one) and the explicit
	// unknown both mean unknown; neither is worth bytes in the index.
	licenseClass := string(e.LicenseClass)
	if licenseClass == string(manifest.LicenseClassUnknown) {
		licenseClass = ""
	} else if _, err := manifest.ParseLicenseClass(licenseClass); err != nil {
		return wireIndexEntryOut{}, err
	}

	out := wireIndexEntryOut{
		Name:           e.Name,
		Version:        e.Version.String(),
		Architecture:   e.Architecture,
		Description:    e.Description,
		License:        e.License,
		LicenseClass:   licenseClass,
		Homepage:       e.Homepage,
		DefaultRoot:    e.DefaultRoot,
		SizeCompressed: e.SizeCompressed,
		SizeInstalled:  e.SizeInstalled,
		Hash:           wireHashOut{Algorithm: indexHashAlgorithm, Value: e.Hash},
		URL:            e.URL,
	}
	if out.Version == "" {
		return wireIndexEntryOut{}, fmt.Errorf("missing version")
	}
	if e.AlternateUpgrade != nil {
		out.AlternateUpgrade = &wireAlternateUpgradeOut{Message: e.AlternateUpgrade.Message}
	}

	var err error
	if out.Dependencies, err = manifest.EncodeDependencyArray(e.Dependencies); err != nil {
		return wireIndexEntryOut{}, err
	}
	if out.OptionalDependencies, err = manifest.EncodeDependencyArray(e.OptionalDependencies); err != nil {
		return wireIndexEntryOut{}, err
	}
	if out.Conflicts, err = manifest.EncodeDependencyArray(e.Conflicts); err != nil {
		return wireIndexEntryOut{}, err
	}
	if out.Provides, err = manifest.EncodeProvidesArray(e.Provides); err != nil {
		return wireIndexEntryOut{}, err
	}
	if out.Replaces, err = manifest.EncodeReplacesArray(e.Replaces); err != nil {
		return wireIndexEntryOut{}, err
	}
	if out.SideEffects, err = manifest.EncodeSideEffectArray(e.SideEffects); err != nil {
		return wireIndexEntryOut{}, err
	}

	// §6.2.3: build is a SUBSET of the manifest's build object —
	// timestamp and farm_id only. source_ref and the rest are
	// deliberately omitted (§6.2.6) as long, low-information fields
	// better read from the package itself.
	if !e.BuildTimestamp.IsZero() || e.BuildFarmID != "" {
		build := &wireBuildOut{FarmID: e.BuildFarmID}
		if !e.BuildTimestamp.IsZero() {
			build.Timestamp = formatUTCTimestamp(e.BuildTimestamp)
		}
		out.Build = build
	}
	return out, nil
}

// formatUTCTimestamp renders t in the form parseUTCTimestamp accepts:
// RFC 3339, in UTC, ending in Z. The conversion to UTC is not a
// formality — a timestamp rendered with a numeric offset parses as
// valid RFC 3339 and is then rejected by the consumer for not ending
// in Z, which would be a confusing way to learn that the publishing
// host was not on UTC.
func formatUTCTimestamp(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}
