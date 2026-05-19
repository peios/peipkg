package archive

import (
	"encoding/json"
	"fmt"
)

// filesSchemaVersion is the files.json schema version this build
// understands (§3.5.1).
const filesSchemaVersion = 1

// hashAlgorithmSHA256 is the only per-file hash algorithm valid in
// v0.22 (§3.5.5, §9.2).
const hashAlgorithmSHA256 = "sha256"

// hashHexLen is the length of a SHA-256 digest as lowercase hex.
const hashHexLen = 64

// fileEntry is one entry of the per-file integrity manifest (§3.5.1):
// a regular-file payload entry and the hash its content must match.
type fileEntry struct {
	path string
	size int64
	hash string // lowercase hex SHA-256
}

// filesManifest is the decoded, validated .peipkg/files.json.
type filesManifest struct {
	// byPath indexes the entries for lookup during the payload walk.
	byPath map[string]fileEntry
}

type wireFiles struct {
	SchemaVersion *int             `json:"schema_version"`
	Algorithm     *string          `json:"algorithm"`
	Entries       *[]wireFileEntry `json:"entries"`
}

type wireFileEntry struct {
	Path *string `json:"path"`
	Size *int64  `json:"size"`
	Hash *string `json:"hash"`
}

// decodeFiles parses and validates the .peipkg/files.json document
// (§3.5.1). It checks the schema, the hash algorithm, and that the
// entries are ordered by path with no duplicates; the cross-check that
// the entry set matches the regular-file payload entries (§3.5.2) is
// done by the archive walk, which alone sees both.
func decodeFiles(data []byte) (*filesManifest, error) {
	var w wireFiles
	if err := json.Unmarshal(data, &w); err != nil {
		return nil, fmt.Errorf("peipkg/archive: invalid files.json: %w", err)
	}
	switch {
	case w.SchemaVersion == nil:
		return nil, fmt.Errorf("peipkg/archive: files.json missing required field %q", "schema_version")
	case w.Algorithm == nil:
		return nil, fmt.Errorf("peipkg/archive: files.json missing required field %q", "algorithm")
	case w.Entries == nil:
		return nil, fmt.Errorf("peipkg/archive: files.json missing required field %q", "entries")
	}
	if *w.SchemaVersion != filesSchemaVersion {
		return nil, fmt.Errorf("peipkg/archive: files.json schema_version is %d, want %d",
			*w.SchemaVersion, filesSchemaVersion)
	}
	if *w.Algorithm != hashAlgorithmSHA256 {
		return nil, fmt.Errorf("peipkg/archive: files.json algorithm %q is not supported (only %q)",
			*w.Algorithm, hashAlgorithmSHA256)
	}

	byPath := make(map[string]fileEntry, len(*w.Entries))
	var prevPath string
	for i, we := range *w.Entries {
		switch {
		case we.Path == nil:
			return nil, fmt.Errorf("peipkg/archive: files.json entry %d missing %q", i, "path")
		case we.Size == nil:
			return nil, fmt.Errorf("peipkg/archive: files.json entry %d missing %q", i, "size")
		case we.Hash == nil:
			return nil, fmt.Errorf("peipkg/archive: files.json entry %d missing %q", i, "hash")
		}
		if *we.Size < 0 {
			return nil, fmt.Errorf("peipkg/archive: files.json entry %q has a negative size", *we.Path)
		}
		if err := validateHashHex(*we.Hash); err != nil {
			return nil, fmt.Errorf("peipkg/archive: files.json entry %q: %w", *we.Path, err)
		}
		// §3.5.1: entries are sorted lexicographically by path. A
		// duplicate path would also break the by-path index.
		if i > 0 {
			if *we.Path < prevPath {
				return nil, fmt.Errorf("peipkg/archive: files.json is not sorted by path "+
					"(%q before %q)", prevPath, *we.Path)
			}
			if *we.Path == prevPath {
				return nil, fmt.Errorf("peipkg/archive: files.json has a duplicate entry %q", *we.Path)
			}
		}
		prevPath = *we.Path
		byPath[*we.Path] = fileEntry{path: *we.Path, size: *we.Size, hash: *we.Hash}
	}
	return &filesManifest{byPath: byPath}, nil
}

// validateHashHex checks a string is a 64-character lowercase-hex
// SHA-256 digest.
func validateHashHex(s string) error {
	if len(s) != hashHexLen {
		return fmt.Errorf("hash is %d characters, want %d", len(s), hashHexLen)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
			return fmt.Errorf("hash contains a non-lowercase-hex character %q", c)
		}
	}
	return nil
}
