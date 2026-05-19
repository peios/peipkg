// Package repository decodes, verifies, and tracks the freshness of a
// package repository's metadata: the descriptor (PSD-009 §6.1), the
// active and archive indexes (§6.2, §6.3), the per-repository trust set
// of signing keys (§5.2.5, §6.1.4), and the §6.2.3 rollback/freeze
// defence.
package repository

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// descriptorSchemaVersion is the descriptor schema version this build
// understands (§6.1.2).
const descriptorSchemaVersion = 1

// signingAlgorithmEd25519 is the only signing algorithm valid in v0.22
// (§6.1.3, §9.2).
const signingAlgorithmEd25519 = "ed25519"

// KeyStatus is a signing key's role in a repository's operation (§6.1.4).
type KeyStatus string

const (
	// KeyActive keys sign new content and verify it.
	KeyActive KeyStatus = "active"
	// KeyTransitioning keys no longer sign but still verify, until their
	// ValidUntil instant.
	KeyTransitioning KeyStatus = "transitioning"
	// KeyRevoked keys never verify — the explicit signal of compromise.
	KeyRevoked KeyStatus = "revoked"
)

// DescriptorKey is one signing-key declaration in a descriptor (§6.1.3).
// The key's public bytes are fetched separately from URL.
type DescriptorKey struct {
	Fingerprint string
	URL         string
	Status      KeyStatus
	// ValidUntil is the expiry of a transitioning key; the zero Time for
	// active and revoked keys.
	ValidUntil time.Time
}

// IndexPointer locates an index and its detached signature (§6.1.5).
type IndexPointer struct {
	URL          string
	SignatureURL string
}

// Descriptor is a decoded, structurally-valid repository descriptor
// (§6.1). Obtain one through [DecodeDescriptor].
type Descriptor struct {
	RepoName     string
	Description  string
	Keys         []DescriptorKey
	ActiveIndex  IndexPointer
	ArchiveIndex IndexPointer
}

type wireDescriptor struct {
	SchemaVersion *int `json:"schema_version"`
	Repo          *struct {
		Name        *string `json:"name"`
		Description string  `json:"description"`
		Signing     *struct {
			Algorithm *string   `json:"algorithm"`
			Keys      []wireKey `json:"keys"`
		} `json:"signing"`
	} `json:"repo"`
	Indexes *struct {
		Active  *wireIndexPointer `json:"active"`
		Archive *wireIndexPointer `json:"archive"`
	} `json:"indexes"`
}

type wireKey struct {
	Fingerprint *string `json:"fingerprint"`
	URL         *string `json:"url"`
	Status      *string `json:"status"`
	ValidUntil  string  `json:"valid_until"`
}

type wireIndexPointer struct {
	URL          *string `json:"url"`
	SignatureURL *string `json:"signature_url"`
}

// DecodeDescriptor parses and validates a repository descriptor from the
// raw bytes of repo.json (§6.1). It does not verify the descriptor's
// detached signature — that is [VerifyDetached], which the caller
// applies against the appropriate trust anchors or trust set.
func DecodeDescriptor(data []byte) (Descriptor, error) {
	var w wireDescriptor
	if err := json.Unmarshal(data, &w); err != nil {
		return Descriptor{}, fmt.Errorf("peipkg/repository: invalid descriptor JSON: %w", err)
	}
	switch {
	case w.SchemaVersion == nil:
		return Descriptor{}, missingDescriptorField("schema_version")
	case w.Repo == nil:
		return Descriptor{}, missingDescriptorField("repo")
	case w.Indexes == nil:
		return Descriptor{}, missingDescriptorField("indexes")
	}
	if *w.SchemaVersion != descriptorSchemaVersion {
		return Descriptor{}, fmt.Errorf("peipkg/repository: descriptor schema_version is %d, want %d",
			*w.SchemaVersion, descriptorSchemaVersion)
	}

	d := Descriptor{}
	if w.Repo.Name == nil || *w.Repo.Name == "" {
		return Descriptor{}, fmt.Errorf("peipkg/repository: descriptor repo.name is missing or empty")
	}
	d.RepoName = *w.Repo.Name
	d.Description = w.Repo.Description

	if w.Repo.Signing == nil {
		return Descriptor{}, missingDescriptorField("repo.signing")
	}
	if w.Repo.Signing.Algorithm == nil || *w.Repo.Signing.Algorithm != signingAlgorithmEd25519 {
		return Descriptor{}, fmt.Errorf(
			"peipkg/repository: descriptor signing algorithm is not %q", signingAlgorithmEd25519)
	}
	keys, err := decodeKeys(w.Repo.Signing.Keys)
	if err != nil {
		return Descriptor{}, err
	}
	d.Keys = keys

	if d.ActiveIndex, err = decodeIndexPointer("active", w.Indexes.Active); err != nil {
		return Descriptor{}, err
	}
	if d.ArchiveIndex, err = decodeIndexPointer("archive", w.Indexes.Archive); err != nil {
		return Descriptor{}, err
	}
	return d, nil
}

// decodeKeys validates the signing-key array (§6.1.3, §6.1.4).
func decodeKeys(wires []wireKey) ([]DescriptorKey, error) {
	if len(wires) == 0 {
		return nil, fmt.Errorf("peipkg/repository: descriptor has no signing keys")
	}
	keys := make([]DescriptorKey, 0, len(wires))
	var prevFingerprint string
	haveActive := false
	for i, w := range wires {
		switch {
		case w.Fingerprint == nil:
			return nil, fmt.Errorf("peipkg/repository: signing key %d is missing %q", i, "fingerprint")
		case w.URL == nil || *w.URL == "":
			return nil, fmt.Errorf("peipkg/repository: signing key %d is missing %q", i, "url")
		case w.Status == nil:
			return nil, fmt.Errorf("peipkg/repository: signing key %d is missing %q", i, "status")
		}
		if err := validateHexFingerprint(*w.Fingerprint); err != nil {
			return nil, fmt.Errorf("peipkg/repository: signing key %d: %w", i, err)
		}
		// §6.1.3: keys are sorted by fingerprint with no duplicates.
		if i > 0 {
			if *w.Fingerprint < prevFingerprint {
				return nil, fmt.Errorf("peipkg/repository: signing keys are not sorted by fingerprint")
			}
			if *w.Fingerprint == prevFingerprint {
				return nil, fmt.Errorf("peipkg/repository: duplicate signing key %s", *w.Fingerprint)
			}
		}
		prevFingerprint = *w.Fingerprint

		key := DescriptorKey{Fingerprint: *w.Fingerprint, URL: *w.URL, Status: KeyStatus(*w.Status)}
		switch key.Status {
		case KeyActive:
			haveActive = true
		case KeyTransitioning:
			// §6.1.4: a transitioning key must carry a valid_until.
			if w.ValidUntil == "" {
				return nil, fmt.Errorf(
					"peipkg/repository: transitioning key %s has no valid_until", key.Fingerprint)
			}
			ts, err := parseUTCTimestamp(w.ValidUntil)
			if err != nil {
				return nil, fmt.Errorf(
					"peipkg/repository: key %s valid_until: %w", key.Fingerprint, err)
			}
			key.ValidUntil = ts
		case KeyRevoked:
		default:
			return nil, fmt.Errorf("peipkg/repository: signing key %s has the invalid status %q",
				key.Fingerprint, key.Status)
		}
		keys = append(keys, key)
	}
	// §6.1.3: at least one key must be active.
	if !haveActive {
		return nil, fmt.Errorf("peipkg/repository: descriptor has no active signing key")
	}
	return keys, nil
}

// decodeIndexPointer validates one index pointer (§6.1.5).
func decodeIndexPointer(name string, w *wireIndexPointer) (IndexPointer, error) {
	if w == nil {
		return IndexPointer{}, fmt.Errorf("peipkg/repository: descriptor is missing the %s index", name)
	}
	if w.URL == nil || *w.URL == "" {
		return IndexPointer{}, fmt.Errorf("peipkg/repository: %s index pointer is missing %q", name, "url")
	}
	if w.SignatureURL == nil || *w.SignatureURL == "" {
		return IndexPointer{}, fmt.Errorf(
			"peipkg/repository: %s index pointer is missing %q", name, "signature_url")
	}
	return IndexPointer{URL: *w.URL, SignatureURL: *w.SignatureURL}, nil
}

// missingDescriptorField builds the error for an absent required field.
func missingDescriptorField(name string) error {
	return fmt.Errorf("peipkg/repository: descriptor is missing required field %q", name)
}

// validateHexFingerprint checks a 64-character lowercase-hex fingerprint
// (§5.2.3).
func validateHexFingerprint(s string) error {
	if len(s) != 64 {
		return fmt.Errorf("fingerprint %q is %d characters, want 64", s, len(s))
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
			return fmt.Errorf("fingerprint %q has a non-lowercase-hex character %q", s, c)
		}
	}
	return nil
}

// parseUTCTimestamp parses an RFC 3339 timestamp that must be UTC, i.e.
// end with Z.
func parseUTCTimestamp(s string) (time.Time, error) {
	if !strings.HasSuffix(s, "Z") {
		return time.Time{}, fmt.Errorf("timestamp %q must be UTC (end with Z)", s)
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("timestamp %q: %w", s, err)
	}
	return t, nil
}
