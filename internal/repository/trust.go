package repository

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/peios/peipkg/internal/signature"
)

// TrustKey is one signing key of a repository's trust set: a
// descriptor key declaration (§6.1.3) joined with the key's fetched
// public bytes.
type TrustKey struct {
	Fingerprint string
	PublicKey   ed25519.PublicKey
	Status      KeyStatus
	// ValidUntil is the expiry of a transitioning key; the zero Time
	// otherwise.
	ValidUntil time.Time
}

// TrustSet is a repository's recorded signing-key state (§5.2.5). It is
// persisted per repository and is the authority for verifying that
// repository's content.
type TrustSet struct {
	Keys []TrustKey
}

// NewTrustSet joins a descriptor's key declarations with the public-key
// bytes fetched for them, keyed by fingerprint. It fails if any key is
// missing or if a fetched key does not hash to its declared fingerprint
// (§5.2.3).
func NewTrustSet(d Descriptor, publicKeys map[string]ed25519.PublicKey) (TrustSet, error) {
	var ts TrustSet
	for _, dk := range d.Keys {
		pub, ok := publicKeys[dk.Fingerprint]
		if !ok {
			return TrustSet{}, fmt.Errorf(
				"peipkg/repository: no public key supplied for fingerprint %s", dk.Fingerprint)
		}
		if signature.Fingerprint(pub) != dk.Fingerprint {
			return TrustSet{}, fmt.Errorf(
				"peipkg/repository: public key does not hash to fingerprint %s", dk.Fingerprint)
		}
		ts.Keys = append(ts.Keys, TrustKey{
			Fingerprint: dk.Fingerprint,
			PublicKey:   pub,
			Status:      dk.Status,
			ValidUntil:  dk.ValidUntil,
		})
	}
	return ts, nil
}

// VerificationKeys returns the public keys whose status permits
// verification at now: active keys always, transitioning keys until
// their ValidUntil, revoked keys never (§6.1.4). It is used for the
// detached descriptor and index signatures, which carry no fingerprint.
func (ts TrustSet) VerificationKeys(now time.Time) []ed25519.PublicKey {
	var keys []ed25519.PublicKey
	for _, k := range ts.Keys {
		if k.verifiableAt(now) {
			keys = append(keys, k.PublicKey)
		}
	}
	return keys
}

// Resolver returns a key resolver for verifying package signatures,
// which name their key by fingerprint. It resolves a fingerprint only
// to a key whose status permits verification at now.
func (ts TrustSet) Resolver(now time.Time) signature.KeyResolver {
	return func(fingerprint string) (ed25519.PublicKey, bool) {
		for _, k := range ts.Keys {
			if k.Fingerprint == fingerprint {
				return k.PublicKey, k.verifiableAt(now)
			}
		}
		return nil, false
	}
}

// verifiableAt reports whether a key's status permits verification at
// now (§6.1.4).
func (k TrustKey) verifiableAt(now time.Time) bool {
	switch k.Status {
	case KeyActive:
		return true
	case KeyTransitioning:
		return !now.After(k.ValidUntil)
	default: // revoked, or an unknown status
		return false
	}
}

type wireTrustKey struct {
	Fingerprint string `json:"fingerprint"`
	PublicKey   string `json:"public_key"` // base64 RawStd of the 32 raw bytes
	Status      string `json:"status"`
	ValidUntil  string `json:"valid_until,omitempty"`
}

// Marshal encodes the trust set as the JSON document stored in the
// package database's repository.trust_keys column.
func (ts TrustSet) Marshal() (string, error) {
	wires := make([]wireTrustKey, 0, len(ts.Keys))
	for _, k := range ts.Keys {
		w := wireTrustKey{
			Fingerprint: k.Fingerprint,
			PublicKey:   base64.RawStdEncoding.EncodeToString(k.PublicKey),
			Status:      string(k.Status),
		}
		if k.Status == KeyTransitioning {
			w.ValidUntil = k.ValidUntil.UTC().Format(time.RFC3339)
		}
		wires = append(wires, w)
	}
	data, err := json.Marshal(wires)
	if err != nil {
		return "", fmt.Errorf("peipkg/repository: encoding trust set: %w", err)
	}
	return string(data), nil
}

// ParseTrustSet decodes a trust set from its stored JSON. The empty
// string and "[]" both yield an empty set.
func ParseTrustSet(s string) (TrustSet, error) {
	if s == "" {
		return TrustSet{}, nil
	}
	var wires []wireTrustKey
	if err := json.Unmarshal([]byte(s), &wires); err != nil {
		return TrustSet{}, fmt.Errorf("peipkg/repository: decoding trust set: %w", err)
	}
	var ts TrustSet
	for _, w := range wires {
		pub, err := base64.RawStdEncoding.DecodeString(w.PublicKey)
		if err != nil {
			return TrustSet{}, fmt.Errorf(
				"peipkg/repository: trust key %s: public_key is not valid base64: %w",
				w.Fingerprint, err)
		}
		if len(pub) != ed25519.PublicKeySize {
			return TrustSet{}, fmt.Errorf(
				"peipkg/repository: trust key %s: public key is %d bytes, want %d",
				w.Fingerprint, len(pub), ed25519.PublicKeySize)
		}
		key := TrustKey{
			Fingerprint: w.Fingerprint,
			PublicKey:   ed25519.PublicKey(pub),
			Status:      KeyStatus(w.Status),
		}
		if w.ValidUntil != "" {
			validUntil, err := parseUTCTimestamp(w.ValidUntil)
			if err != nil {
				return TrustSet{}, fmt.Errorf(
					"peipkg/repository: trust key %s valid_until: %w", w.Fingerprint, err)
			}
			key.ValidUntil = validUntil
		}
		ts.Keys = append(ts.Keys, key)
	}
	return ts, nil
}
