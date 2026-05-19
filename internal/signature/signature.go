// Package signature handles a package's inline signature: decoding the
// `.peipkg/signature` envelope (PSD-009 §5.1.3) and verifying an
// Ed25519 signature against a public key (§5.3).
//
// The package is the cryptographic primitive layer. It does not own the
// trust set or key statuses (active / transitioning / revoked) — those
// are repository-scoped and belong to the repository layer, which uses
// [Fingerprint] to match an envelope's key to a trusted one.
package signature

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

// envelopeSchemaVersion is the signature-envelope schema version this
// build understands (§5.1.3).
const envelopeSchemaVersion = 1

// algorithmEd25519 is the only signature algorithm valid in v0.22 (§9.2).
const algorithmEd25519 = "ed25519"

// fingerprintLen is the length of a key fingerprint: the full SHA-256
// hash as lowercase hex (§5.2.3).
const fingerprintLen = 2 * sha256.Size

// ErrSignatureInvalid reports that a signature did not verify against
// the public key — the package's authenticity is unproven (§5.3).
var ErrSignatureInvalid = errors.New("peipkg/signature: signature does not verify")

// KeyResolver looks up a trusted public key by its fingerprint
// (§5.2.3), reporting false if no trusted key matches. A package
// signature verifier rejects the package when the resolver returns
// false (§5.3 failure condition 6). Callers obtain a resolver scoped to
// the originating repository's trust set.
type KeyResolver func(fingerprint string) (ed25519.PublicKey, bool)

// Envelope is a decoded, structurally-valid `.peipkg/signature`
// document (§5.1.3). Obtain one through [DecodeEnvelope].
type Envelope struct {
	// KeyFingerprint identifies the public key the signature was made
	// with — a 64-character lowercase hex string (§5.2.3).
	KeyFingerprint string
	// Signature is the raw 64-byte Ed25519 signature.
	Signature []byte
}

// wireEnvelope mirrors the envelope's JSON shape. Every field is
// required (§5.1.3); a pointer distinguishes an absent field from a
// present zero value.
type wireEnvelope struct {
	SchemaVersion  *int    `json:"schema_version"`
	Algorithm      *string `json:"algorithm"`
	KeyFingerprint *string `json:"key_fingerprint"`
	Signature      *string `json:"signature"`
}

// DecodeEnvelope parses and validates a signature envelope from the raw
// bytes of a `.peipkg/signature` entry (§5.1.3).
//
// Unlike the manifest, the envelope is parsed strictly: an unknown
// field is rejected, not ignored — §5.1.3 makes signing data a
// deliberate exception to forward-compatible parsing.
func DecodeEnvelope(data []byte) (Envelope, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()

	var w wireEnvelope
	if err := dec.Decode(&w); err != nil {
		return Envelope{}, fmt.Errorf("peipkg/signature: invalid envelope JSON: %w", err)
	}
	if dec.More() {
		return Envelope{}, fmt.Errorf("peipkg/signature: trailing data after the envelope")
	}

	switch {
	case w.SchemaVersion == nil:
		return Envelope{}, missingField("schema_version")
	case w.Algorithm == nil:
		return Envelope{}, missingField("algorithm")
	case w.KeyFingerprint == nil:
		return Envelope{}, missingField("key_fingerprint")
	case w.Signature == nil:
		return Envelope{}, missingField("signature")
	}

	if *w.SchemaVersion != envelopeSchemaVersion {
		return Envelope{}, fmt.Errorf(
			"peipkg/signature: envelope schema_version is %d, want %d",
			*w.SchemaVersion, envelopeSchemaVersion)
	}
	if *w.Algorithm != algorithmEd25519 {
		return Envelope{}, fmt.Errorf(
			"peipkg/signature: algorithm %q is not supported (only %q)",
			*w.Algorithm, algorithmEd25519)
	}
	if err := validateFingerprint(*w.KeyFingerprint); err != nil {
		return Envelope{}, err
	}
	sig, err := base64.RawStdEncoding.DecodeString(*w.Signature)
	if err != nil {
		return Envelope{}, fmt.Errorf("peipkg/signature: signature is not valid base64: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return Envelope{}, fmt.Errorf(
			"peipkg/signature: signature is %d bytes, want %d", len(sig), ed25519.SignatureSize)
	}
	return Envelope{KeyFingerprint: *w.KeyFingerprint, Signature: sig}, nil
}

// Verify checks the envelope's signature against digest — the SHA-256
// of the package's signed bytes (§5.1.2) — using pub. It returns nil if
// the signature is valid, [ErrSignatureInvalid] if it is not, or a
// descriptive error if the inputs are malformed.
//
// The caller is responsible for having selected pub from the trust set
// scoped to the originating repository (§5.2.5); Verify confirms the
// envelope names that key but does not consult key statuses.
func (e Envelope) Verify(pub ed25519.PublicKey, digest []byte) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf(
			"peipkg/signature: public key is %d bytes, want %d", len(pub), ed25519.PublicKeySize)
	}
	if fp := Fingerprint(pub); fp != e.KeyFingerprint {
		return fmt.Errorf(
			"peipkg/signature: public key fingerprint %s does not match the envelope's %s",
			fp, e.KeyFingerprint)
	}
	if !ed25519.Verify(pub, digest, e.Signature) {
		return ErrSignatureInvalid
	}
	return nil
}

// Fingerprint computes a public key's fingerprint (§5.2.3): the
// lowercase hex SHA-256 of the raw 32-byte key.
func Fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}

// validateFingerprint checks a fingerprint string is 64 lowercase hex
// characters (§5.2.3).
func validateFingerprint(s string) error {
	if len(s) != fingerprintLen {
		return fmt.Errorf(
			"peipkg/signature: key_fingerprint is %d characters, want %d", len(s), fingerprintLen)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
			return fmt.Errorf(
				"peipkg/signature: key_fingerprint contains a non-lowercase-hex character %q", c)
		}
	}
	return nil
}

// missingField builds the error for an absent required envelope field.
func missingField(name string) error {
	return fmt.Errorf("peipkg/signature: envelope is missing required field %q", name)
}
