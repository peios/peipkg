package signature

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/pem"
	"fmt"

	"crypto/x509"
)

// Sign produces a signature envelope over digest — the SHA-256 of the
// artifact's signed bytes — using priv (§5.1.3).
//
// The same envelope covers every signed artifact in the format: a
// package's inline `.peipkg/signature`, and the detached signatures on
// a repository descriptor and its indexes (§6.1.6, §6.2.1). One scheme,
// one verifier, one producer.
//
// Ed25519 signatures are deterministic (RFC 8032 §5.1.6), so signing
// the same digest with the same key twice yields byte-identical
// envelopes — the property a reproducible publish depends on.
func Sign(priv ed25519.PrivateKey, digest []byte) (Envelope, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return Envelope{}, fmt.Errorf(
			"peipkg/signature: private key is %d bytes, want %d", len(priv), ed25519.PrivateKeySize)
	}
	// A digest of the wrong length is a caller bug that would otherwise
	// produce a perfectly valid signature over the wrong thing —
	// undetectable until a verifier computes the real digest and fails.
	if len(digest) != sha256Size {
		return Envelope{}, fmt.Errorf(
			"peipkg/signature: digest is %d bytes, want %d", len(digest), sha256Size)
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return Envelope{}, fmt.Errorf("peipkg/signature: private key does not yield an Ed25519 public key")
	}
	return Envelope{
		KeyFingerprint: Fingerprint(pub),
		Signature:      ed25519.Sign(priv, digest),
	}, nil
}

// Encode renders the envelope as the JSON document written to
// `.peipkg/signature` or to a detached `.sig` file (§5.1.3).
//
// The fields are emitted in the order the schema lists them, with a
// single trailing newline: §6.1.7 asks metadata documents to be
// canonically formatted so a publish is reproducible, and the same
// courtesy costs nothing here.
func (e Envelope) Encode() ([]byte, error) {
	if err := validateFingerprint(e.KeyFingerprint); err != nil {
		return nil, err
	}
	if len(e.Signature) != ed25519.SignatureSize {
		return nil, fmt.Errorf(
			"peipkg/signature: signature is %d bytes, want %d",
			len(e.Signature), ed25519.SignatureSize)
	}
	// Built by hand rather than through a struct so the field order is
	// the schema's and not a reflection accident, and so the base64 is
	// unpadded (RFC 4648 §4) — which is what DecodeEnvelope expects.
	doc := fmt.Sprintf(`{
  "schema_version": %d,
  "algorithm": %q,
  "key_fingerprint": %q,
  "signature": %q
}
`, envelopeSchemaVersion, algorithmEd25519, e.KeyFingerprint,
		base64.RawStdEncoding.EncodeToString(e.Signature))
	return []byte(doc), nil
}

// ParsePrivateKey decodes an Ed25519 private key from a key file:
// either a PEM "PRIVATE KEY" block in PKCS#8 form, or the raw 32-byte
// seed.
//
// PSD-009 §5.2.8 deliberately says nothing about private key encoding —
// custody is an operator concern, and the specification "cares only
// about the bytes, not how they were produced". These two forms are
// therefore a local convention rather than a format requirement, and
// they are chosen to match what pekit's signing accepts, so a single
// key file can sign both a package and the repository metadata that
// advertises it. A repository whose descriptor is signed by one key
// while its packages are signed by another is legal but pointlessly
// harder to operate.
func ParsePrivateKey(data []byte) (ed25519.PrivateKey, error) {
	if len(data) == ed25519.SeedSize {
		return ed25519.NewKeyFromSeed(data), nil
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf(
			"peipkg/signature: private key is neither a %d-byte seed nor a PEM block",
			ed25519.SeedSize)
	}
	if block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf(
			"peipkg/signature: PEM block type is %q, want \"PRIVATE KEY\"", block.Type)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("peipkg/signature: parsing private key: %w", err)
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("peipkg/signature: private key is %T, want Ed25519", parsed)
	}
	return key, nil
}

// EncodePublicKey renders pub as a PEM "PUBLIC KEY" block for
// publication at the conventional `keys/<fingerprint>.pub` URL (§6.4.2).
//
// §5.2.2 permits either the raw 32 bytes or PEM; PEM is written because
// a published key is an artifact people copy between machines and paste
// into issues, and a self-describing armoured block survives that
// treatment where 32 raw bytes do not.
func EncodePublicKey(pub ed25519.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("peipkg/signature: encoding public key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}
