package pack

import (
	"crypto/ed25519"

	buildsig "github.com/peios/peipkg/internal/build/signature"
)

// LoadSigningKey reads an Ed25519 private key for [PackOptions.SignKey]
// from a file. Two on-disk encodings are accepted, matching the §5.2
// key-management conventions:
//
//   - the raw 32-byte seed (RFC 8032 §5.1.5), or
//   - a PEM-encoded PKCS#8 `PRIVATE KEY` block, as produced by
//     `openssl genpkey -algorithm ed25519`.
func LoadSigningKey(path string) (ed25519.PrivateKey, error) {
	return buildsig.LoadPrivateKey(path)
}

// ParseSigningKey decodes an Ed25519 private key from key material
// already in memory, accepting the same encodings as [LoadSigningKey].
func ParseSigningKey(data []byte) (ed25519.PrivateKey, error) {
	return buildsig.ParsePrivateKey(data)
}

// SigningKeyFingerprint returns the canonical fingerprint (§5.2.3) of
// the public half of key: the lowercase hex SHA-256 of the raw 32-byte
// public key. It identifies the key a produced signature will name in
// its envelope.
func SigningKeyFingerprint(key ed25519.PrivateKey) string {
	return buildsig.Fingerprint(key.Public().(ed25519.PublicKey))
}
