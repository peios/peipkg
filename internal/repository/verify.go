package repository

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// ErrUntrusted reports that a detached signature did not verify against
// any candidate key — the artifact's authenticity is unproven.
var ErrUntrusted = errors.New(
	"peipkg/repository: signature does not verify against any trusted key")

// VerifyDetached checks a detached signature over content. sigContent is
// the raw body of the .sig file: base64 (RFC 4648 §4, no padding) of a
// 64-byte Ed25519 signature over the artifact's exact bytes (§6.1.6).
//
// The descriptor and index .sig files carry no key fingerprint, so the
// signature is tried against every candidate key; it is accepted if any
// one verifies. The caller supplies the candidates already filtered to
// those whose status permits verification.
func VerifyDetached(content, sigContent []byte, candidates []ed25519.PublicKey) error {
	sig, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(string(sigContent)))
	if err != nil {
		return fmt.Errorf("peipkg/repository: signature is not valid base64: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("peipkg/repository: signature is %d bytes, want %d",
			len(sig), ed25519.SignatureSize)
	}
	for _, key := range candidates {
		if len(key) == ed25519.PublicKeySize && ed25519.Verify(key, content, sig) {
			return nil
		}
	}
	return ErrUntrusted
}
