package repository

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/peios/peipkg/internal/signature"
)

// ErrUntrusted reports that a detached signature did not verify against
// any candidate key — the artifact's authenticity is unproven.
var ErrUntrusted = errors.New(
	"peipkg/repository: signature does not verify against any trusted key")

// VerifyDetached checks a detached signature over content. sigContent is
// the raw body of the .sig file: a signature envelope (§5.1.3) whose
// signature is over SHA-256 of the artifact's exact bytes — the same
// scheme as a package signature (§6.1.6).
//
// The signature is tried against every candidate key and accepted if any
// one verifies; the envelope's key_fingerprint is not consulted for
// selection. The caller supplies the candidates already filtered to those
// whose status permits verification.
func VerifyDetached(content, sigContent []byte, candidates []ed25519.PublicKey) error {
	env, err := signature.DecodeEnvelope(sigContent)
	if err != nil {
		return fmt.Errorf("peipkg/repository: %w", err)
	}
	digest := sha256.Sum256(content)
	for _, key := range candidates {
		if len(key) == ed25519.PublicKeySize && ed25519.Verify(key, digest[:], env.Signature) {
			return nil
		}
	}
	return ErrUntrusted
}
