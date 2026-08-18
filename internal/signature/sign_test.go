package signature_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/peios/peipkg/internal/signature"
)

func keypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return pub, priv
}

// TestSignVerifyRoundTrip is the property the whole signing scheme
// rests on: what Sign produces, Verify accepts, through the wire form.
// Signing and verification living in one package is no guarantee they
// agree — the envelope goes to disk between them.
func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv := keypair(t)
	digest := sha256.Sum256([]byte("a repository index"))

	env, err := signature.Sign(priv, digest[:])
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if env.KeyFingerprint != signature.Fingerprint(pub) {
		t.Errorf("envelope names key %s, want %s", env.KeyFingerprint, signature.Fingerprint(pub))
	}

	encoded, err := env.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	decoded, err := signature.DecodeEnvelope(encoded)
	if err != nil {
		t.Fatalf("DecodeEnvelope of our own output: %v", err)
	}
	if err := decoded.Verify(pub, digest[:]); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// TestSignIsDeterministic pins RFC 8032 §5.1.6 as relied upon: a
// republish of identical content with the same key must produce
// identical bytes, or "reproducible publish" means nothing.
func TestSignIsDeterministic(t *testing.T) {
	_, priv := keypair(t)
	digest := sha256.Sum256([]byte("content"))

	first, err := signature.Sign(priv, digest[:])
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	second, err := signature.Sign(priv, digest[:])
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if string(first.Signature) != string(second.Signature) {
		t.Error("signing the same digest twice produced different signatures")
	}
}

// TestVerifyRejectsATamperedDocument is the check that matters: a
// signature over digest A must not verify against digest B. Without it
// every other test here would pass on an implementation that signed a
// constant.
func TestVerifyRejectsATamperedDocument(t *testing.T) {
	pub, priv := keypair(t)
	original := sha256.Sum256([]byte("index_version 2"))
	tampered := sha256.Sum256([]byte("index_version 1"))

	env, err := signature.Sign(priv, original[:])
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := env.Verify(pub, tampered[:]); err == nil {
		t.Fatal("a signature over one document verified against another")
	}
}

// TestSignRejectsAMisSizedDigest guards a caller bug that would
// otherwise be invisible: signing something that is not a SHA-256
// digest produces a valid signature over the wrong thing, and nothing
// fails until a verifier computes the real digest.
func TestSignRejectsAMisSizedDigest(t *testing.T) {
	_, priv := keypair(t)
	if _, err := signature.Sign(priv, []byte("too short")); err == nil {
		t.Fatal("signed a digest of the wrong length")
	}
}

// TestParsePrivateKeyAcceptsBothForms pins the two encodings the tools
// agree on: a PKCS#8 PEM (what pekit's dev key is) and a raw 32-byte
// seed. The spec is silent on private key encoding, so this test is the
// only place the convention is written down as behaviour.
func TestParsePrivateKeyAcceptsBothForms(t *testing.T) {
	pub, priv := keypair(t)
	want := signature.Fingerprint(pub)

	seed := priv.Seed()
	fromSeed, err := signature.ParsePrivateKey(seed)
	if err != nil {
		t.Fatalf("ParsePrivateKey(seed): %v", err)
	}
	if got := signature.Fingerprint(fromSeed.Public().(ed25519.PublicKey)); got != want {
		t.Errorf("seed yielded key %s, want %s", got, want)
	}

	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	block := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	fromPEM, err := signature.ParsePrivateKey(block)
	if err != nil {
		t.Fatalf("ParsePrivateKey(PEM): %v", err)
	}
	if got := signature.Fingerprint(fromPEM.Public().(ed25519.PublicKey)); got != want {
		t.Errorf("PEM yielded key %s, want %s", got, want)
	}
}

func TestParsePrivateKeyRejectsRubbish(t *testing.T) {
	if _, err := signature.ParsePrivateKey([]byte("not a key")); err == nil {
		t.Fatal("accepted a non-key")
	}
}

// TestPublicKeyRoundTrip closes the loop the repository depends on:
// a key this tool publishes at keys/<fingerprint>.pub must be one the
// consumer's own parser reads back to the same key.
func TestPublicKeyRoundTrip(t *testing.T) {
	pub, _ := keypair(t)
	encoded, err := signature.EncodePublicKey(pub)
	if err != nil {
		t.Fatalf("EncodePublicKey: %v", err)
	}
	if !strings.HasPrefix(string(encoded), "-----BEGIN PUBLIC KEY-----") {
		t.Errorf("published key is not a PEM PUBLIC KEY block: %q", string(encoded))
	}
	parsed, err := signature.ParsePublicKey(encoded)
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	if signature.Fingerprint(parsed) != signature.Fingerprint(pub) {
		t.Error("round-tripped public key has a different fingerprint")
	}
}

// TestEncodedEnvelopeUsesUnpaddedBase64 pins §5.1.3's RFC 4648 §4
// "without padding": a padded signature decodes to the right bytes in
// many libraries but not in the strict decoder the spec mandates, so
// the difference is silent until another implementation reads it.
func TestEncodedEnvelopeUsesUnpaddedBase64(t *testing.T) {
	_, priv := keypair(t)
	digest := sha256.Sum256([]byte("x"))
	env, err := signature.Sign(priv, digest[:])
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	encoded, err := env.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if strings.Contains(string(encoded), "=") {
		t.Errorf("envelope contains base64 padding:\n%s", encoded)
	}
	if !strings.HasSuffix(string(encoded), "}\n") {
		t.Error("envelope does not end with a single trailing newline")
	}
}
