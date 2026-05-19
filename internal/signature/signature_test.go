package signature_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"testing"

	"github.com/peios/peipkg/internal/signature"
)

// signedDigest is a stand-in for a package's signed-bytes hash.
func signedDigest(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}

// envelopeJSON marshals a set of envelope fields to JSON bytes.
func envelopeJSON(t *testing.T, fields map[string]any) []byte {
	t.Helper()
	data, err := json.Marshal(fields)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return data
}

// validEnvelopeFields builds the fields of a well-formed envelope over
// a fresh key pair and a fixed digest.
func validEnvelopeFields(t *testing.T) map[string]any {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	sig := ed25519.Sign(priv, signedDigest("signed bytes"))
	return map[string]any{
		"schema_version":  1,
		"algorithm":       "ed25519",
		"key_fingerprint": signature.Fingerprint(pub),
		"signature":       base64.RawStdEncoding.EncodeToString(sig),
	}
}

func TestFingerprint(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	fp := signature.Fingerprint(pub)
	if len(fp) != 64 {
		t.Errorf("fingerprint length: got %d, want 64", len(fp))
	}
	for _, c := range fp {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("fingerprint contains a non-lowercase-hex character %q", c)
		}
	}
	if signature.Fingerprint(pub) != fp {
		t.Error("Fingerprint is not deterministic")
	}
}

func TestDecodeAndVerifyValidSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	digest := signedDigest("the package's signed bytes")
	sig := ed25519.Sign(priv, digest)

	fp := signature.Fingerprint(pub)
	env, err := signature.DecodeEnvelope(envelopeJSON(t, map[string]any{
		"schema_version":  1,
		"algorithm":       "ed25519",
		"key_fingerprint": fp,
		"signature":       base64.RawStdEncoding.EncodeToString(sig),
	}))
	if err != nil {
		t.Fatalf("DecodeEnvelope: %v", err)
	}
	if env.KeyFingerprint != fp {
		t.Errorf("KeyFingerprint: got %q, want %q", env.KeyFingerprint, fp)
	}
	if len(env.Signature) != ed25519.SignatureSize {
		t.Errorf("Signature length: got %d, want %d", len(env.Signature), ed25519.SignatureSize)
	}
	if err := env.Verify(pub, digest); err != nil {
		t.Errorf("Verify of a valid signature: %v", err)
	}
}

func TestVerifyRejectsTamperedDigest(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	sig := ed25519.Sign(priv, signedDigest("original bytes"))
	env, err := signature.DecodeEnvelope(envelopeJSON(t, map[string]any{
		"schema_version":  1,
		"algorithm":       "ed25519",
		"key_fingerprint": signature.Fingerprint(pub),
		"signature":       base64.RawStdEncoding.EncodeToString(sig),
	}))
	if err != nil {
		t.Fatalf("DecodeEnvelope: %v", err)
	}
	// The signature was made over a different digest.
	err = env.Verify(pub, signedDigest("tampered bytes"))
	if !errors.Is(err, signature.ErrSignatureInvalid) {
		t.Errorf("Verify of a tampered digest: got %v, want ErrSignatureInvalid", err)
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	digest := signedDigest("bytes")
	sig := ed25519.Sign(priv, digest)
	env, err := signature.DecodeEnvelope(envelopeJSON(t, map[string]any{
		"schema_version":  1,
		"algorithm":       "ed25519",
		"key_fingerprint": signature.Fingerprint(pub),
		"signature":       base64.RawStdEncoding.EncodeToString(sig),
	}))
	if err != nil {
		t.Fatalf("DecodeEnvelope: %v", err)
	}
	// A key that does not match the envelope's fingerprint is rejected.
	if err := env.Verify(otherPub, digest); err == nil {
		t.Error("Verify with a key other than the envelope's should fail")
	}
}

func TestDecodeEnvelopeRejectsMissingFields(t *testing.T) {
	for _, field := range []string{"schema_version", "algorithm", "key_fingerprint", "signature"} {
		t.Run(field, func(t *testing.T) {
			m := validEnvelopeFields(t)
			delete(m, field)
			if _, err := signature.DecodeEnvelope(envelopeJSON(t, m)); err == nil {
				t.Errorf("a missing %q should be rejected", field)
			}
		})
	}
}

func TestDecodeEnvelopeRejectsUnknownField(t *testing.T) {
	m := validEnvelopeFields(t)
	m["future_field"] = "from a newer spec"
	// §5.1.3: signing data is parsed strictly — no forward compatibility.
	if _, err := signature.DecodeEnvelope(envelopeJSON(t, m)); err == nil {
		t.Error("an unknown field should be rejected")
	}
}

func TestDecodeEnvelopeRejectsBadValues(t *testing.T) {
	cases := map[string]func(map[string]any){
		"schema version 2":       func(m map[string]any) { m["schema_version"] = 2 },
		"unsupported algorithm":  func(m map[string]any) { m["algorithm"] = "rsa" },
		"short fingerprint":      func(m map[string]any) { m["key_fingerprint"] = "abcd" },
		"uppercase fingerprint":  func(m map[string]any) { m["key_fingerprint"] = strings.Repeat("A", 64) },
		"non-hex fingerprint":    func(m map[string]any) { m["key_fingerprint"] = strings.Repeat("g", 64) },
		"signature not base64":   func(m map[string]any) { m["signature"] = "not base64 !!" },
		"signature wrong length": func(m map[string]any) { m["signature"] = base64.RawStdEncoding.EncodeToString(make([]byte, 10)) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			m := validEnvelopeFields(t)
			mutate(m)
			if _, err := signature.DecodeEnvelope(envelopeJSON(t, m)); err == nil {
				t.Errorf("%s should be rejected", name)
			}
		})
	}
}

func TestDecodeEnvelopeRejectsMalformedJSON(t *testing.T) {
	if _, err := signature.DecodeEnvelope([]byte("{not json")); err == nil {
		t.Error("malformed JSON should be rejected")
	}
}

func TestParsePublicKey(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	// The raw 32-byte encoding.
	if got, err := signature.ParsePublicKey(pub); err != nil || !got.Equal(pub) {
		t.Errorf("ParsePublicKey (raw): got %x, err %v", got, err)
	}

	// The PEM SubjectPublicKeyInfo encoding.
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	if got, err := signature.ParsePublicKey(pemKey); err != nil || !got.Equal(pub) {
		t.Errorf("ParsePublicKey (PEM): got %x, err %v", got, err)
	}

	// Neither form.
	if _, err := signature.ParsePublicKey([]byte("not a public key")); err == nil {
		t.Error("ParsePublicKey should reject input that is neither raw nor PEM")
	}
}
