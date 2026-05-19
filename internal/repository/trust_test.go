package repository_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/peios/peipkg/internal/repository"
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

func TestNewTrustSet(t *testing.T) {
	pub, _ := keypair(t)
	fingerprint := signature.Fingerprint(pub)
	d := repository.Descriptor{
		Keys: []repository.DescriptorKey{{Fingerprint: fingerprint, Status: repository.KeyActive}},
	}
	ts, err := repository.NewTrustSet(d, map[string]ed25519.PublicKey{fingerprint: pub})
	if err != nil {
		t.Fatalf("NewTrustSet: %v", err)
	}
	if len(ts.Keys) != 1 || ts.Keys[0].Fingerprint != fingerprint {
		t.Errorf("Keys: got %+v", ts.Keys)
	}
}

func TestNewTrustSetRejectsMismatchedKey(t *testing.T) {
	pub, _ := keypair(t)
	other, _ := keypair(t)
	fingerprint := signature.Fingerprint(pub)
	d := repository.Descriptor{
		Keys: []repository.DescriptorKey{{Fingerprint: fingerprint, Status: repository.KeyActive}},
	}
	// The supplied key does not hash to the declared fingerprint.
	if _, err := repository.NewTrustSet(d, map[string]ed25519.PublicKey{fingerprint: other}); err == nil {
		t.Error("NewTrustSet should reject a key that does not match its fingerprint")
	}
}

func TestNewTrustSetRejectsMissingKey(t *testing.T) {
	d := repository.Descriptor{
		Keys: []repository.DescriptorKey{{Fingerprint: fp1, Status: repository.KeyActive}},
	}
	if _, err := repository.NewTrustSet(d, map[string]ed25519.PublicKey{}); err == nil {
		t.Error("NewTrustSet should fail when a key's public bytes are missing")
	}
}

func TestVerificationKeysByStatus(t *testing.T) {
	activePub, _ := keypair(t)
	transPub, _ := keypair(t)
	revokedPub, _ := keypair(t)
	now := time.Date(2026, 5, 19, 0, 0, 0, 0, time.UTC)

	ts := repository.TrustSet{Keys: []repository.TrustKey{
		{Fingerprint: signature.Fingerprint(activePub), PublicKey: activePub, Status: repository.KeyActive},
		{Fingerprint: signature.Fingerprint(transPub), PublicKey: transPub,
			Status: repository.KeyTransitioning, ValidUntil: now.Add(24 * time.Hour)},
		{Fingerprint: signature.Fingerprint(revokedPub), PublicKey: revokedPub, Status: repository.KeyRevoked},
	}}

	// Before the transitioning key expires: active + transitioning.
	if keys := ts.VerificationKeys(now); len(keys) != 2 {
		t.Errorf("VerificationKeys(now): got %d keys, want 2 (active + transitioning)", len(keys))
	}
	// After it expires: active only.
	if keys := ts.VerificationKeys(now.Add(48 * time.Hour)); len(keys) != 1 {
		t.Errorf("VerificationKeys(later): got %d keys, want 1 (active only)", len(keys))
	}
}

func TestResolver(t *testing.T) {
	activePub, _ := keypair(t)
	revokedPub, _ := keypair(t)
	transPub, _ := keypair(t)
	now := time.Date(2026, 5, 19, 0, 0, 0, 0, time.UTC)
	activeFp := signature.Fingerprint(activePub)
	revokedFp := signature.Fingerprint(revokedPub)
	transFp := signature.Fingerprint(transPub)

	ts := repository.TrustSet{Keys: []repository.TrustKey{
		{Fingerprint: activeFp, PublicKey: activePub, Status: repository.KeyActive},
		{Fingerprint: revokedFp, PublicKey: revokedPub, Status: repository.KeyRevoked},
		{Fingerprint: transFp, PublicKey: transPub,
			Status: repository.KeyTransitioning, ValidUntil: now.Add(time.Hour)},
	}}

	resolve := ts.Resolver(now)
	if _, ok := resolve(activeFp); !ok {
		t.Error("an active key should resolve")
	}
	if _, ok := resolve(revokedFp); ok {
		t.Error("a revoked key must not resolve")
	}
	if _, ok := resolve(transFp); !ok {
		t.Error("a transitioning key should resolve before valid_until")
	}
	if _, ok := resolve(fp1); ok {
		t.Error("an unknown fingerprint must not resolve")
	}
	if _, ok := ts.Resolver(now.Add(2 * time.Hour))(transFp); ok {
		t.Error("a transitioning key must not resolve after valid_until")
	}
}

func TestTrustSetMarshalRoundTrip(t *testing.T) {
	activePub, _ := keypair(t)
	transPub, _ := keypair(t)
	validUntil := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	ts := repository.TrustSet{Keys: []repository.TrustKey{
		{Fingerprint: signature.Fingerprint(activePub), PublicKey: activePub, Status: repository.KeyActive},
		{Fingerprint: signature.Fingerprint(transPub), PublicKey: transPub,
			Status: repository.KeyTransitioning, ValidUntil: validUntil},
	}}

	data, err := ts.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got, err := repository.ParseTrustSet(data)
	if err != nil {
		t.Fatalf("ParseTrustSet: %v", err)
	}
	if len(got.Keys) != 2 {
		t.Fatalf("round-trip: got %d keys, want 2", len(got.Keys))
	}
	if !got.Keys[0].PublicKey.Equal(activePub) {
		t.Error("active key bytes did not round-trip")
	}
	if !got.Keys[1].ValidUntil.Equal(validUntil) {
		t.Error("transitioning key valid_until did not round-trip")
	}
}

func TestParseEmptyTrustSet(t *testing.T) {
	for _, s := range []string{"", "[]"} {
		ts, err := repository.ParseTrustSet(s)
		if err != nil || len(ts.Keys) != 0 {
			t.Errorf("ParseTrustSet(%q): keys=%d err=%v", s, len(ts.Keys), err)
		}
	}
}

func TestVerifyDetached(t *testing.T) {
	pub, priv := keypair(t)
	content := []byte("the repository descriptor's exact bytes")
	sigContent := []byte(base64.RawStdEncoding.EncodeToString(ed25519.Sign(priv, content)))

	if err := repository.VerifyDetached(content, sigContent, []ed25519.PublicKey{pub}); err != nil {
		t.Errorf("VerifyDetached of a valid signature: %v", err)
	}
	// A trailing newline in the .sig file is tolerated.
	if err := repository.VerifyDetached(content, append(sigContent, '\n'),
		[]ed25519.PublicKey{pub}); err != nil {
		t.Errorf("VerifyDetached with a trailing newline: %v", err)
	}
	// Verifying against the wrong key.
	other, _ := keypair(t)
	if err := repository.VerifyDetached(content, sigContent,
		[]ed25519.PublicKey{other}); !errors.Is(err, repository.ErrUntrusted) {
		t.Errorf("VerifyDetached with the wrong key: got %v, want ErrUntrusted", err)
	}
	// Verifying tampered content.
	if err := repository.VerifyDetached([]byte("tampered"), sigContent,
		[]ed25519.PublicKey{pub}); !errors.Is(err, repository.ErrUntrusted) {
		t.Errorf("VerifyDetached of tampered content: got %v, want ErrUntrusted", err)
	}
}

func TestCheckFreshness(t *testing.T) {
	floorTime := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	index := func(version int64, at time.Time) repository.Index {
		return repository.Index{IndexVersion: version, GeneratedAt: at}
	}
	cases := []struct {
		name     string
		idx      repository.Index
		floorVer int64
		floorAt  time.Time
		want     repository.FreshnessResult
	}{
		{"newer version", index(10, floorTime.Add(time.Hour)), 5, floorTime, repository.FreshnessProgress},
		{"identical version and time", index(5, floorTime), 5, floorTime, repository.FreshnessNoProgress},
		{"rolled-back version", index(4, floorTime), 5, floorTime, repository.FreshnessRejected},
		{"rolled-back generated_at", index(10, floorTime.Add(-time.Hour)), 5, floorTime, repository.FreshnessRejected},
		{"fresh repository, zero floor", index(1, floorTime), 0, time.Time{}, repository.FreshnessProgress},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := repository.CheckFreshness(tc.idx, tc.floorVer, tc.floorAt); got != tc.want {
				t.Errorf("CheckFreshness = %v, want %v", got, tc.want)
			}
		})
	}
}
