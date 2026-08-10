package pack

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadSigningKeyRawSeed(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	path := filepath.Join(t.TempDir(), "seed.key")
	if err := os.WriteFile(path, priv.Seed(), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadSigningKey(path)
	if err != nil {
		t.Fatalf("LoadSigningKey: %v", err)
	}
	if !loaded.Public().(ed25519.PublicKey).Equal(pub) {
		t.Error("loaded raw-seed key does not derive the original public key")
	}
}

func TestLoadSigningKeyPKCS8PEM(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	path := filepath.Join(t.TempDir(), "key.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadSigningKey(path)
	if err != nil {
		t.Fatalf("LoadSigningKey: %v", err)
	}
	if !loaded.Public().(ed25519.PublicKey).Equal(pub) {
		t.Error("loaded PKCS#8 key does not derive the original public key")
	}

	sum := sha256.Sum256(pub)
	if got, want := SigningKeyFingerprint(loaded), hex.EncodeToString(sum[:]); got != want {
		t.Errorf("SigningKeyFingerprint = %s, want %s", got, want)
	}
}

func TestLoadSigningKeyErrors(t *testing.T) {
	if _, err := LoadSigningKey(filepath.Join(t.TempDir(), "absent.key")); err == nil {
		t.Error("expected an error for a missing key file")
	}
	garbage := filepath.Join(t.TempDir(), "garbage.key")
	if err := os.WriteFile(garbage, []byte("not a key, wrong length"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSigningKey(garbage); err == nil {
		t.Error("expected an error for garbage key material")
	}
}
