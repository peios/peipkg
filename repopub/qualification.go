package repopub

import (
	"crypto/ed25519"
	"os"

	"github.com/peios/peipkg/internal/archive"
	internal "github.com/peios/peipkg/internal/repopub"
)

// Qualification binds checked artifacts and repository state to promotion.
// Publish checks all next active install closures, previous closure upgrades,
// signatures, file collisions and hashes before writing a repository index.
type Qualification = internal.Qualification

// StateDigest identifies the exact signed repository snapshot.
func StateDigest(dir string) (string, error) { return internal.StateDigest(dir) }

// PackageInspection is verified archive metadata for a producer-side payload
// linter. It carries no private signing material.
type PackageInspection struct {
	ManifestJSON []byte
	Payload      []PayloadEntry
	Signed       bool
}
type PayloadEntry struct {
	Path       string
	Directory  bool
	Symlink    bool
	LinkTarget string
	Hash       string
}

// InspectPackage verifies the signature and every payload digest before
// exposing metadata. keys must be an operator-established trust set.
func InspectPackage(path string, keys []ed25519.PublicKey) (PackageInspection, error) {
	f, err := os.Open(path)
	if err != nil {
		return PackageInspection{}, err
	}
	defer f.Close()
	trusted := map[string]ed25519.PublicKey{}
	for _, key := range keys {
		trusted[Fingerprint(key)] = key
	}
	pkg, err := archive.Verify(f, func(fp string) (ed25519.PublicKey, bool) { k, ok := trusted[fp]; return k, ok }, archive.NoDeclaredSize)
	if err != nil {
		return PackageInspection{}, err
	}
	out := PackageInspection{ManifestJSON: pkg.ManifestJSON, Signed: pkg.Signed}
	for _, p := range pkg.Payload {
		out.Payload = append(out.Payload, PayloadEntry{Path: p.Path, Directory: p.Type == archive.EntryDir, Symlink: p.Type == archive.EntrySymlink, LinkTarget: p.LinkTarget, Hash: p.Hash})
	}
	return out, nil
}

// EvidenceIdentity describes bytes, modes, links and directory membership.
func EvidenceIdentity(path string) (string, error) { return internal.EvidenceIdentity(path) }
