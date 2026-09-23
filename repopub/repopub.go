// Package repopub is the public surface for publishing a peipkg
// repository from an embedding tool: the library behind peipkg-repo. It
// turns a directory of .peipkg files into the signed state a consumer
// adds and refreshes from. The directory it produces IS the repository,
// and deploying it is a copy.
package repopub

import (
	"crypto/ed25519"
	"time"

	internalrepopub "github.com/peios/peipkg/internal/repopub"
	"github.com/peios/peipkg/internal/signature"
)

// InitOptions configures [Init].
type InitOptions struct {
	// RequireQualification creates publisher schema 2: older tools refuse it.
	RequireQualification bool
	// Name is the repository's name; a consumer's .repo file and the
	// descriptor must agree on it.
	Name        string
	Description string
	// Key signs the initial descriptor and indexes. Its public half
	// becomes the repository's first trust anchor.
	Key ed25519.PrivateKey
	// URLTemplate is the package URL template; empty uses the default.
	URLTemplate string
	// GeneratedAt stamps the initial indexes. Required.
	GeneratedAt time.Time
	// TrustedKeys are further public keys listed as active from the
	// start: the signers of the packages the repository will carry. A
	// package is accepted only if its signer is in the descriptor.
	TrustedKeys []ed25519.PublicKey
}

// Init creates an empty, valid, signed repository at dir, which must be
// empty or absent.
func Init(dir string, opts InitOptions) error {
	return internalrepopub.Init(dir, internalrepopub.InitOptions{
		RequireQualification: opts.RequireQualification,
		Name:                 opts.Name,
		Description:          opts.Description,
		Key:                  opts.Key,
		URLTemplate:          opts.URLTemplate,
		GeneratedAt:          opts.GeneratedAt,
		TrustedKeys:          opts.TrustedKeys,
	})
}

// PublishOptions configures [Publish].
type PublishOptions struct {
	// Key signs the new indexes; it must be one the descriptor trusts.
	Key ed25519.PrivateKey
	// Paths names .peipkg files, or directories to scan for them.
	Paths []string
	// GeneratedAt stamps the new indexes. Required.
	GeneratedAt time.Time
	// URLTemplate overrides the stored template for this publish.
	URLTemplate string
	// AllowUnsigned permits a package with no inline signature.
	AllowUnsigned bool
	// Qualification binds the checked artifacts and base repository state.
	Qualification *Qualification
	// Replace overwrites archived packages of the same name, version and
	// architecture instead of refusing them. It breaks the retention
	// promise for those versions; use it only on a repository nobody
	// consumes yet, such as one being bootstrapped.
	Replace bool
}

// PublishResult reports what a publish did.
type PublishResult struct {
	IndexVersion int64
	Added        int
	// Replaced names each overwritten entry as "name version arch sha256".
	Replaced     []string
	ActiveCount  int
	ArchiveCount int
}

// Publish ingests packages into the repository at dir and writes a new
// signed revision of its indexes. Nothing is written unless every
// package is acceptable.
func Publish(dir string, opts PublishOptions) (PublishResult, error) {
	res, err := internalrepopub.Publish(dir, internalrepopub.PublishOptions{
		Key:           opts.Key,
		Paths:         opts.Paths,
		GeneratedAt:   opts.GeneratedAt,
		URLTemplate:   opts.URLTemplate,
		AllowUnsigned: opts.AllowUnsigned,
		Qualification: opts.Qualification,
		Replace:       opts.Replace,
	})
	if err != nil {
		return PublishResult{}, err
	}
	var replaced []string
	for _, e := range res.Replaced {
		replaced = append(replaced, e.Name+" "+e.Version.String()+" "+e.Architecture+" "+e.Hash)
	}
	return PublishResult{
		IndexVersion: res.IndexVersion,
		Added:        len(res.Added),
		Replaced:     replaced,
		ActiveCount:  res.ActiveCount,
		ArchiveCount: res.ArchiveCount,
	}, nil
}

// ParsePublicKey decodes an Ed25519 public key from a key file: the raw
// 32 bytes, or a PEM "PUBLIC KEY" block.
func ParsePublicKey(data []byte) (ed25519.PublicKey, error) {
	return signature.ParsePublicKey(data)
}

// Fingerprint is a public key's fingerprint as a consumer's .repo file
// names it in trust_anchors: the lowercase hex SHA-256 of the raw key.
func Fingerprint(pub ed25519.PublicKey) string {
	return signature.Fingerprint(pub)
}
