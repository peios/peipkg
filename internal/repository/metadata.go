package repository

import (
	"crypto/ed25519"

	"github.com/peios/peipkg/internal/repodata"
)

// The repository consumer and publisher share the metadata model in repodata.
// Aliases preserve the consumer package's existing API while keeping its
// database-backed client out of publisher dependency graphs.
type KeyStatus = repodata.KeyStatus

const (
	KeyActive        = repodata.KeyActive
	KeyTransitioning = repodata.KeyTransitioning
	KeyRevoked       = repodata.KeyRevoked
)

type DescriptorKey = repodata.DescriptorKey
type IndexPointer = repodata.IndexPointer
type Descriptor = repodata.Descriptor

func DecodeDescriptor(data []byte) (Descriptor, error) {
	return repodata.DecodeDescriptor(data)
}

func EncodeDescriptor(d Descriptor) ([]byte, error) {
	return repodata.EncodeDescriptor(d)
}

type IndexKind = repodata.IndexKind

const (
	IndexActive  = repodata.IndexActive
	IndexArchive = repodata.IndexArchive
)

type IndexEntry = repodata.IndexEntry
type Index = repodata.Index

func DecodeIndex(data []byte) (Index, error) {
	return repodata.DecodeIndex(data)
}

func EncodeIndex(idx Index) ([]byte, error) {
	return repodata.EncodeIndex(idx)
}

var ErrUntrusted = repodata.ErrUntrusted

func VerifyDetached(content, sigContent []byte, candidates []ed25519.PublicKey) error {
	return repodata.VerifyDetached(content, sigContent, candidates)
}
