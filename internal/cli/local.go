package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/peios/peipkg/internal/archive"
	"github.com/peios/peipkg/internal/resolver"
)

// localPeipkgExt is the extension that marks an install argument as a
// local package file rather than a repository package name.
const localPeipkgExt = ".peipkg"

// isLocalPeipkg reports whether an install argument names a local
// package file.
func isLocalPeipkg(arg string) bool {
	return strings.HasSuffix(arg, localPeipkgExt)
}

// readLocalPackage reads and format-validates a local .peipkg and
// builds the synthetic resolver candidate for installing it raw.
//
// A raw install skips the repository trust layer — there is no index
// hash to check, no trust set to verify a signature against, and no
// freshness or rollback protection — but not the package-format
// integrity checks: the archive, the manifest, the integrity manifest,
// and every payload file's hash are still verified (archive.VerifyFormat).
//
// The candidate carries the absolute file path in URL and an empty
// Repo, which the package provider recognises as the local-file marker.
// Its priority is the strongest possible (0), so an explicitly-supplied
// local file outranks any repository version of the same package.
func readLocalPackage(path string) (resolver.Candidate, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return resolver.Candidate{}, err
	}
	raw, err := os.ReadFile(abs)
	if err != nil {
		return resolver.Candidate{}, fmt.Errorf("install: reading %s: %w", path, err)
	}
	pkg, err := archive.VerifyFormat(bytes.NewReader(raw))
	if err != nil {
		return resolver.Candidate{}, fmt.Errorf("install: %s: %w", path, err)
	}
	m := pkg.Manifest
	return resolver.Candidate{
		Name:         m.Name,
		Version:      m.Version,
		Architecture: m.Architecture,
		Dependencies: m.Dependencies,
		Conflicts:    m.Conflicts,
		Provides:     m.Provides,
		Replaces:     m.Replaces,
		Repo:         "", // an empty Repo marks a local-file candidate
		RepoPriority: 0,  // an explicit local file outranks repo versions
		URL:          abs,
	}, nil
}
