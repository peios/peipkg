package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/peios/peipkg/internal/archive"
	"github.com/peios/peipkg/internal/config"
	"github.com/peios/peipkg/internal/install"
	"github.com/peios/peipkg/internal/repository"
	"github.com/peios/peipkg/internal/resolver"
)

// repoProvider fetches and verifies a plan's packages from the
// configured repositories — the install.PackageProvider the executor
// calls during staging.
type repoProvider struct {
	client  *repository.Client
	configs map[string]config.RepoConfig
}

// Provide implements install.PackageProvider.
func (p *repoProvider) Provide(ctx context.Context, op resolver.Operation) (install.ProvidedPackage, error) {
	if op.Candidate == nil {
		return install.ProvidedPackage{},
			fmt.Errorf("operation on %q has no candidate package", op.Name)
	}
	// An empty Repo marks a raw local-file install: the candidate's URL
	// is a filesystem path, read and format-validated rather than
	// fetched and verified against a repository (§ local install).
	if op.Candidate.Repo == "" {
		return provideLocal(*op.Candidate)
	}
	cfg, ok := p.configs[op.Candidate.Repo]
	if !ok {
		return install.ProvidedPackage{},
			fmt.Errorf("no configuration for repository %q", op.Candidate.Repo)
	}
	pkg, raw, err := p.client.FetchPackage(ctx, cfg,
		op.Candidate.URL, op.Candidate.Hash, op.Candidate.SizeCompressed)
	if err != nil {
		return install.ProvidedPackage{}, err
	}
	if err := verifyCandidatePackage(*op.Candidate, pkg, "repository package "+op.Candidate.URL); err != nil {
		return install.ProvidedPackage{}, err
	}
	return install.ProvidedPackage{Pkg: pkg, Archive: bytes.NewReader(raw)}, nil
}

// provideLocal reads and format-validates a local .peipkg for a raw
// install. The file is re-read here, at staging time, so a change
// between planning and staging is caught by the format checks.
func provideLocal(c resolver.Candidate) (install.ProvidedPackage, error) {
	path := c.URL
	raw, err := os.ReadFile(path)
	if err != nil {
		return install.ProvidedPackage{}, fmt.Errorf("reading local package %s: %w", path, err)
	}
	sum := sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); got != c.Hash {
		return install.ProvidedPackage{}, fmt.Errorf(
			"local package %s hash mismatch (got %s, want %s)", path, got, c.Hash)
	}
	pkg, err := archive.VerifyFormat(bytes.NewReader(raw))
	if err != nil {
		return install.ProvidedPackage{}, fmt.Errorf("local package %s: %w", path, err)
	}
	if err := verifyCandidatePackage(c, pkg, "local package "+path); err != nil {
		return install.ProvidedPackage{}, err
	}
	return install.ProvidedPackage{Pkg: pkg, Archive: bytes.NewReader(raw)}, nil
}

func verifyCandidatePackage(c resolver.Candidate, pkg *archive.Package, label string) error {
	if pkg.Manifest.Name != c.Name {
		return fmt.Errorf("%s carries manifest for package %q, planned %q",
			label, pkg.Manifest.Name, c.Name)
	}
	if !pkg.Manifest.Version.Equal(c.Version) {
		return fmt.Errorf("%s carries manifest version %s, planned %s",
			label, pkg.Manifest.Version, c.Version)
	}
	if pkg.Manifest.Architecture != c.Architecture {
		return fmt.Errorf("%s carries architecture %q, planned %q",
			label, pkg.Manifest.Architecture, c.Architecture)
	}
	return nil
}
