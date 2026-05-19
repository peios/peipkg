package cli

import (
	"bytes"
	"context"
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
		return provideLocal(op.Candidate.URL)
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
	return install.ProvidedPackage{Pkg: pkg, Archive: bytes.NewReader(raw)}, nil
}

// provideLocal reads and format-validates a local .peipkg for a raw
// install. The file is re-read here, at staging time, so a change
// between planning and staging is caught by the format checks.
func provideLocal(path string) (install.ProvidedPackage, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return install.ProvidedPackage{}, fmt.Errorf("reading local package %s: %w", path, err)
	}
	pkg, err := archive.VerifyFormat(bytes.NewReader(raw))
	if err != nil {
		return install.ProvidedPackage{}, fmt.Errorf("local package %s: %w", path, err)
	}
	return install.ProvidedPackage{Pkg: pkg, Archive: bytes.NewReader(raw)}, nil
}
