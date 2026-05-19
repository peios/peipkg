package cli

import (
	"bytes"
	"context"
	"fmt"

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
