package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"slices"

	"github.com/peios/peipkg/internal/archive"
	"github.com/peios/peipkg/internal/config"
	"github.com/peios/peipkg/internal/install"
	"github.com/peios/peipkg/internal/manifest"
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
	return reconcileWithIndexEntry(c, pkg, label)
}

// reconcileWithIndexEntry compares every relation the candidate carried
// from the repository index against the manifest that actually shipped
// (§5.33, §5.26 step 8).
//
// The index exists to make planning possible without downloading. It is
// not a second source of truth — §5.33 makes the manifest authoritative
// precisely so that a plan computed from index claims is checked against
// the package before anything is installed.
//
// Without this the resolver's whole dependency and conflict graph was
// built from claims nothing ever confirmed. A repository — a compromised
// signing key, or a malicious operator of a low-priority one — could
// publish an entry declaring *no* conflicts for a package whose manifest
// conflicts with something critical, or omitting dependencies the package
// genuinely needs. The plan was computed on the lie, the operator
// approved that plan, and the manifest's real relations were discovered
// by nothing.
//
// sd_overrides, build.source_ref and schema_version are deliberately
// outside the comparison: the index does not carry them.
func reconcileWithIndexEntry(c resolver.Candidate, pkg *archive.Package, label string) error {
	m := pkg.Manifest
	for _, f := range []struct {
		field       string
		index, real []string
	}{
		{"dependencies", renderDeps(c.Dependencies), renderDeps(m.Dependencies)},
		{"conflicts", renderDeps(c.Conflicts), renderDeps(m.Conflicts)},
		{"provides", renderProvides(c.Provides), renderProvides(m.Provides)},
		{"replaces", renderReplaces(c.Replaces), renderReplaces(m.Replaces)},
	} {
		if !slices.Equal(f.index, f.real) {
			return fmt.Errorf("%s: %s in the manifest is %v, but the index entry that "+
				"selected it declared %v", label, f.field, f.real, f.index)
		}
	}
	if c.DefaultRoot != m.DefaultRoot {
		return fmt.Errorf("%s: default_root in the manifest is %q, but the index entry "+
			"declared %q", label, m.DefaultRoot, c.DefaultRoot)
	}
	// A candidate with no advertised installed size came from a path that
	// does not carry one; only a stated disagreement is a mismatch.
	if c.SizeInstalled != 0 && c.SizeInstalled != m.SizeInstalled {
		return fmt.Errorf("%s: size_installed in the manifest is %d, but the index entry "+
			"declared %d", label, m.SizeInstalled, c.SizeInstalled)
	}
	return nil
}

// The render helpers reduce each relation set to a canonical []string, so
// the comparison is insensitive to a nil slice standing in for an empty
// one and does not depend on reflect reaching inside version.Constraint.
// Both sides are already in the canonical name order the manifest
// encoder imposes.

func renderDeps(in []manifest.Dependency) []string {
	out := make([]string, 0, len(in))
	for _, d := range in {
		out = append(out, fmt.Sprintf("%s|%s|%s", d.Name, d.Constraint, d.Root))
	}
	return out
}

func renderProvides(in []manifest.Provides) []string {
	out := make([]string, 0, len(in))
	for _, p := range in {
		v := ""
		if p.Version != nil {
			v = p.Version.String()
		}
		out = append(out, p.Name+"|"+v)
	}
	return out
}

func renderReplaces(in []manifest.Replaces) []string {
	out := make([]string, 0, len(in))
	for _, r := range in {
		out = append(out, r.Name+"|"+r.Constraint.String())
	}
	return out
}
