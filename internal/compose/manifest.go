// Package compose implements peipkg-compose: building a complete,
// package-owned peipkg root from a declarative manifest.
//
// A build moves through three stages — resolve the manifest's requested
// packages into a concrete closure (the lock); fetch and verify every
// package in that closure; assemble them into a fresh root with a
// seeded package database. The manifest is the operator's intent; the
// lock is the resolved closure that makes a build reproducible. See
// cmd/peipkg-compose/DESIGN.md.
package compose

import (
	"fmt"
	"os"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/peios/peipkg/internal/config"
	"github.com/peios/peipkg/internal/version"
)

// manifestSchema is the manifest schema version this build understands.
// A manifest declaring any other value is rejected.
const manifestSchema = 1

// defaultPriority is the resolution priority of a manifest repository
// that omits the field — the same default the .repo loader applies.
const defaultPriority = 50

// Manifest is a decoded, validated peipkg-compose manifest: the
// declarative description of a root to build. Obtain one through
// [DecodeManifest] or [LoadManifest].
type Manifest struct {
	// Arch is the architecture of the root being built. It becomes the
	// resolver's primary architecture and the database's primary_arch.
	Arch string
	// SourceDate fixes every build-stamped time — a package's
	// installed_at, the synthetic transaction's timestamps — so a build
	// is reproducible. It is the manifest's SOURCE_DATE_EPOCH.
	SourceDate time.Time
	// Repositories are the package sources. They drive metadata fetch
	// and verification during the build, and are written into the root
	// as /conf/peipkg/<name>.repo.
	Repositories []config.RepoConfig
	// LocalPackages are paths or globs of .peipkg files on the build
	// host that join the resolver's candidate set — the bootstrap path
	// for packages not yet served by any repository.
	LocalPackages []string
	// Packages are the top-level package requests: what the operator
	// asked for, by name and an optional version constraint.
	Packages []PackageRequest
}

// PackageRequest is one top-level [[package]] entry of a manifest.
type PackageRequest struct {
	// Name is the package to install.
	Name string
	// Constraint restricts which versions may satisfy the request. The
	// zero Constraint — written as `*` or an omitted version — accepts
	// any version, leaving the resolver to choose the newest.
	Constraint version.Constraint
	// Repository, when set, pins the request to a single source
	// repository; empty lets any configured repository satisfy it.
	Repository string
}

// wireManifest mirrors the manifest's TOML shape for decoding. A
// pointer field is one whose absence must be told apart from a present
// zero value, so a missing required key is reported precisely.
type wireManifest struct {
	Schema        *int             `toml:"schema"`
	Arch          *string          `toml:"arch"`
	SourceDate    *string          `toml:"source_date"`
	Repositories  []wireRepository `toml:"repository"`
	LocalPackages []string         `toml:"local_packages"`
	Packages      []wirePackage    `toml:"package"`
}

type wireRepository struct {
	Name                   *string  `toml:"name"`
	BaseURL                *string  `toml:"base_url"`
	Priority               *int     `toml:"priority"`
	SignaturePolicy        string   `toml:"signature_policy"`
	TrustAnchors           []string `toml:"trust_anchors"`
	AllowInsecureTransport bool     `toml:"allow_insecure_transport"`
	MinIndexVersion        *int64   `toml:"min_index_version"`
}

type wirePackage struct {
	Name       *string `toml:"name"`
	Version    string  `toml:"version"`
	Repository string  `toml:"repository"`
}

// LoadManifest reads and decodes a manifest from a file.
func LoadManifest(path string) (Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("peipkg/compose: reading manifest: %w", err)
	}
	return DecodeManifest(data)
}

// DecodeManifest parses and validates a manifest from its raw TOML
// bytes. An unknown key — anywhere in the document — is an error, so a
// typo is reported rather than silently ignored.
func DecodeManifest(data []byte) (Manifest, error) {
	var w wireManifest
	md, err := toml.Decode(string(data), &w)
	if err != nil {
		return Manifest{}, fmt.Errorf("peipkg/compose: invalid manifest TOML: %w", err)
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		return Manifest{}, fmt.Errorf("peipkg/compose: manifest has the unknown key %q",
			undecoded[0].String())
	}

	switch {
	case w.Schema == nil:
		return Manifest{}, missingKey("schema")
	case w.Arch == nil:
		return Manifest{}, missingKey("arch")
	case w.SourceDate == nil:
		return Manifest{}, missingKey("source_date")
	}
	if *w.Schema != manifestSchema {
		return Manifest{}, fmt.Errorf("peipkg/compose: manifest schema is %d, want %d",
			*w.Schema, manifestSchema)
	}
	if *w.Arch == "" {
		return Manifest{}, fmt.Errorf("peipkg/compose: manifest arch must not be empty")
	}
	sourceDate, err := time.Parse(time.RFC3339, *w.SourceDate)
	if err != nil {
		return Manifest{}, fmt.Errorf("peipkg/compose: manifest source_date %q is not an "+
			"RFC 3339 timestamp: %w", *w.SourceDate, err)
	}

	repos, err := decodeRepositories(w.Repositories)
	if err != nil {
		return Manifest{}, err
	}
	pkgs, err := decodePackageRequests(w.Packages, repos)
	if err != nil {
		return Manifest{}, err
	}
	if len(pkgs) == 0 {
		return Manifest{}, fmt.Errorf("peipkg/compose: manifest requests no packages")
	}
	return Manifest{
		Arch:          *w.Arch,
		SourceDate:    sourceDate,
		Repositories:  repos,
		LocalPackages: w.LocalPackages,
		Packages:      pkgs,
	}, nil
}

// decodeRepositories converts the manifest's [[repository]] entries to
// repository configurations, applying the .repo-file defaults. The
// configurations are validated authoritatively later — when the trust
// ceremony runs and when they are written into the root.
func decodeRepositories(wires []wireRepository) ([]config.RepoConfig, error) {
	repos := make([]config.RepoConfig, 0, len(wires))
	seen := map[string]bool{}
	for i, w := range wires {
		if w.Name == nil || *w.Name == "" {
			return nil, fmt.Errorf("peipkg/compose: repository %d is missing %q", i, "name")
		}
		if w.BaseURL == nil || *w.BaseURL == "" {
			return nil, fmt.Errorf("peipkg/compose: repository %q is missing %q",
				*w.Name, "base_url")
		}
		if seen[*w.Name] {
			return nil, fmt.Errorf("peipkg/compose: repository %q is declared more than once",
				*w.Name)
		}
		seen[*w.Name] = true

		cfg := config.RepoConfig{
			Name:                   *w.Name,
			BaseURL:                *w.BaseURL,
			Priority:               defaultPriority,
			SignaturePolicy:        config.PolicyRequired,
			TrustAnchors:           w.TrustAnchors,
			AllowInsecureTransport: w.AllowInsecureTransport,
		}
		if w.Priority != nil {
			cfg.Priority = *w.Priority
		}
		if w.SignaturePolicy != "" {
			cfg.SignaturePolicy = config.SignaturePolicy(w.SignaturePolicy)
		}
		if w.MinIndexVersion != nil {
			cfg.MinIndexVersion = *w.MinIndexVersion
		}
		repos = append(repos, cfg)
	}
	return repos, nil
}

// decodePackageRequests converts the manifest's [[package]] entries to
// package requests, parsing each version constraint and checking that a
// pinned source repository is one the manifest declares.
func decodePackageRequests(wires []wirePackage, repos []config.RepoConfig) ([]PackageRequest, error) {
	reqs := make([]PackageRequest, 0, len(wires))
	seen := map[string]bool{}
	for i, w := range wires {
		if w.Name == nil || *w.Name == "" {
			return nil, fmt.Errorf("peipkg/compose: package %d is missing %q", i, "name")
		}
		if seen[*w.Name] {
			return nil, fmt.Errorf("peipkg/compose: package %q is requested more than once", *w.Name)
		}
		seen[*w.Name] = true

		req := PackageRequest{Name: *w.Name, Repository: w.Repository}
		// An omitted version, or the explicit `*`, is the zero
		// constraint — any version, resolver's choice.
		if w.Version != "" && w.Version != "*" {
			c, err := version.ParseConstraint(w.Version)
			if err != nil {
				return nil, fmt.Errorf("peipkg/compose: package %q: %w", *w.Name, err)
			}
			req.Constraint = c
		}
		if w.Repository != "" && !repoNamed(repos, w.Repository) {
			return nil, fmt.Errorf("peipkg/compose: package %q names repository %q, which the "+
				"manifest does not declare", *w.Name, w.Repository)
		}
		reqs = append(reqs, req)
	}
	return reqs, nil
}

// repoNamed reports whether repos contains a repository of the name.
func repoNamed(repos []config.RepoConfig, name string) bool {
	for _, r := range repos {
		if r.Name == name {
			return true
		}
	}
	return false
}

// missingKey builds the error for an absent required key.
func missingKey(key string) error {
	return fmt.Errorf("peipkg/compose: missing required key %q", key)
}

// ptr returns a pointer to v — a small helper for building the
// pointer-typed wire structs when encoding.
func ptr[T any](v T) *T { return &v }
