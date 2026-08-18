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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/peios/peipkg/internal/config"
	"github.com/peios/peipkg/internal/manifest"
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
	// as /lcl/conf/peipkg/<name>.repo.
	Repositories []config.RepoConfig
	// LocalPackages are paths or globs of .peipkg files on the build
	// host that join the resolver's candidate set — the bootstrap path
	// for packages not yet served by any repository.
	LocalPackages []string
	// LocalPackageBaseDir is the directory relative local package
	// patterns are resolved against. LoadManifest sets it to the
	// manifest's directory; DecodeManifest callers that leave it empty
	// get the current working directory.
	LocalPackageBaseDir string
	// Roots are the named roots this image is composed of, beyond the
	// output root itself (DESIGN-named-roots.md). Each is registered in
	// the built image's anchor database, and a package may be placed into
	// one. Empty for an ordinary single-root image.
	Roots []Root
	// Packages are the top-level package requests: what the operator
	// asked for, by name and an optional version constraint.
	Packages []PackageRequest
}

// Root is one named root of a composed image: a name and a path relative
// to the output root. Each [[root]] becomes a named_root registry entry
// in the built image's anchor, so the booted system resolves `--root
// <name>` and cascades into it.
type Root struct {
	Name string
	Path string
}

// rootRefs maps each declared root name to its path relative to the
// output root — the reference map the multi-root resolver routes a
// dependency's `root` placement through.
func (m Manifest) rootRefs() map[string]string {
	refs := make(map[string]string, len(m.Roots))
	for _, r := range m.Roots {
		refs[r.Name] = r.Path
	}
	return refs
}

// PackageRequest is one top-level [[package]] entry of a manifest. Each is
// evaluated exactly as `peipkg install <Name> [--root <Root>]` would be:
// Root acts as an explicit --root, and a package that declares neither
// Root nor a default_root lands in the output (anchor) root.
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
	// Root names the root this package is installed into, like a `--root`
	// on a `peipkg install`. It must name a declared [[root]]. Empty means
	// standard placement: the package's own default_root, else the anchor.
	Root string
}

// wireManifest mirrors the manifest's TOML shape for decoding. A
// pointer field is one whose absence must be told apart from a present
// zero value, so a missing required key is reported precisely.
type wireManifest struct {
	Schema        *int             `toml:"schema"`
	Arch          *string          `toml:"arch"`
	SourceDate    *string          `toml:"source_date"`
	Repositories  []wireRepository `toml:"repository"`
	Roots         []wireRoot       `toml:"root"`
	LocalPackages []string         `toml:"local_packages"`
	Packages      []wirePackage    `toml:"package"`
}

type wireRoot struct {
	Name *string `toml:"name"`
	Path *string `toml:"path"`
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
	Root       string  `toml:"root"`
}

// LoadManifest reads and decodes a manifest from a file.
func LoadManifest(path string) (Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("peipkg/compose: reading manifest: %w", err)
	}
	m, err := DecodeManifest(data)
	if err != nil {
		return Manifest{}, err
	}
	base, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return Manifest{}, fmt.Errorf("peipkg/compose: resolving manifest directory: %w", err)
	}
	m.LocalPackageBaseDir = base
	return m, nil
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
	roots, err := decodeRoots(w.Roots)
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
	// A package's explicit root must name a declared [[root]] — the same
	// "an unknown root is a hard error" stance the consumer takes.
	declared := map[string]bool{}
	for _, r := range roots {
		declared[r.Name] = true
	}
	for _, p := range pkgs {
		if p.Root != "" && !declared[p.Root] {
			return Manifest{}, fmt.Errorf("peipkg/compose: package %q targets root %q, which no "+
				"[[root]] declares", p.Name, p.Root)
		}
	}
	base, err := os.Getwd()
	if err != nil {
		return Manifest{}, fmt.Errorf("peipkg/compose: resolving current directory: %w", err)
	}
	return Manifest{
		Arch:                *w.Arch,
		SourceDate:          sourceDate,
		Repositories:        repos,
		Roots:               roots,
		LocalPackages:       w.LocalPackages,
		LocalPackageBaseDir: base,
		Packages:            pkgs,
	}, nil
}

// decodeRoots converts the manifest's [[root]] entries to named roots,
// validating each name against the §3.3.6 grammar and each path as a
// clean, relative, non-escaping path under the output root. Names are
// flat (a nested root — a root with its own registry — is not declared
// here); a duplicate name is an error.
func decodeRoots(wires []wireRoot) ([]Root, error) {
	roots := make([]Root, 0, len(wires))
	seen := map[string]bool{}
	for i, w := range wires {
		if w.Name == nil || *w.Name == "" {
			return nil, fmt.Errorf("peipkg/compose: root %d is missing %q", i, "name")
		}
		name := *w.Name
		if w.Path == nil || *w.Path == "" {
			return nil, fmt.Errorf("peipkg/compose: root %q is missing %q", name, "path")
		}
		if err := manifest.ValidateRootRef(name); err != nil {
			return nil, fmt.Errorf("peipkg/compose: root name %w", err)
		}
		if strings.Contains(name, ".") {
			return nil, fmt.Errorf("peipkg/compose: root name %q must be a single segment; "+
				"nested roots are not declared with [[root]]", name)
		}
		if seen[name] {
			return nil, fmt.Errorf("peipkg/compose: root %q is declared more than once", name)
		}
		seen[name] = true
		clean, err := validateRootRelPath(*w.Path)
		if err != nil {
			return nil, fmt.Errorf("peipkg/compose: root %q: %w", name, err)
		}
		roots = append(roots, Root{Name: name, Path: clean})
	}
	return roots, nil
}

// validateRootRelPath checks a root path is relative to the output root,
// clean, and does not escape it. It returns the cleaned path.
func validateRootRelPath(p string) (string, error) {
	if filepath.IsAbs(p) {
		return "", fmt.Errorf("path %q must be relative to the output root", p)
	}
	clean := filepath.Clean(p)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q escapes the output root", p)
	}
	if clean == "." {
		return "", fmt.Errorf("path %q is the output root itself", p)
	}
	return clean, nil
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
		// Identity is (name, root): the same package may be requested in
		// more than one root (a base library composed into both / and the
		// initramfs), so a request is unique per (root, name).
		key := w.Root + "\x00" + *w.Name
		if seen[key] {
			return nil, fmt.Errorf("peipkg/compose: package %q is requested more than once "+
				"in root %q", *w.Name, w.Root)
		}
		seen[key] = true

		req := PackageRequest{Name: *w.Name, Repository: w.Repository, Root: w.Root}
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

// manifestDigest returns a stable digest of the manifest fields that
// influence resolution. It deliberately excludes the manifest filename,
// which is lock provenance rather than build intent.
func manifestDigest(m Manifest) string {
	type repoDigest struct {
		Name                   string   `json:"name"`
		BaseURL                string   `json:"base_url"`
		Priority               int      `json:"priority"`
		SignaturePolicy        string   `json:"signature_policy"`
		TrustAnchors           []string `json:"trust_anchors"`
		AllowInsecureTransport bool     `json:"allow_insecure_transport"`
		MinIndexVersion        int64    `json:"min_index_version"`
	}
	type packageDigest struct {
		Name       string `json:"name"`
		Constraint string `json:"constraint"`
		Repository string `json:"repository"`
	}
	type digest struct {
		Schema              int             `json:"schema"`
		Arch                string          `json:"arch"`
		SourceDate          string          `json:"source_date"`
		Repositories        []repoDigest    `json:"repositories"`
		LocalPackages       []string        `json:"local_packages"`
		LocalPackageBaseDir string          `json:"local_package_base_dir"`
		Packages            []packageDigest `json:"packages"`
	}

	d := digest{
		Schema:              manifestSchema,
		Arch:                m.Arch,
		SourceDate:          m.SourceDate.UTC().Format(time.RFC3339),
		LocalPackages:       append([]string(nil), m.LocalPackages...),
		LocalPackageBaseDir: localPackageBaseDir(m),
	}
	for _, r := range m.Repositories {
		d.Repositories = append(d.Repositories, repoDigest{
			Name:                   r.Name,
			BaseURL:                r.BaseURL,
			Priority:               r.Priority,
			SignaturePolicy:        string(r.SignaturePolicy),
			TrustAnchors:           append([]string(nil), r.TrustAnchors...),
			AllowInsecureTransport: r.AllowInsecureTransport,
			MinIndexVersion:        r.MinIndexVersion,
		})
	}
	for _, p := range m.Packages {
		d.Packages = append(d.Packages, packageDigest{
			Name: p.Name, Constraint: p.Constraint.String(), Repository: p.Repository,
		})
	}
	raw, _ := json.Marshal(d) // d contains only JSON scalar and slice fields.
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func localPackageBaseDir(m Manifest) string {
	if m.LocalPackageBaseDir != "" {
		return m.LocalPackageBaseDir
	}
	if cwd, err := os.Getwd(); err == nil {
		return cwd
	}
	return "."
}
