package compose

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/peios/peipkg/internal/archive"
	"github.com/peios/peipkg/internal/config"
	"github.com/peios/peipkg/internal/db"
	"github.com/peios/peipkg/internal/repository"
	"github.com/peios/peipkg/internal/resolver"
)

// Resolve turns a manifest into a lock. It fetches and verifies every
// configured repository's signed metadata, joins the local packages to
// the candidate set, resolves the requested packages and their
// dependencies into one closure, and returns it as a Lock.
//
// Resolution is where repository trust is established: descriptor and
// index signatures are verified here, and the content hashes Resolve
// records in the lock are the carried-forward result. A build from the
// lock then needs only to match those hashes.
//
// fetcher retrieves repository documents — the production HTTP fetcher,
// or a test double. manifestName is recorded in the lock as provenance.
// warnings receives non-fatal notices and may be nil.
func Resolve(ctx context.Context, m Manifest, manifestName string,
	fetcher repository.Fetcher, warnings io.Writer) (Lock, error) {

	if warnings == nil {
		warnings = io.Discard
	}

	// A throwaway database and index cache drive the repository client
	// through the trust ceremony. None of it reaches the built root: the
	// root's repository state is bootstrapped on its first refresh.
	scratch, err := os.MkdirTemp("", "peipkg-compose-resolve-")
	if err != nil {
		return Lock{}, fmt.Errorf("peipkg/compose: creating scratch directory: %w", err)
	}
	defer os.RemoveAll(scratch)

	store, err := db.Open(ctx, filepath.Join(scratch, "db.sqlite"))
	if err != nil {
		return Lock{}, err
	}
	defer store.Close()
	client := repository.NewClient(fetcher, store, filepath.Join(scratch, "cache"))

	candidates, err := repositoryCandidates(ctx, client, m.Repositories, warnings)
	if err != nil {
		return Lock{}, err
	}
	locals, err := localCandidates(m.LocalPackages)
	if err != nil {
		return Lock{}, err
	}
	candidates = append(candidates, locals...)

	// A manifest version constraint or repository pin filters that
	// package's candidates; the resolver then picks the newest of what
	// survives. Dependencies are never filtered this way.
	candidates, err = applyManifestPins(candidates, m.Packages)
	if err != nil {
		return Lock{}, err
	}

	reqs := make([]resolver.Request, len(m.Packages))
	for i, p := range m.Packages {
		reqs[i] = resolver.Request{Kind: resolver.Install, Name: p.Name}
	}
	plan, err := resolver.Resolve(reqs, nil, candidates, resolver.Options{PrimaryArch: m.Arch})
	if err != nil {
		return Lock{}, fmt.Errorf("peipkg/compose: resolution failed: %w", err)
	}
	// compose runs unattended, so an elevated action cannot be authorised
	// at build time; it is surfaced for the operator who reviews the lock.
	for _, a := range plan.Authorizations {
		fmt.Fprintf(warnings, "peipkg-compose: warning: the plan contains an elevated action — %s\n",
			a.Detail)
	}

	lock := Lock{Arch: m.Arch, SourceDate: m.SourceDate, Manifest: manifestName}
	for _, op := range plan.Operations {
		if op.Candidate == nil {
			return Lock{}, fmt.Errorf("peipkg/compose: resolved operation for %q carries no "+
				"candidate", op.Name)
		}
		source := op.Candidate.Repo
		if source == "" {
			source = LocalSource
		}
		lock.Packages = append(lock.Packages, LockedPackage{
			Name:         op.Name,
			Version:      op.ToVersion.String(),
			Architecture: op.Candidate.Architecture,
			Source:       source,
			URL:          op.Candidate.URL,
			Hash:         op.Candidate.Hash,
		})
	}
	sort.Slice(lock.Packages, func(i, j int) bool {
		return lock.Packages[i].Name < lock.Packages[j].Name
	})
	return lock, nil
}

// repositoryCandidates adds each manifest repository through the trust
// ceremony and returns the resolver candidates of its active and
// archive indexes. A repository that cannot be added is fatal — a build
// must resolve against every source it declares — but a repository that
// serves no archive index is not.
func repositoryCandidates(ctx context.Context, client *repository.Client,
	repos []config.RepoConfig, warnings io.Writer) ([]resolver.Candidate, error) {

	var candidates []resolver.Candidate
	for _, cfg := range repos {
		if err := client.Add(ctx, cfg); err != nil {
			return nil, fmt.Errorf("peipkg/compose: repository %q: %w", cfg.Name, err)
		}
		active, err := client.ActiveIndex(ctx, cfg.Name)
		if err != nil {
			return nil, fmt.Errorf("peipkg/compose: repository %q: %w", cfg.Name, err)
		}
		candidates = append(candidates, indexCandidates(cfg, active, warnings)...)

		// The archive index carries historical versions, needed only
		// when a manifest pins one. A repository need not serve it.
		archived, err := client.ArchiveIndex(ctx, cfg)
		if err != nil {
			fmt.Fprintf(warnings, "peipkg-compose: warning: archive index of %q unavailable: %v\n",
				cfg.Name, err)
			continue
		}
		candidates = append(candidates, indexCandidates(cfg, archived, warnings)...)
	}
	return candidates, nil
}

// indexCandidates converts a repository index's entries to resolver
// candidates, resolving each entry's package URL to an absolute one so
// the lock is self-contained. An entry with an unresolvable URL is
// dropped with a warning — a malformed entry, not a fatal condition.
func indexCandidates(cfg config.RepoConfig, idx repository.Index,
	warnings io.Writer) []resolver.Candidate {

	out := make([]resolver.Candidate, 0, len(idx.Packages))
	for _, e := range idx.Packages {
		abs, err := resolvePackageURL(cfg.BaseURL, e.URL)
		if err != nil {
			fmt.Fprintf(warnings, "peipkg-compose: warning: repository %q: skipping %s %s: %v\n",
				cfg.Name, e.Name, e.Version, err)
			continue
		}
		out = append(out, resolver.Candidate{
			Name:         e.Name,
			Version:      e.Version,
			Architecture: e.Architecture,
			Dependencies: e.Dependencies,
			Conflicts:    e.Conflicts,
			Provides:     e.Provides,
			Replaces:     e.Replaces,
			Repo:         cfg.Name,
			RepoPriority: cfg.Priority,
			URL:          abs,
			Hash:         e.Hash,
			SizeCompressed: e.SizeCompressed,
			SizeInstalled:  e.SizeInstalled,
		})
	}
	return out
}

// localCandidates reads the manifest's local .peipkg files and returns a
// resolver candidate for each. A glob matching nothing is not an error;
// a file that fails format verification is.
func localCandidates(patterns []string) ([]resolver.Candidate, error) {
	var candidates []resolver.Candidate
	seen := map[string]bool{}
	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return nil, fmt.Errorf("peipkg/compose: local package pattern %q: %w", pattern, err)
		}
		for _, path := range matches {
			abs, err := filepath.Abs(path)
			if err != nil {
				return nil, fmt.Errorf("peipkg/compose: local package %q: %w", path, err)
			}
			if seen[abs] {
				continue
			}
			seen[abs] = true
			cand, err := localCandidate(abs)
			if err != nil {
				return nil, err
			}
			candidates = append(candidates, cand)
		}
	}
	return candidates, nil
}

// localCandidate reads, format-verifies, and hashes one local .peipkg,
// returning the synthetic resolver candidate for it. An empty Repo
// marks it as local; URL carries the absolute file path; priority 0
// lets an explicit local file outrank any repository version.
func localCandidate(abs string) (resolver.Candidate, error) {
	raw, err := os.ReadFile(abs)
	if err != nil {
		return resolver.Candidate{}, fmt.Errorf("peipkg/compose: reading local package: %w", err)
	}
	pkg, err := archive.VerifyFormat(bytes.NewReader(raw))
	if err != nil {
		return resolver.Candidate{}, fmt.Errorf("peipkg/compose: local package %s: %w", abs, err)
	}
	sum := sha256.Sum256(raw)
	m := pkg.Manifest
	return resolver.Candidate{
		Name:          m.Name,
		Version:       m.Version,
		Architecture:  m.Architecture,
		Dependencies:  m.Dependencies,
		Conflicts:     m.Conflicts,
		Provides:      m.Provides,
		Replaces:      m.Replaces,
		Repo:          "",
		RepoPriority:  0,
		URL:           abs,
		Hash:          hex.EncodeToString(sum[:]),
		SizeInstalled: m.SizeInstalled,
	}, nil
}

// applyManifestPins filters the candidate set by the manifest's
// per-package version constraints and repository pins. The filter
// touches only a pinned package's own candidates; dependencies resolve
// freely. A pinned package with candidates of which none satisfy the
// pin is reported as an error here, more clearly than the resolver's
// later "no candidate" would.
func applyManifestPins(candidates []resolver.Candidate, reqs []PackageRequest) (
	[]resolver.Candidate, error) {

	pins := make(map[string]PackageRequest, len(reqs))
	for _, r := range reqs {
		pins[r.Name] = r
	}
	existed := map[string]bool{}
	survived := map[string]bool{}
	out := make([]resolver.Candidate, 0, len(candidates))
	for _, c := range candidates {
		pin, pinned := pins[c.Name]
		if pinned {
			existed[c.Name] = true
			if !pin.Constraint.Matches(c.Version) {
				continue
			}
			if pin.Repository != "" && c.Repo != pin.Repository {
				continue
			}
			survived[c.Name] = true
		}
		out = append(out, c)
	}
	for name := range existed {
		if survived[name] {
			continue
		}
		pin := pins[name]
		detail := "version " + pin.Constraint.String()
		if pin.Repository != "" {
			detail += ", repository " + pin.Repository
		}
		return nil, fmt.Errorf("peipkg/compose: package %q: no available version satisfies the "+
			"manifest pin (%s)", name, detail)
	}
	return out, nil
}

// resolvePackageURL resolves a package URL appearing in a repository
// index against the repository base (§6.4.5): an absolute URL is used
// as is, a /-rooted path is joined to the base, and any other reference
// resolves relative to the base.
func resolvePackageURL(baseURL, ref string) (string, error) {
	u, err := url.Parse(ref)
	if err != nil {
		return "", fmt.Errorf("invalid package URL %q: %w", ref, err)
	}
	if u.IsAbs() {
		return ref, nil
	}
	if strings.HasPrefix(ref, "/") {
		return baseURL + ref, nil
	}
	base, err := url.Parse(baseURL + "/")
	if err != nil {
		return "", fmt.Errorf("invalid repository base URL %q: %w", baseURL, err)
	}
	return base.ResolveReference(u).String(), nil
}
