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

	candidates, err := repositoryCandidates(ctx, client, m.Repositories,
		manifestNeedsArchive(m.Packages), warnings)
	if err != nil {
		return Lock{}, err
	}
	locals, err := localCandidates(m.LocalPackages, localPackageBaseDir(m))
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

	// Each [[package]] is evaluated like its own `peipkg install` (with an
	// optional --root), so requests may target different roots; the
	// multi-root resolver routes each closure and any cross-root `IN`
	// dependencies. A fresh build has no installed set in any root.
	refToPath := m.rootRefs()
	reqs := make([]resolver.Request, len(m.Packages))
	for i, p := range m.Packages {
		rootKey, err := packageRootKey(p, candidates, refToPath)
		if err != nil {
			return Lock{}, err
		}
		reqs[i] = resolver.Request{Kind: resolver.Install, Name: p.Name, Root: rootKey}
	}
	plan, err := resolver.ResolveMultiRoot(reqs, map[string][]resolver.Installed{}, candidates,
		refToPath, resolver.Options{PrimaryArch: m.Arch})
	if err != nil {
		return Lock{}, fmt.Errorf("peipkg/compose: resolution failed: %w", err)
	}
	// compose runs unattended, so an elevated action cannot be authorised
	// at build time; it is surfaced for the operator who reviews the lock.
	for _, a := range plan.Authorizations {
		fmt.Fprintf(warnings, "peipkg-compose: warning: the plan contains an elevated action — %s\n",
			a.Detail)
	}
	// A goal satisfied through `provides` put a package in the root under a
	// name the manifest never mentions. The lock records which one, but the
	// substitution is said out loud rather than left to a lock diff.
	for _, n := range plan.Notices {
		fmt.Fprintf(warnings, "peipkg-compose: note: %s\n", n.Detail)
	}

	lock := Lock{
		Arch: m.Arch, SourceDate: m.SourceDate,
		Manifest: manifestName, ManifestDigest: manifestDigest(m),
	}
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
			Root:         op.Root,
		})
	}
	sort.Slice(lock.Packages, func(i, j int) bool {
		if lock.Packages[i].Root != lock.Packages[j].Root {
			return lock.Packages[i].Root < lock.Packages[j].Root
		}
		return lock.Packages[i].Name < lock.Packages[j].Name
	})
	return lock, nil
}

// packageRootKey resolves the root a top-level [[package]] is installed
// into, as a path relative to the output root ("" = the anchor). It
// mirrors `peipkg install`: an explicit Root wins (like --root), else the
// package's own default_root, else the anchor.
func packageRootKey(p PackageRequest, candidates []resolver.Candidate,
	refToPath map[string]string) (string, error) {

	if p.Root != "" {
		// The manifest decode already checked Root names a declared [[root]].
		return refToPath[p.Root], nil
	}
	switch dr := candidateDefaultRoot(p.Name, candidates); dr {
	case "":
		return "", nil // no preference → the anchor (output) root
	default:
		path, ok := refToPath[dr]
		if !ok {
			return "", fmt.Errorf("peipkg/compose: package %q has default_root %q, which the "+
				"manifest declares no [[root]] for", p.Name, dr)
		}
		return path, nil
	}
}

// candidateDefaultRoot returns the default_root a package declares, read
// from its candidate (the index entry carries it, §6.2.4). default_root is
// a per-package fact, identical across versions, so the first match wins.
func candidateDefaultRoot(name string, candidates []resolver.Candidate) string {
	for _, c := range candidates {
		if c.Name == name {
			return c.DefaultRoot
		}
	}
	return ""
}

// repositoryCandidates adds each manifest repository through the trust
// ceremony and returns the resolver candidates of its active and
// archive indexes. A repository that cannot be added is fatal — a build
// must resolve against every source it declares — but a repository that
// serves no archive index is not.
func repositoryCandidates(ctx context.Context, client *repository.Client,
	repos []config.RepoConfig, needArchive bool, warnings io.Writer) ([]resolver.Candidate, error) {

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

		if !needArchive {
			continue
		}
		// The archive index carries historical versions. It is fetched
		// only when a manifest constraint can need non-current metadata.
		// A repository need not serve it.
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

func manifestNeedsArchive(reqs []PackageRequest) bool {
	for _, r := range reqs {
		if r.Constraint.MayNeedHistoricalVersions() {
			return true
		}
	}
	return false
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
			Name:           e.Name,
			Version:        e.Version,
			Architecture:   e.Architecture,
			DefaultRoot:    e.DefaultRoot,
			Dependencies:   e.Dependencies,
			Conflicts:      e.Conflicts,
			Provides:       e.Provides,
			Replaces:       e.Replaces,
			Repo:           cfg.Name,
			RepoPriority:   cfg.Priority,
			URL:            abs,
			Hash:           e.Hash,
			SizeCompressed: e.SizeCompressed,
			SizeInstalled:  e.SizeInstalled,
		})
	}
	return out
}

// localCandidates reads the manifest's local .peipkg files and returns a
// resolver candidate for each. A glob matching nothing is not an error;
// a file that fails format verification is.
func localCandidates(patterns []string, baseDir string) ([]resolver.Candidate, error) {
	var candidates []resolver.Candidate
	seen := map[string]bool{}
	for _, pattern := range patterns {
		resolved := pattern
		if !filepath.IsAbs(resolved) {
			resolved = filepath.Join(baseDir, resolved)
		}
		matches, err := filepath.Glob(resolved)
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
		DefaultRoot:   m.DefaultRoot,
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

	// A manifest may request the same package name in more than one root
	// with different constraints — package identity in the manifest layer
	// is (root, name), not name. Collecting the pins into a single
	// name-keyed entry let the last one win, so *both* roots were filtered
	// by the last-declared constraint and repository pin.
	//
	// Keying by (root, name) does not help here: this filter runs over one
	// shared, root-agnostic candidate list, so a candidate cannot be
	// attributed to a root. A candidate therefore survives if it satisfies
	// **any** pin on its name, and the per-root constraint is left to the
	// resolver, which does know the roots. The filter keeps its purpose —
	// reporting an unsatisfiable pin here, more clearly than the
	// resolver's later "no candidate" — without over-filtering.
	pins := make(map[string][]PackageRequest, len(reqs))
	for _, r := range reqs {
		pins[r.Name] = append(pins[r.Name], r)
	}
	// satisfied[i] tracks whether reqs[i] has at least one live candidate.
	satisfied := make([]bool, len(reqs))
	pinIndex := make(map[string][]int, len(reqs))
	for i, r := range reqs {
		pinIndex[r.Name] = append(pinIndex[r.Name], i)
	}

	existed := map[string]bool{}
	out := make([]resolver.Candidate, 0, len(candidates))
	for _, c := range candidates {
		idxs, pinned := pinIndex[c.Name]
		if !pinned {
			out = append(out, c)
			continue
		}
		existed[c.Name] = true
		var keep bool
		for _, i := range idxs {
			if matchesPin(reqs[i], c) {
				satisfied[i] = true
				keep = true
			}
		}
		if keep {
			out = append(out, c)
		}
	}
	for i, r := range reqs {
		if satisfied[i] || !existed[r.Name] {
			continue
		}
		detail := "version " + r.Constraint.String()
		if r.Repository != "" {
			detail += ", repository " + r.Repository
		}
		if r.Root != "" {
			detail += ", root " + r.Root
		}
		return nil, fmt.Errorf("peipkg/compose: package %q: no available version satisfies the "+
			"manifest pin (%s)", r.Name, detail)
	}
	return out, nil
}

// matchesPin reports whether a candidate satisfies one manifest pin.
func matchesPin(pin PackageRequest, c resolver.Candidate) bool {
	if !pin.Constraint.Matches(c.Version) {
		return false
	}
	return pin.Repository == "" || c.Repo == pin.Repository
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
