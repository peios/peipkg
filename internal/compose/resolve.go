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

// SourceScan is the verified candidate universe of a manifest's
// declared sources: every repository's trust-verified index entries and
// every local pool file's manifest, gathered once by ScanSources. It is
// immutable, holds pure data — no open handles, no cache directory —
// and serves any number of Resolve calls whose manifests declare the
// same sources. The scan records no content hashes: those are computed
// per lock, for the packages that lock chooses.
type SourceScan struct {
	// digest is sourcesDigest of the scanned manifest; a reusing
	// manifest must match it.
	digest string
	// archive records whether the repositories' archive indexes were
	// fetched — they are, when the scanning manifest's constraints may
	// need historical versions.
	archive    bool
	candidates []resolver.Candidate
}

// ScanSources gathers the candidate universe of m's declared sources.
// This is where repository trust is established: descriptor and index
// signatures are verified here. Local pool files join on their manifest
// alone (see localCandidates).
//
// A scan is a snapshot: sources changing after it are not seen, which
// is exactly what a multi-lock build wants — every lock resolves
// against one universe.
func ScanSources(ctx context.Context, m Manifest, fetcher repository.Fetcher,
	warnings io.Writer) (*SourceScan, error) {

	if warnings == nil {
		warnings = io.Discard
	}

	// A throwaway database and index cache drive the repository client
	// through the trust ceremony. None of it reaches the built root: the
	// root's repository state is bootstrapped on its first refresh.
	scratch, err := os.MkdirTemp("", "peipkg-compose-resolve-")
	if err != nil {
		return nil, fmt.Errorf("peipkg/compose: creating scratch directory: %w", err)
	}
	defer os.RemoveAll(scratch)

	store, err := db.Open(ctx, filepath.Join(scratch, "db.sqlite"))
	if err != nil {
		return nil, err
	}
	defer store.Close()
	client := repository.NewClient(fetcher, store, filepath.Join(scratch, "cache"))

	needArchive := manifestNeedsArchive(m.Packages)
	candidates, err := repositoryCandidates(ctx, client, m.Repositories, needArchive, warnings)
	if err != nil {
		return nil, err
	}
	locals, err := localCandidates(m.LocalPackages, localPackageBaseDir(m))
	if err != nil {
		return nil, err
	}
	return &SourceScan{
		digest:     sourcesDigest(m),
		archive:    needArchive,
		candidates: append(candidates, locals...),
	}, nil
}

// Resolve turns a manifest into a lock: it scans the manifest's sources
// (see ScanSources) and resolves the requested packages and their
// dependencies into one closure.
//
// The content hashes Resolve records in the lock carry the scan's
// verified trust forward. A build from the lock then needs only to
// match those hashes.
//
// fetcher retrieves repository documents — the production HTTP fetcher,
// or a test double. manifestName is recorded in the lock as provenance.
// warnings receives non-fatal notices and may be nil.
func Resolve(ctx context.Context, m Manifest, manifestName string,
	fetcher repository.Fetcher, warnings io.Writer) (Lock, error) {
	return ResolveWithSources(ctx, m, manifestName, fetcher, warnings, nil)
}

// ResolveWithSources is Resolve against an existing source scan; a nil
// scan means scan m's own sources. A non-nil scan must have been taken
// from a manifest declaring exactly m's sources, and must cover the
// archive indexes if m's constraints can need historical versions —
// reuse that could resolve differently than scanning fresh is refused,
// not absorbed.
func ResolveWithSources(ctx context.Context, m Manifest, manifestName string,
	fetcher repository.Fetcher, warnings io.Writer, scan *SourceScan) (Lock, error) {

	if warnings == nil {
		warnings = io.Discard
	}

	if scan == nil {
		var err error
		if scan, err = ScanSources(ctx, m, fetcher, warnings); err != nil {
			return Lock{}, err
		}
	} else {
		if scan.digest != sourcesDigest(m) {
			return Lock{}, fmt.Errorf("peipkg/compose: the manifest declares different package " +
				"sources than the scan was taken from; scan this manifest's own sources")
		}
		if manifestNeedsArchive(m.Packages) && !scan.archive {
			return Lock{}, fmt.Errorf("peipkg/compose: a manifest constraint may need historical " +
				"versions but the scan did not fetch the archive indexes; scan from this manifest")
		}
	}

	// A manifest version constraint or repository pin filters that
	// package's candidates; the resolver then picks the newest of what
	// survives. Dependencies are never filtered this way.
	candidates, err := applyManifestPins(scan.candidates, m.Packages)
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
	// A local candidate joined the set on its manifest alone; the chosen
	// ones are verified and hashed now, so the lock keeps its guarantee:
	// every entry names format-valid bytes by content hash. The same file
	// may be chosen into more than one root — one verification serves both
	// entries.
	hashed := map[string]string{}
	for i := range lock.Packages {
		lp := &lock.Packages[i]
		if lp.Source != LocalSource {
			continue
		}
		h, ok := hashed[lp.URL]
		if !ok {
			if h, err = verifyLocalPackage(lp.URL, lp.Name, lp.Version, lp.Architecture); err != nil {
				return Lock{}, err
			}
			hashed[lp.URL] = h
		}
		lp.Hash = h
	}
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

// localCandidate reads one local .peipkg's manifest — the archive's
// first entry, so candidacy costs kilobytes however large the file —
// and returns the synthetic resolver candidate for it. The archive is
// not verified or hashed here: that work is done at lock time for the
// packages the resolver chooses (see verifyLocalPackage), which is what
// keeps a large pool cheap to resolve against. An empty Repo marks the
// candidate as local; URL carries the absolute file path; priority 0
// lets an explicit local file outrank any repository version; Hash is
// filled when the package is chosen.
func localCandidate(abs string) (resolver.Candidate, error) {
	f, err := os.Open(abs)
	if err != nil {
		return resolver.Candidate{}, fmt.Errorf("peipkg/compose: reading local package: %w", err)
	}
	defer f.Close()
	m, err := archive.ReadManifest(f)
	if err != nil {
		return resolver.Candidate{}, fmt.Errorf("peipkg/compose: local package %s: %w", abs, err)
	}
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
		SizeInstalled: m.SizeInstalled,
	}, nil
}

// verifyLocalPackage format-verifies a chosen local .peipkg and returns
// the content hash the lock records for it. The identity check mirrors
// fetchOne's: the archive's manifest must agree with the candidate the
// resolver chose, or the file changed between the candidate scan and
// now.
func verifyLocalPackage(abs, name, ver, arch string) (string, error) {
	raw, err := os.ReadFile(abs)
	if err != nil {
		return "", fmt.Errorf("peipkg/compose: reading local package %s: %w", abs, err)
	}
	pkg, err := archive.VerifyFormat(bytes.NewReader(raw))
	if err != nil {
		return "", fmt.Errorf("peipkg/compose: local package %s: %w", abs, err)
	}
	m := pkg.Manifest
	if m.Name != name || m.Version.String() != ver || m.Architecture != arch {
		return "", fmt.Errorf("peipkg/compose: local package %s carries %s %s %s, the resolver "+
			"chose %s %s %s (did the file change during resolution?)",
			abs, m.Name, m.Version, m.Architecture, name, ver, arch)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
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
