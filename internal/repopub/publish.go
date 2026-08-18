package repopub

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/peios/peipkg/internal/archive"
	"github.com/peios/peipkg/internal/repository"
	"github.com/peios/peipkg/internal/signature"
	"github.com/peios/peipkg/internal/version"
)

// PublishOptions configures [Publish].
type PublishOptions struct {
	// Key signs the new indexes. It MUST be a key the descriptor lists
	// as active or transitioning (§6.2.1); Publish checks this.
	Key ed25519.PrivateKey
	// Paths names .peipkg files, or directories to scan for them.
	Paths []string
	// GeneratedAt stamps both new indexes.
	GeneratedAt time.Time
	// URLTemplate overrides the state's stored template for entries
	// added by this publish. Empty uses the stored one.
	URLTemplate string
	// AllowUnsigned permits ingesting a package with no inline
	// signature.
	AllowUnsigned bool
	// Rebuild discards the existing archive and reconstructs it from
	// package files on disk.
	Rebuild bool
}

// Result reports what a publish did.
type Result struct {
	IndexVersion int64
	Added        []repository.IndexEntry
	ActiveCount  int
	ArchiveCount int
}

// Publish ingests packages into the state at dir and writes a new
// signed revision of both indexes.
//
// The whole operation is a state transition: read the previous state,
// build the next one entirely in memory, and only then touch the disk.
// Nothing is written until every package has been read, verified and
// found acceptable, so a publish that fails half way through its inputs
// leaves the repository exactly as it was rather than advertising the
// packages it happened to reach first.
func Publish(dir string, opts PublishOptions) (Result, error) {
	st, err := Open(dir)
	if err != nil {
		return Result{}, err
	}
	if opts.GeneratedAt.IsZero() {
		return Result{}, fmt.Errorf("peipkg/repopub: a generation timestamp is required")
	}
	if err := checkSigningKey(st.Descriptor, opts.Key); err != nil {
		return Result{}, err
	}

	template := opts.URLTemplate
	if template == "" {
		template = st.Config.URLTemplate
	}
	if err := validateURLTemplate(template); err != nil {
		return Result{}, err
	}

	// §6.2.3 / §6.3.4: the consumer records ONE index_version floor per
	// repository, not one per index, so the two indexes must advance
	// together. Publishing them at different versions would make
	// whichever is lower look like a rollback the moment a consumer
	// fetched the other first. Taking the max of both and incrementing
	// once is what keeps that invariant true even if a previous publish
	// was interrupted between the two renames.
	next := st.Active.IndexVersion
	if st.Archive.IndexVersion > next {
		next = st.Archive.IndexVersion
	}
	next++

	// The same argument applies to generated_at, which the consumer also
	// floors per repository (§6.2.3): both indexes carry one instant.
	generatedAt := opts.GeneratedAt

	paths, err := resolvePackagePaths(st, opts)
	if err != nil {
		return Result{}, err
	}

	existing := st.Archive.Packages
	if opts.Rebuild {
		// The recovery hatch: the archive on disk is assumed wrong, so
		// it contributes nothing and every entry is rebuilt from the
		// package files themselves. Note what this costs — entries are
		// re-derived from the CURRENT url template, so a rebuild of a
		// repository whose template has changed rewrites historical
		// URLs. That is the right trade for a hatch whose premise is
		// that the recorded state is untrustworthy, but it is a
		// rewrite, not a repair.
		existing = nil
	}

	keys := loadStateKeys(st)
	added := make([]repository.IndexEntry, 0, len(paths))
	staged := make([]stagedPackage, 0, len(paths))
	seen := make(map[string]string, len(existing)+len(paths))
	for _, entry := range existing {
		seen[identityOf(entry)] = "the archive index"
	}

	for _, p := range paths {
		pkg, err := ingest(p, template, keys, opts.AllowUnsigned)
		if err != nil {
			return Result{}, fmt.Errorf("peipkg/repopub: %s: %w", filepath.Base(p), err)
		}
		id := identityOf(pkg.entry)
		// §6.3.1 mandates retention: a published version must stay
		// fetchable forever. Silently overwriting an entry would break
		// that promise invisibly — the index would still list the
		// version while the bytes behind it had changed — so a repeat
		// is refused rather than resolved.
		if where, dup := seen[id]; dup {
			return Result{}, fmt.Errorf(
				"peipkg/repopub: %s is already published (in %s); "+
					"a published version is retained unchanged (§6.3.1), so publish a new revision instead",
				id, where)
		}
		seen[id] = filepath.Base(p)
		added = append(added, pkg.entry)
		staged = append(staged, pkg.staged)
	}

	archiveEntries := append(append([]repository.IndexEntry{}, existing...), added...)
	activeEntries, err := deriveActive(archiveEntries)
	if err != nil {
		return Result{}, err
	}

	index := func(kind repository.IndexKind, entries []repository.IndexEntry) repository.Index {
		return repository.Index{
			RepoName:     st.Descriptor.RepoName,
			Kind:         kind,
			IndexVersion: next,
			GeneratedAt:  generatedAt,
			Packages:     entries,
		}
	}

	w := newWriteSet(dir)
	// Package files first: an index that advertises a URL nothing serves
	// is a repository that fails at fetch time, which is later and more
	// confusing than failing at publish time.
	for _, s := range staged {
		if s.destRel != "" {
			w.addFileCopy(s.destRel, s.srcPath)
		}
	}
	if err := w.addSignedIndex(archiveIndexFile, index(repository.IndexArchive, archiveEntries), opts.Key); err != nil {
		return Result{}, err
	}
	if err := w.addSignedIndex(activeIndexFile, index(repository.IndexActive, activeEntries), opts.Key); err != nil {
		return Result{}, err
	}
	if err := w.commit(); err != nil {
		return Result{}, err
	}

	return Result{
		IndexVersion: next,
		Added:        added,
		ActiveCount:  len(activeEntries),
		ArchiveCount: len(archiveEntries),
	}, nil
}

// identityOf renders the triple that identifies a package (§2.3):
// name, version and architecture together. Two packages differing in
// any one of the three are different packages.
func identityOf(e repository.IndexEntry) string {
	return fmt.Sprintf("%s %s (%s)", e.Name, e.Version, e.Architecture)
}

// checkSigningKey confirms the descriptor lists the signing key with a
// status permitted to sign (§6.2.1).
//
// Signing with a key the descriptor does not list produces a repository
// whose indexes verify against nothing — structurally perfect, entirely
// unusable, and silent until a consumer tries to refresh. It is the
// single easiest way to break a repository, so it is checked before
// anything is read.
func checkSigningKey(d repository.Descriptor, key ed25519.PrivateKey) error {
	pub, err := publicKeyOf(key)
	if err != nil {
		return err
	}
	fingerprint := signature.Fingerprint(pub)
	for _, k := range d.Keys {
		if k.Fingerprint != fingerprint {
			continue
		}
		switch k.Status {
		case repository.KeyActive, repository.KeyTransitioning:
			return nil
		default:
			return fmt.Errorf(
				"peipkg/repopub: signing key %s is %s in this repository's descriptor and must not sign new content",
				fingerprint, k.Status)
		}
	}
	return fmt.Errorf(
		"peipkg/repopub: signing key %s is not listed in this repository's descriptor, "+
			"so nothing it signs would verify", fingerprint)
}

// deriveActive selects the current version of each package (§6.2).
//
// "Current" is the highest version by the §2.2.7 ordering, which ranks
// a pre-release below the release it precedes — so publishing 1.0.0-rc1
// supersedes 0.9.0 but is itself superseded by 1.0.0. There is no
// exclude-pre-releases knob here on purpose: the ordering is the
// spec's, and a repository that wants rc builds kept out of the active
// index should not publish them into it.
//
// Architecture is deliberately NOT part of the grouping key, because
// §6.2.9 keys the active index by name alone. Peios' own farm shows why
// that is the right reading rather than a technicality: fsbase shipped
// as noarch through 1.0.0-2 and as x86_64 from 1.0.0-3, so a package
// changing architecture over its life is an ordinary historical event.
// Grouping by (name, architecture) would advertise the retired noarch
// build as current forever, alongside the real one.
//
// The case §6.2.9 genuinely cannot express is two architectures of one
// package current AT THE SAME TIME — where the versions tie and there
// is no ordering to break it. That is reported rather than resolved:
// picking a winner would drop a whole architecture out of the active
// index, invisible to everyone but the consumers it stranded.
func deriveActive(entries []repository.IndexEntry) ([]repository.IndexEntry, error) {
	byName := make(map[string]repository.IndexEntry, len(entries))
	for _, e := range entries {
		current, ok := byName[e.Name]
		if !ok {
			byName[e.Name] = e
			continue
		}
		switch cmp := version.Compare(e.Version, current.Version); {
		case cmp > 0:
			byName[e.Name] = e
		case cmp < 0:
			// keep what we have
		default:
			// Equal versions. Same architecture too would mean the same
			// package twice, which the retention check already refuses,
			// so reaching here means the architectures differ.
			return nil, fmt.Errorf(
				"peipkg/repopub: %s %s is published for both %s and %s, but the active index "+
					"permits one entry per name (§6.2.9), so one architecture would be dropped; "+
					"serve each architecture from its own repository",
				e.Name, e.Version, current.Architecture, e.Architecture)
		}
	}

	out := make([]repository.IndexEntry, 0, len(byName))
	for _, e := range byName {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// --- ingest -------------------------------------------------------------

// stagedPackage records where a package file must be placed, if
// anywhere. destRel is empty when the entry's URL is absolute: the
// operator hosts the file elsewhere and this repository only points at
// it.
type stagedPackage struct {
	srcPath string
	destRel string
}

type ingested struct {
	entry  repository.IndexEntry
	staged stagedPackage
}

// ingest reads a .peipkg and derives its index entry (§6.2.5).
//
// The package is verified as a package first — archive, manifest,
// integrity manifest, and every payload file's hash — because an index
// entry derived from a corrupt archive is a signed statement that the
// corruption is genuine. Publishing is the last point at which a bad
// package can be caught by the party that can do something about it.
func ingest(pkgPath, template string, keys map[string]ed25519.PublicKey,
	allowUnsigned bool) (ingested, error) {

	f, err := os.Open(pkgPath)
	if err != nil {
		return ingested{}, err
	}
	defer f.Close()

	// Verify rather than VerifyFormat: it performs the same structural
	// checks AND, when the package carries a signature, verifies it
	// against the trust set — here, the keys this repository itself
	// publishes. A package signed by a key the descriptor does not list
	// is rejected by every consumer, because package trust is scoped to
	// the originating repository's key set (§5.2.5), so catching it now
	// is the difference between an error at publish time and a
	// repository that installs nothing. An unsigned package is not an
	// error to Verify; it reports Signed=false and leaves the policy
	// decision here, which is where it belongs.
	pkg, err := archive.Verify(f, resolverOver(keys))
	if err != nil {
		return ingested{}, err
	}
	if !pkg.Signed && !allowUnsigned {
		return ingested{}, fmt.Errorf(
			"package is unsigned; a repository whose consumers use the recommended `required` " +
				"policy (§6.5.3) cannot install it, so publishing one needs an explicit override")
	}

	hash, size, err := hashFile(pkgPath)
	if err != nil {
		return ingested{}, err
	}

	m := pkg.Manifest
	entry := repository.IndexEntry{
		Name:                 m.Name,
		Version:              m.Version,
		Architecture:         m.Architecture,
		Description:          m.Description,
		License:              m.License,
		Homepage:             m.Homepage,
		DefaultRoot:          m.DefaultRoot,
		Dependencies:         m.Dependencies,
		OptionalDependencies: m.OptionalDependencies,
		Conflicts:            m.Conflicts,
		Provides:             m.Provides,
		Replaces:             m.Replaces,
		SideEffects:          m.SideEffects,
		SizeCompressed:       size,
		SizeInstalled:        m.SizeInstalled,
		Hash:                 hash,
		BuildTimestamp:       m.Build.Timestamp,
		BuildFarmID:          m.Build.FarmID,
	}
	entry.URL = expandURLTemplate(template, m.Name, m.Version.String(), m.Architecture)

	st := stagedPackage{srcPath: pkgPath}
	if isRepoRelative(entry.URL) {
		st.destRel = strings.TrimPrefix(entry.URL, "/")
	}
	return ingested{entry: entry, staged: st}, nil
}

// resolverOver adapts the state's published keys to the resolver
// archive.Verify expects.
func resolverOver(keys map[string]ed25519.PublicKey) archive.KeyResolver {
	return func(fingerprint string) (ed25519.PublicKey, bool) {
		key, ok := keys[fingerprint]
		return key, ok
	}
}

// loadStateKeys reads the public keys the repository publishes, keyed
// by fingerprint.
//
// Only keys permitted to have signed content are returned: a revoked
// key never verifies anything (§6.1.4), so a package signed by one must
// not be publishable. Keys whose files are missing are skipped rather
// than fatal — a descriptor may legitimately point a key URL at another
// host, and the consequence of a skip is a package refused for an
// unknown key, which is the safe direction.
func loadStateKeys(st *State) map[string]ed25519.PublicKey {
	keys := make(map[string]ed25519.PublicKey, len(st.Descriptor.Keys))
	for _, k := range st.Descriptor.Keys {
		if k.Status == repository.KeyRevoked {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(st.Dir, keysDir, k.Fingerprint+".pub"))
		if err != nil {
			continue
		}
		pub, err := signature.ParsePublicKey(raw)
		if err != nil {
			continue
		}
		keys[k.Fingerprint] = pub
	}
	return keys
}

// resolvePackagePaths expands the caller's paths into a sorted list of
// .peipkg files.
//
// Sorting makes a publish deterministic: the same inputs in any order
// produce the same indexes, which matters because the operator usually
// supplies a shell glob and glob order is the filesystem's business,
// not theirs.
func resolvePackagePaths(st *State, opts PublishOptions) ([]string, error) {
	paths := opts.Paths
	if opts.Rebuild && len(paths) == 0 {
		// With nothing named, a rebuild reconstructs from the packages
		// the repository already holds. This is the common case: the
		// indexes are damaged, the payload is not.
		paths = []string{filepath.Join(st.Dir, packagesDir)}
	}

	var out []string
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			out = append(out, p)
			continue
		}
		err = filepath.WalkDir(p, func(name string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && strings.HasSuffix(name, ".peipkg") {
				out = append(out, name)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("peipkg/repopub: no .peipkg files found in the given paths")
	}
	sort.Strings(out)
	return out, nil
}
