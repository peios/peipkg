package repopub

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/peios/peipkg/internal/repository"
	"github.com/peios/peipkg/internal/signature"
	"github.com/peios/peipkg/internal/version"
)

// Report is the outcome of [Verify].
type Report struct {
	RepoName     string
	IndexVersion int64
	ActiveCount  int
	ArchiveCount int
	// Problems is empty for a sound repository. Each entry is one
	// finding, phrased so an operator can act on it without reading the
	// spec.
	Problems []string
}

// OK reports whether the state is sound.
func (r Report) OK() bool { return len(r.Problems) == 0 }

// VerifyOptions configures [Verify].
type VerifyOptions struct {
	// Quick skips re-hashing package files, checking only that each is
	// present and the expected size.
	Quick bool
}

// Verify audits a repository state.
//
// It answers one question: would a consumer that added this repository
// today be able to use it? So the checks are the consumer's own, run
// against the local directory — signatures against the descriptor's
// keys, index consistency, and the actual bytes behind every advertised
// URL. Publishing already refuses to write a bad state; Verify exists
// because a state can also be damaged by everything that happens to a
// directory afterwards: a partial upload, a truncated copy, a helpful
// filesystem that dropped a file it thought was junk.
//
// Every finding is collected rather than returned as the first error.
// An operator repairing a repository wants the whole list, not one
// problem per run.
func Verify(dir string, opts VerifyOptions) (Report, error) {
	st, err := Open(dir)
	if err != nil {
		return Report{}, err
	}
	rep := Report{
		RepoName:     st.Descriptor.RepoName,
		IndexVersion: st.Active.IndexVersion,
		ActiveCount:  len(st.Active.Packages),
		ArchiveCount: len(st.Archive.Packages),
	}
	problem := func(format string, args ...any) {
		rep.Problems = append(rep.Problems, fmt.Sprintf(format, args...))
	}

	keys := loadStateKeys(st)
	verifyKeyFiles(st, &rep, problem)
	verifySignatures(st, keys, problem)
	verifyIndexAgreement(st, problem)
	verifyActiveDerivation(st, problem)
	verifyPackageFiles(st, opts, problem)

	sort.Strings(rep.Problems)
	return rep, nil
}

// verifyKeyFiles checks that each key the descriptor points at inside
// the repository is present and is the key it claims to be.
//
// A key file whose contents do not hash to the fingerprint naming it is
// the most dangerous inconsistency a repository can carry: a consumer
// performing the §6.5.2 trust ceremony compares the fingerprint it was
// given out-of-band against the key it fetched, and a mismatch there
// aborts the add with no explanation the operator can act on.
func verifyKeyFiles(st *State, _ *Report, problem func(string, ...any)) {
	for _, k := range st.Descriptor.Keys {
		if !isRepoRelative(k.URL) {
			continue // hosted elsewhere; nothing local to check
		}
		rel := strings.TrimPrefix(k.URL, "/")
		raw, err := os.ReadFile(filepath.Join(st.Dir, filepath.FromSlash(rel)))
		if err != nil {
			problem("key %s is advertised at %s but the file is missing", k.Fingerprint, k.URL)
			continue
		}
		pub, err := signature.ParsePublicKey(raw)
		if err != nil {
			problem("key file %s does not parse: %v", rel, err)
			continue
		}
		if got := signature.Fingerprint(pub); got != k.Fingerprint {
			problem("key file %s holds key %s but is advertised as %s", rel, got, k.Fingerprint)
		}
	}
}

// verifySignatures checks the descriptor and both indexes against the
// keys the descriptor itself declares.
//
// This is deliberately a self-consistency check and not a trust check:
// it cannot tell an operator that the right key signed the repository,
// only that the key the repository names did. Establishing that the key
// is the expected one is the out-of-band trust anchor's job (§6.5.2)
// and cannot be done from inside the directory.
func verifySignatures(st *State, keys map[string]ed25519.PublicKey, problem func(string, ...any)) {
	candidates := make([]ed25519.PublicKey, 0, len(keys))
	for _, k := range keys {
		candidates = append(candidates, k)
	}
	check := func(rel string) {
		content, err := os.ReadFile(filepath.Join(st.Dir, filepath.FromSlash(rel)))
		if err != nil {
			problem("%s is missing", rel)
			return
		}
		sig, err := os.ReadFile(filepath.Join(st.Dir, filepath.FromSlash(rel+signatureSuffix)))
		if err != nil {
			problem("%s has no detached signature at %s", rel, rel+signatureSuffix)
			return
		}
		if err := repository.VerifyDetached(content, sig, candidates); err != nil {
			problem("%s does not verify against any key this repository publishes: %v", rel, err)
		}
	}
	check(descriptorFile)
	check(activeIndexFile)
	check(archiveIndexFile)
}

// verifyIndexAgreement checks the two indexes advance together.
//
// A consumer records ONE index_version floor and ONE generated_at floor
// per repository (§6.2.3), so indexes that disagree make one of the two
// permanently unfetchable: whichever a consumer reads second is
// rejected as a rollback. This is the signature of a publish that was
// interrupted between its two renames, and it is invisible from either
// index alone.
func verifyIndexAgreement(st *State, problem func(string, ...any)) {
	if st.Active.IndexVersion != st.Archive.IndexVersion {
		problem(
			"the active index is at index_version %d but the archive is at %d; "+
				"a consumer floors both together, so the lower one would be rejected as a rollback",
			st.Active.IndexVersion, st.Archive.IndexVersion)
	}
	if !st.Active.GeneratedAt.Equal(st.Archive.GeneratedAt) {
		problem(
			"the two indexes carry different generated_at timestamps (%s and %s); "+
				"a consumer floors generated_at per repository, not per index",
			st.Active.GeneratedAt.Format(time.RFC3339), st.Archive.GeneratedAt.Format(time.RFC3339))
	}
}

// verifyActiveDerivation checks the active index really is the derived
// view §6.2.5 says it is: every entry present in the archive, and every
// entry the current version of its package.
func verifyActiveDerivation(st *State, problem func(string, ...any)) {
	archived := make(map[string]repository.IndexEntry, len(st.Archive.Packages))
	for _, e := range st.Archive.Packages {
		archived[identityOf(e)] = e
	}
	for _, e := range st.Active.Packages {
		if _, ok := archived[identityOf(e)]; !ok {
			problem(
				"the active index advertises %s but the archive does not list it; "+
					"the archive is the record of everything ever published (§6.3.1)",
				identityOf(e))
		}
	}

	want, err := deriveActive(st.Archive.Packages)
	if err != nil {
		problem("the archive cannot be reduced to an active index: %v", err)
		return
	}
	have := make(map[string]version.Version, len(st.Active.Packages))
	for _, e := range st.Active.Packages {
		have[e.Name] = e.Version
	}
	for _, e := range want {
		got, ok := have[e.Name]
		if !ok {
			problem("package %q is in the archive but absent from the active index", e.Name)
			continue
		}
		if version.Compare(got, e.Version) != 0 {
			problem(
				"the active index advertises %s %s, but %s is the highest version in the archive",
				e.Name, got, e.Version)
		}
	}
	for name := range have {
		found := false
		for _, e := range want {
			if e.Name == name {
				found = true
				break
			}
		}
		if !found {
			problem("the active index advertises %q, which the archive does not list at all", name)
		}
	}
}

// verifyPackageFiles checks that the bytes behind every repo-relative
// URL are present and are what the index says they are.
//
// The hash check is the one that matters and the one that costs: an
// index entry is a signed claim about a specific sequence of bytes, and
// a file that has been replaced or truncated since publication turns
// that claim into a consumer-side integrity failure at install time —
// far from the operator who could fix it. VerifyOptions.Quick trades
// the check for speed on large repositories.
func verifyPackageFiles(st *State, opts VerifyOptions, problem func(string, ...any)) {
	for _, e := range st.Archive.Packages {
		if !isRepoRelative(e.URL) {
			continue // hosted elsewhere
		}
		rel := strings.TrimPrefix(e.URL, "/")
		full := filepath.Join(st.Dir, filepath.FromSlash(rel))
		info, err := os.Stat(full)
		if err != nil {
			problem("%s is advertised at %s but the file is missing", identityOf(e), e.URL)
			continue
		}
		if info.Size() != e.SizeCompressed {
			problem("%s is %d bytes on disk but the index says %d",
				rel, info.Size(), e.SizeCompressed)
			continue
		}
		if opts.Quick {
			continue
		}
		hash, _, err := hashFile(full)
		if err != nil {
			problem("%s could not be read: %v", rel, err)
			continue
		}
		if hash != e.Hash {
			problem("%s hashes to %s but the index says %s", rel, hash, e.Hash)
		}
	}
}
