package repopub

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/peios/peipkg/internal/archive"
	repository "github.com/peios/peipkg/internal/repodata"
	"github.com/peios/peipkg/internal/resolver"
)

// Qualification binds a publication to checked bytes and a repository snapshot.
// The publisher also checks every resulting active package's install closure.
// BaseState is StateDigest taken before the coordinator's integration checks.
type Qualification struct {
	BaseState    string
	EvidencePath string
	Artifacts    map[string]string // absolute archive path -> lowercase SHA-256
}

func lockPublication(dir string) (func(), error) {
	f, err := os.Open(filepath.Join(dir, configFile))
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("repository publication is busy: %w", err)
	}
	return func() { _ = f.Close() }, nil
}

// StateDigest binds descriptor, trust anchors and both signed indexes. Package
// hashes in those indexes bind payloads; qualification verifies them separately.
func StateDigest(dir string) (string, error) {
	h := sha256.New()
	for _, p := range []string{configFile, "repo.json", "repo.json.sig", "index/active.json", "index/active.json.sig", "index/archive.json", "index/archive.json.sig"} {
		b, err := os.ReadFile(filepath.Join(dir, p))
		if err != nil {
			return "", err
		}
		fmt.Fprintf(h, "%s:%d:", p, len(b))
		h.Write(b)
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
func checkQualificationBase(dir string, q Qualification) error {
	report, err := Verify(dir, VerifyOptions{Quick: true})
	if err != nil {
		return err
	}
	if !report.OK() {
		return fmt.Errorf("qualification: base repository invalid: %v", report.Problems)
	}
	got, err := StateDigest(dir)
	if err != nil {
		return err
	}
	if q.BaseState == "" || got != q.BaseState {
		return fmt.Errorf("qualification: repository changed since candidate selection")
	}
	if len(q.Artifacts) == 0 {
		return fmt.Errorf("qualification: no qualified artifacts")
	}
	return nil
}

func qualifyClosures(st *State, active, added []repository.IndexEntry, staged []stagedPackage, keys map[string]ed25519.PublicKey) error {
	paths := map[string]string{}
	for i, e := range added {
		paths[e.Hash] = staged[i].srcPath
	}
	packages := map[string]*archive.Package{}
	load := func(e repository.IndexEntry) (*archive.Package, error) {
		if p := packages[e.Hash]; p != nil {
			return p, nil
		}
		p := paths[e.Hash]
		if p == "" {
			if !isRepoRelative(e.URL) {
				return nil, fmt.Errorf("qualification: locally hosted archives required: %s", e.Name)
			}
			rel := strings.TrimPrefix(e.URL, "/")
			if filepath.IsAbs(rel) || filepath.Clean(rel) != rel || strings.HasPrefix(rel, "../") {
				return nil, fmt.Errorf("qualification: invalid archive path")
			}
			p = filepath.Join(st.Dir, rel)
		}
		hash, _, err := hashFile(p)
		if err != nil {
			return nil, err
		}
		if hash != e.Hash {
			return nil, fmt.Errorf("qualification: archive changed: %s", p)
		}
		f, err := os.Open(p)
		if err != nil {
			return nil, err
		}
		pkg, err := archive.Verify(f, resolverOver(keys), e.SizeInstalled)
		f.Close()
		if err != nil {
			return nil, err
		}
		if !pkg.Signed {
			return nil, fmt.Errorf("qualification: unsigned archive %s", p)
		}
		packages[e.Hash] = pkg
		return pkg, nil
	}
	makeCandidates := func(entries []repository.IndexEntry) []resolver.Candidate {
		var out []resolver.Candidate
		for _, e := range entries {
			out = append(out, resolver.Candidate{Name: e.Name, Version: e.Version, Architecture: e.Architecture, Dependencies: e.Dependencies, Conflicts: e.Conflicts, Provides: e.Provides, Replaces: e.Replaces, Repo: st.Descriptor.RepoName})
		}
		return out
	}
	next := makeCandidates(active)
	refs := map[string]string{"main": "main"}
	entries := map[string]repository.IndexEntry{}
	for _, e := range append(append([]repository.IndexEntry{}, st.Active.Packages...), active...) {
		entries[e.Name+"\x00"+e.Version.String()] = e
		if e.DefaultRoot != "" {
			refs[e.DefaultRoot] = e.DefaultRoot
		}
		for _, d := range e.Dependencies {
			if d.Root != "" {
				refs[d.Root] = d.Root
			}
		}
	}
	empty := func() map[string][]resolver.Installed {
		m := map[string][]resolver.Installed{}
		for _, r := range refs {
			m[r] = nil
		}
		return m
	}
	// Validate the actual resolved closures, not a union of every package: two
	// mutually exclusive alternatives need not be co-installable.
	check := func(ops []resolver.Operation) error {
		owners := map[string]string{}
		dirs := map[string]bool{}
		for _, op := range ops {
			if op.Kind == resolver.OpRemove {
				continue
			}
			e := entries[op.Name+"\x00"+op.ToVersion.String()]
			pkg, err := load(e)
			if err != nil {
				return err
			}
			for _, f := range pkg.Payload {
				key := op.Root + "\x00" + f.Path
				if prev, ok := owners[key]; ok && !(dirs[key] && f.Type == archive.EntryDir) {
					return fmt.Errorf("qualification: %s and %s collide in root %s on /%s", prev, op.Name, op.Root, f.Path)
				}
				owners[key] = op.Name
				dirs[key] = f.Type == archive.EntryDir
			}
		}
		for key, owner := range owners {
			sep := strings.IndexByte(key, 0)
			root, p := key[:sep], key[sep+1:]
			for p = filepath.Dir(p); p != "."; p = filepath.Dir(p) {
				k := root + "\x00" + p
				if ancestor, ok := owners[k]; ok && !dirs[k] {
					return fmt.Errorf("qualification: %s payload is below non-directory /%s owned by %s", owner, p, ancestor)
				}
			}
		}
		return nil
	}
	archs := map[string]bool{}
	for _, e := range active {
		if e.Architecture != "noarch" {
			archs[e.Architecture] = true
		}
	}
	if len(archs) == 0 {
		archs["noarch"] = true
	}
	archList := []string{}
	for a := range archs {
		archList = append(archList, a)
	}
	sort.Strings(archList)
	for _, e := range active {
		for _, arch := range archList {
			if e.Architecture != "noarch" && e.Architecture != arch {
				continue
			}
			root := e.DefaultRoot
			if root == "" {
				root = "main"
			}
			plan, err := resolver.ResolveMultiRoot([]resolver.Request{{Kind: resolver.Install, Name: e.Name, Root: root}}, empty(), next, refs, resolver.Options{PrimaryArch: arch})
			if err != nil {
				return fmt.Errorf("qualification: install %s: %w", e.Name, err)
			}
			if len(plan.Authorizations) > 0 {
				return fmt.Errorf("qualification: install %s needs exceptional authorization", e.Name)
			}
			if err := check(plan.Operations); err != nil {
				return err
			}
		}
	}
	// Re-resolve each previously supported closure as an upgrade. A successful
	// fresh install alone is not evidence that dropping an ABI is safe.
	old := makeCandidates(st.Active.Packages)
	for _, e := range st.Active.Packages {
		arch := e.Architecture
		if arch == "noarch" {
			arch = archList[0]
		}
		root := e.DefaultRoot
		if root == "" {
			root = "main"
		}
		prior, err := resolver.ResolveMultiRoot([]resolver.Request{{Kind: resolver.Install, Name: e.Name, Root: root}}, empty(), old, refs, resolver.Options{PrimaryArch: arch})
		if err != nil {
			return fmt.Errorf("qualification: existing repository closure %s is broken: %w", e.Name, err)
		}
		installed := empty()
		final := map[string]resolver.Operation{}
		for _, op := range prior.Operations {
			c := op.Candidate
			installed[op.Root] = append(installed[op.Root], resolver.Installed{Name: c.Name, Version: c.Version, Architecture: c.Architecture, Dependencies: c.Dependencies, Conflicts: c.Conflicts, Provides: c.Provides, Repo: c.Repo})
			final[op.Root+"\x00"+op.Name] = op
		}
		var reqs []resolver.Request
		for r, pkgs := range installed {
			if len(pkgs) > 0 {
				reqs = append(reqs, resolver.Request{Kind: resolver.Upgrade, Root: r})
			}
		}
		sort.Slice(reqs, func(i, j int) bool { return reqs[i].Root < reqs[j].Root })
		plan, err := resolver.ResolveMultiRoot(reqs, installed, next, refs, resolver.Options{PrimaryArch: arch})
		if err != nil {
			return fmt.Errorf("qualification: upgrade %s: %w", e.Name, err)
		}
		if len(plan.Authorizations) > 0 {
			return fmt.Errorf("qualification: upgrade %s needs exceptional authorization", e.Name)
		}
		for _, op := range plan.Operations {
			key := op.Root + "\x00" + op.Name
			if op.Kind == resolver.OpRemove {
				delete(final, key)
			} else {
				final[key] = op
			}
		}
		var ops []resolver.Operation
		for _, op := range final {
			ops = append(ops, op)
		}
		sort.Slice(ops, func(i, j int) bool { return ops[i].Root+ops[i].Name < ops[j].Root+ops[j].Name })
		if err := check(ops); err != nil {
			return err
		}
	}
	return nil
}

// The evidence is signed by the repository authority and checked again at the
// publication boundary. A saved success boolean is never sufficient.
func checkReleaseEvidence(st *State, q Qualification, key ed25519.PrivateKey) error {
	data, err := os.ReadFile(q.EvidencePath)
	if err != nil {
		return fmt.Errorf("qualification: missing evidence: %w", err)
	}
	sig, err := os.ReadFile(q.EvidencePath + ".sig")
	if err != nil {
		return err
	}
	if !ed25519.Verify(key.Public().(ed25519.PublicKey), data, sig) {
		return fmt.Errorf("qualification: invalid evidence signature")
	}
	var record struct {
		Schema    int
		Qualified bool
		Base      string `json:"base_repository"`
		Artifacts []struct{ Path, SHA256 string }
		Evidence  map[string]string
	}
	if err = json.Unmarshal(data, &record); err != nil {
		return err
	}
	if record.Schema != 1 || !record.Qualified || len(record.Evidence) == 0 {
		return fmt.Errorf("qualification: incomplete release evidence")
	}
	if record.Base != q.BaseState && !(record.Base == "absent" && len(st.Archive.Packages) == 0 && st.Active.IndexVersion == 1) {
		return fmt.Errorf("qualification: stale evidence repository")
	}
	if len(record.Artifacts) != len(q.Artifacts) {
		return fmt.Errorf("qualification: evidence artifact set differs")
	}
	seen := map[string]bool{}
	for _, a := range record.Artifacts {
		if seen[a.Path] || a.SHA256 == "" || q.Artifacts[a.Path] != a.SHA256 {
			return fmt.Errorf("qualification: stale artifact evidence")
		}
		seen[a.Path] = true
	}
	for path, want := range record.Evidence {
		got, err := EvidenceIdentity(path)
		if err != nil || want == "" || got != want {
			return fmt.Errorf("qualification: evidence changed or missing: %s", path)
		}
	}
	return nil
}

// EvidenceIdentity includes object type, mode and directory membership so
// deleting a log, redirecting a source link or adding an input is observable.
func EvidenceIdentity(path string) (string, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if st.Mode()&os.ModeSymlink != 0 {
		link, err := os.Readlink(path)
		return "link:" + link, err
	}
	if st.IsDir() {
		entries, err := os.ReadDir(path)
		if err != nil {
			return "", err
		}
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		data, err := json.Marshal(names)
		return fmt.Sprintf("dir:%04o:%s", st.Mode().Perm(), data), err
	}
	if !st.Mode().IsRegular() {
		return "", fmt.Errorf("unsupported evidence object: %s", path)
	}
	hash, _, err := hashFile(path)
	return fmt.Sprintf("file:%04o:%s", st.Mode().Perm(), hash), err
}
