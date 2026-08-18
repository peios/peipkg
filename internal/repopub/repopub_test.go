package repopub_test

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/peios/peipkg/internal/repopub"
	"github.com/peios/peipkg/internal/signature"
)

var at = time.Date(2026, 8, 18, 0, 0, 0, 0, time.UTC)

// newRepo initialises a repository in a temp dir and returns its path
// and signing key.
func newRepo(t *testing.T) (string, ed25519.PrivateKey) {
	t.Helper()
	_, priv := keypair(t)
	dir := filepath.Join(t.TempDir(), "repo")
	if err := repopub.Init(dir, repopub.InitOptions{
		Name: "test-repo", Key: priv, GeneratedAt: at,
	}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	return dir, priv
}

func publish(t *testing.T, dir string, key ed25519.PrivateKey,
	when time.Time, paths ...string) repopub.Result {
	t.Helper()
	res, err := repopub.Publish(dir, repopub.PublishOptions{
		Key: key, Paths: paths, GeneratedAt: when,
	})
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	return res
}

func mustVerify(t *testing.T, dir string) repopub.Report {
	t.Helper()
	rep, err := repopub.Verify(dir, repopub.VerifyOptions{})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	return rep
}

// TestInitProducesAConsumableRepository checks that an empty repository
// is a complete one. An operator should be able to stand up hosting and
// run the trust ceremony before a single package exists, so "empty" has
// to mean "advertising nothing", not "half-built".
func TestInitProducesAConsumableRepository(t *testing.T) {
	dir, key := newRepo(t)

	for _, rel := range []string{
		"repo.json", "repo.json.sig",
		"index/active.json", "index/active.json.sig",
		"index/archive.json", "index/archive.json.sig",
	} {
		if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(rel))); err != nil {
			t.Errorf("a fresh repository is missing %s", rel)
		}
	}
	fp := signature.Fingerprint(key.Public().(ed25519.PublicKey))
	if _, err := os.Stat(filepath.Join(dir, "keys", fp+".pub")); err != nil {
		t.Errorf("the signing key was not published at keys/%s.pub", fp)
	}

	if rep := mustVerify(t, dir); !rep.OK() {
		t.Errorf("a freshly initialised repository does not verify: %v", rep.Problems)
	}

	// §6.2.3: index_version must be a positive integer, and a consumer's
	// recorded floor starts at zero — so a zeroth index would be
	// rejected by the very first refresh.
	active := readJSON(t, filepath.Join(dir, "index", "active.json"))
	if v, _ := active["index_version"].(float64); v != 1 {
		t.Errorf("initial index_version is %v, want 1", active["index_version"])
	}
}

// TestInitRefusesAnExistingRepository guards an unrecoverable mistake:
// re-initialising mints a fresh index_version 1, which every consumer
// that had seen a higher version would reject as a rollback for the
// rest of that repository's life (§6.2.3).
func TestInitRefusesAnExistingRepository(t *testing.T) {
	dir, key := newRepo(t)
	err := repopub.Init(dir, repopub.InitOptions{
		Name: "test-repo", Key: key, GeneratedAt: at})
	if err == nil {
		t.Fatal("re-initialised over an existing repository")
	}
}

// TestPublishDerivesTheActiveIndex is the core behaviour: the archive
// keeps everything, the active index advertises the current version of
// each package.
func TestPublishDerivesTheActiveIndex(t *testing.T) {
	dir, key := newRepo(t)
	src := t.TempDir()
	old := writePackage(t, src, key, pkgSpec{name: "dash", version: "0.5.11-1"})
	cur := writePackage(t, src, key, pkgSpec{name: "dash", version: "0.5.12-2"})
	other := writePackage(t, src, key, pkgSpec{name: "sed", version: "4.9-1"})

	res := publish(t, dir, key, at.Add(time.Hour), old, cur, other)
	if res.ActiveCount != 2 || res.ArchiveCount != 3 {
		t.Fatalf("got %d active / %d archived, want 2 / 3", res.ActiveCount, res.ArchiveCount)
	}

	st, err := repopub.Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	for _, e := range st.Active.Packages {
		if e.Name == "dash" && e.Version.String() != "0.5.12-2" {
			t.Errorf("active advertises dash %s, want 0.5.12-2", e.Version)
		}
	}
	// §6.3.1: every version ever advertised stays listed.
	var dashVersions []string
	for _, e := range st.Archive.Packages {
		if e.Name == "dash" {
			dashVersions = append(dashVersions, e.Version.String())
		}
	}
	if len(dashVersions) != 2 {
		t.Errorf("archive holds dash %v, want both versions", dashVersions)
	}
	if rep := mustVerify(t, dir); !rep.OK() {
		t.Errorf("published repository does not verify: %v", rep.Problems)
	}
}

// TestActiveSurvivesAnArchitectureChange is a regression test taken
// from Peios' own farm, where fsbase shipped as noarch through 1.0.0-2
// and as x86_64 from 1.0.0-3. Grouping the active index by (name,
// architecture) rather than by name — which §6.2.9 does not permit —
// would advertise the retired noarch build as current forever.
func TestActiveSurvivesAnArchitectureChange(t *testing.T) {
	dir, key := newRepo(t)
	src := t.TempDir()
	noarch := writePackage(t, src, key,
		pkgSpec{name: "fsbase", version: "1.0.0-2", arch: "noarch"})
	x86 := writePackage(t, src, key,
		pkgSpec{name: "fsbase", version: "1.0.0-3", arch: "x86_64"})

	res := publish(t, dir, key, at.Add(time.Hour), noarch, x86)
	if res.ActiveCount != 1 {
		t.Fatalf("got %d active entries, want 1", res.ActiveCount)
	}
	st, err := repopub.Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	got := st.Active.Packages[0]
	if got.Version.String() != "1.0.0-3" || got.Architecture != "x86_64" {
		t.Errorf("active advertises fsbase %s (%s), want 1.0.0-3 (x86_64)",
			got.Version, got.Architecture)
	}
	if len(st.Archive.Packages) != 2 {
		t.Errorf("archive holds %d entries, want both", len(st.Archive.Packages))
	}
}

// TestActiveRefusesTwoArchitecturesAtOneVersion pins the case §6.2.9
// genuinely cannot express. Resolving it by picking a winner would drop
// an entire architecture out of the active index, invisible to everyone
// except the consumers it stranded.
func TestActiveRefusesTwoArchitecturesAtOneVersion(t *testing.T) {
	dir, key := newRepo(t)
	src := t.TempDir()
	a := writePackage(t, src, key, pkgSpec{name: "hello", version: "1.0-1", arch: "x86_64"})
	b := writePackage(t, src, key, pkgSpec{name: "hello", version: "1.0-1", arch: "aarch64"})

	_, err := repopub.Publish(dir, repopub.PublishOptions{
		Key: key, Paths: []string{a, b}, GeneratedAt: at.Add(time.Hour)})
	if err == nil {
		t.Fatal("published two architectures of one package at one version")
	}
	if !strings.Contains(err.Error(), "6.2.9") {
		t.Errorf("error does not name the rule it enforces: %v", err)
	}
}

// TestBothIndexesAdvanceTogether pins the invariant that makes a
// repository refreshable: a consumer records ONE index_version floor
// and ONE generated_at floor per repository (§6.2.3), so indexes that
// disagree make whichever is read second look like a rollback.
func TestBothIndexesAdvanceTogether(t *testing.T) {
	dir, key := newRepo(t)
	src := t.TempDir()

	var previous int64
	for i, ver := range []string{"1.0-1", "1.0-2", "1.0-3"} {
		p := writePackage(t, src, key, pkgSpec{name: "pkg", version: ver})
		res := publish(t, dir, key, at.Add(time.Duration(i+1)*time.Hour), p)

		st, err := repopub.Open(dir)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if st.Active.IndexVersion != st.Archive.IndexVersion {
			t.Fatalf("active is at %d but archive is at %d",
				st.Active.IndexVersion, st.Archive.IndexVersion)
		}
		if !st.Active.GeneratedAt.Equal(st.Archive.GeneratedAt) {
			t.Fatalf("indexes carry different generated_at: %s and %s",
				st.Active.GeneratedAt, st.Archive.GeneratedAt)
		}
		if st.Active.IndexVersion <= previous {
			t.Fatalf("index_version did not advance: %d after %d",
				st.Active.IndexVersion, previous)
		}
		previous = st.Active.IndexVersion
		if res.IndexVersion != st.Active.IndexVersion {
			t.Fatalf("reported index_version %d, wrote %d",
				res.IndexVersion, st.Active.IndexVersion)
		}
	}
}

// TestPublishRefusesARepublish pins retention (§6.3.1). Overwriting an
// entry would break the promise invisibly: the index would still list
// the version while the bytes behind it had changed.
func TestPublishRefusesARepublish(t *testing.T) {
	dir, key := newRepo(t)
	src := t.TempDir()
	p := writePackage(t, src, key, pkgSpec{name: "pkg", version: "1.0-1"})
	publish(t, dir, key, at.Add(time.Hour), p)

	_, err := repopub.Publish(dir, repopub.PublishOptions{
		Key: key, Paths: []string{p}, GeneratedAt: at.Add(2 * time.Hour)})
	if err == nil {
		t.Fatal("republished an already-published version")
	}
	if !strings.Contains(err.Error(), "already published") {
		t.Errorf("unhelpful error: %v", err)
	}
}

// TestPublishRefusesTheSameVersionTwiceInOneCall covers the same rule
// within a single invocation, where there is no previous state to
// compare against — the case a naive implementation misses.
func TestPublishRefusesTheSameVersionTwiceInOneCall(t *testing.T) {
	dir, key := newRepo(t)
	a := writePackage(t, t.TempDir(), key, pkgSpec{name: "pkg", version: "1.0-1"})
	b := writePackage(t, t.TempDir(), key, pkgSpec{name: "pkg", version: "1.0-1"})

	_, err := repopub.Publish(dir, repopub.PublishOptions{
		Key: key, Paths: []string{a, b}, GeneratedAt: at.Add(time.Hour)})
	if err == nil {
		t.Fatal("accepted the same package twice in one publish")
	}
}

// TestPublishRefusesAnUnlistedSigningKey guards the easiest way to
// break a repository: signing with a key the descriptor does not name
// produces indexes that verify against nothing, and the failure is
// silent until a consumer refreshes.
func TestPublishRefusesAnUnlistedSigningKey(t *testing.T) {
	dir, key := newRepo(t)
	_, stranger := keypair(t)
	p := writePackage(t, t.TempDir(), key, pkgSpec{name: "pkg", version: "1.0-1"})

	_, err := repopub.Publish(dir, repopub.PublishOptions{
		Key: stranger, Paths: []string{p}, GeneratedAt: at.Add(time.Hour)})
	if err == nil {
		t.Fatal("published with a key the descriptor does not list")
	}
}

// TestPublishRefusesAnUnsignedPackage: a repository whose consumers use
// the recommended `required` policy (§6.5.3) cannot install one, so
// publishing it needs an explicit decision.
func TestPublishRefusesAnUnsignedPackage(t *testing.T) {
	dir, key := newRepo(t)
	p := writePackage(t, t.TempDir(), key,
		pkgSpec{name: "pkg", version: "1.0-1", unsigned: true})

	if _, err := repopub.Publish(dir, repopub.PublishOptions{
		Key: key, Paths: []string{p}, GeneratedAt: at.Add(time.Hour)}); err == nil {
		t.Fatal("published an unsigned package without an override")
	}

	res, err := repopub.Publish(dir, repopub.PublishOptions{
		Key: key, Paths: []string{p}, GeneratedAt: at.Add(time.Hour), AllowUnsigned: true})
	if err != nil {
		t.Fatalf("--allow-unsigned did not permit it: %v", err)
	}
	if res.ArchiveCount != 1 {
		t.Errorf("got %d archived, want 1", res.ArchiveCount)
	}
}

// TestPublishRefusesAPackageSignedByAStranger: package trust is scoped
// to the originating repository's key set (§5.2.5), so a package signed
// by a key the descriptor does not list is one no consumer will
// install. Catching it at publish time is the difference between an
// error the operator sees and a repository that installs nothing.
func TestPublishRefusesAPackageSignedByAStranger(t *testing.T) {
	dir, key := newRepo(t)
	_, stranger := keypair(t)
	p := writePackage(t, t.TempDir(), key,
		pkgSpec{name: "pkg", version: "1.0-1", signWith: stranger})

	if _, err := repopub.Publish(dir, repopub.PublishOptions{
		Key: key, Paths: []string{p}, GeneratedAt: at.Add(time.Hour)}); err == nil {
		t.Fatal("published a package signed by an unlisted key")
	}
}

// TestFailedPublishLeavesTheRepositoryUntouched: a publish is a state
// transition, and a transition that cannot complete must not half
// happen. Here the second package is unsigned, so the batch fails after
// the first has already been read.
func TestFailedPublishLeavesTheRepositoryUntouched(t *testing.T) {
	dir, key := newRepo(t)
	src := t.TempDir()
	good := writePackage(t, src, key, pkgSpec{name: "aaa", version: "1.0-1"})
	bad := writePackage(t, src, key,
		pkgSpec{name: "zzz", version: "1.0-1", unsigned: true})

	before, err := repopub.Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := repopub.Publish(dir, repopub.PublishOptions{
		Key: key, Paths: []string{good, bad}, GeneratedAt: at.Add(time.Hour)}); err == nil {
		t.Fatal("a batch containing an unpublishable package succeeded")
	}
	after, err := repopub.Open(dir)
	if err != nil {
		t.Fatalf("Open after failure: %v", err)
	}
	if after.Active.IndexVersion != before.Active.IndexVersion {
		t.Errorf("index_version moved from %d to %d despite the failure",
			before.Active.IndexVersion, after.Active.IndexVersion)
	}
	if len(after.Archive.Packages) != 0 {
		t.Errorf("a failed publish left %d entries behind", len(after.Archive.Packages))
	}
	// The package that WAS acceptable must not have been staged either.
	if _, err := os.Stat(filepath.Join(dir, "p", "aaa")); err == nil {
		t.Error("a failed publish left package files behind")
	}
}

// TestPublishPlacesPackagesAtTheAdvertisedURL: an index entry pointing
// at a URL nothing serves is a repository that fails at fetch time,
// which is later and more confusing than failing at publish time.
func TestPublishPlacesPackagesAtTheAdvertisedURL(t *testing.T) {
	dir, key := newRepo(t)
	p := writePackage(t, t.TempDir(), key, pkgSpec{name: "pkg", version: "1.0-1"})
	publish(t, dir, key, at.Add(time.Hour), p)

	st, err := repopub.Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	entry := st.Archive.Packages[0]
	want := "/p/pkg/1.0-1/pkg_1.0-1_x86_64.peipkg"
	if entry.URL != want {
		t.Errorf("URL is %q, want %q", entry.URL, want)
	}
	served := filepath.Join(dir, filepath.FromSlash(strings.TrimPrefix(entry.URL, "/")))
	info, err := os.Stat(served)
	if err != nil {
		t.Fatalf("nothing is served at the advertised URL: %v", err)
	}
	if info.Size() != entry.SizeCompressed {
		t.Errorf("served file is %d bytes, index says %d", info.Size(), entry.SizeCompressed)
	}
}

// TestAbsoluteURLTemplateLeavesFilesAlone covers split hosting: indexes
// here, package bytes on a releases page. The publisher must record the
// URL and not try to serve the file itself.
func TestAbsoluteURLTemplateLeavesFilesAlone(t *testing.T) {
	_, priv := keypair(t)
	dir := filepath.Join(t.TempDir(), "repo")
	if err := repopub.Init(dir, repopub.InitOptions{
		Name: "test-repo", Key: priv, GeneratedAt: at,
		URLTemplate: "https://downloads.example.org/{filename}",
	}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	p := writePackage(t, t.TempDir(), priv, pkgSpec{name: "pkg", version: "1.0-1"})
	publish(t, dir, priv, at.Add(time.Hour), p)

	st, err := repopub.Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	want := "https://downloads.example.org/pkg_1.0-1_x86_64.peipkg"
	if st.Archive.Packages[0].URL != want {
		t.Errorf("URL is %q, want %q", st.Archive.Packages[0].URL, want)
	}
	if _, err := os.Stat(filepath.Join(dir, "p")); err == nil {
		t.Error("an externally-hosted package was copied into the repository")
	}
	// Verify must not complain about a file it was never asked to hold.
	if rep := mustVerify(t, dir); !rep.OK() {
		t.Errorf("split hosting reported problems: %v", rep.Problems)
	}
}

// TestInitRejectsACollidingURLTemplate: without {version} or
// {filename}, every version of a package shares one URL, so publishing
// 1.1 makes 1.0 unfetchable — a retention promise (§6.3.1) the operator
// could not keep.
func TestInitRejectsACollidingURLTemplate(t *testing.T) {
	_, priv := keypair(t)
	for _, tmpl := range []string{"/p/{name}.peipkg", "/p/{version}/x.peipkg", ""} {
		dir := filepath.Join(t.TempDir(), "repo")
		err := repopub.Init(dir, repopub.InitOptions{
			Name: "r", Key: priv, GeneratedAt: at, URLTemplate: tmpl})
		if tmpl == "" {
			if err != nil {
				t.Errorf("an empty template should fall back to the default: %v", err)
			}
			continue
		}
		if err == nil {
			t.Errorf("accepted colliding template %q", tmpl)
		}
	}
}

// --- verify -------------------------------------------------------------

func TestVerifyDetectsACorruptedPackage(t *testing.T) {
	dir, key := newRepo(t)
	p := writePackage(t, t.TempDir(), key, pkgSpec{name: "pkg", version: "1.0-1"})
	publish(t, dir, key, at.Add(time.Hour), p)

	served := filepath.Join(dir, "p", "pkg", "1.0-1", "pkg_1.0-1_x86_64.peipkg")
	raw, err := os.ReadFile(served)
	if err != nil {
		t.Fatalf("reading the served package: %v", err)
	}
	// Flip a byte without changing the length, so only the hash check
	// can catch it — the case --quick is documented to miss.
	raw[len(raw)/2] ^= 0xFF
	if err := os.WriteFile(served, raw, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	rep := mustVerify(t, dir)
	if rep.OK() {
		t.Fatal("verify passed a corrupted package")
	}
	quick, err := repopub.Verify(dir, repopub.VerifyOptions{Quick: true})
	if err != nil {
		t.Fatalf("Verify --quick: %v", err)
	}
	if !quick.OK() {
		t.Error("--quick reported a same-length corruption it cannot detect; " +
			"either it hashed, or it found something else")
	}
}

func TestVerifyDetectsAMissingPackageFile(t *testing.T) {
	dir, key := newRepo(t)
	p := writePackage(t, t.TempDir(), key, pkgSpec{name: "pkg", version: "1.0-1"})
	publish(t, dir, key, at.Add(time.Hour), p)

	if err := os.Remove(filepath.Join(dir, "p", "pkg", "1.0-1",
		"pkg_1.0-1_x86_64.peipkg")); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if rep := mustVerify(t, dir); rep.OK() {
		t.Fatal("verify passed a repository advertising a package it does not hold")
	}
}

// TestVerifyDetectsATornPublish simulates a crash between the two index
// renames. Neither index is wrong on its own, which is exactly why this
// needs a cross-check.
func TestVerifyDetectsATornPublish(t *testing.T) {
	dir, key := newRepo(t)
	p := writePackage(t, t.TempDir(), key, pkgSpec{name: "pkg", version: "1.0-1"})
	publish(t, dir, key, at.Add(time.Hour), p)

	// Restore the archive index from a state one revision older by
	// republishing only it: the simplest faithful stand-in is to copy
	// the active index's predecessor, so instead rewind the archive's
	// index_version directly and re-sign nothing — verify should catch
	// both the disagreement and the broken signature.
	archive := filepath.Join(dir, "index", "archive.json")
	raw, err := os.ReadFile(archive)
	if err != nil {
		t.Fatalf("reading archive: %v", err)
	}
	rewound := strings.Replace(string(raw), `"index_version": 2`, `"index_version": 1`, 1)
	if rewound == string(raw) {
		t.Fatal("test fixture did not rewind index_version")
	}
	if err := os.WriteFile(archive, []byte(rewound), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	rep := mustVerify(t, dir)
	if rep.OK() {
		t.Fatal("verify passed indexes at different index_versions")
	}
	joined := strings.Join(rep.Problems, "\n")
	if !strings.Contains(joined, "rollback") {
		t.Errorf("the torn-publish finding was not reported: %v", rep.Problems)
	}
}

// TestVerifyDetectsAnUnsignedIndex: an index whose signature does not
// verify is one a consumer refuses, so a repository carrying one is
// broken even though every document in it parses.
func TestVerifyDetectsAnUnsignedIndex(t *testing.T) {
	dir, key := newRepo(t)
	p := writePackage(t, t.TempDir(), key, pkgSpec{name: "pkg", version: "1.0-1"})
	publish(t, dir, key, at.Add(time.Hour), p)

	active := filepath.Join(dir, "index", "active.json")
	raw, err := os.ReadFile(active)
	if err != nil {
		t.Fatalf("reading active: %v", err)
	}
	// A cosmetic edit: still valid JSON, still a valid index, no longer
	// the bytes that were signed.
	edited := strings.Replace(string(raw), `"repo": "test-repo"`, `"repo": "test-repo" `, 1)
	if err := os.WriteFile(active, []byte(edited), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	rep := mustVerify(t, dir)
	if rep.OK() {
		t.Fatal("verify passed an index whose signature no longer covers it")
	}
}

func TestVerifyDetectsAMisnamedKeyFile(t *testing.T) {
	dir, key := newRepo(t)
	fp := signature.Fingerprint(key.Public().(ed25519.PublicKey))
	other, _ := keypair(t)
	encoded, err := signature.EncodePublicKey(other)
	if err != nil {
		t.Fatalf("EncodePublicKey: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "keys", fp+".pub"), encoded, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	rep := mustVerify(t, dir)
	if rep.OK() {
		t.Fatal("verify passed a key file holding a different key than it is named for")
	}
}

func TestOpenRejectsANonRepository(t *testing.T) {
	if _, err := repopub.Open(t.TempDir()); err == nil {
		t.Fatal("opened a directory that is not a repository")
	}
}

// --- rebuild ------------------------------------------------------------

// TestRebuildReconstructsFromPackagesOnDisk is the recovery hatch: the
// indexes are assumed wrong, the payload is not.
func TestRebuildReconstructsFromPackagesOnDisk(t *testing.T) {
	dir, key := newRepo(t)
	src := t.TempDir()
	a := writePackage(t, src, key, pkgSpec{name: "pkg", version: "1.0-1"})
	b := writePackage(t, src, key, pkgSpec{name: "pkg", version: "1.0-2"})
	publish(t, dir, key, at.Add(time.Hour), a, b)

	before, err := repopub.Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	res, err := repopub.Publish(dir, repopub.PublishOptions{
		Key: key, GeneratedAt: at.Add(2 * time.Hour), Rebuild: true})
	if err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	if res.ArchiveCount != 2 || res.ActiveCount != 1 {
		t.Fatalf("rebuild produced %d archived / %d active, want 2 / 1",
			res.ArchiveCount, res.ActiveCount)
	}
	// A rebuild is still a publication: the version must advance, or a
	// consumer that already holds the previous one sees no change.
	if res.IndexVersion <= before.Active.IndexVersion {
		t.Errorf("rebuild did not advance index_version: %d after %d",
			res.IndexVersion, before.Active.IndexVersion)
	}
	if rep := mustVerify(t, dir); !rep.OK() {
		t.Errorf("rebuilt repository does not verify: %v", rep.Problems)
	}
}

// TestPublishIsOrderIndependent: an operator supplies a shell glob, and
// glob order is the filesystem's business. The same inputs must produce
// the same indexes however they arrive.
func TestPublishIsOrderIndependent(t *testing.T) {
	// One key and one set of package files for both runs. Signing is
	// deterministic (RFC 8032 §5.1.6) but a fresh key per run would
	// produce different package bytes, and therefore different hashes,
	// which would fail this test for a reason that has nothing to do
	// with ordering.
	_, key := keypair(t)
	src := t.TempDir()
	paths := []string{
		writePackage(t, src, key, pkgSpec{name: "aaa", version: "1.0-1"}),
		writePackage(t, src, key, pkgSpec{name: "zzz", version: "2.0-1"}),
		writePackage(t, src, key, pkgSpec{name: "mmm", version: "1.5-1"}),
	}

	build := func(order []int) string {
		dir := filepath.Join(t.TempDir(), "repo")
		if err := repopub.Init(dir, repopub.InitOptions{
			Name: "test-repo", Key: key, GeneratedAt: at}); err != nil {
			t.Fatalf("Init: %v", err)
		}
		var reordered []string
		for _, i := range order {
			reordered = append(reordered, paths[i])
		}
		publish(t, dir, key, at.Add(time.Hour), reordered...)
		raw, err := os.ReadFile(filepath.Join(dir, "index", "archive.json"))
		if err != nil {
			t.Fatalf("reading archive: %v", err)
		}
		return string(raw)
	}
	forward := build([]int{0, 1, 2})
	backward := build([]int{2, 1, 0})
	if forward != backward {
		t.Errorf("publishing the same packages in a different order produced different indexes:\n"+
			"--- forward ---\n%s\n--- backward ---\n%s", forward, backward)
	}
}
