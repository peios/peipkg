package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/peios/peipkg/internal/audit"
	"github.com/peios/peipkg/internal/config"
	"github.com/peios/peipkg/internal/signature"
)

// serveMinimalRepo stands up a repository serving nothing but a signed
// descriptor and a signed empty active index — everything the §6.5.2
// trust ceremony touches, and no more.
func serveMinimalRepo(t *testing.T, name string) (url, fingerprint string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	fp := signature.Fingerprint(pub)

	descriptor := mustMarshal(t, map[string]any{
		"schema_version": 1,
		"repo": map[string]any{"name": name, "signing": map[string]any{
			"algorithm": "ed25519",
			"keys": []any{map[string]any{
				"fingerprint": fp, "url": "/keys/" + fp + ".pub", "status": "active"}}}},
		"indexes": map[string]any{
			"active": map[string]any{
				"url": "/index/active.json", "signature_url": "/index/active.json.sig"},
			"archive": map[string]any{
				"url": "/index/archive.json", "signature_url": "/index/archive.json.sig"}},
	})
	index := mustMarshal(t, map[string]any{
		"schema_version": 1, "repo": name, "kind": "active",
		"index_version": 1, "generated_at": daysAgo(2),
		"packages": []any{},
	})
	served := map[string][]byte{
		"/repo.json":             descriptor,
		"/repo.json.sig":         detachedSig(priv, descriptor),
		"/keys/" + fp + ".pub":   []byte(pub),
		"/index/active.json":     index,
		"/index/active.json.sig": detachedSig(priv, index),
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if body, ok := served[r.URL.Path]; ok {
			_, _ = w.Write(body)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, fp
}

// writeRepoConfig drops a .repo file into the app's config directory,
// standing in for what an image bakes in.
func writeRepoConfig(t *testing.T, app *App, cfg config.RepoConfig) {
	t.Helper()
	if err := app.configProvider().Put(cfg); err != nil {
		t.Fatalf("writing .repo: %v", err)
	}
}

// TestRepoAddConfiguredForm covers the shape an image uses: the .repo
// file is already on disk, carrying its own trust anchors, and the
// operator (or an installer) performs the ceremony without retyping a
// 64-character fingerprint that is sitting right there.
func TestRepoAddConfiguredForm(t *testing.T) {
	app, out := testApp(t)
	url, fp := serveMinimalRepo(t, "medium")

	writeRepoConfig(t, app, config.RepoConfig{
		Name: "medium", BaseURL: url, Priority: 10,
		SignaturePolicy: config.PolicyRequired,
		TrustAnchors:    []string{fp},
		// httptest serves http, which the config layer refuses without
		// this. A real medium repository is file://, which needs nothing.
		AllowInsecureTransport: true,
	})

	if err := cmdRepoAdd(app, []string{"medium"}); err != nil {
		t.Fatalf("repo add (configured form): %v", err)
	}

	// Trust state is recorded, which is the whole point: before the
	// ceremony a configured repository is skipped by every operation.
	out.Reset()
	if err := cmdRepoList(app, nil); err != nil {
		t.Fatalf("repo list: %v", err)
	}
	if !strings.Contains(out.String(), "medium") {
		t.Errorf("the added repository is not listed:\n%s", out.String())
	}
}

func TestRepoAddConfiguredFormRejectsAnUnknownName(t *testing.T) {
	app, _ := testApp(t)
	err := cmdRepoAdd(app, []string{"nothing-here"})
	if err == nil {
		t.Fatal("added a repository that is not configured")
	}
	if !strings.Contains(err.Error(), "no repository named") {
		t.Errorf("unhelpful error: %v", err)
	}
}

// TestRepoAddConfiguredFormRejectsAnchorlessConfig: without an anchor
// there is nothing to verify the descriptor against, so the ceremony
// would either fail confusingly or fall through to the unsigned path.
func TestRepoAddConfiguredFormRejectsAnchorlessConfig(t *testing.T) {
	app, _ := testApp(t)
	url, _ := serveMinimalRepo(t, "medium")
	writeRepoConfig(t, app, config.RepoConfig{
		Name: "medium", BaseURL: url, Priority: 10,
		SignaturePolicy: config.PolicyRequired, AllowInsecureTransport: true,
	})
	err := cmdRepoAdd(app, []string{"medium"})
	if err == nil {
		t.Fatal("added an anchorless repository under the required policy")
	}
	if !strings.Contains(err.Error(), "trust_anchors") {
		t.Errorf("the error does not name what is missing: %v", err)
	}
}

// TestRepoAddConfiguredFormKeepsConfigOnFailure is the distinction that
// matters between the two forms. When `repo add <name> <url>` writes the
// config and the ceremony fails, backing the file out is right — nothing
// else put it there. In the configured form the file came from an image
// or a configuration manager, and deleting it because a ceremony failed
// would turn a retryable failure (medium not mounted yet) into lost
// configuration.
func TestRepoAddConfiguredFormKeepsConfigOnFailure(t *testing.T) {
	app, _ := testApp(t)
	url, _ := serveMinimalRepo(t, "medium")

	// A valid-looking anchor that is not the repository's key, so the
	// ceremony fails at exactly the step it is meant to.
	stranger, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	writeRepoConfig(t, app, config.RepoConfig{
		Name: "medium", BaseURL: url, Priority: 10,
		SignaturePolicy:        config.PolicyRequired,
		TrustAnchors:           []string{signature.Fingerprint(stranger)},
		AllowInsecureTransport: true,
	})

	if err := cmdRepoAdd(app, []string{"medium"}); err == nil {
		t.Fatal("the ceremony succeeded against the wrong anchor")
	}
	if _, found, err := app.configProvider().Repository("medium"); err != nil || !found {
		t.Errorf("a failed ceremony deleted configuration this command did not write "+
			"(found=%v, err=%v)", found, err)
	}
}

// TestRepoAddTwoArgFormStillRollsBack pins the other half: the form that
// DOES write the config must still clean up after a failed ceremony.
func TestRepoAddTwoArgFormStillRollsBack(t *testing.T) {
	app, _ := testApp(t)
	url, _ := serveMinimalRepo(t, "medium")
	stranger, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	err = cmdRepoAdd(app, []string{"medium", url,
		"--anchor", signature.Fingerprint(stranger), "--insecure"})
	if err == nil {
		t.Fatal("the ceremony succeeded against the wrong anchor")
	}
	if _, found, err := app.configProvider().Repository("medium"); err != nil || found {
		t.Errorf("a failed repo add left configuration behind (found=%v, err=%v)", found, err)
	}
}

// TestConfigIsReadFromRealStorageNotTheView pins the reason peipkg
// addresses lcl/conf/peipkg rather than conf/peipkg.
//
// /conf is a StrataFS view over /lcl/conf and /usr/conf, mounted at boot
// by a prelude hook onto the root being pivoted into. A root that has
// not been booted — an installer's mounted target, a chroot being
// prepared, a composed image — has no such view, so reading through
// conf/ finds nothing there and reports "no repositories configured"
// while the file sits in plain sight one directory away.
//
// This test is written against the layout of an offline root on purpose:
// a test that set up conf/peipkg/ would pass against either
// implementation and prove nothing.
func TestConfigIsReadFromRealStorageNotTheView(t *testing.T) {
	app, _ := testApp(t)
	root := app.paths.root

	// Exactly what an installer sees after copying a system onto a
	// target: real strata present, view mountpoints empty or absent.
	if err := os.MkdirAll(filepath.Join(root, "lcl/conf/peipkg"), 0o755); err != nil {
		t.Fatal(err)
	}
	repo := "base_url = \"file:///media/peios/repo\"\n" +
		"priority = 50\n" +
		"signature_policy = \"required\"\n" +
		"trust_anchors = [\"" + strings.Repeat("a", 64) + "\"]\n"
	if err := os.WriteFile(
		filepath.Join(root, "lcl/conf/peipkg/peios-medium.repo"), []byte(repo), 0o644); err != nil {
		t.Fatal(err)
	}

	repos, err := app.configProvider().Repositories()
	if err != nil {
		t.Fatalf("Repositories: %v", err)
	}
	if len(repos) != 1 {
		t.Fatalf("an offline root's configuration is invisible: got %d repositories, want 1",
			len(repos))
	}
	if repos[0].Name != "peios-medium" {
		t.Errorf("name = %q, want %q", repos[0].Name, "peios-medium")
	}
	if repos[0].BaseURL != "file:///media/peios/repo" {
		t.Errorf("base_url = %q", repos[0].BaseURL)
	}

	// And nothing was created at the view's mountpoint, which on a booted
	// system is owned by StrataFS and not ours to write into.
	if _, err := os.Stat(filepath.Join(root, "conf")); !os.IsNotExist(err) {
		t.Errorf("peipkg created <root>/conf, which is a view mountpoint (err = %v)", err)
	}
}

// TestRepoAddWritesToRealStorage: a repository added at runtime must land
// where the next offline read will find it, so a system that added a
// repository and was then installed carries that configuration forward.
func TestRepoAddWritesToRealStorage(t *testing.T) {
	app, _ := testApp(t)
	url, fp := serveMinimalRepo(t, "medium")

	if err := cmdRepoAdd(app, []string{"medium", url, "--anchor", fp, "--insecure"}); err != nil {
		t.Fatalf("repo add: %v", err)
	}
	if _, err := os.Stat(
		filepath.Join(app.paths.root, "lcl/conf/peipkg/medium.repo")); err != nil {
		t.Errorf("repo add did not write to lcl/conf/peipkg: %v", err)
	}
}

// §7.6.3.1 emits peipkg.config-change for "a trust-policy or
// transport-flag change". The event type was declared and referenced by
// nothing — not one emission site, not one test — so an operator
// re-adding an existing repository with a weakened policy produced an
// audit trail identical to a routine add, and trust-policy history could
// not be reconstructed from the event stream at all.
func TestRepoAddEmitsConfigChangeWhenTrustPolicyWeakens(t *testing.T) {
	app, _ := testApp(t)
	url, fp := serveMinimalRepo(t, "medium")
	rec := app.emitter.(*audit.Recorder)

	add := func(policy string) error {
		return cmdRepoAdd(app, []string{
			"--anchor", fp, "--insecure", "--policy", policy, "medium", url})
	}

	if err := add("required"); err != nil {
		t.Fatalf("repo add (first): %v", err)
	}
	// A first add is fully described by peipkg.repo-add; there is no
	// prior policy to have changed.
	if n := countEvents(rec, audit.TypeConfigChange); n != 0 {
		t.Fatalf("a first add emitted %d config-change events, want 0", n)
	}

	// The operator re-adds the same repository, downgrading the policy.
	rec.Events = nil
	if err := add("optional"); err != nil {
		t.Fatalf("repo add (weakened): %v", err)
	}

	var change *audit.Event
	for i := range rec.Events {
		if rec.Events[i].Type == audit.TypeConfigChange {
			change = &rec.Events[i]
		}
	}
	if change == nil {
		t.Fatalf("weakening signature_policy emitted no config-change event; got %+v", rec.Events)
	}
	if change.Repo != "medium" {
		t.Errorf("config-change Repo = %q, want %q", change.Repo, "medium")
	}
	// The detail has to carry both values, or the event records that
	// something changed without recording what it changed from.
	for _, want := range []string{"signature_policy", "required", "optional"} {
		if !strings.Contains(change.Detail, want) {
			t.Errorf("config-change Detail %q does not mention %q", change.Detail, want)
		}
	}
}

// Re-running the ceremony with nothing altered must stay quiet, or the
// event loses its meaning: every routine re-add would look like a policy
// change.
func TestRepoAddEmitsNoConfigChangeWhenNothingChanged(t *testing.T) {
	app, _ := testApp(t)
	url, fp := serveMinimalRepo(t, "medium")
	rec := app.emitter.(*audit.Recorder)

	add := func() error {
		return cmdRepoAdd(app, []string{
			"--anchor", fp, "--insecure", "--policy", "required", "medium", url})
	}
	if err := add(); err != nil {
		t.Fatalf("repo add (first): %v", err)
	}
	rec.Events = nil
	if err := add(); err != nil {
		t.Fatalf("repo add (repeat): %v", err)
	}
	if n := countEvents(rec, audit.TypeConfigChange); n != 0 {
		t.Errorf("an unchanged re-add emitted %d config-change events, want 0", n)
	}
}

func countEvents(rec *audit.Recorder, typ string) int {
	var n int
	for _, e := range rec.Events {
		if e.Type == typ {
			n++
		}
	}
	return n
}
