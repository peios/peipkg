package cli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/peios/peipkg/internal/audit"
	"github.com/peios/peipkg/internal/signature"
)

// altPkg describes one package version an altRepo serves.
type altPkg struct {
	name, ver string
	files     map[string]string
	extra     map[string]any // manifest fields merged in (e.g. alternate_upgrade)
	index     map[string]any // index-entry fields merged in
}

// altRepo is a signed test repository whose active index can be
// re-published mid-test, so an upgrade can be exercised: publish v1,
// install, publish v2, refresh, upgrade.
type altRepo struct {
	t      *testing.T
	pub    ed25519.PublicKey
	priv   ed25519.PrivateKey
	fp     string
	mu     sync.Mutex
	served map[string][]byte
	srv    *httptest.Server
	ver    int
}

func newAltRepo(t *testing.T) *altRepo {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	r := &altRepo{t: t, pub: pub, priv: priv, fp: signature.Fingerprint(pub),
		served: map[string][]byte{}}
	descriptor := mustMarshal(t, map[string]any{
		"schema_version": 1,
		"repo": map[string]any{"name": "test", "signing": map[string]any{
			"algorithm": "ed25519",
			"keys": []any{map[string]any{
				"fingerprint": r.fp, "url": "/keys/" + r.fp + ".pub", "status": "active"}}}},
		"indexes": map[string]any{
			"active": map[string]any{
				"url": "/index/active.json", "signature_url": "/index/active.json.sig"},
			"archive": map[string]any{
				"url": "/index/archive.json", "signature_url": "/index/archive.json.sig"}},
	})
	r.served["/repo.json"] = descriptor
	r.served["/repo.json.sig"] = detachedSig(priv, descriptor)
	r.served["/keys/"+r.fp+".pub"] = []byte(pub)
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		body, ok := r.served[req.URL.Path]
		r.mu.Unlock()
		if ok {
			_, _ = w.Write(body)
			return
		}
		http.NotFound(w, req)
	}))
	t.Cleanup(r.srv.Close)
	return r
}

// publish builds and serves pkgs as the repository's whole active index,
// bumping index_version so a refresh accepts it.
func (r *altRepo) publish(pkgs ...altPkg) {
	r.t.Helper()
	r.ver++
	var entries []any
	r.mu.Lock()
	defer r.mu.Unlock()
	// The index is sorted by name (§5.33).
	sort.Slice(pkgs, func(i, j int) bool { return pkgs[i].name < pkgs[j].name })
	for _, p := range pkgs {
		data, installed := buildSignedPackageEx(r.t, r.priv, r.pub, p.name, p.ver, p.files, p.extra)
		sum := sha256.Sum256(data)
		url := "/p/" + p.name + "/" + p.ver + "/" + p.name + "_" + p.ver + "_x86_64.peipkg"
		r.served[url] = data
		entry := map[string]any{
			"name": p.name, "version": p.ver, "architecture": "x86_64",
			"dependencies": []any{}, "conflicts": []any{},
			"size_compressed": len(data), "size_installed": installed,
			"hash": map[string]any{"algorithm": "sha256", "value": hex.EncodeToString(sum[:])},
			"url":  url,
		}
		for k, v := range p.index {
			entry[k] = v
		}
		entries = append(entries, entry)
	}
	index := mustMarshal(r.t, map[string]any{
		"schema_version": 1, "repo": "test", "kind": "active",
		"index_version": r.ver, "generated_at": daysAgo(2),
		"packages": entries,
	})
	r.served["/index/active.json"] = index
	r.served["/index/active.json.sig"] = detachedSig(r.priv, index)
}

// altApp builds an App with the repository added and its stderr captured.
func (r *altRepo) altApp() (*App, *bytes.Buffer, *bytes.Buffer) {
	r.t.Helper()
	out, errOut := &bytes.Buffer{}, &bytes.Buffer{}
	app := newApp(r.t.TempDir(), strings.NewReader(""), out, errOut)
	app.emitter = &audit.Recorder{}
	if err := cmdRepoAdd(app, []string{"test", r.srv.URL, "--anchor", r.fp, "--insecure"}); err != nil {
		r.t.Fatalf("repo add: %v", err)
	}
	return app, out, errOut
}

const editionMessage = "This edition is upgraded with upgrade-peios.\nRun: upgrade-peios --to 2.0"

// editionPkg is an OS-edition-style package declaring alternate_upgrade
// in both its manifest and its index entry.
func editionPkg(ver, content string) altPkg {
	alt := map[string]any{"message": editionMessage}
	return altPkg{name: "edition", ver: ver,
		files: map[string]string{"usr/share/edition-release": content},
		extra: map[string]any{"alternate_upgrade": alt},
		index: map[string]any{"alternate_upgrade": alt}}
}

func widgetPkg(ver, content string) altPkg {
	return altPkg{name: "widget", ver: ver, files: map[string]string{"usr/bin/widget": content}}
}

// wantRefusal is the exact §5.18 rule-1 error text for the edition package.
const wantRefusal = "The package \"edition\" has an alternate upgrade path.\n\n" +
	editionMessage + "\n\n" +
	"Warning: Alternate upgrade paths may bypass normal peipkg protections; " +
	"ensure you fully trust the authors of the package before running.\n" +
	"peipkg proceeds only with --bypass-alternate-upgrade."

func readRoot(app *App, rel string) string {
	b, _ := os.ReadFile(filepath.Join(app.paths.root, rel))
	return string(b)
}

// TestInstallRefusesAlternateUpgrade: naming an alternate-upgrade package
// is refused with the exact §5.18 report, nothing is applied, and the
// override lets it through.
func TestInstallRefusesAlternateUpgrade(t *testing.T) {
	repo := newAltRepo(t)
	repo.publish(editionPkg("1.0-1", "edition 1"))
	app, _, _ := repo.altApp()

	err := cmdInstall(app, []string{"edition", "--yes"})
	if err == nil {
		t.Fatal("install of an alternate-upgrade package succeeded without the override")
	}
	if err.Error() != wantRefusal {
		t.Errorf("refusal text:\ngot:\n%s\nwant:\n%s", err.Error(), wantRefusal)
	}
	if got := readRoot(app, "usr/share/edition-release"); got != "" {
		t.Errorf("payload was applied despite the refusal: %q", got)
	}

	if err := cmdInstall(app, []string{"edition", "--yes", "--bypass-alternate-upgrade"}); err != nil {
		t.Fatalf("install with --bypass-alternate-upgrade: %v", err)
	}
	if got := readRoot(app, "usr/share/edition-release"); got != "edition 1" {
		t.Errorf("after bypassed install: content %q, want %q", got, "edition 1")
	}
}

// TestInstallRefusesAlternateUpgradeAsDependency: a plan that would pull
// the package in as a dependency of something else is refused too.
func TestInstallRefusesAlternateUpgradeAsDependency(t *testing.T) {
	repo := newAltRepo(t)
	dep := []any{map[string]any{"name": "edition"}}
	repo.publish(editionPkg("1.0-1", "edition 1"), altPkg{
		name: "app", ver: "1.0-1", files: map[string]string{"usr/bin/app": "app"},
		extra: map[string]any{"dependencies": dep},
		index: map[string]any{"dependencies": dep},
	})
	app, _, _ := repo.altApp()

	err := cmdInstall(app, []string{"app", "--yes"})
	if err == nil || err.Error() != wantRefusal {
		t.Fatalf("install via dependency: got %v, want the refusal", err)
	}
	if readRoot(app, "usr/bin/app") != "" {
		t.Error("app was installed despite its dependency's refusal")
	}
}

// TestLocalInstallRefusesAlternateUpgrade: a raw .peipkg file install is
// subject to the same refusal — the declaration is in the manifest.
func TestLocalInstallRefusesAlternateUpgrade(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	data, _ := buildSignedPackageEx(t, priv, pub, "edition", "1.0-1",
		map[string]string{"usr/share/edition-release": "edition 1"},
		map[string]any{"alternate_upgrade": map[string]any{"message": editionMessage}})
	path := filepath.Join(t.TempDir(), "edition_1.0-1_x86_64.peipkg")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	app, _ := testApp(t)
	if err := cmdInstall(app, []string{path, "--yes"}); err == nil || err.Error() != wantRefusal {
		t.Fatalf("local install: got %v, want the refusal", err)
	}
	if err := cmdInstall(app, []string{path, "--yes", "--bypass-alternate-upgrade"}); err != nil {
		t.Fatalf("local install with the override: %v", err)
	}
}

// TestUpgradeHoldsBackAlternateUpgrade: an every-package upgrade holds
// the edition back, reports it on stderr, upgrades everything else and
// succeeds; naming it is refused; the override upgrades it.
func TestUpgradeHoldsBackAlternateUpgrade(t *testing.T) {
	repo := newAltRepo(t)
	repo.publish(editionPkg("1.0-1", "edition 1"), widgetPkg("1.0-1", "widget 1"))
	app, out, errOut := repo.altApp()
	if err := cmdInstall(app, []string{"edition", "widget", "--yes", "--bypass-alternate-upgrade"}); err != nil {
		t.Fatalf("initial install: %v", err)
	}

	repo.publish(editionPkg("2.0-1", "edition 2"), widgetPkg("2.0-1", "widget 2"))
	if err := cmdRefresh(app, nil); err != nil {
		t.Fatalf("refresh: %v", err)
	}

	out.Reset()
	errOut.Reset()
	if err := cmdUpgrade(app, []string{"--yes"}); err != nil {
		t.Fatalf("bulk upgrade should hold back, not fail: %v", err)
	}
	if got := readRoot(app, "usr/bin/widget"); got != "widget 2" {
		t.Errorf("widget after bulk upgrade: %q, want %q", got, "widget 2")
	}
	if got := readRoot(app, "usr/share/edition-release"); got != "edition 1" {
		t.Errorf("edition after bulk upgrade: %q, want it held at %q", got, "edition 1")
	}
	wantBlock := "The package \"edition\" has an alternate upgrade path.\n\n" + editionMessage +
		"\n\nWarning: Alternate upgrade paths may bypass normal peipkg protections; " +
		"ensure you fully trust the authors of the package before running.\n" +
		"held back: edition 1.0-1 -> 2.0-1\n"
	if !strings.Contains(errOut.String(), wantBlock) {
		t.Errorf("hold-back report:\ngot:\n%s\nwant to contain:\n%s", errOut.String(), wantBlock)
	}
	if n := strings.Count(errOut.String(), "held back: edition"); n != 1 {
		t.Errorf("held back reported %d times, want once", n)
	}

	// Naming it is rule 1: refused.
	if err := cmdUpgrade(app, []string{"edition", "--yes"}); err == nil || err.Error() != wantRefusal {
		t.Fatalf("named upgrade: got %v, want the refusal", err)
	}
	if got := readRoot(app, "usr/share/edition-release"); got != "edition 1" {
		t.Errorf("edition after refused upgrade: %q", got)
	}

	// The override includes it normally.
	if err := cmdUpgrade(app, []string{"--yes", "--bypass-alternate-upgrade"}); err != nil {
		t.Fatalf("bulk upgrade with the override: %v", err)
	}
	if got := readRoot(app, "usr/share/edition-release"); got != "edition 2" {
		t.Errorf("edition after bypassed upgrade: %q, want %q", got, "edition 2")
	}
}

// TestUpgradeHoldBackAlone: when the held package is the only thing
// that would move, the upgrade reports it and does nothing else.
func TestUpgradeHoldBackAlone(t *testing.T) {
	repo := newAltRepo(t)
	repo.publish(editionPkg("1.0-1", "edition 1"))
	app, out, errOut := repo.altApp()
	if err := cmdInstall(app, []string{"edition", "--yes", "--bypass-alternate-upgrade"}); err != nil {
		t.Fatalf("initial install: %v", err)
	}
	repo.publish(editionPkg("2.0-1", "edition 2"))
	if err := cmdRefresh(app, nil); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	out.Reset()
	if err := cmdUpgrade(app, []string{"--yes"}); err != nil {
		t.Fatalf("bulk upgrade: %v", err)
	}
	if !strings.Contains(errOut.String(), "held back: edition 1.0-1 -> 2.0-1") {
		t.Errorf("missing hold-back line:\n%s", errOut.String())
	}
	if !strings.Contains(out.String(), "nothing to do") {
		t.Errorf("expected an empty plan after the hold-back:\n%s", out.String())
	}
}

// TestInfoShowsAlternateUpgrade: info prints the message under its
// heading.
func TestInfoShowsAlternateUpgrade(t *testing.T) {
	repo := newAltRepo(t)
	repo.publish(editionPkg("1.0-1", "edition 1"))
	app, out, _ := repo.altApp()
	if err := cmdInstall(app, []string{"edition", "--yes", "--bypass-alternate-upgrade"}); err != nil {
		t.Fatalf("install: %v", err)
	}
	out.Reset()
	if err := cmdInfo(app, []string{"edition"}); err != nil {
		t.Fatalf("info: %v", err)
	}
	if !strings.Contains(out.String(), "Alternate upgrade path:\n"+editionMessage+"\n") {
		t.Errorf("info output:\n%s", out.String())
	}
}
