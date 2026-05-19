package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/peios/peipkg/internal/db"
	"github.com/peios/peipkg/internal/resolver"
)

// testApp builds an App rooted at a fresh temporary directory and
// returns it with the buffer capturing its standard output.
func testApp(t *testing.T) (*App, *bytes.Buffer) {
	t.Helper()
	out := &bytes.Buffer{}
	app := newApp(t.TempDir(), strings.NewReader(""), out, &bytes.Buffer{})
	return app, out
}

// withDB opens the app's database, runs fn against it, and closes it.
func withDB(t *testing.T, app *App, fn func(store *db.DB)) {
	t.Helper()
	store, err := app.openDB(context.Background())
	if err != nil {
		t.Fatalf("openDB: %v", err)
	}
	fn(store)
	if err := store.Close(); err != nil {
		t.Fatalf("db Close: %v", err)
	}
}

func TestRunRejectsUnknownCommand(t *testing.T) {
	if code := Run([]string{"frobnicate"}); code != 2 {
		t.Errorf("unknown command exit code: got %d, want 2", code)
	}
}

func TestRunRequiresACommand(t *testing.T) {
	if code := Run(nil); code != 2 {
		t.Errorf("no-command exit code: got %d, want 2", code)
	}
}

func TestListInstalledPackages(t *testing.T) {
	app, out := testApp(t)
	withDB(t, app, func(store *db.DB) {
		ctx := context.Background()
		for _, name := range []string{"nginx", "libc"} {
			if err := store.InsertPackage(ctx, db.Package{
				Name: name, Version: "1.0-1", Architecture: "x86_64",
				InstalledAt: time.Unix(1_700_000_000, 0), Manifest: "{}",
			}); err != nil {
				t.Fatalf("InsertPackage %q: %v", name, err)
			}
		}
	})
	if err := cmdList(app, nil); err != nil {
		t.Fatalf("cmdList: %v", err)
	}
	for _, name := range []string{"nginx", "libc"} {
		if !strings.Contains(out.String(), name) {
			t.Errorf("list output is missing %q:\n%s", name, out.String())
		}
	}
}

func TestListEmpty(t *testing.T) {
	app, out := testApp(t)
	if err := cmdList(app, nil); err != nil {
		t.Fatalf("cmdList: %v", err)
	}
	if !strings.Contains(out.String(), "no packages") {
		t.Errorf("empty list output: %q", out.String())
	}
}

func TestListJSON(t *testing.T) {
	app, out := testApp(t)
	withDB(t, app, func(store *db.DB) {
		if err := store.InsertPackage(context.Background(), db.Package{
			Name: "nginx", Version: "1.0-1", Architecture: "x86_64",
			InstalledAt: time.Unix(1_700_000_000, 0), Manifest: "{}",
		}); err != nil {
			t.Fatalf("InsertPackage: %v", err)
		}
	})
	if err := cmdList(app, []string{"--json"}); err != nil {
		t.Fatalf("cmdList --json: %v", err)
	}
	if s := out.String(); !strings.HasPrefix(strings.TrimSpace(s), "[") {
		t.Errorf("--json output is not a JSON array: %q", s)
	}
}

func TestInfoAndFilesAndOwns(t *testing.T) {
	app, out := testApp(t)
	withDB(t, app, func(store *db.DB) {
		ctx := context.Background()
		if err := store.InsertPackage(ctx, db.Package{
			Name: "nginx", Version: "1.26.2-3", Architecture: "x86_64",
			OriginRepo: "official", InstalledAt: time.Unix(1_700_000_000, 0), Manifest: "{}",
		}); err != nil {
			t.Fatalf("InsertPackage: %v", err)
		}
		if err := store.InsertPackageFiles(ctx, []db.PackageFile{
			{PackageName: "nginx", Path: "/usr/bin/nginx", Type: db.FileTypeFile, Hash: "abc"},
		}); err != nil {
			t.Fatalf("InsertPackageFiles: %v", err)
		}
	})

	if err := cmdInfo(app, []string{"nginx"}); err != nil {
		t.Fatalf("cmdInfo: %v", err)
	}
	if !strings.Contains(out.String(), "1.26.2-3") {
		t.Errorf("info output missing the version:\n%s", out.String())
	}

	out.Reset()
	if err := cmdFiles(app, []string{"nginx"}); err != nil {
		t.Fatalf("cmdFiles: %v", err)
	}
	if !strings.Contains(out.String(), "/usr/bin/nginx") {
		t.Errorf("files output missing the path:\n%s", out.String())
	}

	out.Reset()
	if err := cmdOwns(app, []string{"/usr/bin/nginx"}); err != nil {
		t.Fatalf("cmdOwns: %v", err)
	}
	if !strings.Contains(out.String(), "nginx") {
		t.Errorf("owns output missing the owner:\n%s", out.String())
	}
}

func TestInfoUnknownPackage(t *testing.T) {
	app, _ := testApp(t)
	if err := cmdInfo(app, []string{"absent"}); err == nil {
		t.Error("info of an uninstalled package should fail")
	}
}

func TestHistory(t *testing.T) {
	app, out := testApp(t)
	withDB(t, app, func(store *db.DB) {
		ctx := context.Background()
		id, err := store.BeginTxn(ctx, "0.1.0-test", 1)
		if err != nil {
			t.Fatalf("BeginTxn: %v", err)
		}
		if err := store.FinishTxn(ctx, id, db.TxnCommitted, "1 installed"); err != nil {
			t.Fatalf("FinishTxn: %v", err)
		}
	})
	if err := cmdHistory(app, nil); err != nil {
		t.Fatalf("cmdHistory: %v", err)
	}
	if !strings.Contains(out.String(), "installed") {
		t.Errorf("history output missing the summary:\n%s", out.String())
	}
}

func TestRepoList(t *testing.T) {
	app, out := testApp(t)
	if err := os.MkdirAll(app.paths.configDir, 0o755); err != nil {
		t.Fatalf("mkdir config: %v", err)
	}
	repoFile := "base_url = \"https://pkgs.peios.org\"\ntrust_anchors = [\"" +
		strings.Repeat("ab", 32) + "\"]\n"
	if err := os.WriteFile(filepath.Join(app.paths.configDir, "official.repo"),
		[]byte(repoFile), 0o644); err != nil {
		t.Fatalf("write .repo: %v", err)
	}
	if err := cmdRepoList(app, nil); err != nil {
		t.Fatalf("cmdRepoList: %v", err)
	}
	if !strings.Contains(out.String(), "official") {
		t.Errorf("repo list output missing the repository:\n%s", out.String())
	}
}

func TestAuthorizeRequiresExplicitYes(t *testing.T) {
	auths := []resolver.Authorization{{Kind: resolver.AuthLowTrustProvides, Detail: "x"}}

	// End-of-input is a refusal — --yes never reaches this gate.
	app := newApp(t.TempDir(), strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	if app.authorize(auths) {
		t.Error("authorize should refuse on end-of-input")
	}
	// An explicit yes authorises the action.
	app = newApp(t.TempDir(), strings.NewReader("y\n"), &bytes.Buffer{}, &bytes.Buffer{})
	if !app.authorize(auths) {
		t.Error("authorize should accept an explicit yes")
	}
	// With no elevated actions it is a no-op pass.
	app = newApp(t.TempDir(), strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	if !app.authorize(nil) {
		t.Error("authorize should pass when there are no elevated actions")
	}
}

func TestVerify(t *testing.T) {
	app, _ := testApp(t)
	const content = "the tool binary"
	sum := sha256.Sum256([]byte(content))
	withDB(t, app, func(store *db.DB) {
		ctx := context.Background()
		if err := store.InsertPackage(ctx, db.Package{
			Name: "tool", Version: "1.0-1", Architecture: "x86_64",
			InstalledAt: time.Unix(1_700_000_000, 0), Manifest: "{}",
		}); err != nil {
			t.Fatalf("InsertPackage: %v", err)
		}
		if err := store.InsertPackageFiles(ctx, []db.PackageFile{{
			PackageName: "tool", Path: "/usr/bin/tool", Type: db.FileTypeFile,
			Hash: hex.EncodeToString(sum[:]),
		}}); err != nil {
			t.Fatalf("InsertPackageFiles: %v", err)
		}
	})

	toolPath := filepath.Join(app.paths.root, "usr/bin/tool")
	if err := os.MkdirAll(filepath.Dir(toolPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(toolPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	// An intact file verifies.
	if err := cmdVerify(app, []string{"tool"}); err != nil {
		t.Errorf("verify of an intact package: %v", err)
	}
	// A modified file fails verification.
	if err := os.WriteFile(toolPath, []byte("tampered"), 0o644); err != nil {
		t.Fatalf("rewrite file: %v", err)
	}
	if err := cmdVerify(app, []string{"tool"}); err == nil {
		t.Error("verify should fail on a modified file")
	}
}

func TestClean(t *testing.T) {
	app, _ := testApp(t)
	if err := os.MkdirAll(app.paths.cacheDir, 0o755); err != nil {
		t.Fatalf("mkdir cache: %v", err)
	}
	for _, f := range []string{
		"official.active.json", "official.active.json.sig",
		"gone.active.json", "gone.active.json.sig",
	} {
		if err := os.WriteFile(filepath.Join(app.paths.cacheDir, f), []byte("{}"), 0o644); err != nil {
			t.Fatalf("write cache file: %v", err)
		}
	}
	// Only "official" is a configured repository.
	if err := os.MkdirAll(app.paths.configDir, 0o755); err != nil {
		t.Fatalf("mkdir config: %v", err)
	}
	repoFile := "base_url = \"https://pkgs.peios.org\"\ntrust_anchors = [\"" +
		strings.Repeat("ab", 32) + "\"]\n"
	if err := os.WriteFile(filepath.Join(app.paths.configDir, "official.repo"),
		[]byte(repoFile), 0o644); err != nil {
		t.Fatalf("write .repo: %v", err)
	}

	if err := cmdClean(app, nil); err != nil {
		t.Fatalf("cmdClean: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(app.paths.cacheDir, "gone.active.json")); !os.IsNotExist(err) {
		t.Error("the orphaned cache file was not removed")
	}
	if _, err := os.Lstat(filepath.Join(app.paths.cacheDir, "official.active.json")); err != nil {
		t.Error("the configured repository's cache file was removed")
	}
}

func TestInverseRequests(t *testing.T) {
	reqs, err := inverseRequests([]db.TxnOp{
		{PackageName: "fresh", Action: db.OpInstall, ToVersion: "1.0-1"},
		{PackageName: "bumped", Action: db.OpUpgrade, FromVersion: "1.0-1", ToVersion: "2.0-1"},
		{PackageName: "gone", Action: db.OpRemove, FromVersion: "3.0-1"},
	})
	if err != nil {
		t.Fatalf("inverseRequests: %v", err)
	}
	if len(reqs) != 3 {
		t.Fatalf("got %d requests, want 3", len(reqs))
	}
	// An install is undone by a removal.
	if reqs[0].Kind != resolver.Remove || reqs[0].Name != "fresh" {
		t.Errorf("install inverse: %+v", reqs[0])
	}
	// An upgrade is undone by restoring the prior version.
	if reqs[1].Kind != resolver.Downgrade || reqs[1].Version.String() != "1.0-1" {
		t.Errorf("upgrade inverse: %+v", reqs[1])
	}
	// A removal is undone by reinstalling the removed version.
	if reqs[2].Kind != resolver.Downgrade || reqs[2].Version.String() != "3.0-1" {
		t.Errorf("remove inverse: %+v", reqs[2])
	}
}

func TestRecoverNothingPending(t *testing.T) {
	app, out := testApp(t)
	if err := cmdRecover(app, nil); err != nil {
		t.Fatalf("cmdRecover: %v", err)
	}
	if !strings.Contains(out.String(), "no interrupted transaction") {
		t.Errorf("recover output: %q", out.String())
	}
}
