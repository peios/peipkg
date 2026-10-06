package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/peios/peipkg/internal/audit"
	"github.com/peios/peipkg/internal/db"
	"github.com/peios/peipkg/internal/install"
	"github.com/peios/peipkg/internal/resolver"
	"github.com/peios/peipkg/internal/version"
)

// testApp builds an App rooted at a fresh temporary directory and
// returns it with the buffer capturing its standard output.
func testApp(t *testing.T) (*App, *bytes.Buffer) {
	t.Helper()
	out := &bytes.Buffer{}
	app := newApp(t.TempDir(), strings.NewReader(""), out, &bytes.Buffer{})
	app.emitter = &audit.Recorder{} // record audit events instead of emitting to KMES
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

func TestInfoJSON(t *testing.T) {
	app, out := testApp(t)
	withDB(t, app, func(store *db.DB) {
		if err := store.InsertPackage(context.Background(), db.Package{
			Name: "nginx", Version: "1.26.2-3", Architecture: "x86_64",
			OriginRepo: "official", InstalledAt: time.Unix(1_700_000_000, 0), Manifest: "{}",
		}); err != nil {
			t.Fatalf("InsertPackage: %v", err)
		}
	})
	if err := cmdInfo(app, []string{"--json", "nginx"}); err != nil {
		t.Fatalf("cmdInfo --json: %v", err)
	}
	var got struct {
		Name, Version, Origin string
		Orphaned              bool   `json:"orphaned"`
		InstalledAt           string `json:"installed_at"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("--json output does not decode: %v\n%s", err, out.String())
	}
	// "official" is not a configured repository in the test app, so the
	// package reads as orphaned — the same judgement list --json makes.
	if got.Name != "nginx" || got.Version != "1.26.2-3" || got.Origin != "official" ||
		!got.Orphaned || got.InstalledAt == "" {
		t.Errorf("unexpected info --json: %+v", got)
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
	officialLive := "official.active." + strings.Repeat("c", 64) + ".json"
	officialStale := "official.active." + strings.Repeat("d", 64) + ".json"
	for _, f := range []string{
		"official.active.json", "official.active.json.sig",
		officialLive, officialStale,
		"gone.active.json", "gone.active.json.sig",
		"gone.active." + strings.Repeat("a", 64) + ".json",
		"gone.active." + strings.Repeat("b", 64) + ".sig",
	} {
		if err := os.WriteFile(filepath.Join(app.paths.cacheDir, f), []byte("{}"), 0o644); err != nil {
			t.Fatalf("write cache file: %v", err)
		}
	}
	pointer := repositoryCachePointerPrefix + `{"index":"` + officialLive + `"}` + "\n"
	if err := os.WriteFile(filepath.Join(app.paths.cacheDir, "official.active.json"),
		[]byte(pointer), 0o644); err != nil {
		t.Fatalf("write cache pointer: %v", err)
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
	if _, err := os.Lstat(filepath.Join(app.paths.cacheDir,
		"gone.active."+strings.Repeat("a", 64)+".json")); !os.IsNotExist(err) {
		t.Error("the orphaned cache object was not removed")
	}
	if _, err := os.Lstat(filepath.Join(app.paths.cacheDir, "official.active.json")); err != nil {
		t.Error("the configured repository's cache file was removed")
	}
	if _, err := os.Lstat(filepath.Join(app.paths.cacheDir, officialLive)); err != nil {
		t.Error("the configured repository's live cache object was removed")
	}
	if _, err := os.Lstat(filepath.Join(app.paths.cacheDir, officialStale)); !os.IsNotExist(err) {
		t.Error("the configured repository's stale cache object was not removed")
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

func TestAuditFailedResolutionEmitsEvent(t *testing.T) {
	app, _ := testApp(t)
	rec := app.emitter.(*audit.Recorder)
	if err := cmdInstall(app, []string{"nonexistent"}); err == nil {
		t.Fatal("install of an unknown package should fail")
	}
	// §7.6: a refused request writes one failed record per package it
	// named, with no transaction, since none opened.
	if len(rec.Events) != 1 || rec.Events[0].Type != audit.TypePackageInstalled {
		t.Fatalf("expected one failed peipkg.package.installed record, got %+v", rec.Events)
	}
	e := rec.Events[0]
	for path, want := range map[string]any{
		audit.FieldOutcomeSuccess: false,
		audit.FieldOutcomeReason:  "unresolvable",
		audit.FieldPackageName:    "nonexistent",
	} {
		if got, _ := e.Get(path); got != want {
			t.Errorf("%s = %v, want %v", path, got, want)
		}
	}
	if _, ok := e.Get(audit.FieldTransactionID); ok {
		t.Error("a refused request carries transaction.id")
	}
	if d, _ := e.Get(audit.FieldOutcomeDetail); d == nil {
		t.Error("a refused request carries no outcome.detail")
	}
}

// An upgrade of everything names no package; its refusal is one record
// without object.package.name.
func TestAuditRefusedUpgradeOfEverythingNamesNoPackage(t *testing.T) {
	app, _ := testApp(t)
	rec := app.emitter.(*audit.Recorder)
	reqs := []resolver.Request{{Kind: resolver.Upgrade}, {Kind: resolver.Upgrade}}
	app.emitRefused(reqs, fmt.Errorf("boom"))
	if len(rec.Events) != 1 || rec.Events[0].Type != audit.TypePackageUpgraded {
		t.Fatalf("got %+v, want one peipkg.package.upgraded", rec.Events)
	}
	if _, ok := rec.Events[0].Get(audit.FieldPackageName); ok {
		t.Error("an upgrade of everything named a package")
	}
	if r, _ := rec.Events[0].Get(audit.FieldOutcomeReason); r != "failed" {
		t.Errorf("outcome.reason = %v, want failed", r)
	}
}

// Each operation of a plan is its own record, typed by what happened to
// that package: an upgrade that pulls in a dependency installs it, a
// downgrade is an upgrade with the versions reversed, and a removal has
// no architecture or source.
func TestAuditPlanWritesOneRecordPerOperation(t *testing.T) {
	app, _ := testApp(t)
	rec := app.emitter.(*audit.Recorder)
	v := func(s string) version.Version {
		ver, err := version.Parse(s)
		if err != nil {
			t.Fatal(err)
		}
		return ver
	}
	plan := resolver.Plan{Operations: []resolver.Operation{
		{Kind: resolver.OpRemove, Name: "old", FromVersion: v("1.0-1")},
		{Kind: resolver.OpInstall, Name: "dep", ToVersion: v("2.0-1"),
			Candidate: &resolver.Candidate{Architecture: "noarch", Repo: "main"}},
		{Kind: resolver.OpDowngrade, Name: "app", FromVersion: v("3.0-1"), ToVersion: v("2.5-1"),
			Candidate: &resolver.Candidate{Architecture: "x86_64", Repo: "archive"}},
	}}
	app.emitPlan(plan, func(resolver.Operation) int64 { return 9 }, nil)
	want := []struct {
		typ    string
		fields map[string]any
		absent []string
	}{
		{audit.TypePackageUninstalled, map[string]any{
			audit.FieldPackageName: "old", audit.FieldPackageVersion: "1.0-1"},
			[]string{audit.FieldPackageArchitecture, audit.FieldSourceRepository, audit.FieldPackageVersionPrev}},
		{audit.TypePackageInstalled, map[string]any{
			audit.FieldPackageName: "dep", audit.FieldPackageVersion: "2.0-1",
			audit.FieldPackageArchitecture: "noarch", audit.FieldSourceRepository: "main"},
			[]string{audit.FieldPackageVersionPrev}},
		{audit.TypePackageUpgraded, map[string]any{
			audit.FieldPackageName: "app", audit.FieldPackageVersion: "2.5-1",
			audit.FieldPackageVersionPrev: "3.0-1", audit.FieldSourceRepository: "archive"},
			nil},
	}
	if len(rec.Events) != len(want) {
		t.Fatalf("got %d records, want %d: %+v", len(rec.Events), len(want), rec.Events)
	}
	for i, w := range want {
		e := rec.Events[i]
		if e.Type != w.typ {
			t.Errorf("record %d: type %q, want %q", i, e.Type, w.typ)
		}
		w.fields[audit.FieldTransactionID] = uint64(9)
		w.fields[audit.FieldOutcomeSuccess] = true
		for p, val := range w.fields {
			if got, _ := e.Get(p); got != val {
				t.Errorf("record %d: %s = %v, want %v", i, p, got, val)
			}
		}
		for _, p := range w.absent {
			if got, ok := e.Get(p); ok {
				t.Errorf("record %d: %s = %v, want absent", i, p, got)
			}
		}
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
	// Every run is recorded, one with nothing to recover included.
	recs := app.emitter.(*audit.Recorder).OfType(audit.TypeTransactionRecovered)
	if len(recs) != 1 {
		t.Fatalf("got %d peipkg.transaction.recovered records, want 1", len(recs))
	}
	if n, _ := recs[0].Get(audit.FieldOperationSucceeded); n != uint64(0) {
		t.Errorf("operation.succeeded-count = %v, want 0", n)
	}
	if s, _ := recs[0].Get(audit.FieldOutcomeSuccess); s != true {
		t.Errorf("outcome.success = %v, want true", s)
	}
}

// A recover that fails is recorded as failed (PEI-617: no record was
// written on recover's failure paths).
func TestRecoverFailureIsRecorded(t *testing.T) {
	app, _ := testApp(t)
	// A root whose state directory is a file cannot be opened.
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "var"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	app.setRoot(root)
	if err := cmdRecover(app, nil); err == nil {
		t.Fatal("recover in an unusable root succeeded")
	}
	recs := app.emitter.(*audit.Recorder).OfType(audit.TypeTransactionRecovered)
	if len(recs) != 1 {
		t.Fatalf("got %d peipkg.transaction.recovered records, want 1", len(recs))
	}
	if s, _ := recs[0].Get(audit.FieldOutcomeSuccess); s != false {
		t.Errorf("outcome.success = %v, want false", s)
	}
	if _, ok := recs[0].Get(audit.FieldOutcomeDetail); !ok {
		t.Error("a failed recover carries no outcome.detail")
	}
}

// §7.3.2: the modified-file decision at uninstall is a deliberate
// per-file act. Only an explicit remove or keep answers it; end-of-input
// — which is what --yes leaves on stdin — aborts (PEI-402).
func TestDecideModifiedRequiresAnExplicitAnswer(t *testing.T) {
	cases := map[string]install.ModifiedDecision{
		"":         install.ModifiedAbort,
		"y\n":      install.ModifiedAbort,
		"a\n":      install.ModifiedAbort,
		"r\n":      install.ModifiedRemove,
		"remove\n": install.ModifiedRemove,
		"k\n":      install.ModifiedKeep,
		"KEEP\n":   install.ModifiedKeep,
	}
	for input, want := range cases {
		out := &bytes.Buffer{}
		app := newApp(t.TempDir(), strings.NewReader(input), out, &bytes.Buffer{})
		rec := &audit.Recorder{}
		app.emitter = rec
		if got := app.decideModified("app", "/usr/etc/app.conf"); got != want {
			t.Errorf("decideModified with input %q = %v, want %v", input, got, want)
		}
		if !strings.Contains(out.String(), "/usr/etc/app.conf") {
			t.Errorf("the prompt does not name the file:\n%s", out.String())
		}
		// Every answer is recorded: only remove authorises the removal;
		// keep and abort decline it.
		recs := rec.OfType(audit.TypeActionAuthorised)
		if len(recs) != 1 {
			t.Fatalf("input %q: %d peipkg.action.authorised records, want 1", input, len(recs))
		}
		for path, w := range map[string]any{
			audit.FieldOperationName:  audit.ActionRemoveModifiedFile,
			audit.FieldPackageName:    "app",
			audit.FieldFilePath:       "/usr/etc/app.conf",
			audit.FieldOutcomeSuccess: want == install.ModifiedRemove,
		} {
			if got, _ := recs[0].Get(path); got != w {
				t.Errorf("input %q: %s = %v, want %v", input, path, got, w)
			}
		}
	}
}

// §7.6.6: each elevated action put to the operator is recorded with its
// answer, a refusal included, and the first refusal stops the rest.
func TestAuthorizeRecordsEveryAnswer(t *testing.T) {
	auths := []resolver.Authorization{
		{Kind: resolver.AuthDowngrade, Package: "app", Detail: "app would move backward"},
		{Kind: resolver.AuthForeignReplaces, Package: "fork", Detail: "fork replaces app"},
		{Kind: resolver.AuthLowTrustProvides, Package: "sub", Detail: "sub provides dep"},
	}
	app := newApp(t.TempDir(), strings.NewReader("y\nn\ny\n"), &bytes.Buffer{}, &bytes.Buffer{})
	rec := &audit.Recorder{}
	app.emitter = rec
	if app.authorize(auths) {
		t.Fatal("authorize returned true after a refusal")
	}
	recs := rec.OfType(audit.TypeActionAuthorised)
	want := []map[string]any{
		{audit.FieldOperationName: audit.ActionDowngrade, audit.FieldPackageName: "app",
			audit.FieldOutcomeSuccess: true, audit.FieldOutcomeDetail: "app would move backward"},
		{audit.FieldOperationName: audit.ActionForeignReplaces, audit.FieldPackageName: "fork",
			audit.FieldOutcomeSuccess: false, audit.FieldOutcomeDetail: "fork replaces app"},
	}
	if len(recs) != len(want) {
		t.Fatalf("got %d records, want %d: %+v", len(recs), len(want), recs)
	}
	for i, fields := range want {
		for path, w := range fields {
			if got, _ := recs[i].Get(path); got != w {
				t.Errorf("record %d: %s = %v, want %v", i, path, got, w)
			}
		}
	}
}
