package cli

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/peios/peipkg/internal/audit"
	"github.com/peios/peipkg/internal/signature"
)

// drive runs one verb in the driven mode against root, with answers as
// its input, and returns its exit code and the events it wrote.
func drive(t *testing.T, root, answers string, verb string, args ...string) (int, []map[string]any) {
	t.Helper()
	out := &bytes.Buffer{}
	app := newApp(root, strings.NewReader(answers), out, &bytes.Buffer{})
	app.emitter = &audit.Recorder{}
	app.startDriven()
	code := app.run(verb, args)
	var events []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var ev map[string]any
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("output line is not a JSON event: %q", line)
		}
		events = append(events, ev)
	}
	return code, events
}

// kinds lists the events' kinds, questions by their own kind, so a test
// can assert the shape of a conversation in one comparison.
func kinds(events []map[string]any) string {
	var ks []string
	for _, ev := range events {
		k := ev["event"].(string)
		switch k {
		case "question":
			k += ":" + ev["kind"].(string)
		case "progress":
			k += ":" + ev["phase"].(string)
		}
		ks = append(ks, k)
	}
	return strings.Join(ks, " ")
}

// last is a run's terminal event, which every driven run ends with.
func last(t *testing.T, events []map[string]any) map[string]any {
	t.Helper()
	if len(events) == 0 {
		t.Fatal("no events")
	}
	return events[len(events)-1]
}

// localPackage writes a signed package to a file and returns its path.
func localPackage(t *testing.T, name, ver string, files map[string]string) string {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	data, _ := buildSignedPackage(t, priv, pub, name, ver, files)
	path := filepath.Join(t.TempDir(), name+"_"+ver+"_x86_64.peipkg")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write package: %v", err)
	}
	return path
}

func TestDrivenInstallAndRemove(t *testing.T) {
	root := t.TempDir()
	pkg := localPackage(t, "tool", "1.0-1", map[string]string{
		"usr/bin/tool": "tool", "usr/etc/tool.conf": "setting=1\n"})

	code, events := drive(t, root, `{"id":1,"answer":"yes"}`+"\n", "install", pkg)
	if code != 0 {
		t.Fatalf("install exit %d: %v", code, events)
	}
	want := "plan question:proceed progress:fetch progress:stage progress:apply " +
		"progress:commit progress:finish done"
	if got := kinds(events); got != want {
		t.Fatalf("install events:\n got %s\nwant %s", got, want)
	}
	op := events[0]["operations"].([]any)[0].(map[string]any)
	if op["kind"] != "install" || op["name"] != "tool" || op["to"] != "1.0-1" || op["local"] != true {
		t.Errorf("plan operation: %v", op)
	}
	if done := last(t, events); done["transaction"] == nil || done["summary"] != "1 operation applied" {
		t.Errorf("done: %v", done)
	}

	// The configuration file is changed, so removing the package asks
	// about it, after proceed; keeping it leaves it in place.
	conf := filepath.Join(root, "usr/etc/tool.conf")
	if err := os.WriteFile(conf, []byte("setting=2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, events = drive(t, root,
		`{"id":1,"answer":"yes"}`+"\n"+`{"id":2,"answer":"keep"}`+"\n", "uninstall", "tool")
	if code != 0 {
		t.Fatalf("uninstall exit %d: %v", code, events)
	}
	if got := kinds(events); !strings.HasPrefix(got, "plan question:proceed question:modified") ||
		!strings.HasSuffix(got, " done") {
		t.Fatalf("uninstall events: %s", got)
	}
	asked := events[2]
	if asked["package"] != "tool" || asked["path"] != "/usr/etc/tool.conf" || asked["id"] != float64(2) {
		t.Errorf("modified question: %v", asked)
	}
	if got, _ := os.ReadFile(conf); string(got) != "setting=2\n" {
		t.Errorf("kept file: %q", got)
	}
}

func TestDrivenRefusals(t *testing.T) {
	root := t.TempDir()
	pkg := localPackage(t, "tool", "1.0-1", map[string]string{"usr/bin/tool": "tool"})

	// Input closed at the proceed question is a refusal.
	code, events := drive(t, root, "", "install", pkg)
	if code != 0 || kinds(events) != "plan question:proceed cancelled" {
		t.Fatalf("closed input: exit %d, %s", code, kinds(events))
	}
	// So is an answer to some other question, which is also reported.
	_, events = drive(t, root, `{"id":7,"answer":"yes"}`+"\n", "install", pkg)
	if kinds(events) != "plan question:proceed warning cancelled" {
		t.Fatalf("wrong id: %s", kinds(events))
	}
	if _, err := os.Stat(filepath.Join(root, "usr/bin/tool")); !os.IsNotExist(err) {
		t.Fatal("a refused install installed something")
	}
	// --yes would approve a plan the caller never saw.
	code, events = drive(t, root, "", "install", pkg, "--yes")
	if end := last(t, events); code != 1 || end["event"] != "error" || end["code"] != "failed" {
		t.Fatalf("--yes: exit %d, %v", code, end)
	}
	// Removing what is not installed has no plan.
	_, events = drive(t, root, "", "uninstall", "absent")
	if end := last(t, events); end["code"] != "unresolvable" {
		t.Fatalf("absent package: %v", end)
	}
}

// repoServer serves a signed test repository whose active and archive
// indexes the test can replace, and adds it to root.
type repoServer struct {
	t      *testing.T
	priv   ed25519.PrivateKey
	pub    ed25519.PublicKey
	served map[string][]byte
	srv    *httptest.Server
}

func newRepoServer(t *testing.T, root string) *repoServer {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	fp := signature.Fingerprint(pub)
	r := &repoServer{t: t, priv: priv, pub: pub, served: map[string][]byte{}}
	descriptor := mustMarshal(t, map[string]any{
		"schema_version": 1,
		"repo": map[string]any{"name": "test", "signing": map[string]any{
			"algorithm": "ed25519",
			"keys": []any{map[string]any{
				"fingerprint": fp, "url": "/keys/" + fp + ".pub", "status": "active"}}}},
		"indexes": map[string]any{
			"active": map[string]any{
				"url": "/index/active.json", "signature_url": "/index/active.json.sig"},
			"archive": map[string]any{
				"url": "/index/archive.json", "signature_url": "/index/archive.json.sig"}},
	})
	r.served["/repo.json"] = descriptor
	r.served["/repo.json.sig"] = detachedSig(priv, descriptor)
	r.served["/keys/"+fp+".pub"] = []byte(pub)
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if body, ok := r.served[req.URL.Path]; ok {
			_, _ = w.Write(body)
			return
		}
		http.NotFound(w, req)
	}))
	t.Cleanup(r.srv.Close)
	return r
}

// add runs the trust ceremony for the repository on root.
func (r *repoServer) add(root string) {
	r.t.Helper()
	app := newApp(root, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	app.emitter = &audit.Recorder{}
	fp := signature.Fingerprint(r.pub)
	if err := cmdRepoAdd(app, []string{"test", r.srv.URL, "--anchor", fp, "--insecure"}); err != nil {
		r.t.Fatalf("repo add: %v", err)
	}
}

// publish serves widget at each version, the newest active and all in
// the archive, under an index generated generatedAt.
func (r *repoServer) publish(indexVersion int, generatedAt string, versions ...string) {
	r.t.Helper()
	var entries []any
	for _, v := range versions {
		data, installed := buildSignedPackage(r.t, r.priv, r.pub, "widget", v,
			map[string]string{"usr/bin/widget": "widget " + v})
		sum := sha256.Sum256(data)
		url := "/p/widget/" + v + "/widget_" + v + "_x86_64.peipkg"
		r.served[url] = data
		entries = append(entries, map[string]any{
			"name": "widget", "version": v, "architecture": "x86_64",
			"dependencies": []any{}, "conflicts": []any{},
			"size_compressed": len(data), "size_installed": installed,
			"hash": map[string]any{"algorithm": "sha256", "value": hex.EncodeToString(sum[:])},
			"url":  url})
	}
	for kind, pkgs := range map[string][]any{"active": entries[len(entries)-1:], "archive": entries} {
		index := mustMarshal(r.t, map[string]any{
			"schema_version": 1, "repo": "test", "kind": kind,
			"index_version": indexVersion, "generated_at": generatedAt, "packages": pkgs})
		r.served["/index/"+kind+".json"] = index
		r.served["/index/"+kind+".json.sig"] = detachedSig(r.priv, index)
	}
}

func TestDrivenUpdatesAndDowngrade(t *testing.T) {
	root := t.TempDir()
	repo := newRepoServer(t, root)
	repo.publish(1, daysAgo(2), "1.0-1")
	repo.add(root)
	if code, events := drive(t, root, `{"id":1,"answer":"yes"}`+"\n", "install", "widget"); code != 0 {
		t.Fatalf("install: %v", events)
	}

	// A newer version appears. A dry-run upgrade is the list of updates.
	repo.publish(2, daysAgo(1), "1.0-1", "2.0-1")
	if code, events := drive(t, root, "", "refresh"); code != 0 {
		t.Fatalf("refresh: %v", events)
	}
	code, events := drive(t, root, "", "upgrade", "--dry-run")
	if code != 0 || kinds(events) != "plan done" || last(t, events)["summary"] != "dry run" {
		t.Fatalf("dry-run upgrade: exit %d, %v", code, events)
	}
	op := events[0]["operations"].([]any)[0].(map[string]any)
	if op["kind"] != "upgrade" || op["from"] != "1.0-1" || op["to"] != "2.0-1" || op["repository"] != "test" {
		t.Errorf("update: %v", op)
	}
	if code, events := drive(t, root, `{"id":1,"answer":"yes"}`+"\n", "upgrade"); code != 0 {
		t.Fatalf("upgrade: %v", events)
	}

	// A downgrade is an elevated action, asked on its own before
	// proceed; refusing it ends the run without a proceed question.
	_, events = drive(t, root, `{"id":1,"answer":"no"}`+"\n", "downgrade", "widget", "1.0-1")
	if kinds(events) != "plan question:authorise cancelled" {
		t.Fatalf("refused authorisation: %s", kinds(events))
	}
	if auths := events[0]["authorisations"].([]any); len(auths) != 1 || auths[0] != events[1]["text"] {
		t.Errorf("the plan's authorisations and the question differ: %v / %v", auths, events[1])
	}
	if got, _ := os.ReadFile(filepath.Join(root, "usr/bin/widget")); string(got) != "widget 2.0-1" {
		t.Fatalf("a refused downgrade changed the file: %q", got)
	}

}

// TestQueryJSONShapes pins the query commands' JSON: snake_case names, and
// an empty list rather than null when there is nothing to list.
func TestQueryJSONShapes(t *testing.T) {
	root := t.TempDir()
	repo := newRepoServer(t, root)
	repo.publish(1, daysAgo(2), "1.0-1")
	repo.add(root)
	if code, events := drive(t, root, `{"id":1,"answer":"yes"}`+"\n", "install", "widget"); code != 0 {
		t.Fatalf("install: %v", events)
	}
	query := func(args ...string) any {
		t.Helper()
		out := &bytes.Buffer{}
		app := newApp(root, strings.NewReader(""), out, &bytes.Buffer{})
		if code := app.run(args[0], args[1:]); code != 0 {
			t.Fatalf("%v: exit %d", args, code)
		}
		var v any
		if err := json.Unmarshal(out.Bytes(), &v); err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
		return v
	}
	has := func(what string, v any, keys ...string) {
		t.Helper()
		m := v.(map[string]any)
		for _, k := range keys {
			if _, ok := m[k]; !ok {
				t.Errorf("%s has no %q: %v", what, k, m)
			}
		}
	}
	has("list", query("list", "--json").([]any)[0], "name", "version", "architecture", "origin",
		"orphaned", "installed_at", "size_installed")
	has("info", query("info", "--json", "widget"), "name", "version", "origin", "installed_at")
	has("search", query("search", "--json", "widget").([]any)[0], "name", "version",
		"repository", "size_download", "size_installed")
	has("repo list", query("repo", "list", "--json").([]any)[0], "name", "base_url",
		"trust_anchors", "trusted", "last_refresh", "stale", "packages")
	has("files", query("files", "--json", "widget").([]any)[0], "path", "type")
	txn := query("history", "--json").([]any)[0]
	has("history", txn, "id", "state", "started_at", "summary", "operations")
	has("a history operation", txn.(map[string]any)["operations"].([]any)[0], "action", "name", "to")
	if owners := query("owns", "--json", "/usr/bin/widget").([]any); len(owners) != 1 || owners[0] != "widget" {
		t.Errorf("owns: %v", owners)
	}
	if problems := query("verify", "--json", "widget").([]any); len(problems) != 0 {
		t.Errorf("verify --json of an intact package: %v, want []", problems)
	}
	if err := os.WriteFile(filepath.Join(root, "usr/bin/widget"), []byte("changed"), 0o755); err != nil {
		t.Fatal(err)
	}
	has("verify", query("verify", "--json", "widget").([]any)[0], "package", "problem")
	if roles := query("claim", "--json").([]any); len(roles) != 0 {
		t.Errorf("claim --json with no roles: %v, want []", roles)
	}
	if none := query("search", "--json", "no-such-thing"); none == nil || len(none.([]any)) != 0 {
		t.Errorf("search with no match: %v, want []", none)
	}
	if none := query("owns", "--json", "/usr/bin/nothing"); len(none.([]any)) != 0 {
		t.Errorf("owns of an unowned path: %v, want []", none)
	}
}

// A repository configured on disk, as an image ships one, is not trusted
// until its trust ceremony runs; until then everything is refused with the
// code that says so.
func TestDrivenUntrustedRepositoryHasItsCode(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "lcl/conf/peipkg")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	config := "base_url = \"file:///nowhere\"\npriority = 50\nsignature_policy = \"required\"\n" +
		"trust_anchors = [\"" + strings.Repeat("ab", 32) + "\"]\n"
	if err := os.WriteFile(filepath.Join(dir, "medium.repo"), []byte(config), 0o644); err != nil {
		t.Fatal(err)
	}
	code, events := drive(t, root, "", "install", "widget")
	if end := last(t, events); code != 1 || end["code"] != "untrusted" {
		t.Fatalf("untrusted: exit %d, %v", code, end)
	}
}

// A driven transaction outlives the program driving it. This runs peipkg
// as a process of its own, as a program would, so that its events go to a
// real standard output: once proceed is answered the driver closes its
// end and goes, and every event after is a write to a broken pipe. Writing
// to a broken standard output kills a Go program unless it ignores SIGPIPE.
func TestDrivenRunOutlivesItsDriver(t *testing.T) {
	if args := os.Getenv("PEIPKG_TEST_RUN"); args != "" {
		os.Exit(Run(strings.Split(args, "\x1f")))
	}
	root := t.TempDir()
	pkg := localPackage(t, "tool", "1.0-1", map[string]string{"usr/bin/tool": "tool"})
	child := exec.Command(os.Args[0], "-test.run=^TestDrivenRunOutlivesItsDriver$")
	child.Env = append(os.Environ(),
		"PEIPKG_TEST_RUN="+strings.Join([]string{"--root", root, "--driven", "install", pkg}, "\x1f"))
	stdin, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	events := bufio.NewScanner(stdout)
	for events.Scan() {
		if strings.Contains(events.Text(), `"kind":"proceed"`) {
			break
		}
	}
	if _, err := stdin.Write([]byte(`{"id":1,"answer":"yes"}` + "\n")); err != nil {
		t.Fatal(err)
	}
	// The driver goes: nothing reads what peipkg says from here on.
	_ = stdout.Close()
	if err := child.Wait(); err != nil {
		t.Fatalf("peipkg did not finish once its driver went: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(root, "usr/bin/tool")); err != nil || string(got) != "tool" {
		t.Fatalf("the install did not land: %q, %v", got, err)
	}
	out := &bytes.Buffer{}
	if code := newApp(root, strings.NewReader(""), out, &bytes.Buffer{}).run("history", []string{"--json"}); code != 0 ||
		!strings.Contains(out.String(), `"state": "committed"`) {
		t.Fatalf("history: exit %d\n%s", code, out)
	}
}

// An operator who may not read the package database is told so, with the
// code that says it: not that something unrelated failed.
func TestAnUnreadableDatabaseIsDenied(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads everything")
	}
	root := t.TempDir()
	if code, _ := drive(t, root, "", "list"); code != 0 {
		t.Fatal("list on a new root failed")
	}
	db := filepath.Join(root, "var/state/peipkg/db.sqlite")
	if err := os.Chmod(db, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(db, 0o644) })
	code, events := drive(t, root, "", "list", "--json")
	if end := last(t, events); code != 1 || end["code"] != "denied" ||
		!strings.Contains(end["message"].(string), "package database can't be read") {
		t.Fatalf("unreadable database: exit %d, %v", code, end)
	}
}

func TestDrivenStaleMetadataHasItsCode(t *testing.T) {
	// Metadata that refreshing cannot freshen is refused with the code
	// that tells the caller --allow-stale is the way on.
	root := t.TempDir()
	repo := newRepoServer(t, root)
	repo.publish(1, daysAgo(200), "1.0-1")
	repo.add(root)
	code, events := drive(t, root, "", "install", "widget")
	if end := last(t, events); code != 1 || end["code"] != "stale" {
		t.Fatalf("stale: exit %d, %v", code, end)
	}
	code, events = drive(t, root, `{"id":1,"answer":"yes"}`+"\n", "install", "widget", "--allow-stale")
	if code != 0 || last(t, events)["event"] != "done" {
		t.Fatalf("--allow-stale: exit %d, %v", code, events)
	}
	var warned bool
	for _, ev := range events {
		warned = warned || ev["event"] == "warning" && strings.Contains(ev["text"].(string), "--allow-stale")
	}
	if !warned {
		t.Errorf("no warning event for proceeding on stale metadata: %v", events)
	}
}
