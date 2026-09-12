package install_test

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/peios/peipkg/internal/install"
	"github.com/peios/peipkg/internal/resolver"
)

// installed installs p into a fresh environment and returns the base
// env a later operation builds on.
func installed(t *testing.T, pkgs ...testPkg) (install.Env, string) {
	t.Helper()
	store, root, lock := freshEnv(t)
	base := install.Env{Root: root, DB: store, LockPath: lock, PeipkgVersion: "0.1.0-test"}
	env := base
	env.Provider = fakeProvider{}
	var ops []resolver.Operation
	for _, p := range pkgs {
		env.Provider.(fakeProvider)[p.name] = provide(t, p)
		ops = append(ops, installOp(t, p.name, p.version))
	}
	if _, err := install.Execute(t.Context(), resolver.Plan{Operations: ops}, env); err != nil {
		t.Fatalf("Execute (install): %v", err)
	}
	return base, root
}

func removeOp(t *testing.T, name, ver string) resolver.Operation {
	return resolver.Operation{Kind: resolver.OpRemove, Name: name, FromVersion: mustVer(t, ver)}
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// The four tests below pin §7.3.2: a configuration file whose content
// no longer matches the recorded hash is surfaced at uninstall, and the
// operator chooses. Before PEI-402 every owned path was renamed aside
// and its backup discarded at commit, with no warning — a customised
// configuration file was destroyed by `peipkg uninstall`.

func TestUninstallAbortsOnAModifiedConfigFileWithoutADecider(t *testing.T) {
	env, root := installed(t, testPkg{name: "app", version: "1.0-1",
		files: map[string]string{"usr/etc/app.conf": "default", "usr/bin/app": "bin"}})
	conf := filepath.Join(root, "usr/etc/app.conf")
	if err := os.WriteFile(conf, []byte("operator's edits"), 0o644); err != nil {
		t.Fatal(err)
	}

	env.Provider = fakeProvider{}
	_, err := install.Execute(t.Context(), resolver.Plan{
		Operations: []resolver.Operation{removeOp(t, "app", "1.0-1")}}, env)
	if err == nil || !strings.Contains(err.Error(), "/usr/etc/app.conf") ||
		!strings.Contains(err.Error(), "modified") {
		t.Fatalf("Execute (remove) = %v, want a refusal naming the modified file", err)
	}
	if got, _ := os.ReadFile(conf); string(got) != "operator's edits" {
		t.Errorf("the modified file was touched by an aborted removal: %q", got)
	}
	if !exists(filepath.Join(root, "usr/bin/app")) {
		t.Error("the aborted removal did not restore the package's other files")
	}
	if _, found, _ := env.DB.GetPackage(t.Context(), "app"); !found {
		t.Error("the aborted removal deregistered the package")
	}
}

func TestUninstallKeepsAModifiedConfigFileOnKeep(t *testing.T) {
	env, root := installed(t, testPkg{name: "app", version: "1.0-1",
		files: map[string]string{"usr/etc/app.conf": "default", "usr/bin/app": "bin"}})
	conf := filepath.Join(root, "usr/etc/app.conf")
	if err := os.WriteFile(conf, []byte("operator's edits"), 0o644); err != nil {
		t.Fatal(err)
	}

	var asked []string
	env.Provider = fakeProvider{}
	env.DecideModified = func(pkg, path string) install.ModifiedDecision {
		asked = append(asked, pkg+" "+path)
		return install.ModifiedKeep
	}
	result, err := install.Execute(t.Context(), resolver.Plan{
		Operations: []resolver.Operation{removeOp(t, "app", "1.0-1")}}, env)
	if err != nil {
		t.Fatalf("Execute (remove): %v", err)
	}
	if len(asked) != 1 || asked[0] != "app /usr/etc/app.conf" {
		t.Errorf("decider asked %v, want exactly the modified config file", asked)
	}
	if got, _ := os.ReadFile(conf); string(got) != "operator's edits" {
		t.Errorf("kept file: content %q, want the operator's edits", got)
	}
	if exists(filepath.Join(root, "usr/bin/app")) {
		t.Error("the package's unmodified file was not removed")
	}
	if _, found, _ := env.DB.GetPackage(t.Context(), "app"); found {
		t.Error("the package is still registered")
	}
	owners, _ := env.DB.FileOwners(t.Context(), "/usr/etc/app.conf")
	if len(owners) != 0 {
		t.Errorf("the kept file still has owners %+v; it should be unowned", owners)
	}
	if !warned(result.Warnings, "/usr/etc/app.conf", "kept") {
		t.Errorf("warnings %v do not say the file was kept", result.Warnings)
	}
}

func TestUninstallRemovesAModifiedConfigFileOnRemoveAndKeepsTheBackup(t *testing.T) {
	env, root := installed(t, testPkg{name: "app", version: "1.0-1",
		files: map[string]string{"usr/etc/app.conf": "default"}})
	conf := filepath.Join(root, "usr/etc/app.conf")
	if err := os.WriteFile(conf, []byte("operator's edits"), 0o644); err != nil {
		t.Fatal(err)
	}

	env.Provider = fakeProvider{}
	env.DecideModified = func(string, string) install.ModifiedDecision {
		return install.ModifiedRemove
	}
	result, err := install.Execute(t.Context(), resolver.Plan{
		Operations: []resolver.Operation{removeOp(t, "app", "1.0-1")}}, env)
	if err != nil {
		t.Fatalf("Execute (remove): %v", err)
	}
	if exists(conf) {
		t.Error("the authorised removal left the file in place")
	}
	// The displaced content survives commit, like an authorised
	// unowned overwrite's does (§7.1.5).
	backups, _ := filepath.Glob(filepath.Join(root, "usr/etc", "*"))
	var kept []byte
	for _, b := range backups {
		kept, _ = os.ReadFile(b)
	}
	if len(backups) != 1 || string(kept) != "operator's edits" {
		t.Errorf("usr/etc holds %v, want exactly one backup carrying the operator's edits", backups)
	}
	if !warned(result.Warnings, "/usr/etc/app.conf", "kept at") {
		t.Errorf("warnings %v do not name the backup", result.Warnings)
	}
}

func TestUninstallDoesNotHashOutsideTheConfigScope(t *testing.T) {
	// §7.3.2's note permits narrowing the check to policy-defined
	// paths; the scope is the one the upgrade's modified-detection
	// uses. A hand-patched binary is removed without a question.
	env, root := installed(t, testPkg{name: "app", version: "1.0-1",
		files: map[string]string{"usr/bin/app": "bin"}})
	if err := os.WriteFile(filepath.Join(root, "usr/bin/app"), []byte("patched"), 0o755); err != nil {
		t.Fatal(err)
	}

	env.Provider = fakeProvider{}
	env.DecideModified = func(pkg, path string) install.ModifiedDecision {
		t.Errorf("decider asked about %s, which is outside the config scope", path)
		return install.ModifiedAbort
	}
	if _, err := install.Execute(t.Context(), resolver.Plan{
		Operations: []resolver.Operation{removeOp(t, "app", "1.0-1")}}, env); err != nil {
		t.Fatalf("Execute (remove): %v", err)
	}
	if exists(filepath.Join(root, "usr/bin/app")) {
		t.Error("the binary was not removed")
	}
}

// §7.3.3: directories a removal leaves unowned and empty are reclaimed,
// deepest first. Before PEI-402 directory rows were skipped outright,
// and because the package's rows were cascaded away with it, the whole
// skeleton was left behind owned by nothing.
func TestUninstallReclaimsEmptyUnownedDirectoriesDeepestFirst(t *testing.T) {
	env, root := installed(t,
		testPkg{name: "app", version: "1.0-1",
			files: map[string]string{"usr/share/app/sub/a": "a", "usr/share/app/b": "b"},
			dirs:  []string{"usr", "usr/share", "usr/share/app", "usr/share/app/sub"}},
		testPkg{name: "other", version: "1.0-1",
			files: map[string]string{"usr/bin/other": "o"},
			dirs:  []string{"usr", "usr/bin"}},
	)

	env.Provider = fakeProvider{}
	result, err := install.Execute(t.Context(), resolver.Plan{
		Operations: []resolver.Operation{removeOp(t, "app", "1.0-1")}}, env)
	if err != nil {
		t.Fatalf("Execute (remove): %v", err)
	}
	for _, gone := range []string{"usr/share/app/sub", "usr/share/app", "usr/share"} {
		if exists(filepath.Join(root, gone)) {
			t.Errorf("%s was left behind, unowned and empty", gone)
		}
	}
	// usr is still owned by "other" (and populated): never a candidate.
	if !exists(filepath.Join(root, "usr/bin/other")) {
		t.Error("the other package's tree was disturbed")
	}
	for _, w := range result.Warnings {
		if strings.Contains(w, "reclaim") {
			t.Errorf("unexpected warning: %s", w)
		}
	}
}

func TestUninstallLeavesADirectoryThatIsStillOwnedOrStillPopulated(t *testing.T) {
	env, root := installed(t,
		testPkg{name: "app", version: "1.0-1",
			files: map[string]string{"usr/share/app/a": "a", "usr/share/app/data/x": "x"},
			dirs:  []string{"usr", "usr/share", "usr/share/app", "usr/share/app/data"}},
		// "shared" owns usr/share/app too, and ships nothing in it.
		testPkg{name: "shared", version: "1.0-1",
			files: map[string]string{"usr/bin/shared": "s"},
			dirs:  []string{"usr", "usr/bin", "usr/share", "usr/share/app"}},
	)
	// A runtime put something unowned under data/.
	unowned := filepath.Join(root, "usr/share/app/data/state.db")
	if err := os.WriteFile(unowned, []byte("state"), 0o644); err != nil {
		t.Fatal(err)
	}

	env.Provider = fakeProvider{}
	result, err := install.Execute(t.Context(), resolver.Plan{
		Operations: []resolver.Operation{removeOp(t, "app", "1.0-1")}}, env)
	if err != nil {
		t.Fatalf("Execute (remove): %v", err)
	}
	if !exists(unowned) || !exists(filepath.Join(root, "usr/share/app/data")) {
		t.Error("a populated directory, or its content, was removed")
	}
	if !exists(filepath.Join(root, "usr/share/app")) {
		t.Error("a directory another package still owns was removed")
	}
	for _, w := range result.Warnings {
		if strings.Contains(w, "reclaim") {
			t.Errorf("a populated directory is not a failure, got warning: %s", w)
		}
	}
}

// §7.2.4: an upgrade reclaims the directories the previous version
// owned that the new payload no longer carries — the same rule, on the
// upgrade's REMOVED set.
func TestUpgradeReclaimsDirectoriesTheNewVersionDropped(t *testing.T) {
	env, root := installed(t, testPkg{name: "app", version: "1.0-1",
		files: map[string]string{"usr/share/app/old/x": "x", "usr/share/app/keep/y": "y"},
		dirs:  []string{"usr", "usr/share", "usr/share/app", "usr/share/app/old", "usr/share/app/keep"}})

	env.Provider = fakeProvider{"app": provide(t, testPkg{name: "app", version: "1.1-1",
		files: map[string]string{"usr/share/app/keep/y": "y2"},
		dirs:  []string{"usr", "usr/share", "usr/share/app", "usr/share/app/keep"}})}
	if _, err := install.Execute(t.Context(), resolver.Plan{
		Operations: []resolver.Operation{upgradeOp(t, "1.0-1", "1.1-1")}}, env); err != nil {
		t.Fatalf("Execute (upgrade): %v", err)
	}
	if exists(filepath.Join(root, "usr/share/app/old")) {
		t.Error("the directory the new version dropped was left behind")
	}
	if !exists(filepath.Join(root, "usr/share/app/keep/y")) {
		t.Error("the directory the new version still ships was disturbed")
	}
}

// §7.3.4: a path scheduled for removal that another installed package
// also owns is the degraded state the schema exists to prevent. It is
// left in place and reported as a database-integrity warning rather
// than removed from under the other owner.
func TestUninstallLeavesAPathAnotherPackageAlsoOwnsAndWarns(t *testing.T) {
	env, root := installed(t,
		testPkg{name: "app", version: "1.0-1", files: map[string]string{
			"usr/bin/tool": "tool", "usr/bin/app": "app"}},
		testPkg{name: "ghost", version: "1.0-1", files: map[string]string{"usr/bin/ghost": "g"}},
	)
	// Forge the overlap the unique index forbids, the way a corrupted
	// or hand-edited database would carry it.
	raw, err := sql.Open("sqlite", filepath.Join(filepath.Dir(root), "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	for _, stmt := range []string{
		"DROP INDEX idx_package_file_collision",
		"INSERT INTO package_file (package_name, path, type, hash) " +
			"SELECT 'ghost', path, type, hash FROM package_file WHERE path = '/usr/bin/tool'",
	} {
		if _, err := raw.Exec(stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}

	env.Provider = fakeProvider{}
	result, err := install.Execute(t.Context(), resolver.Plan{
		Operations: []resolver.Operation{removeOp(t, "app", "1.0-1")}}, env)
	if err != nil {
		t.Fatalf("Execute (remove): %v", err)
	}
	if !exists(filepath.Join(root, "usr/bin/tool")) {
		t.Error("the path ghost also owns was removed from under it")
	}
	if exists(filepath.Join(root, "usr/bin/app")) {
		t.Error("the package's solely-owned file was not removed")
	}
	if !warned(result.Warnings, "database integrity", "/usr/bin/tool") ||
		!warned(result.Warnings, "ghost") {
		t.Errorf("warnings %v do not report the overlap as a database-integrity problem", result.Warnings)
	}
}

// warned reports whether some warning contains every fragment.
func warned(warnings []string, fragments ...string) bool {
	for _, w := range warnings {
		ok := true
		for _, f := range fragments {
			ok = ok && strings.Contains(w, f)
		}
		if ok {
			return true
		}
	}
	return false
}
