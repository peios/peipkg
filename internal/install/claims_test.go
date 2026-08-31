package install_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/peios/peipkg/internal/archive"
	"github.com/peios/peipkg/internal/install"
	"github.com/peios/peipkg/internal/manifest"
	"github.com/peios/peipkg/internal/resolver"
)

// claimProvide builds a verified package with a full, round-trippable
// manifest carrying the given provides and dependencies arrays — claims
// reconciliation reads the stored manifest, so the fixture must decode.
func claimProvide(t *testing.T, p testPkg, provides, deps []any) install.ProvidedPackage {
	t.Helper()
	if deps == nil {
		deps = []any{}
	}
	if provides == nil {
		provides = []any{}
	}
	m := map[string]any{
		"schema_version": 1,
		"name":           p.name,
		"version":        p.version,
		"architecture":   "x86_64",
		"dependencies":   deps,
		"conflicts":      []any{},
		"provides":       provides,
		"size_installed": 1,
		"build": map[string]any{
			"timestamp": "2026-05-19T12:00:00Z", "farm_id": "f", "source_ref": "s"},
	}
	js, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	decoded, err := manifest.Decode(js)
	if err != nil {
		t.Fatalf("decode fixture manifest: %v", err)
	}
	var payload []archive.PayloadEntry
	for path, content := range p.files {
		sum := sha256.Sum256([]byte(content))
		payload = append(payload, archive.PayloadEntry{
			Path: path, Type: archive.EntryFile,
			Size: int64(len(content)), Hash: hex.EncodeToString(sum[:])})
	}
	pkg := &archive.Package{Manifest: decoded, ManifestJSON: js, Payload: payload}
	return install.ProvidedPackage{Pkg: pkg, Archive: bytes.NewReader(archiveBytes(t, p))}
}

// providesRole is a provides entry for role with a binary slot target and
// optional default path.
func providesRole(role, target, defaultPath string) []any {
	slot := map[string]any{"target": target}
	if defaultPath != "" {
		slot["path"] = defaultPath
	}
	return []any{map[string]any{
		"name": role, "claims": map[string]any{"binary": slot}}}
}

// dependsRole is a dependency entry on role declaring a binary claim path.
func dependsRole(role, path string) []any {
	return []any{map[string]any{
		"name": role, "claims": map[string]any{"binary": map[string]any{"path": path}}}}
}

func TestExecuteAutoClaimWithDefaultPath(t *testing.T) {
	ctx := t.Context()
	store, root, lock := freshEnv(t)
	loregd := testPkg{name: "loregd", version: "1.0-1",
		files: map[string]string{"usr/sbin/loregd": "the daemon"}}
	env := install.Env{Root: root, DB: store, LockPath: lock, PeipkgVersion: "test",
		Provider: fakeProvider{"loregd": claimProvide(t, loregd,
			providesRole("registryd", "/usr/sbin/loregd", "/usr/sbin/registryd"), nil)}}
	plan := resolver.Plan{Operations: []resolver.Operation{installOp(t, "loregd", "1.0-1")}}

	if _, err := install.Execute(ctx, plan, env); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	// The role is auto-claimed and the default path materialised.
	if holder, found, _ := store.ClaimHolder(ctx, "registryd"); !found || holder != "loregd" {
		t.Errorf("ClaimHolder: %q found=%v, want loregd", holder, found)
	}
	// Relative target (link lives in /usr/bin, points at sibling loregd).
	target, err := os.Readlink(filepath.Join(root, "usr/sbin/registryd"))
	if err != nil || target != "loregd" {
		t.Errorf("claim symlink: target %q err %v, want loregd", target, err)
	}
	if links, _ := store.ClaimLinks(ctx); len(links) != 1 {
		t.Errorf("ClaimLinks: got %+v, want 1", links)
	}
}

func TestExecuteRetroactiveMaterialisation(t *testing.T) {
	ctx := t.Context()
	store, root, lock := freshEnv(t)

	// Install the holder with no default path and no consumer: held but
	// unmaterialised (§4.4.4).
	loregd := testPkg{name: "loregd", version: "1.0-1",
		files: map[string]string{"usr/sbin/loregd": "the daemon"}}
	env := install.Env{Root: root, DB: store, LockPath: lock, PeipkgVersion: "test",
		Provider: fakeProvider{"loregd": claimProvide(t, loregd,
			providesRole("registryd", "/usr/sbin/loregd", ""), nil)}}
	if _, err := install.Execute(ctx,
		resolver.Plan{Operations: []resolver.Operation{installOp(t, "loregd", "1.0-1")}}, env); err != nil {
		t.Fatalf("Execute loregd: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "usr/sbin/registryd")); !os.IsNotExist(err) {
		t.Fatalf("registryd should not exist yet, Lstat err=%v", err)
	}
	if holder, found, _ := store.ClaimHolder(ctx, "registryd"); !found || holder != "loregd" {
		t.Fatalf("role should be held-but-unmaterialised; holder=%q found=%v", holder, found)
	}

	// Install a consumer declaring the path: it materialises retroactively
	// against the holder already on record.
	peinit := testPkg{name: "peinit", version: "1.0-1",
		files: map[string]string{"usr/bin/peinit": "init"}}
	env.Provider = fakeProvider{"peinit": claimProvide(t, peinit, nil,
		dependsRole("registryd", "/usr/sbin/registryd"))}
	if _, err := install.Execute(ctx,
		resolver.Plan{Operations: []resolver.Operation{installOp(t, "peinit", "1.0-1")}}, env); err != nil {
		t.Fatalf("Execute peinit: %v", err)
	}
	target, err := os.Readlink(filepath.Join(root, "usr/sbin/registryd"))
	if err != nil || target != "loregd" {
		t.Errorf("retroactive symlink: target %q err %v", target, err)
	}
}

func TestExecuteWithdrawalOnHolderRemoval(t *testing.T) {
	ctx := t.Context()
	store, root, lock := freshEnv(t)

	// loregd holds registryd (auto, default path); altregd also provides
	// it but is installed second, so it does not become holder.
	loregd := testPkg{name: "loregd", version: "1.0-1",
		files: map[string]string{"usr/sbin/loregd": "d"}}
	altregd := testPkg{name: "altregd", version: "1.0-1",
		files: map[string]string{"usr/bin/altregd": "d"}}
	env := install.Env{Root: root, DB: store, LockPath: lock, PeipkgVersion: "test",
		Provider: fakeProvider{"loregd": claimProvide(t, loregd,
			providesRole("registryd", "/usr/sbin/loregd", "/usr/sbin/registryd"), nil)}}
	if _, err := install.Execute(ctx,
		resolver.Plan{Operations: []resolver.Operation{installOp(t, "loregd", "1.0-1")}}, env); err != nil {
		t.Fatalf("Execute loregd: %v", err)
	}
	env.Provider = fakeProvider{"altregd": claimProvide(t, altregd,
		providesRole("registryd", "/usr/bin/altregd", "/usr/sbin/registryd"), nil)}
	if _, err := install.Execute(ctx,
		resolver.Plan{Operations: []resolver.Operation{installOp(t, "altregd", "1.0-1")}}, env); err != nil {
		t.Fatalf("Execute altregd: %v", err)
	}
	if holder, _, _ := store.ClaimHolder(ctx, "registryd"); holder != "loregd" {
		t.Fatalf("loregd should still hold registryd, got %q", holder)
	}

	// Uninstall the holder: the claim is withdrawn, the link removed, and
	// a warning names the remaining provider (§7.7.6).
	removeOp := resolver.Operation{Kind: resolver.OpRemove, Name: "loregd", FromVersion: mustVer(t, "1.0-1")}
	res, err := install.Execute(ctx, resolver.Plan{Operations: []resolver.Operation{removeOp}}, env)
	if err != nil {
		t.Fatalf("Execute remove: %v", err)
	}
	if _, found, _ := store.ClaimHolder(ctx, "registryd"); found {
		t.Error("registryd should be unheld after holder removal")
	}
	if _, err := os.Lstat(filepath.Join(root, "usr/sbin/registryd")); !os.IsNotExist(err) {
		t.Errorf("claim symlink should be gone, Lstat err=%v", err)
	}
	if !hasWarning(res.Warnings, "withdrawn") || !hasWarning(res.Warnings, "altregd") {
		t.Errorf("expected a withdrawal warning naming altregd, got %v", res.Warnings)
	}
}

func TestClaimGrantAndRevoke(t *testing.T) {
	ctx := t.Context()
	store, root, lock := freshEnv(t)
	env := install.Env{Root: root, DB: store, LockPath: lock, PeipkgVersion: "test"}

	// loregd auto-holds registryd; altregd is installed but not holder.
	for _, name := range []string{"loregd", "altregd"} {
		pkg := testPkg{name: name, version: "1.0-1",
			files: map[string]string{"usr/sbin/" + name: "d"}}
		env.Provider = fakeProvider{name: claimProvide(t, pkg,
			providesRole("registryd", "/usr/sbin/"+name, "/usr/sbin/registryd"), nil)}
		if _, err := install.Execute(ctx,
			resolver.Plan{Operations: []resolver.Operation{installOp(t, name, "1.0-1")}}, env); err != nil {
			t.Fatalf("Execute %s: %v", name, err)
		}
	}
	if target, _ := os.Readlink(filepath.Join(root, "usr/sbin/registryd")); target != "loregd" {
		t.Fatalf("initial holder link: %q, want loregd", target)
	}

	// Grant the role to altregd: the holder changes and the link repoints.
	if _, err := install.Claim(ctx, env,
		install.ClaimRequest{Role: "registryd", Holder: "altregd"}); err != nil {
		t.Fatalf("Claim grant: %v", err)
	}
	if holder, _, _ := store.ClaimHolder(ctx, "registryd"); holder != "altregd" {
		t.Errorf("holder after grant: %q, want altregd", holder)
	}
	if target, _ := os.Readlink(filepath.Join(root, "usr/sbin/registryd")); target != "altregd" {
		t.Errorf("link after grant: %q, want altregd", target)
	}

	// Revoke: the role goes unheld and the link is removed.
	if _, err := install.Claim(ctx, env, install.ClaimRequest{Role: "registryd"}); err != nil {
		t.Fatalf("Claim revoke: %v", err)
	}
	if _, found, _ := store.ClaimHolder(ctx, "registryd"); found {
		t.Error("registryd should be unheld after revoke")
	}
	if _, err := os.Lstat(filepath.Join(root, "usr/sbin/registryd")); !os.IsNotExist(err) {
		t.Errorf("link should be gone after revoke, Lstat err=%v", err)
	}
}

func TestClaimGrantRejectsIneligible(t *testing.T) {
	ctx := t.Context()
	store, root, lock := freshEnv(t)
	env := install.Env{Root: root, DB: store, LockPath: lock, PeipkgVersion: "test"}
	// nginx provides no role, so it cannot hold registryd.
	nginx := testPkg{name: "nginx", version: "1.0-1",
		files: map[string]string{"usr/bin/nginx": "n"}}
	env.Provider = fakeProvider{"nginx": claimProvide(t, nginx, nil, nil)}
	if _, err := install.Execute(ctx,
		resolver.Plan{Operations: []resolver.Operation{installOp(t, "nginx", "1.0-1")}}, env); err != nil {
		t.Fatalf("Execute nginx: %v", err)
	}
	if _, err := install.Claim(ctx, env,
		install.ClaimRequest{Role: "registryd", Holder: "nginx"}); err == nil {
		t.Fatal("granting to an ineligible package should fail")
	}
	if _, err := install.Claim(ctx, env, install.ClaimRequest{Role: "registryd"}); err == nil {
		t.Fatal("revoking an unheld role should fail")
	}
}

func hasWarning(warnings []string, substr string) bool {
	for _, w := range warnings {
		if bytes.Contains([]byte(w), []byte(substr)) {
			return true
		}
	}
	return false
}

// §5.23: a claim path must not collide with a path owned by any
// installed package, judged against the state the transaction will
// produce rather than the state it started from.
//
// Reading package_file asks the pre-transaction question, because an
// in-flight package's rows are not written until commit — so installing
// the owner and the provider together passed the check and committed
// both a package_file row and a claim_link row for one path (PEI-391).
func TestClaimPathCollidesWithAPayloadInTheSameTransaction(t *testing.T) {
	ctx := t.Context()
	store, root, lock := freshEnv(t)

	// One package owns /usr/sbin/registryd as payload; another provides
	// the role whose default claim path is exactly that.
	owner := testPkg{name: "otherd", version: "1.0-1",
		files: map[string]string{"usr/sbin/registryd": "somebody else's binary"}}
	loregd := testPkg{name: "loregd", version: "1.0-1",
		files: map[string]string{"usr/sbin/loregd": "the daemon"}}
	env := install.Env{Root: root, DB: store, LockPath: lock, PeipkgVersion: "test",
		Provider: fakeProvider{
			"otherd": claimProvide(t, owner, nil, nil),
			"loregd": claimProvide(t, loregd,
				providesRole("registryd", "/usr/sbin/loregd", "/usr/sbin/registryd"), nil),
		}}
	plan := resolver.Plan{Operations: []resolver.Operation{
		installOp(t, "otherd", "1.0-1"),
		installOp(t, "loregd", "1.0-1"),
	}}
	_, err := install.Execute(ctx, plan, env)
	if err == nil {
		t.Fatal("a claim path colliding with a payload path in the same transaction was allowed")
	}
	if !strings.Contains(err.Error(), "owned by package otherd") {
		t.Errorf("error %q does not name the owning package", err)
	}
}

// The symmetric false positive: uninstalling the owner in the same
// transaction that materialises the claim is legal, because the
// post-transaction state has no collision.
func TestClaimPathFreedByARemovalInTheSameTransaction(t *testing.T) {
	ctx := t.Context()
	store, root, lock := freshEnv(t)

	owner := testPkg{name: "otherd", version: "1.0-1",
		files: map[string]string{"usr/sbin/registryd": "somebody else's binary"}}
	env := install.Env{Root: root, DB: store, LockPath: lock, PeipkgVersion: "test",
		Provider: fakeProvider{"otherd": claimProvide(t, owner, nil, nil)}}
	if _, err := install.Execute(ctx,
		resolver.Plan{Operations: []resolver.Operation{installOp(t, "otherd", "1.0-1")}},
		env); err != nil {
		t.Fatalf("installing the owner: %v", err)
	}

	loregd := testPkg{name: "loregd", version: "1.0-1",
		files: map[string]string{"usr/sbin/loregd": "the daemon"}}
	env.Provider = fakeProvider{"loregd": claimProvide(t, loregd,
		providesRole("registryd", "/usr/sbin/loregd", "/usr/sbin/registryd"), nil)}
	plan := resolver.Plan{Operations: []resolver.Operation{
		{Kind: resolver.OpRemove, Name: "otherd", FromVersion: mustVer(t, "1.0-1")},
		installOp(t, "loregd", "1.0-1"),
	}}
	if _, err := install.Execute(ctx, plan, env); err != nil {
		t.Fatalf("the owner is removed in the same transaction, so there is no collision: %v", err)
	}
	if target, err := os.Readlink(filepath.Join(root, "usr/sbin/registryd")); err != nil ||
		target != "loregd" {
		t.Errorf("claim symlink: target %q err %v", target, err)
	}
}

// §5.23: the materialised links must at all times equal the
// cross-product of a role's slots and its holder's declarations. A
// payload entry landing on a live claim path was planned as an ordinary
// replace, and reconciliation could never repair it — claims.Reconcile
// diffs the recorded link set against the desired one, both agree the
// link exists, and it never looks at disk (PEI-392).
func TestPayloadCannotBeInstalledOverALiveClaimLink(t *testing.T) {
	ctx := t.Context()
	store, root, lock := freshEnv(t)

	loregd := testPkg{name: "loregd", version: "1.0-1",
		files: map[string]string{"usr/sbin/loregd": "the daemon"}}
	env := install.Env{Root: root, DB: store, LockPath: lock, PeipkgVersion: "test",
		Provider: fakeProvider{"loregd": claimProvide(t, loregd,
			providesRole("registryd", "/usr/sbin/loregd", "/usr/sbin/registryd"), nil)}}
	if _, err := install.Execute(ctx,
		resolver.Plan{Operations: []resolver.Operation{installOp(t, "loregd", "1.0-1")}},
		env); err != nil {
		t.Fatalf("installing the holder: %v", err)
	}

	// A second package whose payload wants the materialised claim path.
	squatter := testPkg{name: "squatter", version: "1.0-1",
		files: map[string]string{"usr/sbin/registryd": "not the role's binary"}}
	env.Provider = fakeProvider{"squatter": claimProvide(t, squatter, nil, nil)}
	_, err := install.Execute(ctx,
		resolver.Plan{Operations: []resolver.Operation{installOp(t, "squatter", "1.0-1")}}, env)
	if err == nil {
		t.Fatal("a payload path was installed over a live claim link")
	}
	if !strings.Contains(err.Error(), "claim path of role registryd") {
		t.Errorf("error %q does not name the role whose link it protected", err)
	}
	// The link is intact and still agrees with the database.
	if target, err := os.Readlink(filepath.Join(root, "usr/sbin/registryd")); err != nil ||
		target != "loregd" {
		t.Errorf("the claim link was disturbed: target %q err %v", target, err)
	}
}

// §5.23: a provider's claim target names a path the declaring package
// itself installs. The only check was pack's, called by pekit — a
// producer-side lint that says nothing about a package built anywhere
// else, which the format explicitly contemplates (PEI-394).
func TestClaimTargetMustBeThePackagesOwnPayload(t *testing.T) {
	ctx := t.Context()
	store, root, lock := freshEnv(t)

	// The target names a path this package does not ship.
	loregd := testPkg{name: "loregd", version: "1.0-1",
		files: map[string]string{"usr/sbin/loregd": "the daemon"}}
	env := install.Env{Root: root, DB: store, LockPath: lock, PeipkgVersion: "test",
		Provider: fakeProvider{"loregd": claimProvide(t, loregd,
			providesRole("registryd", "/usr/sbin/somebody-elses-binary", "/usr/sbin/registryd"),
			nil)}}
	_, err := install.Execute(ctx,
		resolver.Plan{Operations: []resolver.Operation{installOp(t, "loregd", "1.0-1")}}, env)
	if err == nil {
		t.Fatal("a claim target outside the package's own payload was accepted")
	}
	if !strings.Contains(err.Error(), "not a path this package ships") {
		t.Errorf("error %q does not explain the refusal", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "usr/sbin/registryd")); !os.IsNotExist(err) {
		t.Errorf("a dangling claim link was materialised anyway (err %v)", err)
	}
}

// §5.23: each repoint of a holder swap is atomic, so no consumer of a
// claim path ever observes it absent. It was two renames — the old link
// aside, then the new one in — so a supervisor exec'ing the path during
// `peipkg claim <role> grant <pkg>` got ENOENT, in a window covering a
// full rename round-trip on every link of the role (PEI-393).
func TestClaimRepointNeverLeavesThePathAbsent(t *testing.T) {
	ctx := t.Context()
	store, root, lock := freshEnv(t)
	path := filepath.Join(root, "usr/sbin/registryd")

	loregd := testPkg{name: "loregd", version: "1.0-1",
		files: map[string]string{"usr/sbin/loregd": "the daemon"}}
	altregd := testPkg{name: "altregd", version: "1.0-1",
		files: map[string]string{"usr/sbin/altregd": "the other daemon"}}
	env := install.Env{Root: root, DB: store, LockPath: lock, PeipkgVersion: "test",
		Provider: fakeProvider{
			"loregd": claimProvide(t, loregd,
				providesRole("registryd", "/usr/sbin/loregd", "/usr/sbin/registryd"), nil),
			"altregd": claimProvide(t, altregd,
				providesRole("registryd", "/usr/sbin/altregd", "/usr/sbin/registryd"), nil),
		}}
	if _, err := install.Execute(ctx,
		resolver.Plan{Operations: []resolver.Operation{installOp(t, "loregd", "1.0-1")}},
		env); err != nil {
		t.Fatalf("installing the first holder: %v", err)
	}
	if _, err := install.Execute(ctx,
		resolver.Plan{Operations: []resolver.Operation{installOp(t, "altregd", "1.0-1")}},
		env); err != nil {
		t.Fatalf("installing the second provider: %v", err)
	}

	// Watch the path for as long as the repoint takes. A two-rename
	// repoint leaves a window; an exchange does not.
	stop := make(chan struct{})
	missing := make(chan string, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := os.Lstat(path); err != nil {
				select {
				case missing <- err.Error():
				default:
				}
				return
			}
		}
	}()

	if _, err := install.Claim(ctx, env,
		install.ClaimRequest{Role: "registryd", Holder: "altregd"}); err != nil {
		close(stop)
		<-done
		t.Fatalf("repointing the role: %v", err)
	}
	close(stop)
	<-done
	select {
	case err := <-missing:
		t.Errorf("the claim path was absent during the repoint: %s", err)
	default:
	}

	if target, err := os.Readlink(path); err != nil || target != "altregd" {
		t.Errorf("after the repoint: target %q err %v, want altregd", target, err)
	}
	if holder, found, _ := store.ClaimHolder(ctx, "registryd"); !found || holder != "altregd" {
		t.Errorf("ClaimHolder: %q found=%v, want altregd", holder, found)
	}
}
