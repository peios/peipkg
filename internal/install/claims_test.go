package install_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
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
