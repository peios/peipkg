package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/peios/peipkg/internal/audit"
	"github.com/peios/peipkg/internal/db"
)

func TestClaimDirective(t *testing.T) {
	d, err := claimDirective(false, false, "registryd, logsink ,")
	if err != nil {
		t.Fatalf("claimDirective: %v", err)
	}
	if len(d.Roles) != 2 || d.Roles[0] != "registryd" || d.Roles[1] != "logsink" {
		t.Errorf("Roles: got %v, want [registryd logsink]", d.Roles)
	}
	if _, err := claimDirective(false, true, "registryd"); err == nil {
		t.Error("--claim-all with --claim should be rejected")
	}
	if _, err := claimDirective(true, true, ""); err == nil {
		t.Error("--claim-all with --no-claim should be rejected")
	}
}

// loregdManifest is a full, valid manifest that provides the registryd
// role with a default claim path.
func loregdManifest(t *testing.T) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"schema_version": 1, "name": "loregd", "version": "1.0.0-1", "architecture": "x86_64",
		"dependencies": []any{}, "conflicts": []any{}, "size_installed": 1,
		"provides": []any{map[string]any{"name": "registryd", "claims": map[string]any{
			"binary": map[string]any{"target": "/usr/sbin/loregd", "path": "/usr/sbin/registryd"}}}},
		"build": map[string]any{
			"timestamp": "2026-05-19T00:00:00Z", "farm_id": "t", "source_ref": "t"},
	})
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	return string(b)
}

func TestCmdClaimStatusGrantRevoke(t *testing.T) {
	app, out := testApp(t)
	ctx := context.Background()

	withDB(t, app, func(store *db.DB) {
		if err := store.InsertPackage(ctx, db.Package{
			Name: "loregd", Version: "1.0.0-1", Architecture: "x86_64",
			InstalledAt: time.Unix(1_700_000_000, 0), Manifest: loregdManifest(t)}); err != nil {
			t.Fatalf("InsertPackage: %v", err)
		}
	})

	// Status of an unheld role lists the eligible provider.
	if err := cmdClaim(app, []string{"registryd"}); err != nil {
		t.Fatalf("claim status: %v", err)
	}
	if s := out.String(); !strings.Contains(s, "unheld") || !strings.Contains(s, "loregd") {
		t.Errorf("status output: %q", s)
	}

	// Grant the role to loregd.
	out.Reset()
	if err := cmdClaim(app, []string{"-y", "registryd", "grant", "loregd"}); err != nil {
		t.Fatalf("claim grant: %v", err)
	}
	// On-disk claim links are relative (sibling in /usr/bin).
	if target, err := os.Readlink(filepath.Join(app.paths.root, "usr/sbin/registryd")); err != nil ||
		target != "loregd" {
		t.Errorf("granted symlink: target %q err %v", target, err)
	}
	withDB(t, app, func(store *db.DB) {
		if holder, _, _ := store.ClaimHolder(ctx, "registryd"); holder != "loregd" {
			t.Errorf("holder after grant: %q", holder)
		}
	})
	if !recordedClaimEvent(app) {
		t.Error("grant did not emit a claim audit event")
	}

	// Revoke leaves the role unheld and removes the link.
	out.Reset()
	if err := cmdClaim(app, []string{"-y", "registryd", "revoke"}); err != nil {
		t.Fatalf("claim revoke: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(app.paths.root, "usr/sbin/registryd")); !os.IsNotExist(err) {
		t.Errorf("symlink should be gone after revoke, Lstat err=%v", err)
	}
	withDB(t, app, func(store *db.DB) {
		if _, found, _ := store.ClaimHolder(ctx, "registryd"); found {
			t.Error("registryd should be unheld after revoke")
		}
	})
}

func TestCmdClaimUsageErrors(t *testing.T) {
	app, _ := testApp(t)
	for _, args := range [][]string{
		{},                          // no role
		{"registryd", "frobnicate"}, // unknown subcommand
		{"registryd", "grant"},      // grant without a package
	} {
		if err := cmdClaim(app, args); err == nil {
			t.Errorf("cmdClaim(%v) should have failed", args)
		}
	}
}

func recordedClaimEvent(app *App) bool {
	rec, ok := app.emitter.(*audit.Recorder)
	if !ok {
		return false
	}
	for _, e := range rec.Events {
		if e.Type == audit.TypeClaim && e.Outcome == audit.OutcomeSuccess {
			return true
		}
	}
	return false
}
