package config_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/peios/peipkg/internal/config"
)

// fp is a syntactically valid 64-character lowercase-hex fingerprint.
var fp = strings.Repeat("ab", 32)

// writeRepo writes a .repo file into dir.
func writeRepo(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name+".repo"), []byte(body), 0o644); err != nil {
		t.Fatalf("write %s.repo: %v", name, err)
	}
}

func TestLoadValidRepository(t *testing.T) {
	dir := t.TempDir()
	writeRepo(t, dir, "official", `
base_url = "https://pkgs.peios.org"
priority = 10
signature_policy = "required"
trust_anchors = ["`+fp+`"]
allow_insecure_transport = false
`)
	p := config.NewDirProvider(dir)
	cfg, found, err := p.Repository("official")
	if err != nil || !found {
		t.Fatalf("Repository: found=%v err=%v", found, err)
	}
	if cfg.Name != "official" || cfg.BaseURL != "https://pkgs.peios.org" || cfg.Priority != 10 {
		t.Errorf("config mismatch: %+v", cfg)
	}
	if cfg.SignaturePolicy != config.PolicyRequired {
		t.Errorf("SignaturePolicy: got %q", cfg.SignaturePolicy)
	}
	if len(cfg.TrustAnchors) != 1 || cfg.TrustAnchors[0] != fp {
		t.Errorf("TrustAnchors: got %v", cfg.TrustAnchors)
	}
}

func TestDefaultsApplied(t *testing.T) {
	dir := t.TempDir()
	// A minimal file: only the fields with no sensible default.
	writeRepo(t, dir, "minimal", `
base_url = "https://example.org/peios"
trust_anchors = ["`+fp+`"]
`)
	cfg, _, err := config.NewDirProvider(dir).Repository("minimal")
	if err != nil {
		t.Fatalf("Repository: %v", err)
	}
	if cfg.Priority != 50 {
		t.Errorf("default Priority: got %d, want 50", cfg.Priority)
	}
	if cfg.SignaturePolicy != config.PolicyRequired {
		t.Errorf("default SignaturePolicy: got %q, want required", cfg.SignaturePolicy)
	}
	if cfg.AllowInsecureTransport {
		t.Error("default AllowInsecureTransport: got true, want false")
	}
}

func TestRepositoriesSortedByName(t *testing.T) {
	dir := t.TempDir()
	body := "base_url = \"https://x.example.org\"\ntrust_anchors = [\"" + fp + "\"]\n"
	for _, name := range []string{"universe", "official", "backports"} {
		writeRepo(t, dir, name, body)
	}
	repos, err := config.NewDirProvider(dir).Repositories()
	if err != nil {
		t.Fatalf("Repositories: %v", err)
	}
	got := make([]string, len(repos))
	for i, r := range repos {
		got[i] = r.Name
	}
	if want := []string{"backports", "official", "universe"}; !slices.Equal(got, want) {
		t.Errorf("order: got %v, want %v", got, want)
	}
}

func TestRepositoryNotFound(t *testing.T) {
	p := config.NewDirProvider(t.TempDir())
	if _, found, err := p.Repository("absent"); err != nil || found {
		t.Errorf("Repository of an absent repo: found=%v err=%v", found, err)
	}
}

func TestRepositoriesEmptyOrMissingDir(t *testing.T) {
	repos, err := config.NewDirProvider(filepath.Join(t.TempDir(), "does-not-exist")).Repositories()
	if err != nil {
		t.Fatalf("Repositories of a missing directory: %v", err)
	}
	if len(repos) != 0 {
		t.Errorf("got %d repositories, want 0", len(repos))
	}
}

func TestHTTPAllowedWithInsecureFlag(t *testing.T) {
	dir := t.TempDir()
	writeRepo(t, dir, "dev", `
base_url = "http://localhost:8000"
trust_anchors = ["`+fp+`"]
allow_insecure_transport = true
`)
	if _, _, err := config.NewDirProvider(dir).Repository("dev"); err != nil {
		t.Errorf("an http base_url with allow_insecure_transport should load: %v", err)
	}
}

func TestRejectsInvalidConfig(t *testing.T) {
	cases := map[string]string{
		"base_url with trailing slash":   `base_url = "https://x.example.org/"`,
		"http without the insecure flag": `base_url = "http://x.example.org"`,
		"non-http scheme":                `base_url = "ftp://x.example.org"`,
		"missing base_url":               `priority = 10`,
		"bad signature_policy": `base_url = "https://x.example.org"
signature_policy = "lax"`,
		"non-positive priority": `base_url = "https://x.example.org"
priority = 0`,
		"short trust anchor": `base_url = "https://x.example.org"
trust_anchors = ["abcd"]`,
		"unknown key": `base_url = "https://x.example.org"
flavour = "spicy"`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeRepo(t, dir, "repo", body)
			if _, _, err := config.NewDirProvider(dir).Repository("repo"); err == nil {
				t.Errorf("%s should be rejected", name)
			}
		})
	}
}

func TestPutAndRemove(t *testing.T) {
	p := config.NewDirProvider(t.TempDir())
	want := config.RepoConfig{
		Name:            "custom",
		BaseURL:         "https://custom.example.org",
		Priority:        20,
		SignaturePolicy: config.PolicyOptional,
		TrustAnchors:    []string{fp},
	}
	if err := p.Put(want); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, found, err := p.Repository("custom")
	if err != nil || !found {
		t.Fatalf("Repository after Put: found=%v err=%v", found, err)
	}
	if got.BaseURL != want.BaseURL || got.Priority != want.Priority ||
		got.SignaturePolicy != want.SignaturePolicy {
		t.Errorf("round-trip mismatch: got %+v, want %+v", got, want)
	}

	if err := p.Remove("custom"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, found, _ := p.Repository("custom"); found {
		t.Error("repository still present after Remove")
	}
	// Removing an absent repository is not an error.
	if err := p.Remove("custom"); err != nil {
		t.Errorf("Remove of an absent repository: %v", err)
	}
}

func TestPutRejectsInvalidConfig(t *testing.T) {
	p := config.NewDirProvider(t.TempDir())
	err := p.Put(config.RepoConfig{
		Name: "bad", BaseURL: "https://x.example.org/", // trailing slash
		Priority: 10, SignaturePolicy: config.PolicyRequired,
	})
	if err == nil {
		t.Error("Put should reject an invalid configuration")
	}
}
