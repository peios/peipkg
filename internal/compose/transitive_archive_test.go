package compose

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/peios/peipkg/internal/config"
	"github.com/peios/peipkg/internal/signature"
)

// An unconstrained top-level request can still require an archived package:
// split package revisions commonly depend on an exact runtime revision. A
// shared scan must also cover such constraints in local candidate manifests.
func TestTransitiveArchiveDiscovery(t *testing.T) {
	for _, local := range []bool{false, true} {
		name := "repository-dependency"
		if local {
			name = "local-dependency"
		}
		t.Run(name, func(t *testing.T) {
			fetcher, cfg, devel := transitiveArchiveRepo(t, local)
			m := Manifest{Arch: "x86_64", SourceDate: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
				Repositories: []config.RepoConfig{cfg}, Packages: []PackageRequest{{Name: "kernel-devel"}}}
			if local {
				// Remove the split package from the active index so only the local
				// candidate's dependency can trigger historical discovery.
				path := filepath.Join(t.TempDir(), "devel.peipkg")
				if err := os.WriteFile(path, devel, 0600); err != nil {
					t.Fatal(err)
				}
				m.LocalPackages = []string{path}
			}
			scanManifest := m
			scanManifest.Packages = []PackageRequest{{Name: "kernel"}}
			scan, err := ScanSources(context.Background(), scanManifest, fetcher, nil)
			if err != nil {
				t.Fatal(err)
			}
			if !scan.archive {
				t.Fatal("scan omitted archive needed by dependency")
			}
			// Prove this is an immutable universe: resolving it needs only the
			// package bytes, not a second repository-index fetch.
			for url := range fetcher {
				if !strings.Contains(url, "/pool/") {
					delete(fetcher, url)
				}
			}
			lock, err := ResolveWithSources(context.Background(), m, "test", fetcher, nil, scan)
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]string{}
			for _, p := range lock.Packages {
				got[p.Name] = p.Version
			}
			if got["kernel"] != "1.0-3" || got["kernel-devel"] != "1.0-3" || len(got) != 2 {
				t.Fatalf("resolved %v, want the matching archived runtime", got)
			}
		})
	}
}

func TestTransitiveArchiveRejectsUntrustedIndex(t *testing.T) {
	fetcher, cfg, _ := transitiveArchiveRepo(t, false)
	fetcher[cfg.BaseURL+"/index/archive.json.sig"] = []byte("invalid signature")
	m := Manifest{Arch: "x86_64", Repositories: []config.RepoConfig{cfg}, Packages: []PackageRequest{{Name: "kernel-devel"}}}
	var warnings bytes.Buffer
	if _, err := Resolve(context.Background(), m, "test", fetcher, &warnings); err == nil {
		t.Fatal("resolved historical dependency from an unauthenticated archive index")
	}
	if !strings.Contains(warnings.String(), "archive index") {
		t.Fatalf("missing archive diagnostic: %s", &warnings)
	}
}

func transitiveArchiveRepo(t *testing.T, local bool) (fakeFetcher, config.RepoConfig, []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	makePackage := func(name, ver string, dependencies []any) ([]byte, map[string]any) {
		var doc map[string]any
		if err := json.Unmarshal(minimalManifestJSON(t, name, ver, "x86_64", 1), &doc); err != nil {
			t.Fatal(err)
		}
		if dependencies != nil {
			doc["dependencies"] = dependencies
		}
		data, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		raw := buildPeipkg(t, data, []testEntry{{Path: "usr/share/" + name + "/payload", Content: []byte("x")}})
		hash := sha256.Sum256(raw)
		return raw, map[string]any{"name": name, "version": ver, "architecture": "x86_64", "dependencies": dependencies,
			"conflicts": []any{}, "size_compressed": len(raw), "size_installed": installedSize(t, raw),
			"hash": map[string]any{"algorithm": "sha256", "value": hex.EncodeToString(hash[:])}, "url": "/pool/" + name + "-" + ver + ".peipkg"}
	}
	current, ce := makePackage("kernel", "1.0-10", []any{})
	archived, ae := makePackage("kernel", "1.0-3", []any{})
	devel, de := makePackage("kernel-devel", "1.0-3", []any{map[string]any{"name": "kernel", "constraint": "= 1.0-3"}})
	sum := sha256.Sum256(current)
	fetcher, cfg := publishFakeRepo(t, pub, priv, current, hex.EncodeToString(sum[:]), installedSize(t, current))
	sign := func(b []byte) []byte {
		digest := sha256.Sum256(b)
		data, err := json.Marshal(map[string]any{"schema_version": 1, "algorithm": "ed25519", "key_fingerprint": signature.Fingerprint(pub), "signature": base64.RawStdEncoding.EncodeToString(ed25519.Sign(priv, digest[:]))})
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	active := []any{ce}
	if !local {
		active = append(active, de)
	}
	for kind, entries := range map[string][]any{"active": active, "archive": {ae}} {
		data, err := json.Marshal(map[string]any{"schema_version": 1, "repo": "official", "kind": kind, "index_version": 7, "generated_at": time.Now().UTC().Add(-time.Hour).Format(time.RFC3339), "packages": entries})
		if err != nil {
			t.Fatal(err)
		}
		fetcher[cfg.BaseURL+"/index/"+kind+".json"] = data
		fetcher[cfg.BaseURL+"/index/"+kind+".json.sig"] = sign(data)
	}
	for _, pair := range []struct {
		entry map[string]any
		raw   []byte
	}{{ce, current}, {ae, archived}, {de, devel}} {
		fetcher[cfg.BaseURL+pair.entry["url"].(string)] = pair.raw
	}
	return fetcher, cfg, devel
}
