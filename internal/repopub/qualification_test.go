package repopub_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/peios/peipkg/internal/repopub"
	"github.com/peios/peipkg/pack"
)

func qualificationPackage(t *testing.T, key ed25519.PrivateKey, name, ver, path string, deps []pack.Dependency, provides []pack.Provides) string {
	t.Helper()
	dir := t.TempDir()
	payload := filepath.Join(dir, "payload")
	if err := os.WriteFile(payload, []byte(name), 0644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, name+".peipkg")
	f, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	m := pack.Manifest{Name: name, Version: ver, Architecture: "x86_64", Description: "qualification regression fixture", License: "MIT", Dependencies: deps, Provides: provides, Build: pack.BuildInfo{Timestamp: at.Format("2006-01-02T15:04:05Z07:00")}}
	if name == "qualified-runtime" && (ver == "2.0-1" || ver == "4.0-1") {
		m.Replaces = []pack.Replaces{{Name: "legacy"}}
	}
	if err = pack.Pack(pack.PackOptions{Manifest: m, Files: map[string]string{path: payload}, Out: f, SignKey: key}); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	return out
}
func qualification(t *testing.T, dir string, paths ...string) *repopub.Qualification {
	t.Helper()
	base, err := repopub.StateDigest(dir)
	if err != nil {
		t.Fatal(err)
	}
	q := &repopub.Qualification{BaseState: base, Artifacts: map[string]string{}}
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		q.Artifacts[p] = fmt.Sprintf("%x", sha256.Sum256(b))
	}
	return q
}
func TestQualifiedPublicationRejectsBrokenClosureWithoutWrites(t *testing.T) {
	for _, kind := range []string{"missing", "collision", "stale-base", "changed-archive"} {
		t.Run(kind, func(t *testing.T) {
			dir, key := newRepo(t)
			shared := "usr/bin/halt"
			deps := []pack.Dependency{{Name: "runtime", Constraint: ""}}
			first := qualificationPackage(t, key, "consumer", "1.0-1", shared, deps, nil)
			paths := []string{first}
			if kind != "missing" {
				p := "usr/lib/runtime"
				if kind == "collision" {
					p = shared
				}
				paths = append(paths, qualificationPackage(t, key, "runtime", "1.0-1", p, nil, nil))
			}
			q := qualification(t, dir, paths...)
			if kind == "stale-base" {
				q.BaseState = "old"
			}
			if kind == "changed-archive" {
				q.Artifacts[first] = "wrong"
			}
			before, err := repopub.StateDigest(dir)
			if err != nil {
				t.Fatal(err)
			}
			_, err = repopub.Publish(dir, repopub.PublishOptions{Key: key, Paths: paths, GeneratedAt: at, Qualification: q})
			if err == nil {
				t.Fatal("invalid candidate promoted")
			}
			t.Log(err)
			after, err := repopub.StateDigest(dir)
			if err != nil || after != before {
				t.Fatal("failed qualification altered indexes")
			}
			if _, err = os.Stat(filepath.Join(dir, "p")); !os.IsNotExist(err) {
				t.Fatal("failed qualification copied payloads")
			}
		})
	}
}
func TestQualifiedPublicationRenameTransition(t *testing.T) {
	dir, key := newRepo(t)
	old := qualificationPackage(t, key, "legacy", "1.0-1", "usr/bin/halt", nil, nil)
	renamed := qualificationPackage(t, key, "qualified-runtime", "2.0-1", "usr/bin/halt", nil, []pack.Provides{{Name: "legacy"}})
	// Legacy historical package exists but is not selected while the qualified
	// provider sorts ahead of it by version, matching the real rename incident.
	app := qualificationPackage(t, key, "application", "1.0-1", "usr/bin/app", []pack.Dependency{{Name: "legacy"}, {Name: "qualified-runtime"}}, nil)
	publish(t, dir, key, at, old, renamed, app)
	dropped := qualificationPackage(t, key, "qualified-runtime", "3.0-1", "usr/bin/halt", nil, nil)
	q := qualification(t, dir, dropped)
	_, err := repopub.Publish(dir, repopub.PublishOptions{Key: key, Paths: []string{dropped}, GeneratedAt: at, Qualification: q})
	if err == nil || !strings.Contains(err.Error(), "collide") {
		t.Fatalf("alias drop should reject collision: %v", err)
	}
	fixed := qualificationPackage(t, key, "application", "1.0-2", "usr/bin/app", []pack.Dependency{{Name: "qualified-runtime"}}, nil)
	// A public upgrade must also remove the previously installed legacy
	// provider. Correcting only the new consumer's name cannot do that.
	dropped = qualificationPackage(t, key, "qualified-runtime", "4.0-1", "usr/bin/halt", nil, nil)
	q = qualification(t, dir, dropped, fixed)
	if _, err = repopub.Publish(dir, repopub.PublishOptions{Key: key, Paths: []string{dropped, fixed}, GeneratedAt: at, Qualification: q}); err != nil {
		t.Fatal(err)
	}
}
func TestQualifiedPublicationABIDrop(t *testing.T) {
	dir, key := newRepo(t)
	cap := "elfver(libstdc++.so.6:GLIBCXX_3.4.30)"
	runtime := qualificationPackage(t, key, "cpp-runtime", "1.0-1", "usr/lib/cpp", nil, []pack.Provides{{Name: cap}})
	app := qualificationPackage(t, key, "application", "1.0-1", "usr/bin/app", []pack.Dependency{{Name: cap}}, nil)
	publish(t, dir, key, at, runtime, app)
	next := qualificationPackage(t, key, "cpp-runtime", "1.0-2", "usr/lib/cpp", nil, nil)
	_, err := repopub.Publish(dir, repopub.PublishOptions{Key: key, Paths: []string{next}, GeneratedAt: at, Qualification: qualification(t, dir, next)})
	if err == nil {
		t.Fatal("ABI-breaking candidate published")
	}
}

func TestProtectedPublicationRequiresFreshSignedEvidence(t *testing.T) {
	for _, kind := range []string{"valid", "missing", "signature", "changed-log"} {
		t.Run(kind, func(t *testing.T) {
			_, key := keypair(t)
			dir := filepath.Join(t.TempDir(), "repository")
			if err := repopub.Init(dir, repopub.InitOptions{Name: "protected", Key: key, GeneratedAt: at, RequireQualification: true}); err != nil {
				t.Fatal(err)
			}
			pkg := qualificationPackage(t, key, "fixture-app", "1.0-1", "usr/bin/app", nil, nil)
			q := qualification(t, dir, pkg)
			evidenceDir := t.TempDir()
			log := filepath.Join(evidenceDir, "test.log")
			if err := os.WriteFile(log, []byte("fixture passed"), 0600); err != nil {
				t.Fatal(err)
			}
			identity, err := repopub.EvidenceIdentity(log)
			if err != nil {
				t.Fatal(err)
			}
			q.EvidencePath = filepath.Join(evidenceDir, "release.json")
			record := map[string]any{"schema": 1, "qualified": true, "base_repository": q.BaseState, "artifacts": []map[string]string{{"Path": pkg, "SHA256": q.Artifacts[pkg]}}, "evidence": map[string]string{log: identity}}
			data, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(q.EvidencePath, data, 0600); err != nil {
				t.Fatal(err)
			}
			sig := ed25519.Sign(key, data)
			if kind == "signature" {
				sig[0] ^= 1
			}
			if err = os.WriteFile(q.EvidencePath+".sig", sig, 0600); err != nil {
				t.Fatal(err)
			}
			if kind == "missing" {
				if err = os.Remove(log); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "changed-log" {
				if err = os.WriteFile(log, []byte("changed"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			before, err := repopub.StateDigest(dir)
			if err != nil {
				t.Fatal(err)
			}
			_, err = repopub.Publish(dir, repopub.PublishOptions{Key: key, Paths: []string{pkg}, GeneratedAt: at, Qualification: q})
			if kind == "valid" {
				if err != nil {
					t.Fatal(err)
				}
				receipts, e := filepath.Glob(filepath.Join(dir, "releases/*.json"))
				if e != nil || len(receipts) != 1 {
					t.Fatal("release receipt not retained", receipts, e)
				}
			} else {
				if err == nil {
					t.Fatal("invalid evidence promoted")
				}
				after, e := repopub.StateDigest(dir)
				if e != nil || before != after {
					t.Fatal("invalid evidence changed repository")
				}
			}
		})
	}
}
