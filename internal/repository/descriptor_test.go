package repository_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/peios/peipkg/internal/repository"
)

// fp1, fp2 are syntactically valid 64-hex fingerprints in sorted order.
var (
	fp1 = strings.Repeat("1", 64)
	fp2 = strings.Repeat("2", 64)
)

// validDescriptor returns a well-formed descriptor as a mutable map.
func validDescriptor() map[string]any {
	return map[string]any{
		"schema_version": 1,
		"repo": map[string]any{
			"name":        "peios-official",
			"description": "the official Peios repository",
			"signing": map[string]any{
				"algorithm": "ed25519",
				"keys": []any{
					map[string]any{"fingerprint": fp1, "url": "/keys/k1.pub", "status": "active"},
				},
			},
		},
		"indexes": map[string]any{
			"active": map[string]any{
				"url": "/index/active.json", "signature_url": "/index/active.json.sig",
			},
			"archive": map[string]any{
				"url": "/index/archive.json", "signature_url": "/index/archive.json.sig",
			},
		},
	}
}

func decodeDescriptor(t *testing.T, m map[string]any) (repository.Descriptor, error) {
	t.Helper()
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal descriptor: %v", err)
	}
	return repository.DecodeDescriptor(data)
}

func TestDecodeDescriptorValid(t *testing.T) {
	d, err := decodeDescriptor(t, validDescriptor())
	if err != nil {
		t.Fatalf("DecodeDescriptor: %v", err)
	}
	if d.RepoName != "peios-official" {
		t.Errorf("RepoName: got %q", d.RepoName)
	}
	if len(d.Keys) != 1 || d.Keys[0].Fingerprint != fp1 || d.Keys[0].Status != repository.KeyActive {
		t.Errorf("Keys: got %+v", d.Keys)
	}
	if d.ActiveIndex.URL != "/index/active.json" {
		t.Errorf("ActiveIndex.URL: got %q", d.ActiveIndex.URL)
	}
	if d.ArchiveIndex.SignatureURL != "/index/archive.json.sig" {
		t.Errorf("ArchiveIndex.SignatureURL: got %q", d.ArchiveIndex.SignatureURL)
	}
}

func TestDecodeDescriptorTransitioningKey(t *testing.T) {
	m := validDescriptor()
	signing := m["repo"].(map[string]any)["signing"].(map[string]any)
	signing["keys"] = []any{
		map[string]any{"fingerprint": fp1, "url": "/keys/k1.pub", "status": "active"},
		map[string]any{
			"fingerprint": fp2, "url": "/keys/k2.pub",
			"status": "transitioning", "valid_until": "2027-01-01T00:00:00Z",
		},
	}
	d, err := decodeDescriptor(t, m)
	if err != nil {
		t.Fatalf("DecodeDescriptor: %v", err)
	}
	if len(d.Keys) != 2 || d.Keys[1].Status != repository.KeyTransitioning {
		t.Fatalf("Keys: got %+v", d.Keys)
	}
	if d.Keys[1].ValidUntil.IsZero() {
		t.Error("transitioning key ValidUntil was not parsed")
	}
}

func TestDecodeDescriptorRejects(t *testing.T) {
	cases := map[string]func(map[string]any){
		"bad schema_version": func(m map[string]any) { m["schema_version"] = 2 },
		"missing repo":       func(m map[string]any) { delete(m, "repo") },
		"missing indexes":    func(m map[string]any) { delete(m, "indexes") },
		"empty repo name": func(m map[string]any) {
			m["repo"].(map[string]any)["name"] = ""
		},
		"bad signing algorithm": func(m map[string]any) {
			m["repo"].(map[string]any)["signing"].(map[string]any)["algorithm"] = "rsa"
		},
		"no keys": func(m map[string]any) {
			m["repo"].(map[string]any)["signing"].(map[string]any)["keys"] = []any{}
		},
		"no active key": func(m map[string]any) {
			m["repo"].(map[string]any)["signing"].(map[string]any)["keys"] = []any{
				map[string]any{"fingerprint": fp1, "url": "/k.pub", "status": "revoked"},
			}
		},
		"keys not sorted": func(m map[string]any) {
			m["repo"].(map[string]any)["signing"].(map[string]any)["keys"] = []any{
				map[string]any{"fingerprint": fp2, "url": "/k2.pub", "status": "active"},
				map[string]any{"fingerprint": fp1, "url": "/k1.pub", "status": "active"},
			}
		},
		"bad fingerprint": func(m map[string]any) {
			m["repo"].(map[string]any)["signing"].(map[string]any)["keys"] = []any{
				map[string]any{"fingerprint": "short", "url": "/k.pub", "status": "active"},
			}
		},
		"transitioning without valid_until": func(m map[string]any) {
			m["repo"].(map[string]any)["signing"].(map[string]any)["keys"] = []any{
				map[string]any{"fingerprint": fp1, "url": "/k1.pub", "status": "active"},
				map[string]any{"fingerprint": fp2, "url": "/k2.pub", "status": "transitioning"},
			}
		},
		"invalid key status": func(m map[string]any) {
			m["repo"].(map[string]any)["signing"].(map[string]any)["keys"] = []any{
				map[string]any{"fingerprint": fp1, "url": "/k.pub", "status": "expired"},
			}
		},
		"index pointer missing url": func(m map[string]any) {
			m["indexes"].(map[string]any)["active"] = map[string]any{
				"signature_url": "/index/active.json.sig",
			}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			m := validDescriptor()
			mutate(m)
			if d, err := decodeDescriptor(t, m); err == nil {
				t.Errorf("%s should be rejected, got %+v", name, d)
			}
		})
	}
}
