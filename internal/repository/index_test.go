package repository_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/peios/peipkg/internal/repository"
)

// hashHex is a syntactically valid 64-hex SHA-256 value.
var hashHex = strings.Repeat("a", 64)

// indexEntry returns a valid package entry as a mutable map.
func indexEntry(name, ver string) map[string]any {
	return map[string]any{
		"name":            name,
		"version":         ver,
		"architecture":    "x86_64",
		"dependencies":    []any{},
		"conflicts":       []any{},
		"size_compressed": 1024,
		"size_installed":  4096,
		"hash":            map[string]any{"algorithm": "sha256", "value": hashHex},
		"url":             "/p/" + name + "/" + ver + "/" + name + "_" + ver + "_x86_64.peipkg",
	}
}

// validIndex returns a well-formed active index as a mutable map.
func validIndex() map[string]any {
	return map[string]any{
		"schema_version": 1,
		"repo":           "peios-official",
		"kind":           "active",
		"index_version":  5,
		"generated_at":   "2026-05-19T00:00:00Z",
		"packages":       []any{indexEntry("nginx", "1.26.2-3")},
	}
}

func decodeIndex(t *testing.T, m map[string]any) (repository.Index, error) {
	t.Helper()
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal index: %v", err)
	}
	return repository.DecodeIndex(data)
}

func TestDecodeIndexValid(t *testing.T) {
	m := validIndex()
	m["packages"] = []any{
		indexEntry("libc", "2.39-1"),
		indexEntry("nginx", "1.26.2-3"),
	}
	idx, err := decodeIndex(t, m)
	if err != nil {
		t.Fatalf("DecodeIndex: %v", err)
	}
	if idx.Kind != repository.IndexActive {
		t.Errorf("Kind: got %q", idx.Kind)
	}
	if idx.IndexVersion != 5 {
		t.Errorf("IndexVersion: got %d", idx.IndexVersion)
	}
	if len(idx.Packages) != 2 || idx.Packages[0].Name != "libc" {
		t.Fatalf("Packages: got %+v", idx.Packages)
	}
	if idx.Packages[1].Version.String() != "1.26.2-3" {
		t.Errorf("entry version: got %q", idx.Packages[1].Version.String())
	}
	if idx.Packages[0].Hash != hashHex {
		t.Errorf("entry hash: got %q", idx.Packages[0].Hash)
	}
}

func TestDecodeArchiveIndexAllowsDuplicateNames(t *testing.T) {
	m := validIndex()
	m["kind"] = "archive"
	// The archive index may list a name more than once (one per version).
	m["packages"] = []any{
		indexEntry("nginx", "1.26.2-3"),
		indexEntry("nginx", "1.26.1-1"),
	}
	idx, err := decodeIndex(t, m)
	if err != nil {
		t.Fatalf("DecodeIndex (archive): %v", err)
	}
	if idx.Kind != repository.IndexArchive || len(idx.Packages) != 2 {
		t.Errorf("archive index: got kind=%q, %d packages", idx.Kind, len(idx.Packages))
	}
}

func TestDecodeIndexCarriesDependencies(t *testing.T) {
	m := validIndex()
	entry := indexEntry("nginx", "1.26.2-3")
	entry["dependencies"] = []any{
		map[string]any{"name": "libc", "constraint": ">= 2.39-1"},
		map[string]any{"name": "libssl"},
	}
	m["packages"] = []any{entry}
	idx, err := decodeIndex(t, m)
	if err != nil {
		t.Fatalf("DecodeIndex: %v", err)
	}
	if deps := idx.Packages[0].Dependencies; len(deps) != 2 || deps[0].Name != "libc" {
		t.Errorf("Dependencies: got %+v", idx.Packages[0].Dependencies)
	}
}

func TestDecodeIndexRejects(t *testing.T) {
	cases := map[string]func(map[string]any){
		"bad schema_version":         func(m map[string]any) { m["schema_version"] = 2 },
		"missing kind":               func(m map[string]any) { delete(m, "kind") },
		"bad kind":                   func(m map[string]any) { m["kind"] = "snapshot" },
		"missing index_version":      func(m map[string]any) { delete(m, "index_version") },
		"non-positive index_version": func(m map[string]any) { m["index_version"] = 0 },
		"missing generated_at":       func(m map[string]any) { delete(m, "generated_at") },
		"non-UTC generated_at": func(m map[string]any) {
			m["generated_at"] = "2026-05-19T00:00:00+02:00"
		},
		"packages not sorted": func(m map[string]any) {
			m["packages"] = []any{indexEntry("nginx", "1.0-1"), indexEntry("libc", "2.0-1")}
		},
		"duplicate name in active index": func(m map[string]any) {
			m["packages"] = []any{indexEntry("nginx", "1.0-1"), indexEntry("nginx", "1.1-1")}
		},
		"entry missing url": func(m map[string]any) {
			e := indexEntry("nginx", "1.0-1")
			delete(e, "url")
			m["packages"] = []any{e}
		},
		"entry bad version": func(m map[string]any) {
			m["packages"] = []any{indexEntry("nginx", "not-a-version")}
		},
		"entry bad hash algorithm": func(m map[string]any) {
			e := indexEntry("nginx", "1.0-1")
			e["hash"] = map[string]any{"algorithm": "md5", "value": hashHex}
			m["packages"] = []any{e}
		},
		"entry negative size": func(m map[string]any) {
			e := indexEntry("nginx", "1.0-1")
			e["size_installed"] = -1
			m["packages"] = []any{e}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			m := validIndex()
			mutate(m)
			if idx, err := decodeIndex(t, m); err == nil {
				t.Errorf("%s should be rejected, got %+v", name, idx)
			}
		})
	}
}
