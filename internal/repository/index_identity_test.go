package repository_test

import (
	"strings"
	"testing"
	"time"

	"github.com/peios/peipkg/internal/repository"
)

// PSPU §5.33 requires an index entry's name, version and architecture to
// be validated against §5.3, §5.5 and §5.8 with the same strictness a
// manifest receives. Only version was checked, so the two paths disagreed
// about what a valid identity is: the same repository content was
// rejected at manifest-decode time and accepted here.
//
// That matters because an index arrives from the network and its values
// flow onward — into installableArch, into the {name} and {arch} URL
// placeholders, and into the consumer's own package database.
//
// The empty cases are absent from these tables because the encoder
// refuses to emit them; the decoder's own missing-field checks cover
// them.
func TestIndexRejectsNonConformingNames(t *testing.T) {
	for name, pkgName := range map[string]string{
		"path traversal":   "foo/../bar",
		"slash":            "foo/bar",
		"uppercase":        "Nginx",
		"too short":        "n",
		"too long":         strings.Repeat("a", 65),
		"leading hyphen":   "-nginx",
		"trailing hyphen":  "nginx-",
		"double separator": "ng--inx",
		"space":            "ngin x",
		"underscore":       "nginx_1",
		"newline":          "nginx\nevil",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := repository.DecodeIndex(indexWith(t, pkgName, "x86_64")); err == nil {
				t.Errorf("DecodeIndex accepted name %q", pkgName)
			}
		})
	}
}

func TestIndexRejectsNonConformingArchitectures(t *testing.T) {
	for name, arch := range map[string]string{
		"uppercase":       "X86_64",
		"leading digit":   "6502",
		"hyphen":          "x86-64",
		"too long":        strings.Repeat("a", 17),
		"path traversal":  "../x86_64",
		"url placeholder": "{arch}",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := repository.DecodeIndex(indexWith(t, "nginx", arch)); err == nil {
				t.Errorf("DecodeIndex accepted architecture %q", arch)
			}
		})
	}
}

func TestIndexAcceptsConformingIdentities(t *testing.T) {
	for _, tc := range []struct{ name, arch string }{
		{"nginx", "x86_64"},
		{"lib32-foo", "noarch"},
		{"libstdc++", "aarch64"},
		{"python3.example", "x86_64"},
	} {
		t.Run(tc.name+"/"+tc.arch, func(t *testing.T) {
			idx, err := repository.DecodeIndex(indexWith(t, tc.name, tc.arch))
			if err != nil {
				t.Fatalf("DecodeIndex: %v", err)
			}
			if len(idx.Packages) != 1 {
				t.Fatalf("packages: got %d, want 1", len(idx.Packages))
			}
			if idx.Packages[0].Name != tc.name || idx.Packages[0].Architecture != tc.arch {
				t.Errorf("identity: got %s/%s", idx.Packages[0].Name, idx.Packages[0].Architecture)
			}
		})
	}
}

// indexWith builds an encoded index carrying one entry with the given
// identity, so a decode can be asserted against it.
func indexWith(t *testing.T, name, arch string) []byte {
	t.Helper()
	e := sampleEntry(t, "placeholder", "1.0.0-1")
	e.Name = name
	e.Architecture = arch
	encoded, err := repository.EncodeIndex(repository.Index{
		RepoName: "r", Kind: repository.IndexActive, IndexVersion: 1,
		GeneratedAt: time.Now().UTC(), Packages: []repository.IndexEntry{e},
	})
	if err != nil {
		t.Fatalf("EncodeIndex(%q, %q): %v", name, arch, err)
	}
	return encoded
}
