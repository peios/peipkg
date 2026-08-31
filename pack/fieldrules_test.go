package pack_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/peios/peipkg/pack"
)

// §5.18's field rules are enforced on the producer side: Pack encodes
// the manifest and then decodes it through the consumer's own
// validators before emitting anything, so a non-conforming package
// fails at the farm — which has the recipe, the maintainer and a fast
// feedback loop — rather than at each consumer's install, which has
// none of them (PEI-480).
func TestPackRejectsANonConformingManifest(t *testing.T) {
	base := func() pack.Manifest {
		return pack.Manifest{
			Name: "probe", Version: "1.0-1", Architecture: "x86_64",
			Description: "a conforming description",
			Build: pack.BuildInfo{
				Timestamp: "2026-06-01T00:00:00Z", FarmID: "farm", SourceRef: "ref"},
		}
	}
	// Pack needs a payload; one file is enough.
	dir := t.TempDir()
	src := filepath.Join(dir, "probe")
	if err := os.WriteFile(src, []byte("payload"), 0o755); err != nil {
		t.Fatalf("write: %v", err)
	}
	files := map[string]string{"usr/bin/probe": src}

	// The conforming case packs, so the test measures the rules and not
	// some unrelated refusal.
	var out bytes.Buffer
	if err := pack.Pack(pack.PackOptions{
		Manifest: base(), Files: files, Out: &out}); err != nil {
		t.Fatalf("a conforming manifest did not pack: %v", err)
	}

	for name, mutate := range map[string]func(*pack.Manifest){
		// The rule that surfaced this: 46 shipped manifests carried an em
		// dash and would each have built, published, and failed at install.
		"non-ASCII description": func(m *pack.Manifest) { m.Description = "an em dash — here" },
		"malformed version":     func(m *pack.Manifest) { m.Version = "1.0-0" },
		"bad name grammar":      func(m *pack.Manifest) { m.Name = "Not A Name" },
		"empty architecture":    func(m *pack.Manifest) { m.Architecture = "" },
	} {
		t.Run(name, func(t *testing.T) {
			m := base()
			mutate(&m)
			var buf bytes.Buffer
			err := pack.Pack(pack.PackOptions{Manifest: m, Files: files, Out: &buf})
			if err == nil {
				t.Fatal("a non-conforming manifest packed cleanly")
			}
			if !strings.Contains(err.Error(), "manifest") {
				t.Errorf("error %q does not point at the manifest", err)
			}
		})
	}
}
