package pipsig

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func blob() []byte {
	b := make([]byte, BlobLen)
	b[0] = Version
	return b
}

func TestIsSidecarAndTarget(t *testing.T) {
	for path, want := range map[string]bool{
		"usr/lib/firmware/foo.bin.zst.peios.sig": true,
		"usr/lib/firmware/foo.bin.zst":           false,
		".peios.sig":                             false,
		"usr/lib/firmware/.peios.sig":            false,
		"usr/lib/firmware/foo.peios.sig.bak":     false,
	} {
		if got := IsSidecar(path); got != want {
			t.Errorf("IsSidecar(%q) = %v, want %v", path, got, want)
		}
	}
	if got := Target("a/b.zst.peios.sig"); got != "a/b.zst" {
		t.Errorf("Target = %q", got)
	}
}

func TestValidateBlob(t *testing.T) {
	if err := ValidateBlob(blob()); err != nil {
		t.Errorf("valid blob rejected: %v", err)
	}
	if err := ValidateBlob(blob()[:BlobLen-1]); err == nil || !strings.Contains(err.Error(), "3309 bytes") {
		t.Errorf("short blob: %v", err)
	}
	bad := blob()
	bad[0] = 0x02
	if err := ValidateBlob(bad); err == nil || !strings.Contains(err.Error(), "version") {
		t.Errorf("bad version: %v", err)
	}
}

// TestSidecarsApply drives the collector the way a consumer does. Stamp
// is replaced by a recorder: the real one sets a security.* attribute,
// which needs CAP_SYS_ADMIN, and an ordinary test process has none.
func TestSidecarsApply(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "fw.bin")
	if err := os.WriteFile(target, []byte("firmware bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	elf := filepath.Join(dir, "prog")
	if err := os.WriteFile(elf, []byte("\x7fELF\x02\x01\x01"), 0o755); err != nil {
		t.Fatal(err)
	}

	stamped := map[string][]byte{}
	orig := Stamp
	Stamp = func(path string, b []byte) error { stamped[path] = b; return nil }
	t.Cleanup(func() { Stamp = orig })

	var s Sidecars
	if err := s.Add("usr/lib/firmware/fw.bin.peios.sig", bytes.NewReader(blob())); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := s.Add("bad.peios.sig", bytes.NewReader([]byte("nope"))); err == nil {
		t.Error("malformed blob accepted")
	}
	located := map[string]string{"usr/lib/firmware/fw.bin": target}
	locate := func(p string) (string, bool) { v, ok := located[p]; return v, ok }
	if err := s.Apply(locate); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !bytes.Equal(stamped[target], blob()) {
		t.Errorf("stamped %d bytes on %q; want the blob", len(stamped[target]), target)
	}

	// A sidecar whose target the package did not write as a regular file.
	var orphan Sidecars
	_ = orphan.Add("usr/lib/firmware/missing.peios.sig", bytes.NewReader(blob()))
	if err := orphan.Apply(locate); err == nil || !strings.Contains(err.Error(), "no regular-file target") {
		t.Errorf("orphan sidecar: %v", err)
	}
	// A sidecar whose target is ELF: two carriers for one file.
	var two Sidecars
	_ = two.Add("prog.peios.sig", bytes.NewReader(blob()))
	if err := two.Apply(func(string) (string, bool) { return elf, true }); err == nil || !strings.Contains(err.Error(), "ELF") {
		t.Errorf("ELF target: %v", err)
	}
}
