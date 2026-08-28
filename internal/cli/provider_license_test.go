package cli

import (
	"strings"
	"testing"

	"github.com/peios/peipkg/internal/archive"
	"github.com/peios/peipkg/internal/manifest"
	"github.com/peios/peipkg/internal/resolver"
)

// §5.26 step 8: the manifest's license_class must match the index claim
// the plan was computed from; absent and "unknown" are the same claim.
func TestReconcileLicenseClass(t *testing.T) {
	pkg := func(c manifest.LicenseClass) *archive.Package {
		return &archive.Package{Manifest: manifest.Manifest{Name: "x", LicenseClass: c}}
	}
	cand := func(c manifest.LicenseClass) resolver.Candidate {
		return resolver.Candidate{Name: "x", LicenseClass: c}
	}
	for _, ok := range []struct{ index, real manifest.LicenseClass }{
		{"", ""}, {"", manifest.LicenseClassUnknown}, {manifest.LicenseClassUnknown, ""},
		{manifest.LicenseClassFirmware, manifest.LicenseClassFirmware},
	} {
		if err := reconcileWithIndexEntry(cand(ok.index), pkg(ok.real), "x"); err != nil {
			t.Errorf("index %q vs manifest %q: unexpected %v", ok.index, ok.real, err)
		}
	}
	err := reconcileWithIndexEntry(cand(manifest.LicenseClassFree), pkg(manifest.LicenseClassFirmware), "x")
	if err == nil || !strings.Contains(err.Error(), "license_class") {
		t.Errorf("free vs firmware: got %v, want a license_class mismatch", err)
	}
}
