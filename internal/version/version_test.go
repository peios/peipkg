package version_test

import (
	"testing"

	"github.com/peios/peipkg/internal/version"
)

func TestParseValid(t *testing.T) {
	cases := []struct {
		in       string
		epoch    int
		upstream string
		revision int
	}{
		{"1.26.2-3", 0, "1.26.2", 3},
		{"1.26.2-rc.1-1", 0, "1.26.2-rc.1", 1}, // upstream may itself contain hyphens
		{"2:0.5.0-1", 2, "0.5.0", 1},
		{"0.22-1", 0, "0.22", 1},
		{"0:1.0-1", 0, "1.0", 1}, // an explicit epoch of zero is well-formed
		{"16beta1-1", 0, "16beta1", 1},
		{"1.0~rc.1-42", 0, "1.0~rc.1", 42},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			v, err := version.Parse(tc.in)
			if err != nil {
				t.Fatalf("Parse(%q): %v", tc.in, err)
			}
			if v.Epoch() != tc.epoch {
				t.Errorf("Epoch: got %d, want %d", v.Epoch(), tc.epoch)
			}
			if v.Upstream() != tc.upstream {
				t.Errorf("Upstream: got %q, want %q", v.Upstream(), tc.upstream)
			}
			if v.Revision() != tc.revision {
				t.Errorf("Revision: got %d, want %d", v.Revision(), tc.revision)
			}
			if v.String() != tc.in {
				t.Errorf("String: got %q, want a verbatim round-trip of %q", v.String(), tc.in)
			}
		})
	}
}

func TestParseInvalid(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"no revision", "1.0"},
		{"empty revision", "1.0-"},
		{"empty upstream", "-1"},
		{"revision is zero", "1.0-0"},
		{"revision has a leading zero", "1.0-01"},
		{"epoch has a leading zero", "01:1.0-1"},
		{"empty epoch", ":1.0-1"},
		{"non-numeric epoch", "x:1.0-1"},
		{"upstream starts with a separator", ".5-1"},
		{"space in the version", "1.0 -1"},
		{"invalid upstream character", "1@0-1"},
		{"non-numeric revision", "1.0-1.5"},
		{"revision-less (constraint form, not a full version)", "1.0-rc.1"},
		{"epoch with no version", "2:"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if v, err := version.Parse(tc.in); err == nil {
				t.Errorf("Parse(%q) should have failed, got %+v", tc.in, v)
			}
		})
	}
}
