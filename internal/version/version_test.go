package version_test

import (
	"testing"

	"github.com/peios/peipkg/internal/version"
)

func TestParseValid(t *testing.T) {
	cases := []struct {
		in       string
		epoch    string
		upstream string
		revision string
	}{
		{"1.26.2-3", "0", "1.26.2", "3"},
		{"1.26.2-rc.1-1", "0", "1.26.2-rc.1", "1"}, // upstream may itself contain hyphens
		{"2:0.5.0-1", "2", "0.5.0", "1"},
		{"0.22-1", "0", "0.22", "1"},
		{"0:1.0-1", "0", "1.0", "1"}, // an explicit epoch of zero is well-formed
		{"16beta1-1", "0", "16beta1", "1"},
		{"1.0~rc.1-42", "0", "1.0~rc.1", "42"},
		// §2.2.2/§2.2.4 set no maximum: neither of these fits an int32,
		// and the larger does not fit an int64 either.
		{"4294967296:1.0-2147483648", "4294967296", "1.0", "2147483648"},
		{"1.0-99999999999999999999", "0", "1.0", "99999999999999999999"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			v, err := version.Parse(tc.in)
			if err != nil {
				t.Fatalf("Parse(%q): %v", tc.in, err)
			}
			if v.Epoch() != tc.epoch {
				t.Errorf("Epoch: got %q, want %q", v.Epoch(), tc.epoch)
			}
			if v.Upstream() != tc.upstream {
				t.Errorf("Upstream: got %q, want %q", v.Upstream(), tc.upstream)
			}
			if v.Revision() != tc.revision {
				t.Errorf("Revision: got %q, want %q", v.Revision(), tc.revision)
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

// §5.7 defines exactly one relaxation — a constraint operand may *omit*
// the revision — and says nothing about a trailing group that is present
// but malformed. Falling through for those too silently reinterpreted
// `= 1.0-0` as "upstream literally equals `1.0-0`, any revision", which
// matches nothing: the producer got no diagnostic and the dependency
// quietly became unsatisfiable (PEI-421).
func TestParseRelaxedRejectsAMalformedRevision(t *testing.T) {
	for _, s := range []string{
		"1.0-0",  // §5.5 reserves and forbids revision 0
		"1.0-01", // leading zero
		"1.0-",   // present but empty
	} {
		if _, err := version.ParseRelaxed(s); err == nil {
			t.Errorf("ParseRelaxed(%q) accepted a malformed revision", s)
		}
		// The strict path has always rejected these; relaxed now agrees.
		if _, err := version.Parse(s); err == nil {
			t.Errorf("Parse(%q) accepted a malformed revision", s)
		}
	}
}

// The relaxation itself still works: an omitted revision is fine, and a
// trailing group that is not a number at all is part of the upstream
// version rather than a broken revision.
func TestParseRelaxedStillAcceptsTheRelaxation(t *testing.T) {
	for s, wantUpstream := range map[string]string{
		"3.0":     "3.0",
		"1.0-rc1": "1.0-rc1",
		"1.0~rc1": "1.0~rc1",
		"1.0-2":   "1.0", // a real revision is still parsed as one
	} {
		v, err := version.ParseRelaxed(s)
		if err != nil {
			t.Errorf("ParseRelaxed(%q): %v", s, err)
			continue
		}
		if v.Upstream() != wantUpstream {
			t.Errorf("ParseRelaxed(%q).Upstream() = %q, want %q", s, v.Upstream(), wantUpstream)
		}
	}
}
