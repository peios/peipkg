package version

import "testing"

// PEI-388: a numeric pre-release segment was invisible to the comparison, so
// `1.0~1` sorted *above* the release it precedes. Every Debian-style numeric
// snapshot form is affected, and `peipkg upgrade` pulled the pre-release.
func TestNumericPreReleaseSegmentsSortBelowTheRelease(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		// The reported inversions.
		{"1.0~1-1", "1.0-1", -1},
		{"1.0~2-1", "1.0.1-1", -1},
		{"5.2~20240101-1", "5.2-1", -1},
		{"3.0~2-1", "3.0-1", -1},

		// The equality cases, which were the more damaging half: repopub's
		// deriveActive and the resolver both treat Compare == 0 as identity.
		{"1.0~foo-1", "1.0-foo-1", -1},
		{"1.0~2-1", "1.0-2-1", -1},

		// Ordering within a numeric pre-release tail still works.
		{"1.0~1-1", "1.0~2-1", -1},
		{"1.0~1-1", "1.0~1-2", -1},

		// A numeric pre-release sorts above an alphabetic one, as rule 3 has
		// always had it for the non-tilde forms.
		{"1.0~rc-1", "1.0~1-1", -1},

		// Unaffected cases, asserted so the fix is visibly narrow.
		{"1.0-1", "1.0-1", 0},
		{"1.0-1", "1.0.1-1", -1},
		{"1.0~rc1-1", "1.0-1", -1},
		{"1.0-foo-1", "1.0-1", 1},
		{"1.0~alpha-1", "1.0~a-1", 0},
		{"1.0-alpha-1", "1.0-beta-1", -1},
		{"1.0a1-1", "1.0b1-1", -1},
	}

	for _, tc := range cases {
		a, err := Parse(tc.a)
		if err != nil {
			t.Fatalf("parse %q: %v", tc.a, err)
		}
		b, err := Parse(tc.b)
		if err != nil {
			t.Fatalf("parse %q: %v", tc.b, err)
		}
		if got := Compare(a, b); got != tc.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
		if got := Compare(b, a); got != -tc.want {
			t.Errorf("Compare(%q, %q) = %d, want %d (asymmetry)", tc.b, tc.a, got, -tc.want)
		}
	}
}
