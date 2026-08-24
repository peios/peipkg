package version_test

import (
	"testing"

	"github.com/peios/peipkg/internal/version"
)

// PSPU §2.2.2 states the epoch is a non-negative integer and §2.2.4 the
// revision a positive integer, neither with a maximum. §2.2.5's stability
// clause then requires any two conforming implementations to agree on
// every pair of valid version strings.
//
// Holding either field in a platform int broke both halves of that: a
// revision above 2^63 was rejected outright, and one above 2^31 was
// accepted on a 64-bit build while a 32-bit build rejected it — so the
// same code disagreed with itself about which strings are valid.
func TestEpochAndRevisionAreNotBoundedByThePlatformInt(t *testing.T) {
	// Every one of these exceeds int64, so none of them can round-trip
	// through a fixed-width conversion.
	huge := []string{
		"1.0-99999999999999999999",
		"99999999999999999999:1.0-1",
		"340282366920938463463374607431768211456:1.0-2",
	}
	for _, s := range huge {
		if _, err := version.Parse(s); err != nil {
			t.Errorf("Parse(%q): %v — the grammar sets no maximum", s, err)
		}
	}

	// int32 and int64 boundaries: accepted identically on every platform.
	for _, s := range []string{
		"1.0-2147483647", "1.0-2147483648", "1.0-2147483649",
		"1.0-9223372036854775807", "1.0-9223372036854775808",
	} {
		if _, err := version.Parse(s); err != nil {
			t.Errorf("Parse(%q): %v", s, err)
		}
	}
}

// Ordering must stay numeric right through the range where an int would
// have overflowed or wrapped.
func TestOversizedEpochsAndRevisionsStillOrderNumerically(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		// Revisions either side of the int64 ceiling.
		{"1.0-9223372036854775807", "1.0-9223372036854775808", -1},
		{"1.0-9223372036854775808", "1.0-9223372036854775807", 1},
		// A longer digit string is the larger number, not the lesser.
		{"1.0-99999999999999999999", "1.0-100000000000000000000", -1},
		{"1.0-2", "1.0-10", -1},
		// Epochs, which dominate the upstream version entirely.
		{"9223372036854775807:1.0-1", "9223372036854775808:0.1-1", -1},
		{"99999999999999999999:1.0-1", "99999999999999999999:1.0-1", 0},
		// Equal values of differing width cannot occur — a leading zero
		// is rejected — so equality is exact string equality.
		{"1.0-99999999999999999999", "1.0-99999999999999999999", 0},
	}
	for _, tc := range cases {
		a, err := version.Parse(tc.a)
		if err != nil {
			t.Fatalf("Parse(%q): %v", tc.a, err)
		}
		b, err := version.Parse(tc.b)
		if err != nil {
			t.Fatalf("Parse(%q): %v", tc.b, err)
		}
		if got := version.Compare(a, b); got != tc.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}
