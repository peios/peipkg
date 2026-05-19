package version_test

import (
	"math/rand/v2"
	"slices"
	"testing"

	"github.com/peios/peipkg/internal/version"
)

// mustParse parses a version the test author asserts is valid.
func mustParse(t *testing.T, s string) version.Version {
	t.Helper()
	v, err := version.Parse(s)
	if err != nil {
		t.Fatalf("Parse(%q): %v", s, err)
	}
	return v
}

// sign normalises an ordering result to -1, 0, or +1.
func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	default:
		return 0
	}
}

// compareVectors are the worked examples from §9.3 — and the §2.2
// end-of-string and aliasing examples — expressed as full version
// strings (a `-1` revision appended where §9.3 wrote a bare upstream).
// want is the expected sign of Compare(a, b).
var compareVectors = []struct {
	a, b string
	want int
}{
	// §9.3 worked-example table.
	{"1.0-1", "1.0-1", 0},             // identical
	{"1.0-1", "2.0-1", -1},            // numeric segment differs
	{"1.10-1", "1.9-1", 1},            // numeric, not lexical
	{"1.0-1", "1.0.1-1", -1},          // longer continues numerically
	{"1.0-1", "1.0-rc.1-1", 1},        // longer continues with a pre-release
	{"1.0-rc.1-1", "1.0-rc.2-1", -1},  // numeric within a pre-release
	{"1.0-alpha-1", "1.0-beta-1", -1}, // pre-release rank alpha(1) < beta(2)
	{"1.0-rc-1", "1.0-pre-1", 1},      // pre-release rank rc(4) > pre(3)
	{"1.0a1-1", "1.0a2-1", -1},        // numeric within a concatenated pre-release
	{"1.0a1-1", "1.0b1-1", -1},        // pre-release rank a(1) < b(2)
	{"1.0~rc1-1", "1.0-1", -1},        // tilde forces pre-release
	{"0:1.0-1", "1:0.5-1", -1},        // epoch dominates
	{"1.0-1", "1.0-2", -1},            // peios revision differs
	{"1.0-foo-1", "1.0-1", 1},         // `foo` is not a pre-release token (rank-5)
	// §2.2 end-of-string handling.
	{"1.0-1", "1.0.alpha-1", 1}, // a pre-release alphabetic tail makes the longer side older
	// §2.2.7.2 aliasing — recognised pre-release tokens compare equal.
	{"1.0~alpha-1", "1.0~a-1", 0},
	{"1.0~beta-1", "1.0~b-1", 0},
	{"1.0~Alpha-1", "1.0~ALPHA-1", 0}, // recognition is case-insensitive
	{"1.0-foo-1", "1.0-zzz-1", -1},    // rank-5 tiebreak by ASCII byte order
	// epoch and revision.
	{"5:1.0-1", "5:1.0-1", 0},
	{"1.0-9", "1.0-10", -1}, // revision compared numerically, not lexically
}

func TestCompare(t *testing.T) {
	for _, tc := range compareVectors {
		t.Run(tc.a+" vs "+tc.b, func(t *testing.T) {
			a, b := mustParse(t, tc.a), mustParse(t, tc.b)
			if got := sign(version.Compare(a, b)); got != tc.want {
				t.Errorf("Compare(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
			}
			// Comparison must be antisymmetric.
			if got := sign(version.Compare(b, a)); got != -tc.want {
				t.Errorf("Compare(%q, %q) = %d, want %d (antisymmetry)",
					tc.b, tc.a, got, -tc.want)
			}
		})
	}
}

func TestEqualAndLess(t *testing.T) {
	older := mustParse(t, "1.0-1")
	newer := mustParse(t, "2.0-1")

	if !older.Less(newer) {
		t.Error("1.0-1 should order before 2.0-1")
	}
	if newer.Less(older) {
		t.Error("2.0-1 should not order before 1.0-1")
	}
	if !older.Equal(mustParse(t, "1.0-1")) {
		t.Error("1.0-1 should equal 1.0-1")
	}
	if older.Equal(newer) {
		t.Error("1.0-1 should not equal 2.0-1")
	}
	// Pre-release token aliases are equivalent.
	if !mustParse(t, "1.0~alpha-1").Equal(mustParse(t, "1.0~a-1")) {
		t.Error("1.0~alpha-1 should equal 1.0~a-1")
	}
}

// TestSortOrder confirms Compare is a usable total order by sorting a
// scrambled but known-ascending sequence back into place.
func TestSortOrder(t *testing.T) {
	ascending := []string{
		"1.0~dev-1", "1.0~alpha-1", "1.0~beta-1", "1.0~pre-1", "1.0~rc-1",
		"1.0-1", "1.0-2", "1.0.1-1", "1.1-1", "2.0-1", "1:0.1-1",
	}
	want := slices.Clone(ascending)

	shuffled := slices.Clone(ascending)
	rng := rand.New(rand.NewPCG(1, 2))
	rng.Shuffle(len(shuffled), func(i, j int) {
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	})

	parsed := make([]version.Version, len(shuffled))
	for i, s := range shuffled {
		parsed[i] = mustParse(t, s)
	}
	slices.SortFunc(parsed, version.Compare)

	got := make([]string, len(parsed))
	for i, v := range parsed {
		got[i] = v.String()
	}
	if !slices.Equal(got, want) {
		t.Errorf("sorted order:\n got  %v\n want %v", got, want)
	}
}
