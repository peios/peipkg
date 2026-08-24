package repository

import "testing"

// PSPU §3.5.4 caps the download at the advertised compressed size plus
// "the lesser of 1% or 16 MiB". Taking the flat 16 MiB made the second
// half of that phrase unreachable: 1% only exceeds 16 MiB above a 1.6 GiB
// package, so every real package was fetched with a wildly over-generous
// bound — a 1 KB package with 16 MB of slack rather than ten bytes.
func TestPackageFetchAllowanceIsTheLesserOfOnePercentOr16MiB(t *testing.T) {
	const mib = 1 << 20
	cases := []struct {
		name           string
		sizeCompressed int64
		want           int64
	}{
		{"a 1 KB package gets ten bytes", 1000, 10},
		{"a 100 MB package gets 1 MB", 100 * 1000 * 1000, 1000000},
		{"1% is still the lesser just under the crossover", 1000 * mib, 1000 * mib / 100},
		{"at 1.6 GiB the two are equal", 1600 * mib, 16 * mib},
		{"above the crossover 16 MiB caps it", 10000 * mib, 16 * mib},
		{"a tiny package gets a tiny allowance", 50, 0},
		// A missing or nonsensical advertised size must not widen the bound.
		{"zero", 0, 0},
		{"negative", -1, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := packageFetchAllowance(tc.sizeCompressed); got != tc.want {
				t.Errorf("packageFetchAllowance(%d) = %d, want %d",
					tc.sizeCompressed, got, tc.want)
			}
		})
	}
}

// The allowance must never exceed the 16 MiB ceiling, whatever is
// advertised — including a size large enough to overflow a naive
// percentage computation.
func TestPackageFetchAllowanceNeverExceedsTheCeiling(t *testing.T) {
	for _, size := range []int64{1 << 40, 1 << 50, 1<<62 - 1} {
		if got := packageFetchAllowance(size); got > maxPackageFetchAllowance {
			t.Errorf("packageFetchAllowance(%d) = %d, above the %d ceiling",
				size, got, int64(maxPackageFetchAllowance))
		}
	}
}
