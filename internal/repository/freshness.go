package repository

import "time"

// FreshnessResult is the outcome of the §6.2.3 rollback/freeze check on
// a freshly fetched index.
type FreshnessResult int

const (
	// FreshnessRejected: the index is older than the recorded floor — a
	// rollback. The refresh must fail; trust state is retained (§6.5.4).
	FreshnessRejected FreshnessResult = iota
	// FreshnessNoProgress: the index exactly equals the recorded floor.
	// It is valid but stale; the content may be used, but the
	// last-successful-refresh time MUST NOT advance, so a frozen
	// repository cannot hold a consumer past the maximum trusted age.
	FreshnessNoProgress
	// FreshnessProgress: the index is newer than the floor. The refresh
	// succeeds and the recorded floor advances.
	FreshnessProgress
)

// CheckFreshness applies the §6.2.3 rollback/freeze defence: it compares
// a fetched index against the floor recorded for its repository — the
// highest index_version ever accepted and the generated_at of the
// last-trusted index.
//
// A fresh repository, with no recorded floor, passes any index: a zero
// recordedVersion is below every valid index_version, and a zero
// recordedGeneratedAt is before every real timestamp.
func CheckFreshness(idx Index, recordedVersion int64, recordedGeneratedAt time.Time) FreshnessResult {
	// A rollback in either dimension is rejected, even if the other
	// dimension advanced.
	if idx.IndexVersion < recordedVersion {
		return FreshnessRejected
	}
	if idx.GeneratedAt.Before(recordedGeneratedAt) {
		return FreshnessRejected
	}
	if idx.IndexVersion == recordedVersion && idx.GeneratedAt.Equal(recordedGeneratedAt) {
		return FreshnessNoProgress
	}
	return FreshnessProgress
}
